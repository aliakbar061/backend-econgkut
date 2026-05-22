from fastapi import FastAPI, APIRouter, HTTPException, Request, Header
from fastapi.responses import Response, JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from contextlib import asynccontextmanager
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', '')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'econgkut_db')]

# Lifespan event handler
@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.info("Application starting up...")
    yield
    logging.info("Application shutting down...")
    client.close()

cors_origins = os.environ.get('CORS_ORIGINS')


# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    email: str
    name: str
    picture: Optional[str] = None
    role: str = "user"
    division: Optional[str] = None
    position: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WasteType(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    category: str
    price_per_kg: float
    recyclable: bool = False

class BookingCreate(BaseModel):
    pickup_address: str
    waste_type_id: str
    estimated_weight: float
    pickup_date: str
    pickup_time: str
    notes: Optional[str] = None

class BookingUpdate(BaseModel):
    status: str

class Booking(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_email: str
    pickup_address: str
    waste_type_id: str
    waste_type_name: str
    waste_category: str
    estimated_weight: float
    estimated_price: float
    pickup_date: str
    pickup_time: str
    notes: Optional[str] = None
    status: str = "pending"
    payment_status: str = "unpaid"
    payment_session_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AdminStats(BaseModel):
    total_bookings: int
    pending_bookings: int
    completed_bookings: int
    total_revenue: float
    total_waste_collected: float

class UserUpdateAdmin(BaseModel):
    role: Optional[str] = None
    division: Optional[str] = None
    position: Optional[str] = None

class Location(BaseModel):
    lat: float
    lng: float

class Attendance(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    division: Optional[str] = None
    date: str
    time: str
    status: str
    location: Optional[Location] = None
    photo_base64: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttendanceCreate(BaseModel):
    status: str
    location: Optional[Location] = None
    photo_base64: Optional[str] = None

# ==================== CREATE APP & ROUTER ====================

app = FastAPI(lifespan=lifespan)
api_router = APIRouter(prefix="/api")

# ==================== AUTH HELPERS ====================

async def get_current_user(request: Request, authorization: Optional[str] = Header(None)) -> Optional[User]:
    """Get current user from session token (cookie or header)"""
    session_token = None
    
    if "session_token" in request.cookies:
        session_token = request.cookies["session_token"]
    elif authorization and authorization.startswith("Bearer "):
        session_token = authorization.replace("Bearer ", "")
    
    if not session_token:
        return None
    
    # ✅ FIX: Gunakan datetime object untuk comparison, bukan string
    session = await db.user_sessions.find_one({
        "session_token": session_token,
        "expires_at": {"$gt": datetime.now(timezone.utc).isoformat()}
    })
    
    if not session:
        return None
    
    user_doc = await db.users.find_one({"id": session["user_id"]}, {"_id": 0})
    if not user_doc:
        return None
    
    return User(**user_doc)

async def require_auth(request: Request, authorization: Optional[str] = Header(None)) -> User:
    """Require authentication"""
    user = await get_current_user(request, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

async def require_admin(request: Request, authorization: Optional[str] = Header(None)) -> User:
    """Require admin role"""
    user = await require_auth(request, authorization)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ==================== AUTH ENDPOINTS ====================

class GoogleAuthRequest(BaseModel):
    token: str
    user: Dict

@api_router.post("/auth/google")
async def google_auth(auth_data: GoogleAuthRequest):
    """Verify Google token and create session"""
    try:
        idinfo = id_token.verify_oauth2_token(
            auth_data.token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )
        
        google_user_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', email)
        picture = idinfo.get('picture')
        
        user_doc = await db.users.find_one({"email": email}, {"_id": 0})
        
        if not user_doc:
            user = User(
                id=google_user_id,
                email=email,
                name=name,
                picture=picture,
                role="user"
            )
            user_dict = user.model_dump()
            user_dict['created_at'] = user_dict['created_at'].isoformat()
            await db.users.insert_one(user_dict)
        else:
            user = User(**user_doc)
            if picture and user_doc.get('picture') != picture:
                await db.users.update_one(
                    {"email": email},
                    {"$set": {"picture": picture}}
                )
        
        session_token = str(uuid.uuid4())
        # ✅ FIX: Perpanjang expire time ke 30 hari
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        session_obj = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        
        session_dict = session_obj.model_dump()
        session_dict['expires_at'] = session_dict['expires_at'].isoformat()
        session_dict['created_at'] = session_dict['created_at'].isoformat()
        
        await db.user_sessions.delete_many({"user_id": user.id})
        await db.user_sessions.insert_one(session_dict)
        
        response_data = {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "picture": user.picture,
            "role": user.role,
            "sessionToken": session_token
        }
        
        return JSONResponse(content=response_data)
        
    except ValueError as e:
        logging.error(f"Invalid Google token: {e}")
        raise HTTPException(status_code=401, detail="Invalid Google token")
    except Exception as e:
        logging.error(f"Google auth error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/auth/me")
async def get_me(request: Request, authorization: Optional[str] = Header(None)):
    """Get current user info"""
    user = await require_auth(request, authorization)
    return user

@api_router.post("/auth/logout")
async def logout(request: Request, authorization: Optional[str] = Header(None)):
    """Logout user"""
    session_token = request.cookies.get("session_token")
    if not session_token and authorization:
        session_token = authorization.replace("Bearer ", "")
    
    if session_token:
        await db.user_sessions.delete_one({"session_token": session_token})
    
    response = JSONResponse(content={"success": True})
    response.delete_cookie("session_token", path="/")
    return response

# ==================== WASTE TYPES ENDPOINTS ====================

@api_router.get("/waste-types", response_model=List[WasteType])
async def get_waste_types():
    """Get all waste types"""
    waste_types = await db.waste_types.find({}, {"_id": 0}).to_list(100)
    return waste_types

# ==================== BOOKING ENDPOINTS ====================

@api_router.post("/bookings")
async def create_booking(booking_data: BookingCreate, request: Request, authorization: Optional[str] = Header(None)):
    """Create a new booking"""
    user = await require_auth(request, authorization)
    
    waste_type = await db.waste_types.find_one({"id": booking_data.waste_type_id}, {"_id": 0})
    if not waste_type:
        raise HTTPException(status_code=404, detail="Waste type not found")
    
    estimated_price = waste_type["price_per_kg"] * booking_data.estimated_weight
    
    booking = Booking(
        user_id=user.id,
        user_email=user.email,
        pickup_address=booking_data.pickup_address,
        waste_type_id=waste_type["id"],
        waste_type_name=waste_type["name"],
        waste_category=waste_type["category"],
        estimated_weight=booking_data.estimated_weight,
        estimated_price=estimated_price,
        pickup_date=booking_data.pickup_date,
        pickup_time=booking_data.pickup_time,
        notes=booking_data.notes,
        status="pending",
        payment_status="unpaid"
    )
    
    booking_dict = booking.model_dump()
    booking_dict['created_at'] = booking_dict['created_at'].isoformat()
    booking_dict['updated_at'] = booking_dict['updated_at'].isoformat()
    
    await db.bookings.insert_one(booking_dict)
    
    return booking

@api_router.get("/bookings", response_model=List[Booking])
async def get_user_bookings(request: Request, authorization: Optional[str] = Header(None)):
    """Get user's bookings"""
    user = await require_auth(request, authorization)
    
    bookings = await db.bookings.find({"user_id": user.id}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for booking in bookings:
        if isinstance(booking['created_at'], str):
            booking['created_at'] = datetime.fromisoformat(booking['created_at'])
        if isinstance(booking['updated_at'], str):
            booking['updated_at'] = datetime.fromisoformat(booking['updated_at'])
    
    return bookings

@api_router.get("/bookings/{booking_id}", response_model=Booking)
async def get_booking(booking_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Get booking details"""
    user = await require_auth(request, authorization)
    
    booking = await db.bookings.find_one({"id": booking_id, "user_id": user.id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    if isinstance(booking['created_at'], str):
        booking['created_at'] = datetime.fromisoformat(booking['created_at'])
    if isinstance(booking['updated_at'], str):
        booking['updated_at'] = datetime.fromisoformat(booking['updated_at'])
    
    return Booking(**booking)

@api_router.patch("/bookings/{booking_id}/confirm")
async def confirm_booking(
    booking_id: str, 
    request: Request, 
    authorization: Optional[str] = Header(None)
):
    """Confirm a booking (change status from pending to confirmed)"""
    user = await require_auth(request, authorization)
    
    booking = await db.bookings.find_one({"id": booking_id, "user_id": user.id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    if booking["status"] != "pending":
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot confirm booking with status: {booking['status']}"
        )
    
    result = await db.bookings.update_one(
        {"id": booking_id, "user_id": user.id},
        {
            "$set": {
                "status": "confirmed",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=500, detail="Failed to confirm booking")
    
    updated_booking = await db.bookings.find_one({"id": booking_id}, {"_id": 0})
    
    if isinstance(updated_booking['created_at'], str):
        updated_booking['created_at'] = datetime.fromisoformat(updated_booking['created_at'])
    if isinstance(updated_booking['updated_at'], str):
        updated_booking['updated_at'] = datetime.fromisoformat(updated_booking['updated_at'])
    
    return Booking(**updated_booking)

# ==================== DELETE BOOKING ENDPOINT ====================

@api_router.delete("/bookings/{booking_id}")
async def delete_booking(booking_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Delete a booking (user can only delete their own bookings)"""
    user = await require_auth(request, authorization)
    
    # Find booking and verify ownership
    booking = await db.bookings.find_one({"id": booking_id, "user_id": user.id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Check if booking can be deleted (only pending or cancelled bookings)
    if booking["status"] not in ["pending", "cancelled"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete booking with status: {booking['status']}. Only pending or cancelled bookings can be deleted."
        )
    
    # Delete the booking
    result = await db.bookings.delete_one({"id": booking_id, "user_id": user.id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=500, detail="Failed to delete booking")
    
    return {"success": True, "message": "Booking deleted successfully"}

# ==================== ADMIN ENDPOINTS ====================

@api_router.get("/admin/bookings", response_model=List[Booking])
async def get_all_bookings(request: Request, authorization: Optional[str] = Header(None)):
    """Get all bookings (admin only)"""
    await require_admin(request, authorization)
    
    bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for booking in bookings:
        if isinstance(booking['created_at'], str):
            booking['created_at'] = datetime.fromisoformat(booking['created_at'])
        if isinstance(booking['updated_at'], str):
            booking['updated_at'] = datetime.fromisoformat(booking['updated_at'])
    
    return bookings

@api_router.patch("/admin/bookings/{booking_id}")
async def update_booking_status(booking_id: str, update_data: BookingUpdate, request: Request, authorization: Optional[str] = Header(None)):
    """Update booking status (admin only)"""
    await require_admin(request, authorization)
    
    # ✅ Prepare update data
    update_fields = {
        "status": update_data.status,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    # ✅ LOGIKA: Auto update payment_status ke "paid" jika status menjadi "completed"
    if update_data.status == "completed":
        update_fields["payment_status"] = "paid"
    
    result = await db.bookings.update_one(
        {"id": booking_id},
        {"$set": update_fields}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    return {"success": True}

@api_router.get("/admin/stats", response_model=AdminStats)
async def get_admin_stats(request: Request, authorization: Optional[str] = Header(None)):
    """Get admin dashboard stats"""
    await require_admin(request, authorization)
    
    total_bookings = await db.bookings.count_documents({})
    pending_bookings = await db.bookings.count_documents({"status": "pending"})
    completed_bookings = await db.bookings.count_documents({"status": "completed"})
    
    paid_bookings = await db.bookings.find({"payment_status": "paid"}, {"_id": 0}).to_list(10000)
    total_revenue = sum([b["estimated_price"] for b in paid_bookings])
    total_waste_collected = sum([b["estimated_weight"] for b in paid_bookings if b["status"] == "completed"])
    
    return AdminStats(
        total_bookings=total_bookings,
        pending_bookings=pending_bookings,
        completed_bookings=completed_bookings,
        total_revenue=total_revenue,
        total_waste_collected=total_waste_collected
    )

@api_router.get("/admin/users")
async def get_all_users(request: Request, authorization: Optional[str] = Header(None)):
    """Get all users (admin only)"""
    await require_admin(request, authorization)
    users = await db.users.find({}, {"_id": 0}).to_list(1000)
    return users

@api_router.patch("/admin/users/{user_id}")
async def update_user_admin(
    user_id: str,
    update_data: UserUpdateAdmin,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """Update user role, division, position (admin only)"""
    await require_admin(request, authorization)
    
    update_fields: Dict[str, Any] = {}
    if update_data.role is not None:
        update_fields["role"] = update_data.role
    if update_data.division is not None:
        update_fields["division"] = update_data.division
    if update_data.position is not None:
        update_fields["position"] = update_data.position
    
    if not update_fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    result = await db.users.update_one({"id": user_id}, {"$set": update_fields})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"success": True}

# ==================== SEED DATA ====================

# ==================== ATTENDANCE ENDPOINTS ====================

@api_router.post("/attendance")
async def create_attendance(data: AttendanceCreate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    
    # Check Waktu (WITA = UTC+8)
    now_utc = datetime.now(timezone.utc)
    wita_timezone = timezone(timedelta(hours=8))
    now_wita = now_utc.astimezone(wita_timezone)
    
    date_str = now_wita.strftime("%Y-%m-%d")
    time_str = now_wita.strftime("%H:%M:%S")
    
    # Logic status
    final_status = data.status
    if data.status == "Hadir":
        hour = now_wita.hour
        # If after 08:00, marked as Terlambat
        if hour >= 8 and (hour > 8 or now_wita.minute > 0):
            final_status = "Terlambat"
            
    user_dict = user.model_dump()
    attendance = Attendance(
        user_id=user.id,
        user_name=user.name,
        division=user_dict.get("division", "Umum"),
        date=date_str,
        time=time_str,
        status=final_status,
        location=data.location,
        photo_base64=data.photo_base64
    )
    
    att_dict = attendance.model_dump()
    att_dict['created_at'] = att_dict['created_at'].isoformat()
    
    await db.attendance.insert_one(att_dict)
    return attendance

@api_router.get("/attendance/me", response_model=List[Attendance])
async def get_my_attendance(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    records = await db.attendance.find({"user_id": user.id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    for r in records:
        if isinstance(r.get('created_at'), str):
            r['created_at'] = datetime.fromisoformat(r['created_at'])
    return records

@api_router.get("/attendance/report", response_model=List[Attendance])
async def get_attendance_report(month: int, year: int, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    
    if user.role not in ["admin", "staff"]:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    date_prefix = f"{year}-{month:02d}"
    query = {"date": {"$regex": f"^{date_prefix}"}}
    
    user_dict = user.model_dump()
    if user.role == "staff" and user_dict.get("position") == "Kepala Divisi":
        if user_dict.get("division"):
            query["division"] = user_dict.get("division")
            
    records = await db.attendance.find(query, {"_id": 0}).sort("created_at", -1).to_list(1000)
    for r in records:
        if isinstance(r.get('created_at'), str):
            r['created_at'] = datetime.fromisoformat(r['created_at'])
    return records

@api_router.post("/seed-data")
async def seed_data():
    """Seed initial waste types data"""
    count = await db.waste_types.count_documents({})
    if count > 0:
        return {"message": "Data already seeded"}
    
    waste_types = [
        {
            "id": str(uuid.uuid4()),
            "name": "Sisa Makanan",
            "category": "organic",
            "price_per_kg": 5000,
            "recyclable": False
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Daun & Ranting",
            "category": "organic",
            "price_per_kg": 6000,
            "recyclable": False
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Plastik",
            "category": "non-organic",
            "price_per_kg": 10000,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Kertas & Kardus",
            "category": "non-organic",
            "price_per_kg": 8000,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Logam",
            "category": "non-organic",
            "price_per_kg": 15000,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Kaca",
            "category": "non-organic",
            "price_per_kg": 20000,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Elektronik",
            "category": "non-organic",
            "price_per_kg": 15000,
            "recyclable": True
        }
    ]
    
    await db.waste_types.insert_many(waste_types)
    
    return {"message": "Data seeded successfully", "count": len(waste_types)}

# ==================== MIDDLEWARE & ROUTER ====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.get("/")
async def root():
    return {"status": "ok", "message": "Econgkut API is running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}