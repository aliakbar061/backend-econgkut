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

app = FastAPI(lifespan=lifespan)
api_router = APIRouter(prefix="/api")

# CORS origins: support comma-separated list in env variable
# Format: CORS_ORIGINS=https://econgkut.vercel.app,http://localhost:3000
_cors_env = os.environ.get('CORS_ORIGINS', '')
cors_origins = [o.strip() for o in _cors_env.split(',') if o.strip()]

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
    name: Optional[str] = None
    role: Optional[str] = None
    division: Optional[str] = None
    position: Optional[str] = None

class Location(BaseModel):
    lat: float
    lng: float
    address: Optional[str] = None

class Attendance(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    division: Optional[str] = None
    date: str
    time: str
    status: str
    location: Optional[Location] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttendanceCreate(BaseModel):
    status: str
    location: Optional[Location] = None

class AttendanceUpdate(BaseModel):
    status: str

class FinanceTransactionCreate(BaseModel):
    type: str # 'expense' or 'revenue'
    category: str
    amount: float
    date: str
    notes: Optional[str] = None

class FinanceTransaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    type: str
    category: str
    amount: float
    date: str
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WasteProcessingCreate(BaseModel):
    source_waste_category: str
    weight_processed: float
    result_product: str
    result_quantity: str
    notes: Optional[str] = None

class WasteProcessing(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_by: str
    created_by_name: str
    source_waste_category: str
    weight_processed: float
    result_product: str
    result_quantity: str
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    action: str
    details: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SystemIssueCreate(BaseModel):
    issue_type: str
    description: str
    priority: str = "Sedang"
    contact_info: str = "" 

class SystemIssueUpdateStatus(BaseModel):
    status: str

class SystemIssue(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    reporter_id: str
    reporter_name: str
    reporter_division: Optional[str] = None
    issue_type: str
    description: str
    priority: str = "Sedang"
    contact_info: str = ""
    status: str = "Open" # Open, In Progress, Resolved
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

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



async def log_activity(user_id: str, user_name: str, action: str, details: str):
    try:
        from pydantic import BaseModel
        # Ensure it works even if ActivityLog model is placed differently
        log_entry = {"id": str(uuid.uuid4()), "user_id": user_id, "user_name": user_name, "action": action, "details": details, "created_at": datetime.now(timezone.utc)}
        await db.activity_logs.insert_one(log_entry)
    except Exception as e:
        print(f"Log Error: {e}")

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
        
        
        # Log successful login
        await log_activity(user.id, user.name, "LOGIN", "Berhasil login ke sistem")
        
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
    
    await log_activity(user.id, user.name, "CREATE_BOOKING", f"Membuat pesanan baru untuk {waste_type['name']}")
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
    
    await log_activity(user.id, user.name, "DELETE_BOOKING", f"Membatalkan pesanan {booking_id}")
    return {"success": True, "message": "Booking deleted successfully"}

# ==================== ADMIN ENDPOINTS ====================

@api_router.get("/admin/bookings", response_model=List[Booking])
async def get_all_bookings(request: Request, authorization: Optional[str] = Header(None)):
    """Get all bookings"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Operasional", "Pengolahan", "Operasional & Pengolahan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak. Membutuhkan divisi Operasional & Pengolahan.")
    
    bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    for booking in bookings:
        if isinstance(booking['created_at'], str):
            booking['created_at'] = datetime.fromisoformat(booking['created_at'])
        if isinstance(booking['updated_at'], str):
            booking['updated_at'] = datetime.fromisoformat(booking['updated_at'])
    
    return bookings

@api_router.patch("/admin/bookings/{booking_id}")
async def update_booking_status(booking_id: str, update_data: BookingUpdate, request: Request, authorization: Optional[str] = Header(None)):
    """Update booking status"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Operasional", "Pengolahan", "Operasional & Pengolahan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
    
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
    
    await log_activity(user.id, user.name, "UPDATE_BOOKING_STATUS", f"Mengubah status pesanan {booking_id} menjadi {update_data.status}")
    return {"success": True}

@api_router.delete("/admin/bookings/{booking_id}")
async def admin_delete_booking(booking_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Delete a specific booking (Admin/Operasional only)"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["Operasional", "Pengolahan", "Operasional & Pengolahan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
    
    result = await db.bookings.delete_one({"id": booking_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Booking not found")
        
    await log_activity(user.id, user.name, "DELETE_BOOKING", f"Menghapus pesanan {booking_id}")
    return {"success": True, "message": "Booking deleted successfully"}

@api_router.delete("/admin/bookings")
async def admin_delete_all_bookings(request: Request, authorization: Optional[str] = Header(None)):
    """Delete all bookings (Admin/Operasional only)"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["Operasional", "Pengolahan", "Operasional & Pengolahan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
    
    result = await db.bookings.delete_many({})
    return {"success": True, "message": f"Successfully deleted {result.deleted_count} bookings", "deleted_count": result.deleted_count}

@api_router.get("/admin/stats", response_model=AdminStats)
async def get_admin_stats(request: Request, authorization: Optional[str] = Header(None)):
    """Get admin dashboard stats"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Keuangan", "Operasional", "Pengolahan", "Operasional & Pengolahan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
    
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
    """Get all users"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak. Membutuhkan divisi SDM atau IT.")
    users = await db.users.find({}, {"_id": 0}).to_list(1000)
    return users

@api_router.patch("/admin/users/{user_id}")
async def update_user_admin(
    user_id: str,
    update_data: UserUpdateAdmin,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """Update user role, division, position"""
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
        
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Non-admin cannot modify an admin or Pimpinan user
    if user.role != "admin" and (target_user.get("role") == "admin" or target_user.get("position") == "Pimpinan"):
        raise HTTPException(status_code=403, detail="Anda tidak memiliki izin untuk mengubah data Admin/Pimpinan.")
        
    # Non-admin cannot grant admin role or Pimpinan position
    if update_data.role == "admin" and user.role != "admin":
        raise HTTPException(status_code=403, detail="Anda tidak dapat memberikan akses Admin.")
    if update_data.position == "Pimpinan" and user.role != "admin":
        raise HTTPException(status_code=403, detail="Anda tidak dapat mengatur posisi menjadi Pimpinan.")
    
    # Hanya admin atau Kepala/Pimpinan Divisi yang bisa ganti role
    if update_data.role is not None and user.role != "admin" and user.position not in ["Kepala", "Pimpinan", "Kepala Divisi"]:
        raise HTTPException(status_code=403, detail="Hanya Kepala/Pimpinan Divisi yang bisa mengubah role.")
    
    update_fields = {}
    if update_data.name is not None:
        update_fields["name"] = update_data.name
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
    
    await log_activity(user.id, user.name, "UPDATE_USER", f"Mengubah role/divisi untuk {target_user.get('email', user_id)}")
    return {"success": True}

@api_router.delete("/admin/users/{user_id}")
async def delete_user_admin(
    user_id: str,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    """Delete a user from the system"""
    user = await require_auth(request, authorization)
    
    # Check permissions (only Admin or SDM/IT)
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak.")
        
    target_user = await db.users.find_one({"id": user_id})
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Prevent deleting an admin or Pimpinan if not admin
    if user.role != "admin" and (target_user.get("role") == "admin" or target_user.get("position") == "Pimpinan"):
        raise HTTPException(status_code=403, detail="Anda tidak memiliki izin untuk menghapus data Admin/Pimpinan.")
        
    # Prevent self-deletion
    if user.id == user_id:
        raise HTTPException(status_code=400, detail="Anda tidak dapat menghapus akun Anda sendiri.")

    # Delete the user
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=500, detail="Gagal menghapus pengguna")
    
    await log_activity(user.id, user.name, "DELETE_USER", f"Menghapus pengguna {user_id}")
    return {"success": True, "message": "Pengguna berhasil dihapus"}

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
    )
    
    att_dict = attendance.model_dump()
    att_dict['created_at'] = att_dict['created_at'].isoformat()
    
    # Serialize nested location object jika ada
    if att_dict.get('location') and hasattr(att_dict['location'], '__dict__'):
        att_dict['location'] = att_dict['location'].__dict__
    
    await db.attendance.insert_one(att_dict)
    await log_activity(user.id, user.name, "CREATE_ATTENDANCE", f"Melakukan absensi {data.type}")
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
    
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
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

@api_router.patch("/attendance/{att_id}")
async def update_attendance_status(att_id: str, update_data: AttendanceUpdate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.attendance.update_one(
        {"id": att_id},
        {"$set": {"status": update_data.status}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Attendance record not found")
        
    await log_activity(user.id, user.name, "UPDATE_ATTENDANCE", f"Mengubah status absensi {att_id} menjadi {update_data.status}")
    return {"success": True}

@api_router.delete("/attendance/{att_id}")
async def delete_attendance(att_id: str, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    result = await db.attendance.delete_one({"id": att_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Attendance record not found")
        
    await log_activity(user.id, user.name, "DELETE_ATTENDANCE", f"Menghapus data absensi {att_id}")
    return {"success": True}

@api_router.delete("/attendance/report/all")
async def delete_all_attendance(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    
    if user.role != "admin" and user.division not in ["SDM", "IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    # Hapus semua data absensi
    await db.attendance.delete_many({})
    return {"success": True}

# ==================== FINANCE ENDPOINTS ====================

@api_router.post("/finance/transactions")
async def create_finance_transaction(data: FinanceTransactionCreate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division != "Keuangan" and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    transaction = FinanceTransaction(
        user_id=user.id,
        user_name=user.name,
        type=data.type,
        category=data.category,
        amount=data.amount,
        date=data.date,
        notes=data.notes
    )
    
    t_dict = transaction.model_dump()
    t_dict['created_at'] = t_dict['created_at'].isoformat()
    
    await db.finance_transactions.insert_one(t_dict)
    await log_activity(user.id, user.name, "CREATE_FINANCE", f"Mencatat keuangan {data.type}: Rp {data.amount}")
    return transaction

@api_router.get("/finance/transactions", response_model=List[FinanceTransaction])
async def get_finance_transactions(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division != "Keuangan" and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    transactions = await db.finance_transactions.find({}, {"_id": 0}).sort("date", -1).to_list(1000)
    for t in transactions:
        if isinstance(t.get('created_at'), str):
            t['created_at'] = datetime.fromisoformat(t['created_at'])
    return transactions

@api_router.get("/finance/report")
async def get_finance_report(request: Request, month: Optional[int] = None, year: Optional[int] = None, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division != "Keuangan" and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    # Ambil semua paid bookings (sama persis dengan logic di AdminDashboard)
    all_paid_bookings = await db.bookings.find({"payment_status": "paid"}, {"_id": 0}).to_list(10000)
    all_time_revenue_bookings = sum([b["estimated_price"] for b in all_paid_bookings])
    
    # Filter by month and year if provided
    date_query_finance = {}
    if month and year:
        date_prefix = f"{year}-{month:02d}"
        date_query_finance["date"] = {"$regex": f"^{date_prefix}"}
    
    paid_bookings_monthly = []
    if month and year:
        for b in all_paid_bookings:
            dt = b.get('updated_at') or b.get('created_at')
            if isinstance(dt, str):
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            if dt and dt.month == month and dt.year == year:
                paid_bookings_monthly.append(b)
    else:
        paid_bookings_monthly = all_paid_bookings

    total_revenue_bookings = sum([b["estimated_price"] for b in paid_bookings_monthly])
    
    manual_transactions = await db.finance_transactions.find(date_query_finance, {"_id": 0}).to_list(10000)
    
    total_expense = 0
    total_revenue_manual = 0
    for t in manual_transactions:
        if t["type"] == "expense":
            total_expense += t["amount"]
        elif t["type"] == "revenue":
            total_revenue_manual += t["amount"]
            
    total_revenue = total_revenue_bookings + total_revenue_manual
    net_profit = total_revenue - total_expense
    
    # Hitung all_time_manual
    all_time_manual_tx = await db.finance_transactions.find({}, {"_id": 0}).to_list(10000)
    all_time_revenue_manual = sum([t["amount"] for t in all_time_manual_tx if t["type"] == "revenue"])
    all_time_expense = sum([t["amount"] for t in all_time_manual_tx if t["type"] == "expense"])
    all_time_revenue_total = all_time_revenue_bookings + all_time_revenue_manual
    
    return {
        "revenue_from_bookings": total_revenue_bookings,
        "revenue_from_manual": total_revenue_manual,
        "total_revenue": total_revenue,
        "total_expense": total_expense,
        "net_profit": net_profit,
        "transactions_count": len(manual_transactions),
        "paid_bookings_count": len(paid_bookings_monthly),
        "all_time_revenue": all_time_revenue_total,
        "all_time_expense": all_time_expense
    }

@api_router.delete("/finance/transactions/{tx_id}")
async def delete_finance_transaction(tx_id: str, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Keuangan"] and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    result = await db.finance_transactions.delete_one({"id": tx_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Transaction not found")
        
    await log_activity(user.id, user.name, "DELETE_FINANCE", f"Menghapus transaksi keuangan {tx_id}")
    return {"success": True}


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

@api_router.get("/processing")
async def get_all_processing(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Operasional", "Pengolahan", "Operasional & Pengolahan"] and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    processings = await db.waste_processing.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return processings

@api_router.post("/processing")
async def create_processing(data: WasteProcessingCreate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Operasional", "Pengolahan", "Operasional & Pengolahan"] and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    # Check if there is enough waste available
    # Total accumulated organic/non-organic waste
    pipeline = [
        {"$match": {"status": "completed", "waste_category": data.source_waste_category}},
        {"$group": {"_id": None, "total": {"$sum": "$estimated_weight"}}}
    ]
    result = await db.bookings.aggregate(pipeline).to_list(1)
    total_waste = result[0]["total"] if result else 0

    # Total processed
    pipeline_processed = [
        {"$match": {"source_waste_category": data.source_waste_category}},
        {"$group": {"_id": None, "total": {"$sum": "$weight_processed"}}}
    ]
    result_processed = await db.waste_processing.aggregate(pipeline_processed).to_list(1)
    total_processed = result_processed[0]["total"] if result_processed else 0

    sisa_sampah = total_waste - total_processed

    if data.weight_processed > sisa_sampah:
        raise HTTPException(status_code=400, detail=f"Sisa sampah {data.source_waste_category} tidak mencukupi (sisa: {sisa_sampah} kg).")

    new_processing = WasteProcessing(
        created_by=user.id,
        created_by_name=user.name,
        **data.model_dump()
    )
    
    await db.waste_processing.insert_one(new_processing.model_dump())
    await log_activity(user.id, user.name, "CREATE_PROCESSING", f"Mengolah {data.weight_processed}kg sampah {data.source_waste_category}")
    return {"success": True, "data": new_processing.model_dump()}

@api_router.delete("/processing/{processing_id}")
async def delete_processing(processing_id: str, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "Operasional", "Pengolahan", "Operasional & Pengolahan"] and user.position != "Pimpinan":
        raise HTTPException(status_code=403, detail="Akses ditolak")
        
    result = await db.waste_processing.delete_one({"id": processing_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Data tidak ditemukan")
        
    await log_activity(user.id, user.name, "DELETE_PROCESSING", f"Menghapus data pengolahan {processing_id}")
    return {"success": True}


# ==================== LOGS & ISSUES ====================

@api_router.get("/logs")
async def get_activity_logs(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    logs = await db.activity_logs.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return logs

@api_router.post("/issues")
async def create_issue(data: SystemIssueCreate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    new_issue = SystemIssue(
        reporter_id=user.id,
        reporter_name=user.name,
        reporter_division=user.division,
        **data.model_dump()
    )
    await db.system_issues.insert_one(new_issue.model_dump())
    await log_activity(user.id, user.name, "REPORT_ISSUE", f"Melaporkan kendala: {data.issue_type}")
    return {"success": True, "data": new_issue.model_dump()}

@api_router.get("/issues")
async def get_all_issues(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT", "Pimpinan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    issues = await db.system_issues.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return issues

@api_router.put("/issues/{issue_id}/status")
async def update_issue_status(issue_id: str, data: SystemIssueUpdateStatus, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    
    result = await db.system_issues.update_one(
        {"id": issue_id},
        {"$set": {"status": data.status, "updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Kendala tidak ditemukan")
        
    await log_activity(user.id, user.name, "UPDATE_ISSUE", f"Mengubah status kendala {issue_id} menjadi {data.status}")
    return {"success": True}

# ==================== CORS MIDDLEWARE & ROUTER INCLUSION ====================

# ==================== CORS MIDDLEWARE ====================
# Selalu izinkan: Vercel domains, localhost, dan semua yang ada di CORS_ORIGINS env
_default_origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
]

# Regex: izinkan semua *.vercel.app dan origin dari env
# allow_origin_regex mendukung credentials=True (berbeda dengan allow_origins=["*"])
_vercel_regex = r"https://.*\.vercel\.app"

final_origins = list(set(_default_origins + cors_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=final_origins,
    allow_origin_regex=_vercel_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import dateutil.parser
from datetime import timezone

@api_router.get("/seed_csv_logs")
async def seed_csv_logs():
    csv_data = """id,user_id,user_name,action,details,created_at
act-001,100583532387678793779,Ali Akbar,LOGIN,Berhasil login ke sistem,2025-11-10T08:00:00.000000
act-002,200583532387678793780,Yulianti,LOGIN,Berhasil login ke sistem,2025-11-10T08:05:00.000000
act-003,300583532387678793781,Eka Wahyuni,LOGIN,Berhasil login ke sistem,2025-11-10T08:10:00.000000
act-004,400583532387678793782,Syahru Ramadhan Saharuddin,LOGIN,Berhasil login ke sistem,2025-11-11T07:55:00.000000
act-005,500583532387678793783,Budi Santoso,CREATE_BOOKING,Membuat pesanan baru untuk Sampah Organik (estimasi 30 kg) dengan ID PES-001,2025-11-11T09:00:00.000000
act-006,100583532387678793779,Ali Akbar,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi confirmed,2025-11-11T09:15:00.000000
act-007,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi in-transit,2025-11-11T13:00:00.000000
act-008,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-001 menjadi completed,2025-11-11T14:30:00.000000
act-009,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Membuat pesanan baru untuk Plastik dan Kertas (estimasi 15 kg) dengan ID PES-002,2025-11-12T10:00:00.000000
act-010,200583532387678793780,Yulianti,EXPORT_REPORT,Mengekspor laporan absensi bulan Oktober 2025 ke Excel,2025-11-12T11:00:00.000000
act-011,800583532387678793786,Yasinta Weka,LOGIN,Berhasil login ke sistem,2025-11-13T08:20:00.000000
act-012,800583532387678793786,Yasinta Weka,CREATE_EXPENSE,Menambahkan pengeluaran operasional: Pembelian solar Rp 500.000,2025-11-13T09:00:00.000000
act-013,900583532387678793787,Syahiq Arminanda,LOGIN,Berhasil login ke sistem,2025-11-14T08:00:00.000000
act-014,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup database harian ke Google Drive - sukses,2025-11-15T15:00:00.000000
act-015,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Data karyawan tidak bisa diubah,2025-11-16T09:30:00.000000
act-016,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-001 menjadi Resolved,2025-11-16T10:15:00.000000
act-017,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pemesanan untuk pelanggan tetap: Bapak RT RW (Sampah Campuran 50 kg) ID PES-003,2025-11-17T08:30:00.000000
act-018,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-003 menjadi in-transit,2025-11-17T09:45:00.000000
act-019,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-003 menjadi completed,2025-11-17T11:20:00.000000
act-020,300583532387678793781,Eka Wahyuni,VIEW_DASHBOARD,Melihat dashboard ringkasan pendapatan dan kinerja divisi,2025-11-20T09:00:00.000000
act-021,100583532387678793779,Ali Akbar,CHECK_SYSTEM,Melakukan pengecekan rutin server - semua normal,2025-12-01T08:00:00.000000
act-022,200583532387678793780,Yulianti,MANAGE_USER,Menambahkan user baru: Andi Saputra sebagai staff IT,2025-12-02T10:30:00.000000
act-023,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Menambahkan pendapatan dari pelanggan Budi Santoso Rp 150.000,2025-12-03T14:00:00.000000
act-024,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Memverifikasi pembayaran dari Dewi Kartika,2025-12-04T11:00:00.000000
act-025,400583532387678793782,Syahru Ramadhan Saharuddin,EXPORT_REPORT,Mengekspor laporan operasional bulan November 2025,2025-12-05T09:30:00.000000
act-026,600583532387678793784,Siti Rahima Rahim,INPUT_WEIGHT,Menginput berat sampah pesanan PES-002: 16.5 kg,2025-12-06T08:00:00.000000
act-027,100583532387678793779,Ali Akbar,UPDATE_RBAC,Menambahkan akses untuk divisi baru: Marketing,2025-12-10T13:00:00.000000
act-028,300583532387678793781,Eka Wahyuni,APPROVE_BUDGET,Menyetujui anggaran pembelian alat pengolahan sampah Rp 5.000.000,2025-12-15T10:00:00.000000
act-029,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Fitur absensi tidak sinkron,2026-01-05T08:45:00.000000
act-030,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-002 menjadi In Progress,2026-01-05T09:20:00.000000
act-031,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Mengubah status kendala ISSUE-002 menjadi Resolved - perbaikan sinkronisasi,2026-01-06T11:00:00.000000
act-032,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Membuat pesanan baru untuk Kardus (estimasi 20 kg) ID PES-004,2026-01-10T09:00:00.000000
act-033,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi confirmed,2026-01-10T09:30:00.000000
act-034,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi in-transit,2026-01-10T13:15:00.000000
act-035,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Mengubah status pesanan PES-004 menjadi completed,2026-01-10T15:00:00.000000
act-036,800583532387678793786,Yasinta Weka,EXPORT_FINANCE,Mengekspor laporan keuangan Desember 2025,2026-01-15T10:00:00.000000
act-037,900583532387678793787,Syahiq Arminanda,INPUT_EXPENSE,Input biaya perawatan kendaraan Rp 750.000,2026-01-20T11:30:00.000000
act-038,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup mingguan ke harddisk eksternal - sukses,2026-01-22T16:00:00.000000
act-039,500583532387678793783,Budi Santoso,LOGIN,Berhasil login,2026-02-01T07:00:00.000000
act-040,500583532387678793783,Budi Santoso,CREATE_BOOKING,Pesanan rutin sampah organik 35 kg ID PES-005,2026-02-01T07:15:00.000000
act-041,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-005,2026-02-01T08:00:00.000000
act-042,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-005,2026-02-01T09:30:00.000000
act-043,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-005 - berat 34 kg,2026-02-01T11:00:00.000000
act-044,200583532387678793780,Yulianti,EXPORT_REPORT,Ekspor rekap kehadiran Januari 2026,2026-02-05T09:00:00.000000
act-045,300583532387678793781,Eka Wahyuni,VIEW_REPORT,Melihat laporan laba rugi Januari 2026,2026-02-10T14:00:00.000000
act-046,100583532387678793779,Ali Akbar,CHECK_SERVER,Pengecekan server - response time 1.2 detik,2026-02-15T08:00:00.000000
act-047,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Menambahkan pemasukan dari pelanggan Dewi Kartika Rp 200.000,2026-03-01T09:00:00.000000
act-048,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Memverifikasi pembayaran dari Bapak RT RW,2026-03-02T10:00:00.000000
act-049,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Pesanan plastik dan kaca ID PES-006,2026-03-05T11:00:00.000000
act-050,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-006,2026-03-05T11:30:00.000000
act-051,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-006,2026-03-05T13:00:00.000000
act-052,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-006 - berat 22 kg,2026-03-05T15:30:00.000000
act-053,200583532387678793780,Yulianti,REPORT_ISSUE,Kendala: Laporan evaluasi kinerja tidak muncul,2026-03-10T08:30:00.000000
act-054,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Resolved ISSUE-003 - query error diperbaiki,2026-03-10T10:00:00.000000
act-055,300583532387678793781,Eka Wahyuni,APPROVE_RECRUITMENT,Menyetujui rekrutmen 2 orang karyawan lapangan,2026-03-15T13:00:00.000000
act-056,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup database penuh ke Google Drive,2026-03-25T15:00:00.000000
act-057,800583532387678793786,Yasinta Weka,EXPORT_FINANCE,Ekspor laporan keuangan Maret 2026,2026-04-01T09:00:00.000000
act-058,900583532387678793787,Syahiq Arminanda,INPUT_EXPENSE,Biaya perbaikan mesin pengolahan Rp 1.200.000,2026-04-05T10:30:00.000000
act-059,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pesanan dari pelanggan baru: Toko Makmur (sampah kardus 100 kg) ID PES-007,2026-04-10T08:00:00.000000
act-060,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Confirmed PES-007,2026-04-10T08:30:00.000000
act-061,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-007,2026-04-10T10:00:00.000000
act-062,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-007 - berat 105 kg,2026-04-10T14:00:00.000000
act-063,200583532387678793780,Yulianti,MANAGE_USER,Menonaktifkan akun karyawan yang berhenti: Andi Saputra,2026-04-15T11:00:00.000000
act-064,100583532387678793779,Ali Akbar,UPDATE_RBAC,Menyesuaikan hak akses untuk divisi Keuangan,2026-04-20T09:00:00.000000
act-065,300583532387678793781,Eka Wahyuni,VIEW_DASHBOARD,Melihat dashboard bulan April - pendapatan naik 15%,2026-04-25T08:00:00.000000
act-066,500583532387678793783,Budi Santoso,CREATE_BOOKING,Pesanan rutin 40 kg sampah campuran ID PES-008,2026-05-02T07:00:00.000000
act-067,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-008,2026-05-02T07:45:00.000000
act-068,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-008,2026-05-02T09:00:00.000000
act-069,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-008 - berat 42 kg,2026-05-02T11:30:00.000000
act-070,800583532387678793786,Yasinta Weka,CREATE_REVENUE,Pendapatan dari pesanan PES-008 Rp 210.000,2026-05-02T13:00:00.000000
act-071,200583532387678793780,Yulianti,EXPORT_REPORT,Ekspor rekap evaluasi kinerja April 2026,2026-05-05T09:00:00.000000
act-072,100583532387678793779,Ali Akbar,CHECK_SYSTEM,Pengecekan sistem - semua berjalan normal,2026-05-10T08:00:00.000000
act-073,700583532387678793785,Dewi Kartika,LOGIN,Berhasil login,2026-05-12T10:00:00.000000
act-074,700583532387678793785,Dewi Kartika,CREATE_BOOKING,Pesanan plastik dan kertas ID PES-009,2026-05-12T10:15:00.000000
act-075,400583532387678793782,Syahru Ramadhan Saharuddin,UPDATE_BOOKING_STATUS,Confirmed PES-009,2026-05-12T10:45:00.000000
act-076,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-009,2026-05-12T13:00:00.000000
act-077,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-009 - berat 18 kg,2026-05-12T15:00:00.000000
act-078,900583532387678793787,Syahiq Arminanda,VERIFY_PAYMENT,Verifikasi pembayaran dari Toko Makmur,2026-05-15T11:00:00.000000
act-079,300583532387678793781,Eka Wahyuni,APPROVE_BUDGET,Menyetujui anggaran pengembangan aplikasi ECOngkut,2026-05-20T14:00:00.000000
act-080,100583532387678793779,Ali Akbar,BACKUP_DATA,Backup full + restore test - sukses,2026-05-27T16:00:00.000000
act-081,600583532387678793784,Siti Rahima Rahim,INPUT_WEIGHT,Input berat sampah pesanan PES-010 (belum tercatat),2026-06-01T08:00:00.000000
act-082,400583532387678793782,Syahru Ramadhan Saharuddin,CREATE_BOOKING,Pesanan dari pelanggan "Kenektik 1" untuk Kaca 10 kg ID PES-010,2026-06-02T08:30:00.000000
act-083,100583532387678793779,Ali Akbar,UPDATE_BOOKING_STATUS,Confirmed PES-010,2026-06-02T09:00:00.000000
act-084,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,In-transit PES-010,2026-06-02T10:00:00.000000
act-085,600583532387678793784,Siti Rahima Rahim,UPDATE_BOOKING_STATUS,Completed PES-010,2026-06-02T11:00:00.000000
act-086,200583532387678793780,Yulianti,REPORT_ISSUE,Melaporkan kendala: Export data karyawan lambat,2026-06-02T13:00:00.000000
act-087,100583532387678793779,Ali Akbar,UPDATE_ISSUE,Resolved ISSUE-004 - optimized query,2026-06-02T13:30:00.000000
act-088,300583532387678793781,Eka Wahyuni,VIEW_REPORT,Melihat laporan kinerja bulan Mei,2026-06-02T14:00:00.000000
"""
    lines = csv_data.strip().split('\n')[1:]
    logs = []
    issues = {}
    for line in lines:
        if not line.strip(): continue
        parts = line.split(',')
        if len(parts) >= 6:
            act_id = parts[0]
            user_id = parts[1]
            user_name = parts[2]
            action = parts[3]
            created_at_str = parts[-1]
            details = ','.join(parts[4:-1])
            created_at = dateutil.parser.isoparse(created_at_str).replace(tzinfo=timezone.utc)
            existing = await db.activity_logs.find_one({"id": act_id})
            if not existing:
                logs.append({
                    "id": act_id,
                    "user_id": user_id,
                    "user_name": user_name,
                    "action": action,
                    "details": details,
                    "created_at": created_at
                })
            if action == 'REPORT_ISSUE':
                issue_num = ""
                if act_id == "act-015": issue_num = "ISSUE-001"
                elif act_id == "act-029": issue_num = "ISSUE-002"
                elif act_id == "act-053": issue_num = "ISSUE-003"
                elif act_id == "act-086": issue_num = "ISSUE-004"
                if issue_num:
                    issues[issue_num] = {
                        "id": issue_num,
                        "reporter_id": user_id,
                        "reporter_name": user_name,
                        "reporter_division": "Operasional",
                        "issue_type": "Lainnya",
                        "description": details,
                        "priority": "Sedang",
                        "contact_info": "",
                        "status": "Pending",
                        "created_at": created_at,
                        "updated_at": created_at
                    }
            if action == 'UPDATE_ISSUE':
                if "ISSUE-001" in details and "ISSUE-001" in issues:
                    issues["ISSUE-001"]["status"] = "Resolved"
                    issues["ISSUE-001"]["updated_at"] = created_at
                if "ISSUE-002" in details and "ISSUE-002" in issues:
                    if "In Progress" in details: issues["ISSUE-002"]["status"] = "In Progress"
                    if "Resolved" in details: issues["ISSUE-002"]["status"] = "Resolved"
                    issues["ISSUE-002"]["updated_at"] = created_at
                if "ISSUE-003" in details and "ISSUE-003" in issues:
                    issues["ISSUE-003"]["status"] = "Resolved"
                    issues["ISSUE-003"]["updated_at"] = created_at
                if "ISSUE-004" in details and "ISSUE-004" in issues:
                    issues["ISSUE-004"]["status"] = "Resolved"
                    issues["ISSUE-004"]["updated_at"] = created_at

    if logs:
        await db.activity_logs.insert_many(logs)
    for issue_id, issue_data in issues.items():
        existing_issue = await db.issues.find_one({"id": issue_id})
        if not existing_issue:
            await db.issues.insert_one(issue_data)
        else:
            await db.issues.update_one({"id": issue_id}, {"$set": {"status": issue_data["status"], "updated_at": issue_data["updated_at"]}})

    return {"success": True, "logs_inserted": len(logs), "issues_processed": len(issues)}

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