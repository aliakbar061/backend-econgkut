from fastapi import FastAPI, APIRouter, HTTPException, Request, Header
from fastapi.responses import Response
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict
import uuid
from datetime import datetime, timezone, timedelta
import aiohttp
import stripe

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Stripe configuration
stripe.api_key = os.environ.get('STRIPE_API_KEY', 'sk_test_emergent')

# ==================== MODELS ====================

class User(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    id: str
    email: str
    name: str
    picture: Optional[str] = None
    role: str = "user"  # "user" or "admin"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSession(BaseModel):
    user_id: str
    session_token: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class WasteType(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    category: str  # "organic" or "non-organic"
    price_per_kg: float
    recyclable: bool = False

class BookingCreate(BaseModel):
    pickup_address: str
    waste_type_id: str
    estimated_weight: float  # in kg
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
    status: str = "pending"  # pending, confirmed, in-transit, completed, cancelled
    payment_status: str = "unpaid"  # unpaid, paid
    payment_session_id: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class PaymentTransaction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    booking_id: str
    user_id: str
    session_id: str
    amount: float
    currency: str
    payment_status: str = "pending"  # pending, paid, failed, expired
    metadata: Optional[Dict] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CheckoutRequest(BaseModel):
    booking_id: str
    origin_url: str

class AdminStats(BaseModel):
    total_bookings: int
    pending_bookings: int
    completed_bookings: int
    total_revenue: float
    total_waste_collected: float

# ==================== AUTH HELPERS ====================

async def get_current_user(request: Request, authorization: Optional[str] = Header(None)) -> Optional[User]:
    """Get current user from session token (cookie or header)"""
    session_token = None
    
    # Try cookie first
    if "session_token" in request.cookies:
        session_token = request.cookies["session_token"]
    # Fallback to Authorization header
    elif authorization and authorization.startswith("Bearer "):
        session_token = authorization.replace("Bearer ", "")
    
    if not session_token:
        return None
    
    # Check if session exists and is valid
    session = await db.user_sessions.find_one({
        "session_token": session_token,
        "expires_at": {"$gt": datetime.now(timezone.utc).isoformat()}
    })
    
    if not session:
        return None
    
    # Get user
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

class SessionRequest(BaseModel):
    session_id: str

@api_router.post("/auth/session")
async def create_session(request: SessionRequest, http_request: Request):
    """Exchange session_id for session_token and user data"""
    try:
        # Call Emergent auth service
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                headers={"X-Session-ID": request.session_id}
            ) as resp:
                if resp.status != 200:
                    raise HTTPException(status_code=400, detail="Invalid session ID")
                
                data = await resp.json()
        
        # Check if user exists
        user_doc = await db.users.find_one({"email": data["email"]}, {"_id": 0})
        
        if not user_doc:
            # Create new user
            user = User(
                id=data["id"],
                email=data["email"],
                name=data["name"],
                picture=data.get("picture"),
                role="user"
            )
            user_dict = user.model_dump()
            user_dict['created_at'] = user_dict['created_at'].isoformat()
            await db.users.insert_one(user_dict)
        else:
            user = User(**user_doc)
        
        # Create session
        session_token = data["session_token"]
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        
        session_obj = UserSession(
            user_id=user.id,
            session_token=session_token,
            expires_at=expires_at
        )
        
        session_dict = session_obj.model_dump()
        session_dict['expires_at'] = session_dict['expires_at'].isoformat()
        session_dict['created_at'] = session_dict['created_at'].isoformat()
        
        await db.user_sessions.insert_one(session_dict)
        
        # Return user data and set cookie
        response = Response(
            content=user.model_dump_json(),
            media_type="application/json"
        )
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            secure=True,
            samesite="none",
            path="/",
            max_age=7*24*60*60
        )
        
        return response
        
    except Exception as e:
        logging.error(f"Session creation error: {e}")
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
    
    response = Response(content='{"success": true}', media_type="application/json")
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
    
    # Get waste type details
    waste_type = await db.waste_types.find_one({"id": booking_data.waste_type_id}, {"_id": 0})
    if not waste_type:
        raise HTTPException(status_code=404, detail="Waste type not found")
    
    # Calculate estimated price
    estimated_price = waste_type["price_per_kg"] * booking_data.estimated_weight
    
    # Create booking
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
    
    # Convert ISO string timestamps back to datetime
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
    
    # Convert ISO string timestamps
    if isinstance(booking['created_at'], str):
        booking['created_at'] = datetime.fromisoformat(booking['created_at'])
    if isinstance(booking['updated_at'], str):
        booking['updated_at'] = datetime.fromisoformat(booking['updated_at'])
    
    return Booking(**booking)

# ==================== PAYMENT ENDPOINTS ====================

@api_router.post("/payments/checkout")
async def create_checkout(checkout_req: CheckoutRequest, request: Request, authorization: Optional[str] = Header(None)):
    """Create Stripe checkout session for booking"""
    user = await require_auth(request, authorization)
    
    # Get booking
    booking = await db.bookings.find_one({"id": checkout_req.booking_id, "user_id": user.id}, {"_id": 0})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    if booking["payment_status"] == "paid":
        raise HTTPException(status_code=400, detail="Booking already paid")
    
    # Build URLs from provided origin
    success_url = f"{checkout_req.origin_url}/payment-success?session_id={{CHECKOUT_SESSION_ID}}&booking_id={booking['id']}"
    cancel_url = f"{checkout_req.origin_url}/bookings"
    
    # Create Stripe checkout session
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f"Pickup Sampah - {booking['waste_type_name']}",
                        'description': f"{booking['estimated_weight']} kg sampah {booking['waste_type_name']}",
                    },
                    'unit_amount': int(booking['estimated_price'] * 100),  # Convert to cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                'booking_id': booking['id'],
                'user_id': user.id,
                'user_email': user.email
            }
        )
    except Exception as e:
        logging.error(f"Stripe checkout error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create checkout session: {str(e)}")
    
    # Create payment transaction record
    payment = PaymentTransaction(
        booking_id=booking['id'],
        user_id=user.id,
        session_id=session.id,
        amount=float(booking['estimated_price']),
        currency='usd',
        payment_status='pending',
        metadata={
            'booking_id': booking['id'],
            'user_id': user.id,
            'user_email': user.email
        }
    )
    
    payment_dict = payment.model_dump()
    payment_dict['created_at'] = payment_dict['created_at'].isoformat()
    payment_dict['updated_at'] = payment_dict['updated_at'].isoformat()
    
    await db.payment_transactions.insert_one(payment_dict)
    
    # Update booking with session ID
    await db.bookings.update_one(
        {"id": booking['id']},
        {"$set": {"payment_session_id": session.id}}
    )
    
    return {"url": session.url, "session_id": session.id}

@api_router.get("/payments/status/{session_id}")
async def get_payment_status(session_id: str, request: Request, authorization: Optional[str] = Header(None)):
    """Get payment status"""
    user = await require_auth(request, authorization)
    
    try:
        # Get checkout session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        payment_status = "paid" if session.payment_status == "paid" else "pending"
        
        # Update payment transaction
        payment = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
        
        if payment:
            # Check if already processed to avoid double processing
            if payment["payment_status"] != "paid" and payment_status == "paid":
                # Update payment transaction
                await db.payment_transactions.update_one(
                    {"session_id": session_id},
                    {
                        "$set": {
                            "payment_status": payment_status,
                            "updated_at": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                
                # Update booking
                await db.bookings.update_one(
                    {"id": payment["booking_id"]},
                    {
                        "$set": {
                            "payment_status": "paid",
                            "status": "confirmed",
                            "updated_at": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
        
        return {
            "session_id": session.id,
            "payment_status": payment_status,
            "amount_total": session.amount_total / 100 if session.amount_total else 0,
            "currency": session.currency
        }
    
    except stripe.error.StripeError as e:
        logging.error(f"Stripe error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhooks"""
    try:
        body_bytes = await request.body()
        stripe_signature = request.headers.get("Stripe-Signature")
        
        # Verify webhook signature (optional but recommended)
        webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        
        try:
            if webhook_secret:
                event = stripe.Webhook.construct_event(
                    body_bytes, stripe_signature, webhook_secret
                )
            else:
                event = stripe.Event.construct_from(
                    await request.json(), stripe.api_key
                )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")
        
        # Handle the event
        if event.type == 'checkout.session.completed':
            session = event.data.object
            
            # Update payment transaction
            payment = await db.payment_transactions.find_one({"session_id": session.id}, {"_id": 0})
            
            if payment and payment["payment_status"] != "paid":
                await db.payment_transactions.update_one(
                    {"session_id": session.id},
                    {
                        "$set": {
                            "payment_status": "paid",
                            "updated_at": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
                
                # Update booking
                await db.bookings.update_one(
                    {"id": payment["booking_id"]},
                    {
                        "$set": {
                            "payment_status": "paid",
                            "status": "confirmed",
                            "updated_at": datetime.now(timezone.utc).isoformat()
                        }
                    }
                )
        
        return {"success": True}
    except Exception as e:
        logging.error(f"Webhook error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# ==================== ADMIN ENDPOINTS ====================

@api_router.get("/admin/bookings", response_model=List[Booking])
async def get_all_bookings(request: Request, authorization: Optional[str] = Header(None)):
    """Get all bookings (admin only)"""
    await require_admin(request, authorization)
    
    bookings = await db.bookings.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    
    # Convert ISO string timestamps
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
    
    result = await db.bookings.update_one(
        {"id": booking_id},
        {
            "$set": {
                "status": update_data.status,
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
        }
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
    
    # Calculate total revenue from paid bookings
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

# ==================== SEED DATA ====================

@api_router.post("/seed-data")
async def seed_data():
    """Seed initial waste types data"""
    # Check if data already exists
    count = await db.waste_types.count_documents({})
    if count > 0:
        return {"message": "Data already seeded"}
    
    waste_types = [
        {
            "id": str(uuid.uuid4()),
            "name": "Sisa Makanan",
            "category": "organic",
            "price_per_kg": 2.50,
            "recyclable": False
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Daun & Ranting",
            "category": "organic",
            "price_per_kg": 1.50,
            "recyclable": False
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Plastik",
            "category": "non-organic",
            "price_per_kg": 3.00,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Kertas & Kardus",
            "category": "non-organic",
            "price_per_kg": 2.00,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Logam",
            "category": "non-organic",
            "price_per_kg": 5.00,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Kaca",
            "category": "non-organic",
            "price_per_kg": 2.50,
            "recyclable": True
        },
        {
            "id": str(uuid.uuid4()),
            "name": "Elektronik",
            "category": "non-organic",
            "price_per_kg": 10.00,
            "recyclable": True
        }
    ]
    
    await db.waste_types.insert_many(waste_types)
    
    return {"message": "Data seeded successfully", "count": len(waste_types)}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()