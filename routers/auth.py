from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from utils.database import users_collection, otps_collection
from utils.email import generate_otp, send_otp_email
from datetime import datetime, timedelta
import hashlib
import os

router = APIRouter()

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str

class VerifyOTPRequest(BaseModel):
    email: str
    otp: str

class LoginRequest(BaseModel):
    email: str
    password: str

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

@router.post("/register")
async def register(req: RegisterRequest):
    # Check if user exists
    existing = await users_collection.find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Generate OTP
    otp = generate_otp()
    expiry = datetime.utcnow() + timedelta(minutes=10)

    # Save OTP to database
    await otps_collection.delete_many({"email": req.email})
    await otps_collection.insert_one({
        "email": req.email,
        "otp": otp,
        "expiry": expiry,
        "name": req.name,
        "password": hash_password(req.password)
    })

    # Send OTP email
    sent = send_otp_email(req.email, otp)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email")

    return {
        "status": "success",
        "message": f"OTP sent to {req.email}"
    }

@router.post("/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    # Find OTP
    otp_doc = await otps_collection.find_one({"email": req.email})
    if not otp_doc:
        raise HTTPException(status_code=400, detail="No OTP found for this email")

    # Check expiry
    if datetime.utcnow() > otp_doc["expiry"]:
        raise HTTPException(status_code=400, detail="OTP expired")

    # Check OTP
    if otp_doc["otp"] != req.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Create user
    await users_collection.insert_one({
        "email": req.email,
        "name": otp_doc["name"],
        "password": otp_doc["password"],
        "created_at": datetime.utcnow(),
        "verified": True
    })

    # Delete OTP
    await otps_collection.delete_many({"email": req.email})

    return {
        "status": "success",
        "message": "Account verified successfully!"
    }

@router.post("/login")
async def login(req: LoginRequest):
    user = await users_collection.find_one({"email": req.email})
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    if user["password"] != hash_password(req.password):
        raise HTTPException(status_code=400, detail="Invalid password")

    return {
        "status": "success",
        "message": "Login successful",
        "user": {
            "email": user["email"],
            "name": user["name"]
        }
    }
