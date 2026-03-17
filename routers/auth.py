from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthCredentials
from pydantic import BaseModel, EmailStr, Field
from utils.database import users_collection, otps_collection
from utils.email import generate_otp, send_otp_email
from utils.security import (
    hash_password, verify_password, create_access_token, verify_token,
    validate_email, validate_password, validate_otp
)
from utils.logger import log_info, log_error, log_security_event
from datetime import datetime, timedelta
import os

router = APIRouter()
security = HTTPBearer()

# ─── Request Models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "john@example.com",
                "password": "SecurePass123!"
            }
        }


class VerifyOTPRequest(BaseModel):
    email: EmailStr
    otp: str = Field(..., regex=r'^\d{6}$')


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


# ─── Response Models ──────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds

class UserResponse(BaseModel):
    email: str
    name: str
    created_at: str


# ─── Dependencies ─────────────────────────────────────────────────────────────

async def get_current_user(credentials: HTTPAuthCredentials = Depends(security)):
    """Verify JWT token and return user email"""
    try:
        payload = verify_token(credentials.credentials)
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ─── Auth Endpoints ───────────────────────────────────────────────────────────

@router.post("/register", status_code=200)
async def register(req: RegisterRequest):
    """
    Register new user with OTP verification
    """
    try:
        # Validate inputs
        if not validate_email(req.email):
            raise HTTPException(status_code=400, detail="Invalid email format")
        
        is_strong, msg = validate_password(req.password)
        if not is_strong:
            raise HTTPException(status_code=400, detail=msg)
        
        # Check if user exists
        existing_user = await users_collection.find_one({"email": req.email})
        if existing_user:
            log_security_event("DUPLICATE_REGISTRATION_ATTEMPT", user=req.email)
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Generate OTP
        otp = generate_otp()
        hashed_password = hash_password(req.password)
        
        # Store OTP with expiry (10 minutes)
        await otps_collection.insert_one({
            "email": req.email,
            "otp": otp,
            "name": req.name,
            "password": hashed_password,
            "created_at": datetime.utcnow(),
            "expiry": datetime.utcnow() + timedelta(minutes=10)
        })
        
        # Send OTP email
        try:
            send_otp_email(req.email, otp)
        except Exception as e:
            log_error("Failed to send OTP email", error=e, email=req.email)
            raise HTTPException(status_code=500, detail="Failed to send OTP")
        
        log_info("User registered successfully", email=req.email)
        
        return {
            "status": "success",
            "message": "OTP sent to email. Please verify within 10 minutes."
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log_error("Registration error", error=e)
        raise HTTPException(status_code=500, detail="Registration failed")


@router.post("/verify-otp", status_code=200)
async def verify_otp(req: VerifyOTPRequest):
    """
    Verify OTP and create user account
    """
    try:
        if not validate_otp(req.otp):
            raise HTTPException(status_code=400, detail="Invalid OTP format")
        
        # Find OTP
        otp_doc = await otps_collection.find_one({"email": req.email})
        if not otp_doc:
            log_security_event("INVALID_OTP_REQUEST", user=req.email)
            raise HTTPException(status_code=400, detail="No OTP found for this email")
        
        # Check expiry
        if datetime.utcnow() > otp_doc["expiry"]:
            await otps_collection.delete_one({"email": req.email})
            raise HTTPException(status_code=400, detail="OTP expired")
        
        # Check OTP
        if otp_doc["otp"] != req.otp:
            log_security_event("INVALID_OTP_ATTEMPT", user=req.email)
            raise HTTPException(status_code=400, detail="Invalid OTP")
        
        # Create user with verified status
        await users_collection.insert_one({
            "email": req.email,
            "name": otp_doc["name"],
            "password": otp_doc["password"],
            "created_at": datetime.utcnow(),
            "verified": True,
            "last_login": None
        })
        
        # Delete OTP
        await otps_collection.delete_one({"email": req.email})
        
        log_security_event("USER_VERIFIED", user=req.email)
        
        return {
            "status": "success",
            "message": "Account verified successfully!"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log_error("OTP verification error", error=e, email=req.email)
        raise HTTPException(status_code=500, detail="Verification failed")


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    """
    Login user and return JWT tokens
    """
    try:
        # Find user
        user = await users_collection.find_one({"email": req.email})
        if not user:
            log_security_event("LOGIN_FAILED_USER_NOT_FOUND", user=req.email)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        if not verify_password(req.password, user["password"]):
            log_security_event("LOGIN_FAILED_INVALID_PASSWORD", user=req.email)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Create tokens
        access_token = create_access_token({
            "email": user["email"],
            "name": user["name"]
        })
        
        refresh_token = create_access_token(
            {"email": user["email"], "type": "refresh"},
            expires_delta=timedelta(days=7)
        )
        
        # Update last login
        await users_collection.update_one(
            {"email": req.email},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        log_security_event("LOGIN_SUCCESS", user=req.email)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 24 * 60 * 60  # 24 hours in seconds
        }
    
    except HTTPException:
        raise
    except Exception as e:
        log_error("Login error", error=e, email=req.email)
        raise HTTPException(status_code=500, detail="Login failed")


@router.post("/refresh-token", response_model=TokenResponse)
async def refresh_token(req: RefreshTokenRequest):
    """
    Refresh access token using refresh token
    """
    try:
        payload = verify_token(req.refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        email = payload.get("email")
        user = await users_collection.find_one({"email": email})
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Create new access token
        access_token = create_access_token({
            "email": user["email"],
            "name": user["name"]
        })
        
        return {
            "access_token": access_token,
            "refresh_token": req.refresh_token,
            "token_type": "bearer",
            "expires_in": 24 * 60 * 60
        }
    
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        log_error("Token refresh error", error=e)
        raise HTTPException(status_code=500, detail="Token refresh failed")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    """
    Get current user information
    """
    try:
        user = await users_collection.find_one({"email": current_user})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "email": user["email"],
            "name": user["name"],
            "created_at": user["created_at"].isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        log_error("Get user info error", error=e, email=current_user)
        raise HTTPException(status_code=500, detail="Failed to get user info")


@router.post("/logout", status_code=200)
async def logout(current_user: str = Depends(get_current_user)):
    """
    Logout user (client should discard tokens)
    """
    log_security_event("USER_LOGOUT", user=current_user)
    return {"status": "success", "message": "Logged out successfully"}
