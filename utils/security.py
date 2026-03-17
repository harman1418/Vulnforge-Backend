"""
Security utilities: JWT tokens, password hashing, input validation
"""
import os
import jwt
import bcrypt
import re
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours

# ─── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False


# ─── JWT Token Management ─────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")


def decode_token(token: str) -> Optional[dict]:
    """Safely decode token, return None if invalid"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None


# ─── Input Validation & Sanitization ──────────────────────────────────────────

def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_target(target: str) -> bool:
    """Validate target (domain or URL)"""
    if not target or len(target) > 255:
        return False
    
    # Remove http/https
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    # Allow domains and IPs
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(domain_pattern, clean_target))


def sanitize_target(target: str) -> str:
    """Sanitize and normalize target"""
    if not validate_target(target):
        raise ValueError(f"Invalid target: {target}")
    
    # Ensure http/https
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    
    return target.lower()


def validate_username(username: str) -> bool:
    """Validate username format"""
    pattern = r'^[a-zA-Z0-9_-]{3,32}$'
    return bool(re.match(pattern, username))


def validate_password(password: str) -> tuple[bool, str]:
    """
    Validate password strength
    Returns: (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain digit"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain special character"
    
    return True, "Password is strong"


def validate_otp(otp: str) -> bool:
    """Validate OTP format (6 digits)"""
    return bool(re.match(r'^\d{6}$', otp))


def escape_subprocess_arg(arg: str) -> str:
    """Escape arguments for subprocess to prevent injection"""
    # Allow only safe characters
    if not re.match(r'^[a-zA-Z0-9._\-/:]*$', arg):
        raise ValueError(f"Invalid characters in argument: {arg}")
    return arg


# ─── Error Responses ──────────────────────────────────────────────────────────

class SecurityError(Exception):
    """Base security error"""
    pass


class AuthenticationError(SecurityError):
    """Authentication failed"""
    pass


class ValidationError(SecurityError):
    """Validation failed"""
    pass
