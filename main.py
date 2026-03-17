from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from routers import (
    portscan, subdomain, whois_lookup, headers, waf,
    ssl_scan, wpscan, sqli, xss, nuclei_scan,
    gobuster_scan, hydra_scan, auth, fullscan, history, targets
)
from utils.logger import log_info, log_error, log_security_event
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# ─── FastAPI App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="VulnForge API",
    description="Autonomous Penetration Testing Platform",
    version="2.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

# ─── Rate Limiter ─────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    log_security_event("RATE_LIMIT_EXCEEDED", ip=request.client.host)
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Please try again later."}
    )

# ─── Security Middleware ──────────────────────────────────────────────────────

# CORS - Restrict origins
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)

# Trusted Host middleware
TRUSTED_HOSTS = os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1,*.azurewebsites.net").split(",")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=TRUSTED_HOSTS
)

# ─── Logging Middleware ───────────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all HTTP requests"""
    start_time = datetime.utcnow()
    
    # Log request
    log_info(
        f"{request.method} {request.url.path}",
        method=request.method,
        path=request.url.path,
        ip=request.client.host if request.client else "unknown"
    )
    
    try:
        response = await call_next(request)
        
        # Log response
        duration = (datetime.utcnow() - start_time).total_seconds()
        log_info(
            f"{request.method} {request.url.path} - {response.status_code}",
            status_code=response.status_code,
            duration_seconds=duration
        )
        
        return response
    
    except Exception as e:
        duration = (datetime.utcnow() - start_time).total_seconds()
        log_error(
            f"Request error: {request.method} {request.url.path}",
            error=e,
            duration_seconds=duration
        )
        raise

# ─── Security Headers Middleware ──────────────────────────────────────────────

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to responses"""
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    return response

# ─── Route Inclusion ──────────────────────────────────────────────────────────

# Auth routes (no rate limit on register/login)
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])

# Scanning tools with rate limiting (10 requests per minute)
app.include_router(portscan.router, prefix="/api/portscan", tags=["Port Scanner"])
app.include_router(subdomain.router, prefix="/api/subdomain", tags=["Subdomain Finder"])
app.include_router(whois_lookup.router, prefix="/api/whois", tags=["Whois Lookup"])
app.include_router(headers.router, prefix="/api/headers", tags=["Header Fingerprint"])
app.include_router(waf.router, prefix="/api/waf", tags=["WAF Detector"])
app.include_router(ssl_scan.router, prefix="/api/ssl", tags=["SSL Scanner"])
app.include_router(wpscan.router, prefix="/api/wpscan", tags=["WordPress Scanner"])
app.include_router(sqli.router, prefix="/api/sqli", tags=["SQLi Scanner"])
app.include_router(xss.router, prefix="/api/xss", tags=["XSS Scanner"])
app.include_router(nuclei_scan.router, prefix="/api/nuclei", tags=["CVE Scanner"])
app.include_router(gobuster_scan.router, prefix="/api/gobuster", tags=["URL Fuzzer"])
app.include_router(hydra_scan.router, prefix="/api/hydra", tags=["Password Auditor"])

# Full scan and management
app.include_router(fullscan.router, prefix="/api/fullscan", tags=["Full Scan"])
app.include_router(history.router, prefix="/api/history", tags=["Scan History"])
app.include_router(targets.router, prefix="/api/targets", tags=["Targets"])

# ─── Health & Info Endpoints ──────────────────────────────────────────────────

@app.get("/")
def root():
    """API info endpoint"""
    return {
        "name": "VulnForge",
        "status": "online",
        "version": "2.0.0",
        "tools": 15,
        "docs": "/api/docs"
    }

@app.get("/health")
def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

# ─── Startup/Shutdown Events ──────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    log_info("VulnForge API started", version="2.0.0")

@app.on_event("shutdown")
async def shutdown_event():
    """Run on shutdown"""
    log_info("VulnForge API stopped")

# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    log_error(
        f"Unhandled exception: {request.method} {request.url.path}",
        error=exc,
        ip=request.client.host if request.client else "unknown"
    )
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        log_level="info"
    )
