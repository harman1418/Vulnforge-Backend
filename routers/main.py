from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import portscan, subdomain, whois_lookup, headers, waf, ssl_scan, wpscan, sqli, xss, nuclei_scan, gobuster_scan, hydra_scan, auth, fullscan, history

app = FastAPI(
    title="VulnForge API",
    description="Autonomous Penetration Testing Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(fullscan.router, prefix="/api/fullscan", tags=["Full Scan"])
app.include_router(history.router, prefix="/api/history", tags=["Scan History"])

@app.get("/")
def root():
    return {
        "name": "VulnForge",
        "status": "online",
        "version": "2.0.0",
        "tools": 15
    }

@app.get("/health")
def health():
    return {"status": "healthy"}
