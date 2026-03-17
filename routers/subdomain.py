from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def subdomain_finder(target: str):
    try:
        cmd = ["subfinder", "-d", target, "-silent"]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        subdomains = [
            line.strip() 
            for line in result.stdout.splitlines() 
            if line.strip()
        ]

        return {
            "target": target,
            "status": "success",
            "count": len(subdomains),
            "subdomains": subdomains
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
