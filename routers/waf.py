from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def waf_detect(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = ["wafw00f", url, "-o", "-", "-f", "json"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        return {
            "target": target,
            "status": "success",
            "raw": result.stdout,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
