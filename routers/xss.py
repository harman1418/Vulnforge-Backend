from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def xss_scan(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = [
            "python3",
            "/opt/XSStrike/xsstrike.py",
            "-u", url,
            "--crawl",
            "--blind",
            "--skip",
            "--json",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        output = result.stdout
        vulnerable = "xss" in output.lower() or "payload" in output.lower()

        return {
            "target": target,
            "status": "success",
            "vulnerable": vulnerable,
            "raw": output,
            "error": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
