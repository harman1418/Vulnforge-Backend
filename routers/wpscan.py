from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def wp_scan(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--no-update",
            "--random-user-agent",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        try:
            data = json.loads(result.stdout)
            return {
                "target": target,
                "status": "success",
                "is_wordpress": True,
                "version": data.get("version", {}),
                "plugins": data.get("plugins", {}),
                "themes": data.get("themes", {}),
                "users": data.get("users", {}),
                "vulnerabilities": data.get("vulnerabilities", []),
                "interesting_findings": data.get("interesting_findings", []),
            }
        except:
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
