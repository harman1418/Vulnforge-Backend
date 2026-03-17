from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def sqli_scan(target: str):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--random-agent",
            "--level=1",
            "--risk=1",
            "--output-dir=/tmp/sqlmap",
            "--forms",
            "--crawl=2",
            "-v", "0",
            "--json-errors",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # Parse output for vulnerabilities
        output = result.stdout
        vulnerable = "injectable" in output.lower() or "sqlmap identified" in output.lower()

        return {
            "target": target,
            "status": "success",
            "vulnerable": vulnerable,
            "raw": output,
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
