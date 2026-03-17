from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def gobuster_scan(target: str, wordlist: str = "common"):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        # Choose wordlist
        if wordlist == "common":
            wl = "/usr/share/wordlists/dirb/common.txt"
        elif wordlist == "big":
            wl = "/usr/share/wordlists/dirb/big.txt"
        else:
            wl = "/usr/share/wordlists/dirb/common.txt"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wl,
            "-t", "50",
            "--no-progress",
            "-q",
            "-o", "/tmp/gobuster_output.txt"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # Parse results
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("Error"):
                findings.append(line)

        return {
            "target": target,
            "status": "success",
            "wordlist": wordlist,
            "total_found": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
