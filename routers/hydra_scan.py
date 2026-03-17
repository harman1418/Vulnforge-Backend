from fastapi import APIRouter
import subprocess

router = APIRouter()

@router.get("/")
def hydra_scan(
    target: str,
    service: str = "ssh",
    username: str = "admin",
    wordlist: str = "common"
):
    try:
        # Choose wordlist
        if wordlist == "common":
            wl = "/usr/share/wordlists/metasploit/common_passwords.txt"
        elif wordlist == "rockyou":
            wl = "/usr/share/wordlists/rockyou.txt"
        else:
            wl = "/usr/share/wordlists/metasploit/common_passwords.txt"

        cmd = [
            "hydra",
            "-l", username,
            "-P", wl,
            "-t", "4",
            "-f",
            "-o", "/tmp/hydra_output.txt",
            target,
            service,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        output = result.stdout
        cracked = "login:" in output.lower()

        # Parse cracked credentials
        credentials = []
        for line in output.splitlines():
            if "login:" in line.lower():
                credentials.append(line.strip())

        return {
            "target": target,
            "service": service,
            "username": username,
            "status": "success",
            "cracked": cracked,
            "credentials": credentials,
            "raw": output
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
