from fastapi import APIRouter
import httpx
import builtwith

router = APIRouter()

@router.get("/")
def header_fingerprint(target: str):
    try:
        # Make sure target has http/https
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        # Fetch headers
        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=30,
            verify=False
        )

        headers = dict(response.headers)

        # Detect technologies
        try:
            technologies = builtwith.parse(url)
        except:
            technologies = {}

        # Security headers check
        security_headers = {
            "X-Frame-Options": headers.get("x-frame-options", "❌ Missing"),
            "X-Content-Type-Options": headers.get("x-content-type-options", "❌ Missing"),
            "Strict-Transport-Security": headers.get("strict-transport-security", "❌ Missing"),
            "Content-Security-Policy": headers.get("content-security-policy", "❌ Missing"),
            "X-XSS-Protection": headers.get("x-xss-protection", "❌ Missing"),
            "Referrer-Policy": headers.get("referrer-policy", "❌ Missing"),
        }

        return {
            "target": target,
            "status": "success",
            "status_code": response.status_code,
            "headers": headers,
            "security_headers": security_headers,
            "technologies": technologies,
            "server": headers.get("server", "Unknown"),
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}
