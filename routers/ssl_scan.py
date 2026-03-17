from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def ssl_scan(target: str):
    try:
        # Remove http/https if present
        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        cmd = [
            "sslyze",
            "--json_out=-",
            "--regular",
            host
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        # Parse JSON output
        try:
            data = json.loads(result.stdout)
            server_scan = data["server_scan_results"][0]
            scan_result = server_scan["scan_result"]

            return {
                "target": host,
                "status": "success",
                "certificate_info": scan_result.get("certificate_info", {}),
                "ssl_2_0": scan_result.get("ssl_2_0_cipher_suites", {}),
                "ssl_3_0": scan_result.get("ssl_3_0_cipher_suites", {}),
                "tls_1_0": scan_result.get("tls_1_0_cipher_suites", {}),
                "tls_1_1": scan_result.get("tls_1_1_cipher_suites", {}),
                "tls_1_2": scan_result.get("tls_1_2_cipher_suites", {}),
                "tls_1_3": scan_result.get("tls_1_3_cipher_suites", {}),
                "heartbleed": scan_result.get("heartbleed", {}),
                "openssl_ccs": scan_result.get("openssl_ccs_injection", {}),
            }
        except:
            return {
                "target": host,
                "status": "success",
                "raw": result.stdout
            }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
