from fastapi import APIRouter
import subprocess
import json

router = APIRouter()

@router.get("/")
def nuclei_scan(target: str, severity: str = "critical,high"):
    try:
        if not target.startswith("http"):
            url = f"https://{target}"
        else:
            url = target

        cmd = [
            "nuclei",
            "-u", url,
            "-severity", severity,
            "-json",
            "-silent",
            "-no-color",
            "-timeout", "10",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse JSONL output (one JSON per line)
        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", ""),
                        "description": finding.get("info", {}).get("description", ""),
                        "matched_at": finding.get("matched-at", ""),
                        "tags": finding.get("info", {}).get("tags", []),
                    })
                except:
                    pass

        return {
            "target": target,
            "status": "success",
            "severity_filter": severity,
            "total_findings": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Scan timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
