from fastapi import APIRouter
from fastapi.responses import FileResponse
from utils.database import scans_collection
import os

router = APIRouter()


@router.get("/")
async def get_all_scans():
    try:
        cursor = scans_collection.find(
            {},
            {
                "_id": 1,
                "target": 1,
                "created_at": 1,
                "risk_level": 1,
                "security_score": 1,
                "ai_analysis": 1,
            }
        ).sort("created_at", -1).limit(50)

        scans = []
        async for scan in cursor:
            scans.append({
                "id": str(scan["_id"]),
                "target": scan.get("target", ""),
                "created_at": scan.get("created_at", ""),
                "risk_level": scan.get("risk_level", "UNKNOWN"),
                "security_score": scan.get("security_score", 0),
                "executive_summary": scan.get("ai_analysis", {}).get("executive_summary", ""),
                "critical_findings_count": len(scan.get("ai_analysis", {}).get("critical_findings", [])),
            })

        return {"status": "success", "scans": scans}

    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/download/{scan_id}")
async def download_scan_report(scan_id: str):
    try:
        scan = await scans_collection.find_one({"_id": scan_id})
        if not scan:
            return {"status": "error", "message": "Scan not found"}

        target = scan.get("target", "unknown").replace(".", "_")
        path = f"/tmp/vulnforge_report_{target}.pdf"

        if os.path.exists(path):
            return FileResponse(
                path,
                filename=f"vulnforge_{target}_{scan_id[:8]}.pdf",
                media_type="application/pdf"
            )

        # Regenerate if missing
        from routers.fullscan import generate_report
        new_path = generate_report(
            scan["target"],
            scan.get("scan_results", {}),
            scan.get("ai_analysis", {}),
            scan.get("attack_results", [])
        )
        return FileResponse(
            new_path,
            filename=f"vulnforge_{target}_{scan_id[:8]}.pdf",
            media_type="application/pdf"
        )

    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    try:
        scan = await scans_collection.find_one({"_id": scan_id})
        if not scan:
            return {"status": "error", "message": "Scan not found"}

        scan["id"] = str(scan["_id"])
        del scan["_id"]
        return {"status": "success", "scan": scan}

    except Exception as e:
        return {"status": "error", "message": str(e)}
