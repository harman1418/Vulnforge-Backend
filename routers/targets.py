from fastapi import APIRouter
from utils.database import db
from datetime import datetime

router = APIRouter()

targets_collection = db.targets


@router.get("/")
async def get_targets():
    try:
        cursor = targets_collection.find({}).sort("created_at", -1)
        targets = []
        async for t in cursor:
            targets.append({
                "target": t.get("target", ""),
                "created_at": t.get("created_at", ""),
                "scan_count": t.get("scan_count", 0),
            })
        return {"status": "success", "targets": targets}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/")
async def add_target(data: dict):
    try:
        target = data.get("target", "").strip()
        if not target:
            return {"status": "error", "message": "Target is required"}

        existing = await targets_collection.find_one({"target": target})
        if existing:
            return {"status": "error", "message": "Target already exists"}

        await targets_collection.insert_one({
            "target": target,
            "created_at": datetime.now().isoformat(),
            "scan_count": 0,
        })
        return {"status": "success", "message": f"Target {target} added"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.delete("/{target}")
async def delete_target(target: str):
    try:
        result = await targets_collection.delete_one({"target": target})
        if result.deleted_count == 0:
            return {"status": "error", "message": "Target not found"}
        return {"status": "success", "message": f"Target {target} deleted"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
