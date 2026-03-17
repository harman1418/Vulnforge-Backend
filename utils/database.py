from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/vulnforge")

client = AsyncIOMotorClient(MONGODB_URL)
db = client.vulnforge

# Collections
users_collection = db.users
otps_collection = db.otps
scans_collection = db.scans
targets_collection = db.targets
