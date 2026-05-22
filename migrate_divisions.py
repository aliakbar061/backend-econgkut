import asyncio
import os
from motor.motor_asyncio import AsyncIOMotorClient

async def update_divisions():
    MONGODB_URL = "mongodb+srv://aliakbar06110:bXkItE2H2iKxW1Kz@cluster0.zox2c.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = AsyncIOMotorClient(MONGODB_URL)
    db = client.econgkut
    
    # Update users
    print("Updating users...")
    await db.users.update_many({"division": "SDM"}, {"$set": {"division": "SDM & IT"}})
    await db.users.update_many({"division": "IT"}, {"$set": {"division": "SDM & IT"}})
    await db.users.update_many({"division": "Operasional"}, {"$set": {"division": "Operasional & Pengolahan"}})
    await db.users.update_many({"division": "Pengolahan"}, {"$set": {"division": "Operasional & Pengolahan"}})
    
    # Update attendance
    print("Updating attendance records...")
    await db.attendance.update_many({"division": "SDM"}, {"$set": {"division": "SDM & IT"}})
    await db.attendance.update_many({"division": "IT"}, {"$set": {"division": "SDM & IT"}})
    await db.attendance.update_many({"division": "Operasional"}, {"$set": {"division": "Operasional & Pengolahan"}})
    await db.attendance.update_many({"division": "Pengolahan"}, {"$set": {"division": "Operasional & Pengolahan"}})

    print("Done")

if __name__ == "__main__":
    asyncio.run(update_divisions())
