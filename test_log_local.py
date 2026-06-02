import asyncio
from fastapi.testclient import TestClient
from server import app, log_activity, db
from unittest.mock import AsyncMock, patch

client = TestClient(app)

async def test_log():
    # Mock db to avoid real network call
    app.mongodb_client = AsyncMock()
    app.db = AsyncMock()
    
    with patch("server.db") as mock_db:
        mock_db.activity_logs.insert_one = AsyncMock()
        try:
            await log_activity("test_id", "test_name", "DELETE_BOOKING", "Menghapus pesanan 123")
            print("log_activity executed successfully without DB network call.")
        except Exception as e:
            print("ERROR in log_activity:", repr(e))

if __name__ == "__main__":
    asyncio.run(test_log())
