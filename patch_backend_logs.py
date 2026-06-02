import re
import os

filepath = r"c:\Users\Ali Akbar\Downloads\econgkut\backend-econgkut-main\backend-econgkut-main\server.py"

with open(filepath, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add Models
models_code = """
class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    user_name: str
    action: str
    details: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SystemIssueCreate(BaseModel):
    issue_type: str
    description: str

class SystemIssueUpdateStatus(BaseModel):
    status: str

class SystemIssue(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    reporter_id: str
    reporter_name: str
    reporter_division: Optional[str] = None
    issue_type: str
    description: str
    status: str = "Open" # Open, In Progress, Resolved
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
"""
content = re.sub(r'(# ==================== CREATE APP & ROUTER ====================)', models_code + r'\n\1', content)

# 2. Add log_activity helper
helper_code = """
async def log_activity(user_id: str, user_name: str, action: str, details: str):
    log_entry = ActivityLog(user_id=user_id, user_name=user_name, action=action, details=details)
    await db.activity_logs.insert_one(log_entry.model_dump())
"""
content = re.sub(r'(async def require_auth\(request: Request, authorization: Optional\[str\] = None\) -> User:)', helper_code + r'\n\1', content)

# 3. Add Endpoints
endpoints_code = """
# ==================== LOGS & ISSUES ====================

@api_router.get("/logs")
async def get_activity_logs(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    logs = await db.activity_logs.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return logs

@api_router.post("/issues")
async def create_issue(data: SystemIssueCreate, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    new_issue = SystemIssue(
        reporter_id=user.id,
        reporter_name=user.name,
        reporter_division=user.division,
        **data.model_dump()
    )
    await db.system_issues.insert_one(new_issue.model_dump())
    await log_activity(user.id, user.name, "REPORT_ISSUE", f"Melaporkan kendala: {data.issue_type}")
    return {"success": True, "data": new_issue.model_dump()}

@api_router.get("/issues")
async def get_all_issues(request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT", "Pimpinan"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    issues = await db.system_issues.find({}, {"_id": 0}).sort("created_at", -1).to_list(1000)
    return issues

@api_router.put("/issues/{issue_id}/status")
async def update_issue_status(issue_id: str, data: SystemIssueUpdateStatus, request: Request, authorization: Optional[str] = Header(None)):
    user = await require_auth(request, authorization)
    if user.role != "admin" and user.division not in ["IT", "SDM & IT"]:
        raise HTTPException(status_code=403, detail="Akses ditolak")
    
    result = await db.system_issues.update_one(
        {"id": issue_id},
        {"$set": {"status": data.status, "updated_at": datetime.now(timezone.utc)}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Kendala tidak ditemukan")
        
    await log_activity(user.id, user.name, "UPDATE_ISSUE", f"Mengubah status kendala {issue_id} menjadi {data.status}")
    return {"success": True}
"""
content = re.sub(r'(# ==================== CORS MIDDLEWARE & ROUTER INCLUSION ====================)', endpoints_code + r'\n\1', content)

# 4. Inject log_activity into specific functions

# Login
content = re.sub(r'(return JSONResponse\(content=\{"token": session_token, "user": user\.model_dump\(\)\}\))', r'await log_activity(user.id, user.name, "LOGIN", "Berhasil login ke sistem")\n        \1', content)

# Update Booking Status
content = re.sub(r'(return \{"success": True, "status": data\.status\})', r'await log_activity(user.id, user.name, "UPDATE_BOOKING_STATUS", f"Mengubah status pesanan {booking_id} menjadi {data.status}")\n    \1', content)

# Delete Booking
content = re.sub(r'(return \{"success": True\})', r'await log_activity(user.id, user.name, "DELETE_BOOKING", f"Menghapus pesanan {booking_id}")\n    \1', content, count=1) # only first occurrence near delete booking

# Update User
content = re.sub(r'(return \{"success": True, "message": "User updated successfully"\})', r'await log_activity(user.id, user.name, "UPDATE_USER", f"Mengubah data user {target_user_id}")\n    \1', content)

# Add Processing
content = re.sub(r'(return \{"success": True, "data": new_processing\.model_dump\(\)\})', r'await log_activity(user.id, user.name, "CREATE_PROCESSING", f"Mengolah {data.weight_processed}kg sampah {data.source_waste_category}")\n    \1', content)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(content)

print("Patch backend applied successfully.")
