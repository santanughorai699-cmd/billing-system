from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from pathlib import Path
from typing import Optional
import hashlib
import secrets
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

# ---------------------------------------------------------
# USERS  ->  1 admin + 3 employees
# ---------------------------------------------------------
users_db = {
    "Samaresh": {"password": hash_pw("s1"), "role": "admin",    "name": "Administrator"},
    "Bimal":  {"password": hash_pw("b2"),  "role": "employee", "name": "Bimal"},
    "Susama": {"password": hash_pw("s3"), "role": "employee", "name": "Susama"},
    "..":  {"password": hash_pw("0"),  "role": "employee", "name": ".."},
}

sessions = {}   # token  ->  user_id

# ---------------------------------------------------------
# DEMO BILLS
# ---------------------------------------------------------
bills_db = [
    {"id": 1, "name": "John Doe",   "phone": "919876543210", "billNo": "B001",
     "orderTrack": "ORD-001", "item": "Electronics", "amount": 5000,  "down": 1000,
     "pending": 4000,  "created_by": "ravi"},
    {"id": 2, "name": "Jane Smith", "phone": "918765432109", "billNo": "B002",
     "orderTrack": "ORD-002", "item": "Furniture",   "amount": 15000, "down": 5000,
     "pending": 10000, "created_by": "priya"},
    {"id": 3, "name": "Mike Johnson","phone": "917654321098","billNo": "B003",
     "orderTrack": "ORD-003", "item": "Appliances",  "amount": 8500,  "down": 2500,
     "pending": 6000,  "created_by": "amit"},
]

# ---------------------------------------------------------
# MODELS
# ---------------------------------------------------------
class LoginData(BaseModel):
    user_id: str
    password: str

class BillInput(BaseModel):
    name: str
    phone: str
    billNo: str
    orderTrack: str
    item: str
    amount: float
    down: float

class UserCreate(BaseModel):
    user_id: str
    password: str
    name: str = ""
    role: str = "employee"

class PasswordReset(BaseModel):
    password: str

class RoleUpdate(BaseModel):
    role: str

# ---------------------------------------------------------
# AUTH HELPERS
# ---------------------------------------------------------
def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1].strip()
    user_id = sessions.get(token)
    if not user_id or user_id not in users_db:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return user_id

def require_admin(user_id: str = Depends(current_user)):
    if users_db[user_id]["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user_id

# ---------------------------------------------------------
# AUTH ENDPOINTS
# ---------------------------------------------------------
@app.post("/api/login")
def login(data: LoginData):
    user = users_db.get(data.user_id)
    if not user or user["password"] != hash_pw(data.password):
        raise HTTPException(status_code=401, detail="Invalid user ID or password")
    token = secrets.token_hex(24)
    sessions[token] = data.user_id
    return {
        "token": token,
        "user_id": data.user_id,
        "role": user["role"],
        "name": user["name"],
    }

@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        sessions.pop(token, None)
    return {"message": "Logged out"}

@app.get("/api/me")
def me(user_id: str = Depends(current_user)):
    u = users_db[user_id]
    return {"user_id": user_id, "role": u["role"], "name": u["name"]}

# ---------------------------------------------------------
# BILLS  (admin sees all, employees see only their own)
# ---------------------------------------------------------
@app.get("/api/bills")
def get_bills(user_id: str = Depends(current_user)):
    if users_db[user_id]["role"] == "admin":
        return bills_db
    return [b for b in bills_db if b.get("created_by") == user_id]

@app.post("/api/bills")
def create_bill(bill: BillInput, user_id: str = Depends(current_user)):
    new_bill = {
        "id": max((item["id"] for item in bills_db), default=0) + 1,
        "name": bill.name,
        "phone": bill.phone,
        "billNo": bill.billNo,
        "orderTrack": bill.orderTrack,
        "item": bill.item,
        "amount": bill.amount,
        "down": bill.down,
        "pending": max(bill.amount - bill.down, 0),
        "created_by": user_id,
    }
    bills_db.append(new_bill)
    return new_bill

@app.put("/api/bills/{bill_id}")
def update_bill(bill_id: int, bill: BillInput, user_id: str = Depends(current_user)):
    is_admin = users_db[user_id]["role"] == "admin"
    for i, item in enumerate(bills_db):
        if item["id"] == bill_id:
            if not is_admin and item.get("created_by") != user_id:
                raise HTTPException(status_code=403, detail="You can only edit your own bills")
            bills_db[i] = {
                **item,
                "name": bill.name, "phone": bill.phone,
                "billNo": bill.billNo, "orderTrack": bill.orderTrack,
                "item": bill.item, "amount": bill.amount, "down": bill.down,
                "pending": max(bill.amount - bill.down, 0),
            }
            return bills_db[i]
    raise HTTPException(status_code=404, detail="Bill not found")

@app.delete("/api/bills/{bill_id}")
def delete_bill(bill_id: int, user_id: str = Depends(current_user)):
    if users_db[user_id]["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete bills")
    for i, item in enumerate(bills_db):
        if item["id"] == bill_id:
            del bills_db[i]
            return {"message": "Bill deleted"}
    raise HTTPException(status_code=404, detail="Bill not found")

# ---------------------------------------------------------
# USERS  (admin only)
# ---------------------------------------------------------
@app.get("/api/users")
def list_users(admin: str = Depends(require_admin)):
    return [{"user_id": uid, "name": u["name"], "role": u["role"]}
            for uid, u in users_db.items()]

@app.post("/api/users")
def create_user(data: UserCreate, admin: str = Depends(require_admin)):
    if data.user_id in users_db:
        raise HTTPException(status_code=400, detail="User ID already exists")
    if data.role not in ("admin", "employee"):
        raise HTTPException(status_code=400, detail="Role must be admin or employee")
    users_db[data.user_id] = {
        "password": hash_pw(data.password),
        "role": data.role,
        "name": data.name or data.user_id,
    }
    return {"message": f"User {data.user_id} created"}

@app.put("/api/users/{user_id}")
def update_role(user_id: str, data: RoleUpdate, admin: str = Depends(require_admin)):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    if data.role not in ("admin", "employee"):
        raise HTTPException(status_code=400, detail="Invalid role")
    users_db[user_id]["role"] = data.role
    return {"message": f"Role updated for {user_id}"}

@app.put("/api/users/{user_id}/password")
def reset_password(user_id: str, data: PasswordReset, admin: str = Depends(require_admin)):
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    users_db[user_id]["password"] = hash_pw(data.password)
    return {"message": f"Password updated for {user_id}"}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, admin: str = Depends(require_admin)):
    if user_id == admin:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    users_db.pop(user_id)
    for t in [t for t, u in sessions.items() if u == user_id]:
        sessions.pop(t, None)
    return {"message": f"User {user_id} deleted"}

# ---------------------------------------------------------
# SERVE FRONTEND
# ---------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    html_path = Path(__file__).resolve().parent / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>index.html not found</h1>", status_code=404)

@app.get("/index.html", response_class=HTMLResponse)
def serve_index_file():
    return serve_frontend()

@app.get("/billing", response_class=HTMLResponse)
def serve_billing_frontend():
    return serve_frontend()

if __name__ == "__main__":
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)
