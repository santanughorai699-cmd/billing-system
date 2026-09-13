from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator
from pathlib import Path
from typing import Optional
import hashlib
import secrets
import uvicorn
import sqlite3
import re
from datetime import datetime
import os

# Cloud Database support (PostgreSQL)
try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

DATABASE_URL = os.getenv("DATABASE_URL")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def hash_pw(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# ---------------------------------------------------------
# DYNAMIC DATABASE SETUP (SQLite for Local, Postgres for Render)
# ---------------------------------------------------------
def get_db():
    if DATABASE_URL and DATABASE_URL.startswith("postgres"):
        if not psycopg2:
            raise Exception("psycopg2-binary is not installed! Add it to requirements.txt")
        
        try:
            # Try direct connection first - Render should handle the URL correctly
            conn = psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
            return conn, "postgres"
        except psycopg2.OperationalError as e:
            # If channel_binding parameter causes issues, strip it from URL
            if "channel_binding" in str(e):
                clean_url = DATABASE_URL.replace("?channel_binding=disable", "")
                conn = psycopg2.connect(clean_url, cursor_factory=DictCursor)
                return conn, "postgres"
            raise
    else:
        conn = sqlite3.connect("billing_system.db")
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"

def execute(c, db_type, query, params=()):
    if db_type == "postgres":
        query = query.replace("?", "%s")
        query = query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    c.execute(query, params)

def init_db():
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, '''CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL
    )''')
    
    execute(c, db_type, '''CREATE TABLE IF NOT EXISTS bills (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        billNo TEXT NOT NULL,
        orderTrack TEXT,
        item TEXT,
        amount REAL NOT NULL,
        down REAL NOT NULL,
        pending REAL NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT
    )''')
    
    execute(c, db_type, '''CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT
    )''')
    
    conn.commit()
    
    execute(c, db_type, "SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        default_users = {
            "Samaresh": {"password": hash_pw("s1"), "role": "admin", "name": "Samaresh"},
            "Bimal": {"password": hash_pw("b2"), "role": "employee", "name": "Bimal"},
            "Susama": {"password": hash_pw("s3"), "role": "employee", "name": "Susama"},
        }
        for user_id, data in default_users.items():
            execute(c, db_type, "INSERT INTO users (user_id, password, name, role) VALUES (?, ?, ?, ?)", 
                     (user_id, data["password"], data["name"], data["role"]))
        conn.commit()
    
    conn.close()

init_db()

# ---------------------------------------------------------
# VALIDATION HELPERS
# ---------------------------------------------------------
def is_valid_name(name: str) -> bool:
    return bool(re.match(r"^[a-zA-Z\s]+$", name.strip())) and len(name.strip()) > 0

def is_valid_user_id(user_id: str) -> bool:
    return bool(re.match(r"^[a-zA-Z]+$", user_id.strip())) and len(user_id.strip()) > 0

def is_valid_phone(phone: str) -> bool:
    return bool(re.match(r"^[0-9]{10}$", phone.strip()))

def format_phone_with_country_code(phone: str) -> str:
    clean_phone = re.sub(r"[^0-9]", "", phone)[-10:]
    return f"91{clean_phone}"

# ---------------------------------------------------------
# MODELS
# ---------------------------------------------------------
class LoginData(BaseModel):
    user_id: str
    password: str
    
    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v):
        if not is_valid_user_id(v):
            raise ValueError('User ID must contain only alphabets')
        return v

class BillInput(BaseModel):
    name: str
    phone: str
    billNo: str
    orderTrack: str
    item: str
    amount: float
    down: float
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if not is_valid_name(v):
            raise ValueError('Name must contain only alphabets and spaces')
        return v.strip()
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        if not is_valid_phone(v):
            raise ValueError('Phone must be 10 digits (India only)')
        return format_phone_with_country_code(v)

class UserCreate(BaseModel):
    user_id: str
    password: str
    name: str = ""
    role: str = "employee"
    
    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v):
        if not is_valid_user_id(v):
            raise ValueError('User ID must contain only alphabets')
        return v
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v and not is_valid_name(v):
            raise ValueError('Name must contain only alphabets and spaces')
        return v.strip()

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
    token = authorization.split(" ", 1).strip()
    
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT user_id FROM sessions WHERE token = ?", (token,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    return row[0]

def require_admin(user_id: str = Depends(current_user)):
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT role FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row or row[0] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user_id

# ---------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------
@app.post("/api/login")
def login(data: LoginData):
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT password, role, name FROM users WHERE user_id = ?", (data.user_id,))
    row = c.fetchone()
    
    if not row or row[0] != hash_pw(data.password):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid user ID or password")
    
    token = secrets.token_hex(24)
    execute(c, db_type, "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
             (token, data.user_id, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    return {
        "token": token,
        "user_id": data.user_id,
        "role": row[1],
        "name": row[2],
    }

@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1).strip()
        conn, db_type = get_db()
        c = conn.cursor()
        execute(c, db_type, "DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"message": "Logged out"}

@app.get("/api/me")
def me(user_id: str = Depends(current_user)):
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT role, name FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    
    return {"user_id": user_id, "role": row[0], "name": row[1]}

@app.get("/api/bills")
def get_bills(user_id: str = Depends(current_user)):
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT id, name, phone, billNo, orderTrack, item, amount, down, pending, created_by FROM bills ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/bills")
def create_bill(bill: BillInput, user_id: str = Depends(current_user)):
    pending = max(bill.amount - bill.down, 0)
    
    conn, db_type = get_db()
    c = conn.cursor()
    
    query = """INSERT INTO bills (name, phone, billNo, orderTrack, item, amount, down, pending, created_by, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    params = (bill.name, bill.phone, bill.billNo, bill.orderTrack, bill.item, 
              bill.amount, bill.down, pending, user_id, datetime.now().isoformat())
              
    if db_type == "postgres":
        execute(c, db_type, query + " RETURNING id", params)
        bill_id = c.fetchone()[0]
    else:
        execute(c, db_type, query, params)
        c.execute("SELECT last_insert_rowid()")
        bill_id = c.fetchone()[0]
        
    conn.commit()
    conn.close()
    
    return {
        "id": bill_id,
        "name": bill.name,
        "phone": bill.phone,
        "billNo": bill.billNo,
        "orderTrack": bill.orderTrack,
        "item": bill.item,
        "amount": bill.amount,
        "down": bill.down,
        "pending": pending,
        "created_by": user_id,
    }

@app.put("/api/bills/{bill_id}")
def update_bill(bill_id: int, bill: BillInput, user_id: str = Depends(current_user)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, "SELECT created_by FROM bills WHERE id = ?", (bill_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Bill not found")
    
    pending = max(bill.amount - bill.down, 0)
    execute(c, db_type, """UPDATE bills SET name = ?, phone = ?, billNo = ?, orderTrack = ?, item = ?, amount = ?, down = ?, pending = ?
                 WHERE id = ?""",
             (bill.name, bill.phone, bill.billNo, bill.orderTrack, bill.item, bill.amount, bill.down, pending, bill_id))
    conn.commit()
    conn.close()
    
    return {
        "id": bill_id,
        "name": bill.name,
        "phone": bill.phone,
        "billNo": bill.billNo,
        "orderTrack": bill.orderTrack,
        "item": bill.item,
        "amount": bill.amount,
        "down": bill.down,
        "pending": pending,
        "created_by": row[0],
    }

@app.delete("/api/bills/{bill_id}")
def delete_bill(bill_id: int, user_id: str = Depends(current_user)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, "SELECT role FROM users WHERE user_id = ?", (user_id,))
    if c.fetchone()[0] != "admin":
        conn.close()
        raise HTTPException(status_code=403, detail="Only admin can delete bills")
    
    execute(c, db_type, "DELETE FROM bills WHERE id = ?", (bill_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Bill deleted"}

@app.get("/api/users")
def list_users(admin: str = Depends(require_admin)):
    conn, db_type = get_db()
    c = conn.cursor()
    execute(c, db_type, "SELECT user_id, name, role FROM users")
    rows = c.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/users")
def create_user(data: UserCreate, admin: str = Depends(require_admin)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (data.user_id,))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="User ID already exists")
    
    if data.role not in ("admin", "employee"):
        conn.close()
        raise HTTPException(status_code=400, detail="Role must be admin or employee")
    
    execute(c, db_type, "INSERT INTO users (user_id, password, name, role) VALUES (?, ?, ?, ?)",
             (data.user_id, hash_pw(data.password), data.name or data.user_id, data.role))
    conn.commit()
    conn.close()
    
    return {"message": f"User {data.user_id} created"}

@app.put("/api/users/{user_id}")
def update_role(user_id: str, data: RoleUpdate, admin: str = Depends(require_admin)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    if data.role not in ("admin", "employee"):
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid role")
    
    execute(c, db_type, "UPDATE users SET role = ? WHERE user_id = ?", (data.role, user_id))
    conn.commit()
    conn.close()
    
    return {"message": f"Role updated for {user_id}"}

@app.put("/api/users/{user_id}/password")
def reset_password(user_id: str, data: PasswordReset, admin: str = Depends(require_admin)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    execute(c, db_type, "UPDATE users SET password = ? WHERE user_id = ?", (hash_pw(data.password), user_id))
    conn.commit()
    conn.close()
    
    return {"message": f"Password updated for {user_id}"}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, admin: str = Depends(require_admin)):
    conn, db_type = get_db()
    c = conn.cursor()
    
    if user_id == admin:
        conn.close()
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    
    execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    execute(c, db_type, "DELETE FROM users WHERE user_id = ?", (user_id,))
    execute(c, db_type, "DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    
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
