from fastapi import FastAPI, HTTPException, Header, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import hashlib
import json
import secrets
import uvicorn
import sqlite3
import re
import os
import time
import html
import urllib.parse
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
security_logger = logging.getLogger("SECURITY_FIREWALL")
MEASUREMENT_FIELDS = ("ঝুল", "ছাতি", "কোমর", "পুট", "হাতা", "মহরী", "মহড়া", "পে", "কছ")

try:
    import psycopg2
    from psycopg2.extras import DictCursor
except ImportError:
    psycopg2 = None

DATABASE_URL = os.getenv("DATABASE_URL")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000,null").split(",")
    if origin.strip()
]
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "*").split(",")
    if host.strip()
]

MAX_BODY_SIZE = 1 * 1024 * 1024
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 120
LOGIN_RATE_LIMIT_WINDOW = 300
MAX_LOGIN_ATTEMPTS = 5
WAF_STRIKE_LIMIT = 5
IP_BAN_DURATION = 1800
SESSION_TTL_HOURS = 24
PBKDF2_ITERATIONS = 260_000

ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


SQLI_PATTERNS = [
    re.compile(r"(?i)\b(union\s+(all\s+)?select|select\s+[\w\*\,\s]+\s+from|insert\s+into|delete\s+from|update\s+\w+\s+set|drop\s+(table|database)|alter\s+table|truncate\s+table)\b"),
    re.compile(r"(?i)\b(or|and)\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?"),
    re.compile(r"(?i)(--|#|/\*[\s\S]*?\*/|;\s*(shutdown|xp_cmdshell|exec|execute))"),
    re.compile(r"(?i)\b(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|information_schema|sqlite_master)\b"),
]

XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script[^>]*>"),
    re.compile(r"(?i)<\s*/\s*script\s*>"),
    re.compile(r"(?i)(javascript|vbscript|data)\s*:"),
    re.compile(r"(?i)\bon(load|error|click|dblclick|mouseover|mouseout|keydown|keyup|focus|blur|submit|change|input|toggle|wheel)\s*="),
    re.compile(r"(?i)<\s*(iframe|object|embed|applet|meta|link|style|base|form|svg|math)[^>]*>"),
    re.compile(r"(?i)(document\.(cookie|domain|write|location)|window\.location|eval\s*\(|setTimeout\s*\(|setInterval\s*\()"),
]

PATH_TRAVERSAL_AND_CMD_PATTERNS = [
    re.compile(r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)"),
    re.compile(r"(?i)(/etc/passwd|/etc/shadow|/proc/self|c:\\windows|cmd\.exe|/bin/sh|/bin/bash)"),
    re.compile(r"(?i)(\|\||&&|;\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|php|whoami|id)\b|\$\([^)]+\)|`[^`]+`)"),
    re.compile(r"(?i)(<!ENTITY|SYSTEM\s+['\"]file://)"),
]

SUSPICIOUS_USER_AGENTS = re.compile(
    r"(?i)(sqlmap|nikto|nmap|masscan|nessus|acunetix|burpsuite|dirbuster|gobuster|wfuzz|nuclei|zgrab|havij)"
)

ALL_WAF_PATTERNS = SQLI_PATTERNS + XSS_PATTERNS + PATH_TRAVERSAL_AND_CMD_PATTERNS

ip_request_log: Dict[str, List[float]] = defaultdict(list)
ip_login_log: Dict[str, List[float]] = defaultdict(list)
ip_strikes: Dict[str, int] = defaultdict(int)
banned_ips: Dict[str, float] = {}


def get_client_ip(request: Request) -> str:
    """Safely extract client IP (only trust X-Forwarded-For if behind a known reverse proxy)."""
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def normalize_payload(payload: str) -> str:
    """Recursively URL-decode and unescape HTML entities to defeat double-encoding evasion."""
    decoded = payload
    for _ in range(3):
        unquoted = urllib.parse.unquote_plus(decoded)
        unescaped = html.unescape(unquoted)
        if unescaped == decoded:
            break
        decoded = unescaped
    return decoded


def check_malicious_payload(payload: str) -> Optional[str]:
    """Inspects string for null bytes and WAF patterns. Returns matched threat category or None."""
    if not payload:
        return None
    if "\x00" in payload or "%00" in payload.lower():
        return "Null-byte injection"
    normalized = normalize_payload(payload)
    for pattern in ALL_WAF_PATTERNS:
        if pattern.search(normalized):
            return f"Signature match ({pattern.pattern[:35]}...)"
    return None


def record_strike(ip: str, reason: str):
    ip_strikes[ip] += 1
    security_logger.warning(f"WAF Strike [{ip_strikes[ip]}/{WAF_STRIKE_LIMIT}] IP={ip} Reason={reason}")
    if ip_strikes[ip] >= WAF_STRIKE_LIMIT:
        banned_ips[ip] = time.time() + IP_BAN_DURATION
        security_logger.error(f"IP BANNED for {IP_BAN_DURATION}s: {ip}")


def is_rate_limited(ip: str, tracker: Dict[str, List[float]], window: int, limit: int) -> bool:
    now = time.time()
    timestamps = [t for t in tracker[ip] if now - t < window]
    tracker[ip] = timestamps
    if len(timestamps) >= limit:
        return True
    tracker[ip].append(now)
    return False



@app.middleware("http")
async def security_firewall(request: Request, call_next):
    client_ip = get_client_ip(request)
    now = time.time()

    if client_ip in banned_ips:
        if now < banned_ips[client_ip]:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Firewall Blocked: Your IP is temporarily banned due to suspicious activity."},
            )
        else:
            del banned_ips[client_ip]
            ip_strikes[client_ip] = 0

   
    if is_rate_limited(client_ip, ip_request_log, RATE_LIMIT_WINDOW, MAX_REQUESTS_PER_WINDOW):
        record_strike(client_ip, "Rate limit exceeded")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Too many requests. Please slow down."},
        )

    
    if request.url.path == "/api/login" and request.method == "POST":
        if is_rate_limited(client_ip, ip_login_log, LOGIN_RATE_LIMIT_WINDOW, MAX_LOGIN_ATTEMPTS):
            record_strike(client_ip, "Login brute-force limit exceeded")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many login attempts. Try again in 5 minutes."},
            )

    user_agent = request.headers.get("user-agent", "")
    if SUSPICIOUS_USER_AGENTS.search(user_agent) or check_malicious_payload(user_agent):
        record_strike(client_ip, f"Malicious User-Agent: {user_agent[:50]}")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Firewall Blocked: Suspicious User-Agent detected"},
        )

    raw_url_target = f"{request.url.path}?{request.url.query}" if request.url.query else request.url.path
    url_threat = check_malicious_payload(raw_url_target)
    if url_threat:
        record_strike(client_ip, f"Malicious URL ({url_threat})")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Firewall Blocked: Suspicious URL parameters detected"},
        )

    
    if request.method in ["POST", "PUT", "PATCH"]:
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": "Firewall Blocked: Payload too large"},
            )

        try:
            body_bytes = await request.body()
            if len(body_bytes) > MAX_BODY_SIZE:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Firewall Blocked: Payload too large"},
                )
            if body_bytes:
                body_str = body_bytes.decode("utf-8", errors="replace")
                body_threat = check_malicious_payload(body_str)
                if body_threat:
                    record_strike(client_ip, f"Malicious Body ({body_threat})")
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": "Firewall Blocked: Malicious payload detected"},
                    )

            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Malformed request payload"},
            )

    response = await call_next(request)

    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    return response



def hash_pw(password: str) -> str:
    """Hashes a password using salted PBKDF2-HMAC-SHA256."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_pw(plain_password: str, stored_hash: str) -> Tuple[bool, bool]:
    """
    Verifies password against stored hash in constant time.
    Returns (is_valid, needs_rehash) to seamlessly upgrade legacy SHA-256 hashes.
    """
    if stored_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations_str, salt, hash_hex = stored_hash.split("$", 3)
            iterations = int(iterations_str)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt.encode("utf-8"),
                iterations,
            )
            is_valid = secrets.compare_digest(dk.hex(), hash_hex)
            needs_rehash = iterations < PBKDF2_ITERATIONS
            return is_valid, needs_rehash
        except Exception:
            return False, False
    else:
        
        legacy_hash = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
        is_valid = secrets.compare_digest(legacy_hash, stored_hash)
        return is_valid, True


def hash_session_token(token: str) -> str:
    """Hashes session tokens before DB storage so a DB dump cannot hijack sessions."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()



def get_db():
    if DATABASE_URL and DATABASE_URL.startswith("postgres"):
        if not psycopg2:
            raise RuntimeError("psycopg2-binary is not installed! Add it to requirements.txt")
        clean_url = DATABASE_URL.split("?")[0]
        conn = psycopg2.connect(clean_url, cursor_factory=DictCursor)
        return conn, "postgres"
    else:
        conn = sqlite3.connect("billing_system.db", timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"


@contextmanager
def db_session():
    """Ensures DB connections are always closed, even if exceptions occur."""
    conn, db_type = get_db()
    try:
        yield conn, conn.cursor(), db_type
    finally:
        conn.close()


def execute(c, db_type: str, query: str, params: tuple = ()):
    if db_type == "postgres":
        query = query.replace("?", "%s")
        query = query.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    c.execute(query, params)


def init_db():
    with db_session() as (conn, c, db_type):
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

        if db_type == "postgres":
            execute(
                c, db_type,
                "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'bills'",
            )
            bill_columns = {row[0] for row in c.fetchall()}
        else:
            execute(c, db_type, "PRAGMA table_info(bills)")
            bill_columns = {row[1] for row in c.fetchall()}
        if "delivery_date" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN delivery_date TEXT")
        if "delivery_alert_accepted" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN delivery_alert_accepted INTEGER NOT NULL DEFAULT 0")
        if "delivery_remind_on" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN delivery_remind_on TEXT")
        if "measurements" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN measurements TEXT NOT NULL DEFAULT '{}'")
        if "work_completed_by" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN work_completed_by TEXT")
        if "work_completed_at" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN work_completed_at TEXT")
        if "work_change_requested_by" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN work_change_requested_by TEXT")
        if "work_change_requested_to" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN work_change_requested_to TEXT")
        if "work_change_requested_at" not in bill_columns:
            execute(c, db_type, "ALTER TABLE bills ADD COLUMN work_change_requested_at TEXT")

        conn.commit()

        execute(c, db_type, "SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            default_users = {
                "samaresh": {"password": hash_pw(os.getenv("ADMIN_DEFAULT_PASS", "s1")), "role": "admin", "name": "samaresh"},
                "bimal": {"password": hash_pw(os.getenv("EMP1_DEFAULT_PASS", "b2")), "role": "employee", "name": "bimal"},
                "susama": {"password": hash_pw(os.getenv("EMP2_DEFAULT_PASS", "s3")), "role": "employee", "name": "susama"},
            }
            for user_id, data in default_users.items():
                execute(
                    c, db_type,
                    "INSERT INTO users (user_id, password, name, role) VALUES (?, ?, ?, ?)",
                    (user_id, data["password"], data["name"], data["role"]),
                )
            conn.commit()


init_db()



def is_valid_name(name: str) -> bool:
    cleaned = name.strip()
    return bool(re.match(r"^[a-zA-Z\s]{1,80}$", cleaned))


def is_valid_user_id(user_id: str) -> bool:
    cleaned = user_id.strip()
    return bool(re.match(r"^[a-zA-Z]{2,32}$", cleaned))


def is_valid_phone(phone: str) -> bool:
    return bool(re.match(r"^[6-9][0-9]{9}$", phone.strip()))


def format_phone_with_country_code(phone: str) -> str:
    clean_phone = re.sub(r"[^0-9]", "", phone)[-10:]
    return f"91{clean_phone}"


def sanitize_text(value: str, max_len: int = 120) -> str:
    """Strips control chars and HTML-escapes strings to prevent Stored XSS."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", value.strip())[:max_len]
    return html.escape(cleaned, quote=True)


class LoginData(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v):
        if not is_valid_user_id(v):
            raise ValueError("User ID must contain only alphabets (2-32 chars)")
        return v.strip().lower()


class BillInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    phone: str = Field(..., min_length=10, max_length=15)
    billNo: str = Field(..., min_length=1, max_length=50)
    orderTrack: str = Field(default="", max_length=100)
    item: str = Field(..., min_length=1, max_length=150)
    deliveryDate: str = Field(..., min_length=10, max_length=10)
    measurements: Dict[str, str] = Field(
        default_factory=lambda: {field: "" for field in MEASUREMENT_FIELDS}
    )
    amount: float = Field(..., ge=0, le=100_000_000)
    down: float = Field(..., ge=0, le=100_000_000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if not is_valid_name(v):
            raise ValueError("Name must contain only alphabets and spaces")
        return v.strip()

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        digits = re.sub(r"[^0-9]", "", v)
        if len(digits) == 12 and digits.startswith("91"):
            digits = digits[2:]
        if not is_valid_phone(digits):
            raise ValueError("Phone must be a valid 10-digit Indian mobile number")
        return format_phone_with_country_code(digits)

    @field_validator("billNo", "orderTrack", "item")
    @classmethod
    def sanitize_fields(cls, v):
        return sanitize_text(v, max_len=150)

    @field_validator("deliveryDate")
    @classmethod
    def validate_delivery_date(cls, v):
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            raise ValueError("Delivery date must be a valid YYYY-MM-DD date")
        try:
            parsed = datetime.strptime(v, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("Delivery date must be a valid YYYY-MM-DD date") from exc
        if parsed.strftime("%Y-%m-%d") != v:
            raise ValueError("Delivery date must be a valid YYYY-MM-DD date")
        return v

    @field_validator("measurements")
    @classmethod
    def validate_measurements(cls, values):
        unknown_fields = set(values) - set(MEASUREMENT_FIELDS)
        if unknown_fields:
            raise ValueError("Unknown measurement field")
        if any(not isinstance(value, str) or len(value) > 40 for value in values.values()):
            raise ValueError("Each measurement must be text up to 40 characters")
        return {field: values.get(field, "") for field in MEASUREMENT_FIELDS}


def parse_measurements(value):
    measurements = json.loads(value or "{}")
    return {field: measurements.get(field, "") for field in MEASUREMENT_FIELDS}


class DeliveryReminderInput(BaseModel):
    remindOn: str = Field(..., min_length=10, max_length=10)

    @field_validator("remindOn")
    @classmethod
    def validate_reminder_date(cls, v):
        try:
            reminder_date = datetime.strptime(v, "%Y-%m-%d").date()
        except ValueError as exc:
            raise ValueError("Reminder date must be a valid future date") from exc
        if reminder_date <= datetime.now().date():
            raise ValueError("Reminder date must be a valid future date")
        return v


class UserCreate(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=32)
    password: str = Field(..., min_length=6, max_length=128)
    name: str = Field(default="", max_length=80)
    role: str = Field(default="employee")

    @field_validator("user_id")
    @classmethod
    def validate_user_id(cls, v):
        if not is_valid_user_id(v):
            raise ValueError("User ID must contain only alphabets (2-32 chars)")
        return v.strip().lower()

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if v and not is_valid_name(v):
            raise ValueError("Name must contain only alphabets and spaces")
        return v.strip()


class PasswordReset(BaseModel):
    password: str = Field(..., min_length=6, max_length=128)


class RoleUpdate(BaseModel):
    role: str


class WorkCompletionAssignment(BaseModel):
    workerId: str = Field(..., min_length=2, max_length=32)

    @field_validator("workerId")
    @classmethod
    def validate_worker_id(cls, value):
        if not is_valid_user_id(value):
            raise ValueError("Worker ID must contain only alphabets")
        return value.strip()


class WorkChangeResponse(BaseModel):
    accept: bool



def current_user(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    raw_token = authorization.split(" ", 1)[1].strip()
    if not raw_token or len(raw_token) > 128:
        raise HTTPException(status_code=401, detail="Invalid session token format")

    token_hash = hash_session_token(raw_token)

    with db_session() as (conn, c, db_type):
    
        execute(
            c, db_type,
            "SELECT user_id, created_at, token FROM sessions WHERE token = ? OR token = ?",
            (token_hash, raw_token),
        )
        row = c.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        user_id, created_at_str, stored_token = row[0], row[1], row[2]

       
        if created_at_str:
            try:
                created_at = datetime.fromisoformat(created_at_str)
                if created_at.tzinfo is None:
                    created_at = created_at.replace(tzinfo=timezone.utc)
                now_utc = datetime.now(timezone.utc)
                if now_utc - created_at > timedelta(hours=SESSION_TTL_HOURS):
                    execute(c, db_type, "DELETE FROM sessions WHERE token = ?", (stored_token,))
                    conn.commit()
                    raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
            except HTTPException:
                raise
            except Exception:
                pass

        return user_id


def require_admin(user_id: str = Depends(current_user)) -> str:
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT role FROM users WHERE user_id = ?", (user_id,))
        row = c.fetchone()

        if not row or row[0] != "admin":
            raise HTTPException(status_code=403, detail="Admin access required")
        return user_id


@app.post("/api/login")
def login(data: LoginData):
    with db_session() as (conn, c, db_type):
        execute(
            c, db_type,
            "SELECT user_id, password, role, name FROM users WHERE LOWER(user_id) = ?",
            (data.user_id,),
        )
        row = c.fetchone()

        if not row:
            verify_pw(data.password, "pbkdf2_sha256$260000$0000000000000000$" + "0" * 64)
            raise HTTPException(status_code=401, detail="Invalid user ID or password")

        is_valid, needs_rehash = verify_pw(data.password, row[1])
        if not is_valid:
            raise HTTPException(status_code=401, detail="Invalid user ID or password")

        if needs_rehash:
            execute(
                c, db_type,
                "UPDATE users SET password = ? WHERE user_id = ?",
                (hash_pw(data.password), row[0]),
            )

        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_session_token(raw_token)
        now_iso = datetime.now(timezone.utc).isoformat()

        execute(
            c, db_type,
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token_hash, row[0], now_iso),
        )
        conn.commit()

        return {
            "token": raw_token,
            "user_id": row[0],
            "role": row[2],
            "name": row[3],
        }


@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
        token_hash = hash_session_token(raw_token)
        with db_session() as (conn, c, db_type):
            execute(c, db_type, "DELETE FROM sessions WHERE token = ? OR token = ?", (token_hash, raw_token))
            conn.commit()
    return {"message": "Logged out"}


@app.get("/api/me")
def me(user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT role, name FROM users WHERE user_id = ?", (user_id,))
        row = c.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="User not found")

        return {"user_id": user_id, "role": row[0], "name": row[1]}


@app.get("/api/bills")
def get_bills(user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(
            c, db_type,
            """SELECT bills.id, bills.name, bills.phone, bills.billNo, bills.orderTrack, bills.item, bills.amount, bills.down, bills.pending,
                      bills.created_at, bills.created_by, COALESCE(creator.name, bills.created_by) AS created_by_name,
                      bills.work_completed_by, worker.name AS work_completed_by_name, worker.role AS work_completed_by_role, bills.work_completed_at,
                      bills.work_change_requested_by, requester.name AS work_change_requested_by_name,
                      bills.work_change_requested_to, target.name AS work_change_requested_to_name, bills.work_change_requested_at,
                      bills.delivery_date, bills.delivery_alert_accepted, bills.delivery_remind_on, bills.measurements
               FROM bills
               LEFT JOIN users AS creator ON creator.user_id = bills.created_by
               LEFT JOIN users AS worker ON worker.user_id = bills.work_completed_by
               LEFT JOIN users AS requester ON requester.user_id = bills.work_change_requested_by
               LEFT JOIN users AS target ON target.user_id = bills.work_change_requested_to
               ORDER BY bills.id DESC""",
        )
        rows = c.fetchall()
        bills = [dict(row) for row in rows]
        for bill in bills:
            bill["measurements"] = parse_measurements(bill["measurements"])
        return bills


@app.post("/api/bills")
def create_bill(bill: BillInput, user_id: str = Depends(current_user)):
    pending = round(max(bill.amount - bill.down, 0.0), 2)
    created_at = datetime.now(timezone.utc).isoformat()

    with db_session() as (conn, c, db_type):
        query = """INSERT INTO bills (name, phone, billNo, orderTrack, item, amount, down, pending, created_by, created_at, delivery_date, delivery_alert_accepted, delivery_remind_on, measurements)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)"""
        params = (
            bill.name, bill.phone, bill.billNo, bill.orderTrack, bill.item,
            bill.amount, bill.down, pending, user_id, created_at,
            bill.deliveryDate or None, json.dumps(bill.measurements, ensure_ascii=False),
        )

        if db_type == "postgres":
            execute(c, db_type, query + " RETURNING id", params)
            bill_id = c.fetchone()[0]
        else:
            execute(c, db_type, query, params)
            c.execute("SELECT last_insert_rowid()")
            bill_id = c.fetchone()[0]

        conn.commit()

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
            "created_at": created_at,
            "created_by": user_id,
            "delivery_date": bill.deliveryDate or None,
            "delivery_alert_accepted": 0,
            "delivery_remind_on": None,
            "measurements": bill.measurements,
        }


@app.put("/api/bills/{bill_id}")
def update_bill(bill_id: int, bill: BillInput, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT created_by, created_at, delivery_date, delivery_alert_accepted, delivery_remind_on FROM bills WHERE id = ?", (bill_id,))
        row = c.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Bill not found")

        pending = round(max(bill.amount - bill.down, 0.0), 2)
        delivery_date = bill.deliveryDate or None
        delivery_alert_accepted = row[3] if row[2] == delivery_date else 0
        delivery_remind_on = row[4] if row[2] == delivery_date else None
        execute(
            c, db_type,
            """UPDATE bills SET name = ?, phone = ?, billNo = ?, orderTrack = ?, item = ?, amount = ?, down = ?, pending = ?, delivery_date = ?, delivery_alert_accepted = ?, delivery_remind_on = ?, measurements = ?
               WHERE id = ?""",
            (bill.name, bill.phone, bill.billNo, bill.orderTrack, bill.item, bill.amount, bill.down, pending, delivery_date, delivery_alert_accepted, delivery_remind_on, json.dumps(bill.measurements, ensure_ascii=False), bill_id),
        )
        conn.commit()

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
            "created_at": row[1],
            "created_by": row[0],
            "delivery_date": delivery_date,
            "delivery_alert_accepted": delivery_alert_accepted,
            "delivery_remind_on": delivery_remind_on,
            "measurements": bill.measurements,
        }


@app.post("/api/bills/{bill_id}/delivery-alert/accept")
def accept_delivery_alert(bill_id: int, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT id FROM bills WHERE id = ?", (bill_id,))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="Bill not found")
        execute(c, db_type, "UPDATE bills SET delivery_alert_accepted = 1, delivery_remind_on = NULL WHERE id = ?", (bill_id,))
        conn.commit()
    return {"message": "Delivery alert accepted"}


@app.post("/api/bills/{bill_id}/work-complete")
def mark_work_complete(bill_id: int, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT name, role FROM users WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        completed_at = datetime.now(timezone.utc).isoformat()
        execute(
            c, db_type,
            "UPDATE bills SET work_completed_by = ?, work_completed_at = ? WHERE id = ? AND work_completed_by IS NULL",
            (user_id, completed_at, bill_id),
        )
        if c.rowcount == 0:
            execute(c, db_type, "SELECT id FROM bills WHERE id = ?", (bill_id,))
            if not c.fetchone():
                raise HTTPException(status_code=404, detail="Bill not found")
            raise HTTPException(status_code=409, detail="Work has already been marked complete")
        conn.commit()

    return {
        "work_completed_by": user_id,
        "work_completed_by_name": user[0],
        "work_completed_by_role": user[1],
        "work_completed_at": completed_at,
        "work_change_requested_by": None,
        "work_change_requested_to": None,
        "work_change_requested_at": None,
    }


@app.put("/api/bills/{bill_id}/work-complete")
def update_work_completion(bill_id: int, assignment: WorkCompletionAssignment, admin: str = Depends(require_admin)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT work_completed_at FROM bills WHERE id = ?", (bill_id,))
        bill = c.fetchone()
        if not bill:
            raise HTTPException(status_code=404, detail="Bill not found")
        if not bill[0]:
            raise HTTPException(status_code=409, detail="Work must be marked complete before changing its employee")

        execute(c, db_type, "SELECT user_id, name, role FROM users WHERE user_id = ? AND role IN ('employee', 'admin')", (assignment.workerId,))
        worker = c.fetchone()
        if not worker:
            raise HTTPException(status_code=400, detail="Select a valid employee or admin")

        execute(
            c, db_type,
            "UPDATE bills SET work_completed_by = ?, work_change_requested_by = NULL, work_change_requested_to = NULL, work_change_requested_at = NULL WHERE id = ?",
            (worker[0], bill_id),
        )
        conn.commit()

    return {
        "work_completed_by": worker[0],
        "work_completed_by_name": worker[1],
        "work_completed_by_role": worker[2],
        "work_completed_at": bill[0],
        "work_change_requested_by": None,
        "work_change_requested_to": None,
        "work_change_requested_at": None,
    }


@app.get("/api/workers")
def get_working_users(user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id, name, role FROM users WHERE role IN ('employee', 'admin') ORDER BY role, name")
        return [dict(row) for row in c.fetchall()]


@app.post("/api/bills/{bill_id}/work-change-request")
def request_work_change(bill_id: int, assignment: WorkCompletionAssignment, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id, name FROM users WHERE user_id = ? AND role IN ('employee', 'admin')", (assignment.workerId,))
        target = c.fetchone()
        if not target:
            raise HTTPException(status_code=400, detail="Select a valid employee or admin")
        execute(c, db_type, "SELECT name FROM users WHERE user_id = ?", (user_id,))
        requester = c.fetchone()

        requested_at = datetime.now(timezone.utc).isoformat()
        execute(
            c, db_type,
            """UPDATE bills SET work_change_requested_by = ?, work_change_requested_to = ?, work_change_requested_at = ?
               WHERE id = ? AND work_completed_by IS NOT NULL AND work_completed_by != ?
                 AND work_change_requested_to IS NULL""",
            (user_id, target[0], requested_at, bill_id, target[0]),
        )
        if c.rowcount == 0:
            execute(c, db_type, "SELECT work_completed_by, work_change_requested_to FROM bills WHERE id = ?", (bill_id,))
            bill = c.fetchone()
            if not bill:
                raise HTTPException(status_code=404, detail="Bill not found")
            if not bill[0]:
                raise HTTPException(status_code=409, detail="Work must be completed before changing its worker")
            if bill[0] == target[0]:
                raise HTTPException(status_code=400, detail="This worker is already assigned")
            raise HTTPException(status_code=409, detail="Another work change request is already pending")
        conn.commit()

    return {
        "message": "Work change request sent",
        "work_change_requested_by": user_id,
        "work_change_requested_by_name": requester[0],
        "work_change_requested_to": target[0],
        "work_change_requested_to_name": target[1],
        "work_change_requested_at": requested_at,
    }


@app.get("/api/work-change-requests")
def get_work_change_requests(user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT role FROM users WHERE user_id = ?", (user_id,))
        user = c.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        execute(
            c, db_type,
            """SELECT bills.id AS bill_id, bills.name AS customer_name, bills.billNo, bills.work_change_requested_by,
                      requester.name AS requester_name, bills.work_change_requested_to, target.name AS target_name,
                      bills.work_change_requested_at, bills.work_completed_by, current_worker.name AS current_worker_name
               FROM bills
               JOIN users AS requester ON requester.user_id = bills.work_change_requested_by
               JOIN users AS current_worker ON current_worker.user_id = bills.work_completed_by
               JOIN users AS target ON target.user_id = bills.work_change_requested_to
               WHERE ? = 'admin' OR bills.work_completed_by = ?
               ORDER BY bills.work_change_requested_at""",
            (user[0], user_id),
        )
        return [dict(row) for row in c.fetchall()]


@app.post("/api/bills/{bill_id}/work-change-response")
def respond_to_work_change(bill_id: int, response: WorkChangeResponse, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(
            c, db_type,
            """SELECT bills.work_change_requested_by, bills.work_change_requested_to,
                      bills.work_completed_by, bills.work_completed_at, target.name, target.role,
                      current_worker.name, current_worker.role
               FROM bills
               LEFT JOIN users AS current_worker ON current_worker.user_id = bills.work_completed_by
               LEFT JOIN users AS target ON target.user_id = bills.work_change_requested_to
               WHERE bills.id = ?""",
            (bill_id,),
        )
        bill = c.fetchone()
        if not bill:
            raise HTTPException(status_code=404, detail="Bill not found")
        if not bill[1]:
            raise HTTPException(status_code=409, detail="Work change request is no longer pending")
        if bill[2] != user_id:
            execute(c, db_type, "SELECT role FROM users WHERE user_id = ?", (user_id,))
            user = c.fetchone()
            if not user or user[0] != "admin":
                raise HTTPException(status_code=403, detail="Only the current worker or an admin can respond to this request")
        if response.accept and not bill[4]:
            raise HTTPException(status_code=409, detail="The assigned user no longer exists")

        if response.accept:
            execute(
                c, db_type,
                """UPDATE bills SET work_completed_by = ?, work_change_requested_by = NULL,
                          work_change_requested_to = NULL, work_change_requested_at = NULL
                   WHERE id = ? AND work_completed_by = ? AND work_change_requested_by = ? AND work_change_requested_to = ?""",
                (bill[1], bill_id, bill[2], bill[0], bill[1]),
            )
        else:
            execute(
                c, db_type,
                """UPDATE bills SET work_change_requested_by = NULL, work_change_requested_to = NULL,
                          work_change_requested_at = NULL
                   WHERE id = ? AND work_completed_by = ? AND work_change_requested_by = ? AND work_change_requested_to = ?""",
                (bill_id, bill[2], bill[0], bill[1]),
            )
        if c.rowcount == 0:
            raise HTTPException(status_code=409, detail="Work change request is no longer pending")
        conn.commit()

    return {
        "bill_id": bill_id,
        "accepted": response.accept,
        "work_completed_by": bill[1] if response.accept else bill[2],
        "work_completed_by_name": bill[4] if response.accept else bill[6],
        "work_completed_by_role": bill[5] if response.accept else bill[7],
        "work_completed_at": bill[3],
        "work_change_requested_by": None,
        "work_change_requested_to": None,
        "work_change_requested_at": None,
    }


@app.get("/api/work-stats")
def get_work_stats(admin: str = Depends(require_admin)):
    with db_session() as (conn, c, db_type):
        if db_type == "postgres":
            query = """SELECT ((bills.work_completed_at::timestamptz AT TIME ZONE 'Asia/Kolkata')::date)::text AS work_date,
                              bills.work_completed_by AS worker_id, COALESCE(users.name, bills.work_completed_by) AS worker_name,
                              COALESCE(users.role, 'unknown') AS worker_role, COUNT(*) AS job_count
                       FROM bills LEFT JOIN users ON users.user_id = bills.work_completed_by
                       WHERE bills.work_completed_at IS NOT NULL
                       GROUP BY work_date, worker_id, worker_name, worker_role
                       ORDER BY work_date DESC, worker_name"""
        else:
            query = """SELECT strftime('%Y-%m-%d', bills.work_completed_at, '+5 hours', '+30 minutes') AS work_date,
                              bills.work_completed_by AS worker_id, COALESCE(users.name, bills.work_completed_by) AS worker_name,
                              COALESCE(users.role, 'unknown') AS worker_role, COUNT(*) AS job_count
                       FROM bills LEFT JOIN users ON users.user_id = bills.work_completed_by
                       WHERE bills.work_completed_at IS NOT NULL
                       GROUP BY work_date, worker_id, worker_name, worker_role
                       ORDER BY work_date DESC, worker_name"""
        execute(c, db_type, query)
        return [dict(row) for row in c.fetchall()]


@app.post("/api/bills/{bill_id}/delivery-alert/remind")
def remind_delivery_alert(bill_id: int, data: DeliveryReminderInput, user_id: str = Depends(current_user)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT id FROM bills WHERE id = ?", (bill_id,))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="Bill not found")
        execute(c, db_type, "UPDATE bills SET delivery_remind_on = ? WHERE id = ?", (data.remindOn, bill_id))
        conn.commit()
    return {"message": "Delivery reminder rescheduled", "delivery_remind_on": data.remindOn}


@app.delete("/api/bills/{bill_id}")
def delete_bill(bill_id: int, admin: str = Depends(require_admin)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "DELETE FROM bills WHERE id = ?", (bill_id,))
        conn.commit()
    return {"message": "Bill deleted"}


@app.get("/api/users")
def list_users(admin: str = Depends(require_admin)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id, name, role FROM users")
        rows = c.fetchall()
        return [dict(row) for row in rows]


@app.post("/api/users")
def create_user(data: UserCreate, admin: str = Depends(require_admin)):
    if data.role not in ("admin", "employee"):
        raise HTTPException(status_code=400, detail="Role must be admin or employee")

    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (data.user_id,))
        if c.fetchone():
            raise HTTPException(status_code=400, detail="User ID already exists")

        execute(
            c, db_type,
            "INSERT INTO users (user_id, password, name, role) VALUES (?, ?, ?, ?)",
            (data.user_id, hash_pw(data.password), data.name or data.user_id, data.role),
        )
        conn.commit()

    return {"message": f"User {data.user_id} created"}


@app.put("/api/users/{user_id}")
def update_role(user_id: str, data: RoleUpdate, admin: str = Depends(require_admin)):
    if data.role not in ("admin", "employee"):
        raise HTTPException(status_code=400, detail="Invalid role")

    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        execute(c, db_type, "UPDATE users SET role = ? WHERE user_id = ?", (data.role, user_id))
        conn.commit()

    return {"message": f"Role updated for {user_id}"}


@app.put("/api/users/{user_id}/password")
def reset_password(user_id: str, data: PasswordReset, admin: str = Depends(require_admin)):
    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        execute(c, db_type, "UPDATE users SET password = ? WHERE user_id = ?", (hash_pw(data.password), user_id))
        execute(c, db_type, "DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()

    return {"message": f"Password updated and active sessions revoked for {user_id}"}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, admin: str = Depends(require_admin)):
    if user_id == admin:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    with db_session() as (conn, c, db_type):
        execute(c, db_type, "SELECT user_id FROM users WHERE user_id = ?", (user_id,))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        execute(c, db_type, "DELETE FROM users WHERE user_id = ?", (user_id,))
        execute(c, db_type, "DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()

    return {"message": f"User {user_id} deleted"}


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
    is_dev = os.getenv("ENV", "production").lower() == "development"
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=is_dev, server_header=False)
    