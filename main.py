import base64
import hashlib
import argparse
import shutil
from datetime import datetime
import sys
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Depends, Header, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, field_validator
from urllib.parse import urlencode
from urllib.request import Request as URLRequest, urlopen
from urllib.error import URLError, HTTPError

DB_NAME = os.getenv("SOKO_DB_PATH", "local_market.db")
TOKEN_SECRET = os.getenv("SOKO_TOKEN_SECRET", "")
TOKEN_TTL = int(os.getenv("SOKO_TOKEN_TTL_SECONDS", "86400"))
ADMIN_RESET_KEY = os.getenv("SOKO_ADMIN_RESET_KEY", "").strip()
ADMIN_RESET_TTL_SECONDS = 1800  # 30 minutes
ADMIN_RESET_MAX_ATTEMPTS = 5
ALLOWED_ORIGINS = [x.strip() for x in os.getenv(
    "SOKO_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500"
).split(",") if x.strip()]
MAX_IMAGES = 4
MAX_IMAGE_CHARS = 1_000_000
AT_USERNAME = os.getenv("AT_USERNAME", "").strip()
AT_API_KEY = os.getenv("AT_API_KEY", "").strip()
AT_SENDER_ID = os.getenv("AT_SENDER_ID", "").strip()
AT_ENV = os.getenv("AT_ENV", "live").strip().lower()
OTP_TTL_SECONDS = 600
OTP_RESEND_SECONDS = 60
OTP_MAX_PER_HOUR = 3
OTP_MAX_ATTEMPTS = 5
app = FastAPI(title="Soko la Mtaa API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS,
                   allow_credentials=False, allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type"])

@contextmanager
def db():
    conn = sqlite3.connect(DB_NAME, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Create tables and safely add columns missing from older databases.

    Existing rows and tables are preserved; indexes are created only after
    the required columns have been checked/added.
    """
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, phone TEXT, location TEXT, token_version INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT, seller_id INTEGER, title TEXT NOT NULL,
            description TEXT, category TEXT, item_type TEXT DEFAULT 'product', price REAL NOT NULL,
            condition TEXT, location TEXT, region TEXT, district TEXT, ward TEXT, street TEXT,
            phone TEXT, image_url TEXT, is_sold INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS buyer_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, buyer_id INTEGER, buyer_name TEXT,
            title TEXT NOT NULL, description TEXT, category TEXT, item_type TEXT DEFAULT 'product',
            budget REAL NOT NULL, location TEXT, region TEXT, district TEXT, ward TEXT, street TEXT,
            phone TEXT, status TEXT DEFAULT 'active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT, item_id INTEGER, item_type TEXT,
            buyer_id INTEGER, seller_id INTEGER, quantity INTEGER DEFAULT 1,
            status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, author_id INTEGER, author_name TEXT,
            title TEXT NOT NULL, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        c.execute("""CREATE TABLE IF NOT EXISTS password_reset_otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            phone_norm TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0,
            request_ip TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_phone_created ON password_reset_otps(phone_norm, created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_otps(user_id, consumed)")
        c.execute("""CREATE TABLE IF NOT EXISTS admin_password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0,
            request_ip TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_admin_reset_user ON admin_password_resets(user_id, consumed)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_admin_reset_ip_created ON admin_password_resets(request_ip, created_at)")

        # Add columns expected by this version when upgrading an older DB.
        # Declarations intentionally avoid NOT NULL without a default so SQLite
        # can migrate tables that already contain rows.
        required_columns = {
            "users": {
                "username": "TEXT", "password": "TEXT", "phone": "TEXT", "location": "TEXT",
                "token_version": "INTEGER DEFAULT 0",
            },
            "products": {
                "seller_id": "INTEGER", "title": "TEXT", "description": "TEXT",
                "category": "TEXT", "item_type": "TEXT DEFAULT 'product'", "price": "REAL",
                "condition": "TEXT", "location": "TEXT", "region": "TEXT", "district": "TEXT",
                "ward": "TEXT", "street": "TEXT", "phone": "TEXT", "image_url": "TEXT",
                "is_sold": "INTEGER DEFAULT 0", "created_at": "TIMESTAMP",
            },
            "buyer_requests": {
                "buyer_id": "INTEGER", "buyer_name": "TEXT", "title": "TEXT",
                "description": "TEXT", "category": "TEXT", "item_type": "TEXT DEFAULT 'product'",
                "budget": "REAL", "location": "TEXT", "region": "TEXT", "district": "TEXT",
                "ward": "TEXT", "street": "TEXT", "phone": "TEXT",
                "status": "TEXT DEFAULT 'active'", "created_at": "TIMESTAMP",
            },
            "orders": {
                "item_id": "INTEGER", "item_type": "TEXT", "buyer_id": "INTEGER",
                "seller_id": "INTEGER", "quantity": "INTEGER DEFAULT 1",
                "status": "TEXT DEFAULT 'pending'", "created_at": "TIMESTAMP",
            },
            "community_posts": {
                "author_id": "INTEGER", "author_name": "TEXT", "title": "TEXT",
                "content": "TEXT", "created_at": "TIMESTAMP",
            },
        }
        for table, columns in required_columns.items():
            existing = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
            for column, declaration in columns.items():
                if column not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

        # Index creation must happen after legacy-schema migrations.
        product_columns = {row["name"] for row in c.execute("PRAGMA table_info(products)")}
        if {"region", "item_type"}.issubset(product_columns):
            c.execute("CREATE INDEX IF NOT EXISTS idx_products_region_type ON products(region, item_type)")
        request_columns = {row["name"] for row in c.execute("PRAGMA table_info(buyer_requests)")}
        if "status" in request_columns:
            c.execute("CREATE INDEX IF NOT EXISTS idx_buyer_requests_status ON buyer_requests(status)")

# Skip automatic initialization when running the destructive reset CLI command.
# Normal Uvicorn imports still initialize/migrate the database as before.
if not (len(sys.argv) > 1 and sys.argv[1] == "reset-database"):
    init_db()

def clean_text(value: Optional[str], max_len: int = 500) -> Optional[str]:
    if value is None: return None
    value = value.strip()
    if len(value) > max_len: raise ValueError(f"Maandishi yasizidi herufi {max_len}.")
    return value

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, rounds, salt, expected = stored.split("$", 3)
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt), int(rounds))
            return hmac.compare_digest(base64.urlsafe_b64encode(actual).decode(), expected)
        # Compatibility with legacy SHA-256 hashes; successful login upgrades hash.
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
    except (ValueError, TypeError):
        return False

def make_token(user_id: int, token_version: int = 0) -> str:
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "Seva ya akaunti haijasanidiwa: weka SOKO_TOKEN_SECRET yenye angalau herufi 32.")
    payload = {"sub": user_id, "exp": int(time.time()) + TOKEN_TTL, "ver": token_version}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(TOKEN_SECRET.encode(), raw.encode(), hashlib.sha256).digest()
    return raw + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Ingia kwenye akaunti ili kuendelea.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        raw, signature = token.split(".", 1)
        expected = hmac.new(TOKEN_SECRET.encode(), raw.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not TOKEN_SECRET or not hmac.compare_digest(expected, supplied): raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if int(payload["exp"]) < int(time.time()): raise ValueError()
        uid = int(payload["sub"])
        token_version = int(payload.get("ver", 0))
    except Exception:
        raise HTTPException(401, "Kikao kimeisha au si sahihi. Ingia tena.")
    with db() as c:
        row = c.execute("SELECT id, username, phone, location, token_version FROM users WHERE id=?", (uid,)).fetchone()
    if not row: raise HTTPException(401, "Akaunti haipatikani.")
    if int(row["token_version"] or 0) != token_version:
        raise HTTPException(401, "Nenosiri limebadilishwa. Ingia tena.")
    return dict(row)

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class UserRegister(StrictModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    phone: Optional[str] = Field(default=None, max_length=30)
    location: Optional[str] = Field(default=None, max_length=120)

class UserLogin(StrictModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=256)

class PasswordResetRequest(StrictModel):
    username: str = Field(min_length=1, max_length=40)
    phone: str = Field(min_length=7, max_length=30)

class PasswordResetVerify(StrictModel):
    username: str = Field(min_length=1, max_length=40)
    phone: str = Field(min_length=7, max_length=30)
    code: str = Field(pattern=r"^\d{6}$")
    new_password: str = Field(min_length=8, max_length=256)

class AdminPasswordResetCreate(StrictModel):
    username: str = Field(min_length=1, max_length=40)

class AdminPasswordResetComplete(StrictModel):
    username: str = Field(min_length=1, max_length=40)
    reset_code: str = Field(pattern=r"^\d{8}$")
    new_password: str = Field(min_length=8, max_length=256)

class ProductCreate(StrictModel):
    title: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=3000)
    category: str = Field(min_length=1, max_length=80)
    item_type: Literal["product", "service"] = "product"
    price: float = Field(gt=0, le=1_000_000_000)
    condition: Optional[str] = Field(default="Mpya", max_length=40)
    location: Optional[str] = Field(default="", max_length=120)
    region: Optional[str] = Field(default="", max_length=100)
    district: Optional[str] = Field(default="", max_length=100)
    ward: Optional[str] = Field(default="", max_length=100)
    street: Optional[str] = Field(default="", max_length=120)
    phone: str = Field(min_length=5, max_length=30)
    image_url: Optional[str] = Field(default=None, max_length=MAX_IMAGE_CHARS * MAX_IMAGES + 100)
    @field_validator("image_url")
    @classmethod
    def validate_images(cls, v):
        if not v: return v
        parts = v.split("|||")
        if len(parts) > MAX_IMAGES: raise ValueError(f"Unaweza kuweka picha zisizozidi {MAX_IMAGES}.")
        for item in parts:
            if not item: continue
            m = re.fullmatch(r"data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=\r\n]+)", item)
            if not m: raise ValueError("Picha lazima iwe JPEG, PNG au WebP yenye Base64 halali.")
            if len(item) > MAX_IMAGE_CHARS: raise ValueError("Picha ni kubwa mno; punguza ukubwa wake.")
            try: base64.b64decode(m.group(2), validate=True)
            except Exception: raise ValueError("Data ya picha si halali.")
        return v

class BuyerRequestCreate(StrictModel):
    title: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=3000)
    category: str = Field(min_length=1, max_length=80)
    item_type: Literal["product", "service"] = "product"
    budget: float = Field(gt=0, le=1_000_000_000)
    location: Optional[str] = Field(default="", max_length=120)
    region: Optional[str] = Field(default="", max_length=100)
    district: Optional[str] = Field(default="", max_length=100)
    ward: Optional[str] = Field(default="", max_length=100)
    street: Optional[str] = Field(default="", max_length=120)
    phone: str = Field(min_length=5, max_length=30)

class OrderCreate(StrictModel):
    item_id: int = Field(gt=0)
    item_type: Literal["product", "service"]
    quantity: int = Field(default=1, ge=1, le=10000)

class CommunityPostCreate(StrictModel):
    title: str = Field(min_length=2, max_length=150)
    content: str = Field(min_length=2, max_length=5000)

@app.get("/")
def home(): return {"status": "ok", "message": "Soko la Mtaa API ipo tayari!"}

@app.post("/api/users/register", status_code=201)
def register_user(user: UserRegister):
    with db() as c:
        try:
            cur = c.execute("INSERT INTO users(username,password,phone,location) VALUES(?,?,?,?)",
                            (user.username.strip(), hash_password(user.password), user.phone, user.location))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Jina hili la mtumiaji tayari limeshatumika.")
        return {"message": "Mtumiaji amesajiliwa kikamilifu",
                "user": {"id": cur.lastrowid, "username": user.username.strip(), "phone": user.phone, "location": user.location}}

@app.post("/api/users/login")
def login_user(user: UserLogin):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (user.username.strip(),)).fetchone()
        if not row or not verify_password(user.password, row["password"]):
            raise HTTPException(401, "Jina au nenosiri si sahihi.")
        if not row["password"].startswith("pbkdf2_sha256$"):
            c.execute("UPDATE users SET password=? WHERE id=?", (hash_password(user.password), row["id"]))
        public_user = {"id": row["id"], "username": row["username"], "phone": row["phone"], "location": row["location"]}
    return {"message": "Umeingia kikamilifu", "user": public_user, "access_token": make_token(row["id"], int(row["token_version"] or 0)), "token_type": "bearer"}

def normalize_tz_phone(phone: str) -> str:
    """Normalize Tanzanian phone numbers to 255XXXXXXXXX."""
    digits = re.sub(r"\D", "", phone or "")
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith("0") and len(digits) == 10:
        digits = "255" + digits[1:]
    elif len(digits) == 9 and digits[0] in "67":
        digits = "255" + digits
    if not re.fullmatch(r"255[67][0-9]{8}", digits):
        raise HTTPException(400, "Weka namba halali ya Tanzania, mfano 0712345678 au +255712345678.")
    return digits

def otp_digest(code: str, phone_norm: str) -> str:
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "Huduma ya kurejesha nenosiri haijasanidiwa vizuri.")
    return hmac.new(TOKEN_SECRET.encode(), f"password-reset:{phone_norm}:{code}".encode(), hashlib.sha256).hexdigest()

def send_password_reset_sms(phone_norm: str, code: str) -> None:
    """Send OTP through Africa's Talking; credentials stay server-side."""
    if not AT_USERNAME or not AT_API_KEY:
        raise HTTPException(503, "Huduma ya SMS haijasanidiwa. Weka AT_USERNAME na AT_API_KEY kwenye Render Environment.")
    if AT_ENV == "sandbox":
        endpoint = "https://api.sandbox.africastalking.com/version1/messaging"
    else:
        endpoint = "https://api.africastalking.com/version1/messaging"
    message = f"Soko la Mtaa: Msimbo wako wa kubadilisha nenosiri ni {code}. Unaisha baada ya dakika 10. Usimpe mtu yeyote msimbo huu."
    fields = {"username": AT_USERNAME, "to": "+" + phone_norm, "message": message}
    if AT_SENDER_ID:
        fields["from"] = AT_SENDER_ID
    request = URLRequest(endpoint, data=urlencode(fields).encode(), method="POST", headers={
        "apiKey": AT_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    })
    try:
        with urlopen(request, timeout=12) as response:
            payload = response.read(100_000).decode("utf-8", errors="replace")
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"SMS provider HTTP {response.status}")
        result = json.loads(payload)
        recipients = result.get("SMSMessageData", {}).get("Recipients", [])
        if not recipients or not any(str(r.get("status", "")).lower() in ("success", "sent", "accepted") or r.get("statusCode") in (100, 101, 102) for r in recipients):
            raise RuntimeError("SMS provider did not accept the message")
    except (HTTPError, URLError, TimeoutError, ValueError, RuntimeError) as exc:
        # Do not log API key, OTP, or full provider response.
        print(f"SMS provider error: {type(exc).__name__}")
        raise HTTPException(502, "SMS haikutumwa. Hakikisha akaunti ya SMS, API key na salio viko sawa, kisha jaribu tena.")

@app.post("/api/users/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, request: Request):
    """Request an SMS OTP for a matching username + registered phone number."""
    # Check global configuration before account lookup to avoid account-enumeration side channels.
    if not AT_USERNAME or not AT_API_KEY:
        raise HTTPException(503, "Huduma ya SMS haijasanidiwa. Msimamizi aweke AT_USERNAME na AT_API_KEY kwenye Render Environment.")
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "SOKO_TOKEN_SECRET haijasanidiwa vizuri kwenye Render.")

    phone_norm = normalize_tz_phone(payload.phone)
    username_norm = payload.username.strip().lower()
    now = int(time.time())
    ip = (request.client.host if request.client else "unknown")[:64]
    generic = {"message": "Ikiwa jina la mtumiaji na namba vinaendana na akaunti, utapokea SMS yenye msimbo wa uthibitisho."}

    with db() as c:
        # Limit requests by phone and IP to reduce abuse and unexpected SMS charges.
        recent_phone = c.execute(
            "SELECT COUNT(*) n, MAX(created_at) last FROM password_reset_otps WHERE phone_norm=? AND created_at>?",
            (phone_norm, now - 3600),
        ).fetchone()
        recent_ip = c.execute(
            "SELECT COUNT(*) n FROM password_reset_otps WHERE request_ip=? AND created_at>?",
            (ip, now - 3600),
        ).fetchone()
        if recent_phone["last"] and now - recent_phone["last"] < OTP_RESEND_SECONDS:
            raise HTTPException(429, "Subiri dakika moja kabla ya kuomba msimbo mwingine.")
        if recent_phone["n"] >= OTP_MAX_PER_HOUR or recent_ip["n"] >= 10:
            raise HTTPException(429, "Umeomba misimbo mara nyingi. Jaribu tena baada ya muda.")

        candidates = c.execute(
            "SELECT id, username, phone FROM users WHERE lower(username)=?",
            (username_norm,),
        ).fetchall()
        matched = next((row for row in candidates if normalize_phone_safe(row["phone"] or "") == phone_norm), None)

        if not matched:
            # Record a consumed dummy row so unknown usernames/numbers are also rate-limited.
            c.execute("INSERT INTO password_reset_otps(user_id,phone_norm,code_hash,created_at,expires_at,attempts,consumed,request_ip) VALUES(?,?,?,?,?,0,1,?)",
                      (0, phone_norm, secrets.token_hex(32), now, now + OTP_TTL_SECONDS, ip))
            return generic

        user_id = int(matched["id"])
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = otp_digest(code, phone_norm)
        c.execute("UPDATE password_reset_otps SET consumed=1 WHERE user_id=? AND consumed=0", (user_id,))
        c.execute("INSERT INTO password_reset_otps(user_id,phone_norm,code_hash,created_at,expires_at,request_ip) VALUES(?,?,?,?,?,?)",
                  (user_id, phone_norm, digest, now, now + OTP_TTL_SECONDS, ip))

    try:
        send_password_reset_sms(phone_norm, code)
    except HTTPException as exc:
        with db() as c:
            c.execute("UPDATE password_reset_otps SET consumed=1 WHERE user_id=? AND consumed=0", (user_id,))
        # Same outward response as a non-matching account; provider details stay in server logs.
        print(f"Password reset SMS delivery failed: HTTP {exc.status_code}")
        return generic
    return generic

def normalize_phone_safe(phone: str) -> str:
    digits = re.sub(r"\D", "", phone or "")
    if digits.startswith("00"): digits = digits[2:]
    if digits.startswith("0") and len(digits) == 10: digits = "255" + digits[1:]
    elif len(digits) == 9 and digits[:1] in "67": digits = "255" + digits
    return digits

@app.post("/api/users/password-reset/verify")
def verify_password_reset(payload: PasswordResetVerify):
    phone_norm = normalize_tz_phone(payload.phone)
    username_norm = payload.username.strip().lower()
    now = int(time.time())
    bad_code = False
    error_message = None
    with db() as c:
        user = c.execute("SELECT id FROM users WHERE lower(username)=?", (username_norm,)).fetchone()
        if not user or normalize_phone_safe(c.execute("SELECT phone FROM users WHERE id=?", (user["id"],)).fetchone()["phone"] or "") != phone_norm:
            error_message = "Msimbo si sahihi au muda wake umeisha. Omba OTP mpya."
        else:
            row = c.execute("""SELECT * FROM password_reset_otps WHERE user_id=? AND phone_norm=? AND consumed=0
                ORDER BY id DESC LIMIT 1""", (user["id"], phone_norm)).fetchone()
            if not row or row["expires_at"] < now or row["attempts"] >= OTP_MAX_ATTEMPTS:
                if row and row["attempts"] >= OTP_MAX_ATTEMPTS:
                    c.execute("UPDATE password_reset_otps SET consumed=1 WHERE id=?", (row["id"],))
                error_message = "Msimbo umeisha muda wake au si sahihi. Omba msimbo mpya."
            else:
                digest = otp_digest(payload.code, phone_norm)
                if not hmac.compare_digest(digest, row["code_hash"]):
                    attempts = int(row["attempts"]) + 1
                    c.execute("UPDATE password_reset_otps SET attempts=?, consumed=? WHERE id=?",
                              (attempts, 1 if attempts >= OTP_MAX_ATTEMPTS else 0, row["id"]))
                    bad_code = True
                else:
                    c.execute("UPDATE users SET password=?, token_version=COALESCE(token_version,0)+1 WHERE id=?",
                              (hash_password(payload.new_password), user["id"]))
                    c.execute("UPDATE password_reset_otps SET consumed=1 WHERE user_id=? AND consumed=0", (user["id"],))
    if error_message:
        raise HTTPException(400, error_message)
    if bad_code:
        raise HTTPException(400, "Msimbo si sahihi. Una hadi majaribio 5; angalia OTP ya SMS.")
    return {"message": "Nenosiri limebadilishwa. Kikao cha zamani kimefungwa; ingia kwa nenosiri jipya."}

def admin_reset_digest(user_id: int, code: str) -> str:
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "Huduma ya kurejesha nenosiri haijasanidiwa vizuri.")
    return hmac.new(TOKEN_SECRET.encode(), f"admin-password-reset:{user_id}:{code}".encode(), hashlib.sha256).hexdigest()

@app.post("/api/admin/password-reset/create")
def create_admin_password_reset(
    payload: AdminPasswordResetCreate,
    request: Request,
    x_admin_reset_key: Optional[str] = Header(default=None, alias="X-Admin-Reset-Key"),
):
    """Admin-only: create a short-lived code to give privately to the account owner."""
    if len(ADMIN_RESET_KEY) < 32:
        raise HTTPException(503, "Msimamizi hajaweka SOKO_ADMIN_RESET_KEY yenye angalau herufi 32 kwenye Render Environment.")
    if not x_admin_reset_key or not hmac.compare_digest(x_admin_reset_key, ADMIN_RESET_KEY):
        # Do not reveal whether the configured key exists or is close to correct.
        raise HTTPException(401, "Huruhusiwi kutumia huduma hii.")
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "SOKO_TOKEN_SECRET haijasanidiwa vizuri kwenye Render.")

    now = int(time.time())
    ip = (request.client.host if request.client else "unknown")[:64]
    username = payload.username.strip().lower()
    with db() as c:
        recent_ip = c.execute(
            "SELECT COUNT(*) n FROM admin_password_resets WHERE request_ip=? AND created_at>?",
            (ip, now - 3600),
        ).fetchone()["n"]
        if recent_ip >= 10:
            raise HTTPException(429, "Majaribio mengi ya kurejesha akaunti kutoka kwenye muunganisho huu. Jaribu baadaye.")
        user = c.execute("SELECT id, username FROM users WHERE lower(username)=?", (username,)).fetchone()
        if not user:
            raise HTTPException(404, "Akaunti hiyo haijapatikana. Hakikisha jina la mtumiaji limeandikwa sawa.")
        recent_user = c.execute(
            "SELECT COUNT(*) n FROM admin_password_resets WHERE user_id=? AND created_at>?",
            (user["id"], now - 3600),
        ).fetchone()["n"]
        if recent_user >= 3:
            raise HTTPException(429, "Akaunti hii imeombewa misimbo mara nyingi. Jaribu tena baadaye.")
        code = f"{secrets.randbelow(100_000_000):08d}"
        digest = admin_reset_digest(int(user["id"]), code)
        c.execute("UPDATE admin_password_resets SET consumed=1 WHERE user_id=? AND consumed=0", (user["id"],))
        c.execute(
            "INSERT INTO admin_password_resets(user_id,code_hash,created_at,expires_at,request_ip) VALUES(?,?,?,?,?)",
            (user["id"], digest, now, now + ADMIN_RESET_TTL_SECONDS, ip),
        )
    # This response is available only after successful admin-key authentication.
    return {"message": "Msimbo umetengenezwa. Mtumie mmiliki wa akaunti kupitia njia ya faragha.",
            "username": user["username"], "reset_code": code, "expires_in_minutes": 30,
            "warning": "Usiweke msimbo huu kwenye tovuti ya umma au ujumbe wa kundi. Ni wa matumizi mara moja tu."}

@app.post("/api/users/password-reset/admin-verify")
def complete_admin_password_reset(payload: AdminPasswordResetComplete, request: Request):
    """Public owner flow: complete reset using a one-time code issued by an authenticated admin."""
    now = int(time.time())
    ip = (request.client.host if request.client else "unknown")[:64]
    username = payload.username.strip().lower()
    error = "Msimbo wa msimamizi si sahihi, umeisha muda wake, au hauendani na akaunti. Wasiliana na msimamizi upate msimbo mpya."
    with db() as c:
        # Limit repeated attempts from an IP before touching account data.
        recent_ip = c.execute(
            "SELECT COUNT(*) n FROM admin_password_resets WHERE request_ip=? AND created_at>?",
            (ip, now - 3600),
        ).fetchone()["n"]
        if recent_ip >= 30:
            raise HTTPException(429, "Majaribio mengi sana. Jaribu baadaye.")
        user = c.execute("SELECT id FROM users WHERE lower(username)=?", (username,)).fetchone()
        if not user:
            raise HTTPException(400, error)
        row = c.execute("""SELECT * FROM admin_password_resets
            WHERE user_id=? AND consumed=0 ORDER BY id DESC LIMIT 1""", (user["id"],)).fetchone()
        if not row or int(row["expires_at"]) < now or int(row["attempts"]) >= ADMIN_RESET_MAX_ATTEMPTS:
            if row and int(row["attempts"]) >= ADMIN_RESET_MAX_ATTEMPTS:
                c.execute("UPDATE admin_password_resets SET consumed=1 WHERE id=?", (row["id"],))
            raise HTTPException(400, error)
        digest = admin_reset_digest(int(user["id"]), payload.reset_code)
        if not hmac.compare_digest(digest, row["code_hash"]):
            attempts = int(row["attempts"]) + 1
            c.execute("UPDATE admin_password_resets SET attempts=?, consumed=? WHERE id=?",
                      (attempts, 1 if attempts >= ADMIN_RESET_MAX_ATTEMPTS else 0, row["id"]))
            raise HTTPException(400, error)
        c.execute("UPDATE users SET password=?, token_version=COALESCE(token_version,0)+1 WHERE id=?",
                  (hash_password(payload.new_password), user["id"]))
        c.execute("UPDATE admin_password_resets SET consumed=1 WHERE user_id=? AND consumed=0", (user["id"],))
        c.execute("UPDATE password_reset_otps SET consumed=1 WHERE user_id=? AND consumed=0", (user["id"],))
    return {"message": "Nenosiri limebadilishwa. Kikao cha zamani kimefungwa; ingia kwa nenosiri jipya."}

@app.get("/api/users/me")
def me(user=Depends(current_user)): return {"user": user}

@app.post("/api/products", status_code=201)
def create_product(product: ProductCreate, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("""INSERT INTO products
        (seller_id,title,description,category,item_type,price,condition,location,region,district,ward,street,phone,image_url)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (user["id"], product.title.strip(), product.description, product.category.strip(), product.item_type,
         product.price, product.condition, product.location, product.region, product.district, product.ward,
         product.street, product.phone, product.image_url))
        return {"message": "Tangazo limeongezwa kikamilifu", "id": cur.lastrowid}

@app.get("/api/products")
def get_products(item_type: Optional[Literal["product", "service"]] = None, region: Optional[str] = None,
                 include_sold: bool = True):
    query = """SELECT p.id,p.seller_id,p.title,p.description,p.category,p.item_type,p.price,p.condition,
    p.location,p.region,p.district,p.ward,p.street,p.phone,p.image_url,p.is_sold,p.created_at,
    u.username AS seller_name FROM products p LEFT JOIN users u ON u.id=p.seller_id WHERE 1=1"""
    params = []
    if item_type: query += " AND p.item_type=?"; params.append(item_type)
    if region: query += " AND p.region=?"; params.append(region)
    if not include_sold: query += " AND p.is_sold=0"
    query += " ORDER BY p.id DESC"
    with db() as c: rows = c.execute(query, params).fetchall()
    return [dict(r, is_sold=bool(r["is_sold"])) for r in rows]

@app.put("/api/products/{product_id}/sold")
def mark_product_as_sold(product_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute("SELECT seller_id,is_sold FROM products WHERE id=?", (product_id,)).fetchone()
        if not row: raise HTTPException(404, "Tangazo halijapatikana.")
        if row["seller_id"] != user["id"]: raise HTTPException(403, "Mmiliki pekee ndiye anayeweza kubadilisha hali ya tangazo.")
        c.execute("UPDATE products SET is_sold=1 WHERE id=?", (product_id,))
    return {"message": "Tangazo limewekwa alama ya IMEUZWA", "is_sold": True}

@app.delete("/api/products/{product_id}")
def delete_product(product_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute("SELECT seller_id FROM products WHERE id=?", (product_id,)).fetchone()
        if not row: raise HTTPException(404, "Tangazo halijapatikana.")
        if row["seller_id"] != user["id"]: raise HTTPException(403, "Mmiliki pekee ndiye anayeweza kufuta tangazo.")
        c.execute("DELETE FROM products WHERE id=?", (product_id,))
    return {"message": "Tangazo limefutwa kikamilifu"}

@app.post("/api/buyer-requests", status_code=201)
def create_buyer_request(req: BuyerRequestCreate, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("""INSERT INTO buyer_requests
        (buyer_id,buyer_name,title,description,category,item_type,budget,location,region,district,ward,street,phone)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (user["id"], user["username"], req.title.strip(), req.description, req.category.strip(), req.item_type,
         req.budget, req.location, req.region, req.district, req.ward, req.street, req.phone))
        return {"message": "Tangazo la mnunuzi limewekwa kikamilifu", "id": cur.lastrowid}

@app.get("/api/buyer-requests")
def get_buyer_requests(region: Optional[str] = None):
    query = """SELECT id,buyer_id,buyer_name,title,description,category,item_type,budget,location,
    region,district,ward,street,phone,status,created_at FROM buyer_requests WHERE status='active'"""
    params = []
    if region: query += " AND region=?"; params.append(region)
    query += " ORDER BY id DESC"
    with db() as c: return [dict(r) for r in c.execute(query, params).fetchall()]

@app.post("/api/orders", status_code=201)
def place_order(order: OrderCreate, user=Depends(current_user)):
    with db() as c:
        item = c.execute("SELECT id,seller_id,item_type,is_sold FROM products WHERE id=?", (order.item_id,)).fetchone()
        if not item: raise HTTPException(404, "Bidhaa au huduma haipatikani.")
        if item["item_type"] != order.item_type: raise HTTPException(400, "Aina ya tangazo haifanani.")
        if item["is_sold"]: raise HTTPException(409, "Tangazo hili tayari limeuzwa.")
        if item["seller_id"] == user["id"]: raise HTTPException(400, "Huwezi kuagiza tangazo lako mwenyewe.")
        cur = c.execute("INSERT INTO orders(item_id,item_type,buyer_id,seller_id,quantity) VALUES(?,?,?,?,?)",
                        (order.item_id, order.item_type, user["id"], item["seller_id"], order.quantity))
        return {"message": "Ombi limewasilishwa kikamilifu", "order_id": cur.lastrowid}

@app.get("/api/orders")
def get_my_orders(user=Depends(current_user)):
    with db() as c:
        rows = c.execute("""SELECT * FROM orders WHERE buyer_id=? OR seller_id=? ORDER BY id DESC""",
                         (user["id"], user["id"])).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/community")
def get_community_posts():
    with db() as c:
        return [dict(r) for r in c.execute("SELECT id,author_id,author_name,title,content,created_at FROM community_posts ORDER BY id DESC").fetchall()]

@app.post("/api/community", status_code=201)
def create_community_post(post: CommunityPostCreate, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("INSERT INTO community_posts(author_id,author_name,title,content) VALUES(?,?,?,?)",
                        (user["id"], user["username"], post.title.strip(), post.content.strip()))
        return {"message": "Mada imetumwa kikamilifu", "id": cur.lastrowid}


def reset_database():
    """Delete marketplace data after creating a timestamped backup."""
    path = DB_NAME
    if not os.path.isfile(path):
        raise SystemExit(
            f"Database haipo: {path}. Hakuna kilichofutwa. "
            "Hakikisha SOKO_DB_PATH inaelekeza kwenye database sahihi."
        )

    backup = path + ".backup-before-reset-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(path, backup)
    conn = sqlite3.connect(path, timeout=15)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        for table in ("orders", "community_posts", "buyer_requests", "products", "users"):
            if table in tables:
                conn.execute(f'DELETE FROM "{table}"')
                print(f"Data imefutwa: {table}")
        if "sqlite_sequence" in tables:
            conn.execute("DELETE FROM sqlite_sequence")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    print("Ufutaji umekamilika. Backup imehifadhiwa kwenye:", backup)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Soko la Mtaa backend maintenance")
    subparsers = parser.add_subparsers(dest="command", required=True)
    reset_parser = subparsers.add_parser(
        "reset-database", help="Futa data za soko baada ya kutengeneza backup"
    )
    reset_parser.add_argument(
        "--confirm-delete-all", action="store_true",
        help="Thibitisha kufuta akaunti, bidhaa, oda, maombi na machapisho"
    )
    args = parser.parse_args()
    if args.command == "reset-database":
        if not args.confirm_delete_all:
            raise SystemExit(
                "HAKUNA KILICHOFUTWA. Rudia amri na --confirm-delete-all "
                "ikiwa una uhakika unataka kufuta data zote."
            )
        reset_database()
