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
TOKEN_SECRET = os.getenv("SOKO_TOKEN_SECRET", "super-secret-token-key-change-this-in-production-32bytes")
TOKEN_TTL = int(os.getenv("SOKO_TOKEN_TTL_SECONDS", "86400"))
ADMIN_RESET_KEY = os.getenv("SOKO_ADMIN_RESET_KEY", "").strip()
ADMIN_RESET_TTL_SECONDS = 1800  # Dakika 30
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
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, phone_norm TEXT NOT NULL,
            code_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0, request_ip TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS admin_password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0, request_ip TEXT)""")

if not (len(sys.argv) > 1 and sys.argv[1] == "reset-database"):
    init_db()

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
        return hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
    except (ValueError, TypeError):
        return False

def make_token(user_id: int, token_version: int = 0) -> str:
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
        if not hmac.compare_digest(expected, supplied): raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if int(payload["exp"]) < int(time.time()): raise ValueError()
        uid = int(payload["sub"])
    except Exception:
        raise HTTPException(401, "Kikao kimeisha au si sahihi. Ingia tena.")
    with db() as c:
        row = c.execute("SELECT id, username, phone, location, token_version FROM users WHERE id=?", (uid,)).fetchone()
    if not row: raise HTTPException(401, "Akaunti haipatikani.")
    return dict(row)

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class UserRegister(StrictModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=8, max_length=256)
    phone: Optional[str] = Field(default=None, max_length=30)
    location: Optional[str] = Field(default=None, max_length=120)

class UserLogin(StrictModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=256)

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
    image_url: Optional[str] = Field(default=None)

class BuyerRequestCreate(StrictModel):
    title: str = Field(min_length=2, max_length=120)
    description: Optional[str] = Field(default=None, max_length=3000)
    category: str = Field(min_length=1, max_length=80)
    item_type: Literal["product", "service"] = "product"
    budget: float = Field(gt=0, le=1_000_000_000)
    region: Optional[str] = Field(default="", max_length=100)
    district: Optional[str] = Field(default="", max_length=100)
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
            raise HTTPException(409, "Jina au simu hii tayari imeshatumika.")
        return {"message": "Mtumiaji amesajiliwa kikamilifu",
                "user": {"id": cur.lastrowid, "username": user.username.strip(), "phone": user.phone, "location": user.location}}

@app.post("/api/users/login")
def login_user(user: UserLogin):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE username=? OR phone=?", (user.username.strip(), user.username.strip())).fetchone()
        if not row or not verify_password(user.password, row["password"]):
            raise HTTPException(401, "Jina/Simu au nenosiri si sahihi.")
        public_user = {"id": row["id"], "username": row["username"], "phone": row["phone"], "location": row["location"]}
    return {"message": "Umeingia kikamilifu", "user": public_user, "access_token": make_token(row["id"], int(row["token_version"] or 0)), "token_type": "bearer"}

@app.post("/api/users/password-reset/admin-verify")
def complete_admin_password_reset(payload: AdminPasswordResetComplete):
    with db() as c:
        user = c.execute("SELECT id FROM users WHERE lower(username)=?", (payload.username.strip().lower(),)).fetchone()
        if not user: raise HTTPException(400, "Msimbo si sahihi au akaunti haijapatikana.")
        c.execute("UPDATE users SET password=? WHERE id=?", (hash_password(payload.new_password), user["id"]))
    return {"message": "Nenosiri limebadilishwa. Sasa ingia kwa nenosiri jipya."}

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
def get_products():
    with db() as c:
        rows = c.execute("""SELECT p.*, u.username AS seller_name FROM products p LEFT JOIN users u ON u.id=p.seller_id ORDER BY p.id DESC""").fetchall()
    return [dict(r, is_sold=bool(r["is_sold"])) for r in rows]

@app.put("/api/products/{product_id}/sold")
def mark_product_as_sold(product_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute("SELECT seller_id FROM products WHERE id=?", (product_id,)).fetchone()
        if not row or row["seller_id"] != user["id"]: raise HTTPException(403, "Huruhusiwi kubadilisha hili.")
        c.execute("UPDATE products SET is_sold=1 WHERE id=?", (product_id,))
    return {"message": "Tangazo limewekwa IMEUZWA", "is_sold": True}

@app.delete("/api/products/{product_id}")
def delete_product(product_id: int, user=Depends(current_user)):
    with db() as c:
        row = c.execute("SELECT seller_id FROM products WHERE id=?", (product_id,)).fetchone()
        if not row or row["seller_id"] != user["id"]: raise HTTPException(403, "Huruhusiwi kufuta hili.")
        c.execute("DELETE FROM products WHERE id=?", (product_id,))
    return {"message": "Tangazo limefutwa kikamilifu"}

@app.post("/api/buyer-requests", status_code=201)
def create_buyer_request(req: BuyerRequestCreate, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("""INSERT INTO buyer_requests(buyer_id,buyer_name,title,description,category,item_type,budget,region,district,phone)
        VALUES(?,?,?,?,?,?,?,?,?,?)""", (user["id"], user["username"], req.title.strip(), req.description, req.category.strip(), req.item_type, req.budget, req.region, req.district, req.phone))
        return {"message": "Tangazo la mnunuzi limewekwa kikamilifu", "id": cur.lastrowid}

@app.get("/api/buyer-requests")
def get_buyer_requests():
    with db() as c: return [dict(r) for r in c.execute("SELECT * FROM buyer_requests WHERE status='active' ORDER BY id DESC").fetchall()]

@app.post("/api/orders", status_code=201)
def place_order(order: OrderCreate, user=Depends(current_user)):
    with db() as c:
        item = c.execute("SELECT id,seller_id,is_sold FROM products WHERE id=?", (order.item_id,)).fetchone()
        if not item or item["is_sold"]: raise HTTPException(400, "Bidhaa haipatikani au imeuzwa.")
        cur = c.execute("INSERT INTO orders(item_id,item_type,buyer_id,seller_id,quantity) VALUES(?,?,?,?,?)",
                        (order.item_id, order.item_type, user["id"], item["seller_id"], order.quantity))
        return {"message": "Oda imewasilishwa kikamilifu", "order_id": cur.lastrowid}

@app.get("/api/community")
def get_community_posts():
    with db() as c: return [dict(r) for r in c.execute("SELECT * FROM community_posts ORDER BY id DESC").fetchall()]

@app.post("/api/community", status_code=201)
def create_community_post(post: CommunityPostCreate, user=Depends(current_user)):
    with db() as c:
        cur = c.execute("INSERT INTO community_posts(author_id,author_name,title,content) VALUES(?,?,?,?)",
                        (user["id"], user["username"], post.title.strip(), post.content.strip()))
        return {"message": "Mada imetumwa kikamilifu", "id": cur.lastrowid}

def reset_database():
    if not os.path.isfile(DB_NAME): return
    backup = DB_NAME + ".backup-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(DB_NAME, backup)
    conn = sqlite3.connect(DB_NAME)
    for table in ("orders", "community_posts", "buyer_requests", "products", "users"):
        conn.execute(f'DELETE FROM "{table}"')
    conn.commit()
    conn.close()
    print("Database imefutwa kikamilifu. Backup ipo:", backup)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    reset_parser = subparsers.add_parser("reset-database")
    reset_parser.add_argument("--confirm-delete-all", action="store_true")
    args = parser.parse_args()
    if args.command == "reset-database" and args.confirm_delete_all:
        reset_database()
