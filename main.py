import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, field_validator

DB_NAME = os.getenv("SOKO_DB_PATH", "local_market.db")
TOKEN_SECRET = os.getenv("SOKO_TOKEN_SECRET", "")
TOKEN_TTL = int(os.getenv("SOKO_TOKEN_TTL_SECONDS", "86400"))
ALLOWED_ORIGINS = [x.strip() for x in os.getenv(
    "SOKO_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500,http://127.0.0.1:5500"
).split(",") if x.strip()]
MAX_IMAGES = 4
MAX_IMAGE_CHARS = 1_000_000
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
            password TEXT NOT NULL, phone TEXT, location TEXT)""")
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

        # Add columns expected by this version when upgrading an older DB.
        # Declarations intentionally avoid NOT NULL without a default so SQLite
        # can migrate tables that already contain rows.
        required_columns = {
            "users": {
                "username": "TEXT", "password": "TEXT", "phone": "TEXT", "location": "TEXT",
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

def make_token(user_id: int) -> str:
    if len(TOKEN_SECRET) < 32:
        raise HTTPException(503, "Seva ya akaunti haijasanidiwa: weka SOKO_TOKEN_SECRET yenye angalau herufi 32.")
    payload = {"sub": user_id, "exp": int(time.time()) + TOKEN_TTL}
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
    except Exception:
        raise HTTPException(401, "Kikao kimeisha au si sahihi. Ingia tena.")
    with db() as c:
        row = c.execute("SELECT id, username, phone, location FROM users WHERE id=?", (uid,)).fetchone()
    if not row: raise HTTPException(401, "Akaunti haipatikani.")
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
    return {"message": "Umeingia kikamilifu", "user": public_user, "access_token": make_token(row["id"]), "token_type": "bearer"}

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
