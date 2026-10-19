import sqlite3
import hashlib
from typing import Optional, List
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_NAME = "local_market.db"

app = FastAPI(title="Soko la Mtaa API", version="2.0.0")

# Ruhusu CORS kwa ajili ya Frontend (Netlify/Localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE INITIALIZATION ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            location TEXT,
            user_type TEXT DEFAULT 'both'
        )
    """)

    # 2. Products & Services Table (Muuzaji / Mtoa Huduma)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            item_type TEXT DEFAULT 'product', -- 'product' au 'service'
            price REAL NOT NULL,
            condition TEXT,
            location TEXT,
            region TEXT,
            district TEXT,
            phone TEXT,
            image_url TEXT,
            is_sold INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Buyer Requests Table (Mnunuzi anachotafuta / Bajeti yake)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS buyer_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            buyer_id INTEGER,
            buyer_name TEXT,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            item_type TEXT DEFAULT 'product', -- 'product' au 'service'
            budget REAL NOT NULL,
            location TEXT,
            region TEXT,
            district TEXT,
            phone TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 4. Orders / Inquiries Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER,
            item_type TEXT, -- 'product' au 'buyer_request'
            buyer_id INTEGER,
            seller_id INTEGER,
            quantity INTEGER DEFAULT 1,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 5. Community Forum Posts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER,
            author_name TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

init_db()

# --- PYDANTIC SCHEMAS ---

class UserRegister(BaseModel):
    username: str
    password: str
    phone: Optional[str] = None
    location: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class ProductCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str
    item_type: Optional[str] = "product"  # 'product' au 'service'
    price: float
    condition: Optional[str] = "Mpya"
    location: str
    region: Optional[str] = "Dar es Salaam"
    district: Optional[str] = "Ubungo"
    phone: str
    seller_id: Optional[int] = 1
    image_url: Optional[str] = None

class BuyerRequestCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str
    item_type: Optional[str] = "product"  # 'product' au 'service'
    budget: float
    location: str
    region: Optional[str] = "Dar es Salaam"
    district: Optional[str] = "Ubungo"
    phone: str
    buyer_id: Optional[int] = 1
    buyer_name: Optional[str] = "Mnunuzi"

class OrderCreate(BaseModel):
    item_id: int
    item_type: str  # 'product' au 'buyer_request'
    buyer_id: int
    seller_id: int
    quantity: Optional[int] = 1

class CommunityPostCreate(BaseModel):
    author_id: int
    author_name: str
    title: str
    content: str

# --- ROUTES & ENDPOINTS ---

@app.get("/")
def home():
    return {"message": "Soko la Mtaa API v2.0 - Bidhaa, Huduma na Matangazo ya Wanunuzi ipo tayari!"}

# --- USERS ---
@app.post("/api/users/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, phone, location) VALUES (?, ?, ?, ?)",
            (user.username, hashed_password, user.phone, user.location)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"message": "Mtumiaji amesajiliwa kikamilifu", "user": {"id": user_id, "username": user.username, "phone": user.phone, "location": user.location}}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Jina hili la mtumiaji tayari limeshatumika.")

@app.post("/api/users/login")
def login_user(user: UserLogin):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    cursor.execute(
        "SELECT id, username, phone, location FROM users WHERE username = ? AND password = ?",
        (user.username, hashed_password)
    )
    db_user = cursor.fetchone()
    conn.close()
    if db_user:
        return {
            "message": "Umeingia kikamilifu",
            "user": {"id": db_user[0], "username": db_user[1], "phone": db_user[2], "location": db_user[3]}
        }
    else:
        raise HTTPException(status_code=401, detail="Jina au nenosiri si sahihi.")

# --- PRODUCTS & SERVICES (MUUZAJI / MTOA HUDUMA) ---
@app.post("/api/products")
def create_product(product: ProductCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (seller_id, title, description, category, item_type, price, condition, location, region, district, phone, image_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        product.seller_id, product.title, product.description, product.category,
        product.item_type, product.price, product.condition, product.location,
        product.region, product.district, product.phone, product.image_url
    ))
    conn.commit()
    product_id = cursor.lastrowid
    conn.close()
    return {"message": "Imewekwa kikamilifu", "id": product_id}

@app.get("/api/products")
def get_products(item_type: Optional[str] = None, region: Optional[str] = None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    query = "SELECT id, seller_id, title, description, category, item_type, price, condition, location, region, district, phone, image_url, is_sold FROM products WHERE 1=1"
    params = []
    
    if item_type:
        query += " AND item_type = ?"
        params.append(item_type)
    if region:
        query += " AND region = ?"
        params.append(region)
        
    query += " ORDER BY id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [{
        "id": r[0], "seller_id": r[1], "title": r[2], "description": r[3],
        "category": r[4], "item_type": r[5], "price": r[6], "condition": r[7],
        "location": r[8], "region": r[9], "district": r[10], "phone": r[11],
        "image_url": r[12], "is_sold": bool(r[13])
    } for r in rows]

@app.put("/api/products/{product_id}/sold")
def mark_product_as_sold(product_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET is_sold = 1 WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Bidhaa imewekwa alama ya kuuzwa"}

@app.delete("/api/products/{product_id}")
def delete_product(product_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Imefutwa kikamilifu"}

# --- BUYER REQUESTS (MATANGAZO YA WANUNUZI) ---
@app.post("/api/buyer-requests")
def create_buyer_request(req: BuyerRequestCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO buyer_requests (buyer_id, buyer_name, title, description, category, item_type, budget, location, region, district, phone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        req.buyer_id, req.buyer_name, req.title, req.description, req.category,
        req.item_type, req.budget, req.location, req.region, req.district, req.phone
    ))
    conn.commit()
    req_id = cursor.lastrowid
    conn.close()
    return {"message": "Tangazo la mnunuzi limewekwa kikamilifu", "id": req_id}

@app.get("/api/buyer-requests")
def get_buyer_requests(region: Optional[str] = None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    query = "SELECT id, buyer_id, buyer_name, title, description, category, item_type, budget, location, region, district, phone, status FROM buyer_requests WHERE status = 'active'"
    params = []
    if region:
        query += " AND region = ?"
        params.append(region)
    query += " ORDER BY id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return [{
        "id": r[0], "buyer_id": r[1], "buyer_name": r[2], "title": r[3],
        "description": r[4], "category": r[5], "item_type": r[6], "budget": r[7],
        "location": r[8], "region": r[9], "district": r[10], "phone": r[11], "status": r[12]
    } for r in rows]

# --- ORDERS & CONTACT REVEAL ---
@app.post("/api/orders")
def place_order(order: OrderCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO orders (item_id, item_type, buyer_id, seller_id, quantity)
        VALUES (?, ?, ?, ?, ?)
    """, (order.item_id, order.item_type, order.buyer_id, order.seller_id, order.quantity))
    conn.commit()
    order_id = cursor.lastrowid
    conn.close()
    return {"message": "Ombi / Order imewekwa kikamilifu", "order_id": order_id}

# --- COMMUNITY FORUM ---
@app.get("/api/community")
def get_community_posts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, author_id, author_name, title, content FROM community_posts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "author_id": r[1], "author_name": r[2], "title": r[3], "content": r[4]} for r in rows]

@app.post("/api/community")
def create_community_post(post: CommunityPostCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO community_posts (author_id, author_name, title, content) VALUES (?, ?, ?, ?)",
                   (post.author_id, post.author_name, post.title, post.content))
    conn.commit()
    conn.close()
    return {"message": "Mada imetumwa kikamilifu"}
