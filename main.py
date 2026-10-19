import sqlite3
import hashlib
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="Soko la Mtaa API",
    description="Backend API kwa ajili ya Mobile App ya Soko la Mtaa na Community Forum",
    version="1.0.0"
)

# --- CORS CONFIGURATION (ONGEZA HAPA) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Inaruhusu maombi kutoka sehemu yoyote (ikiwemo localhost:8080)
    allow_credentials=True,
    allow_methods=["*"],  # Inaruhusu GET, POST, PUT, DELETE n.k.
    allow_headers=["*"],  # Inaruhusu headers zote
)

# --- DATABASE INITIALIZATION ---
DB_NAME = "local_market.db"
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Meza ya Watumiaji (Ipo tayari)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT,
            location TEXT
        )
    """)

    # Meza ya Bidhaa (Hakikisha description na image_url zipo)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            price REAL NOT NULL,
            condition TEXT,
            location TEXT,
            phone TEXT,
            image_url TEXT
        )
    """)

    # Meza ya Majadiliano (Ipo tayari)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER,
            author_name TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# --- PYDANTIC SCHEMAS (Data Validation) ---
# --- PYDANTIC MODELS ---
class UserRegister(BaseModel):
    username: str
    password: str
    phone: Optional[str] = None
    location: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

# --- REGISTER ENDPOINT ---
@app.post("/api/users/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserRegister):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Hash password kwa usalama
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password, phone, location) VALUES (?, ?, ?, ?)",
            (user.username, hashed_password, user.phone, user.location)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {"message": "Mtumiaji amesajiliwa kikamilifu", "user_id": user_id}
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Jina hili la mtumiaji tayari limeshatumika."
        )

# --- LOGIN ENDPOINT ---
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
            "user": {
                "id": db_user[0],
                "username": db_user[1],
                "phone": db_user[2],
                "location": db_user[3]
            }
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Jina au nenosiri si sahihi."
        )
class ProductCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: str
    price: float
    condition: str
    location: str
    phone: str
    seller_id: Optional[int] = 1
    image_url: Optional[str] = None
class CommunityPostCreate(BaseModel):
    author_id: int
    author_name: str
    title: str
    content: str


# --- API ENDPOINTS ---

@app.get("/")
def home():
    return {"message": "Karibu kwenye Soko la Mtaa API! Mfumo uko LIVE."}

# 1. USER AUTHENTICATION
@app.post("/api/register", status_code=210)
def register(user: UserRegister):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username.lower(),))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username hii tayari ipo!")

    hashed_pw = hash_password(user.password)
    cursor.execute(
        "INSERT INTO users (username, password, phone, location) VALUES (?, ?, ?, ?)",
        (user.username.lower(), hashed_pw, user.phone, user.location)
    )
    conn.commit()
    conn.close()
    return {"message": "Akaunti imetengenezwa kikamilifu!"}

@app.post("/api/login")
def login(user: UserLogin):
    hashed_pw = hash_password(user.password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, phone, location FROM users WHERE username = ? AND password = ?",
        (user.username.lower(), hashed_pw)
    )
    db_user = cursor.fetchone()
    conn.close()

    if not db_user:
        raise HTTPException(status_code=401, detail="Username au Password siyo sahihi!")

    return {
        "id": db_user[0],
        "username": db_user[1],
        "phone": db_user[2],
        "location": db_user[3]
    }

# 2. PRODUCTS ENDPOINTS
@app.get("/api/products")
def get_products(category: Optional[str] = None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    if category:
        cursor.execute(
            "SELECT id, title, category, price, condition, location, phone FROM products WHERE status = 'Available' AND category = ?",
            (category,)
        )
    else:
        cursor.execute(
            "SELECT id, title, category, price, condition, location, phone FROM products WHERE status = 'Available'"
        )
        
    rows = cursor.fetchall()
    conn.close()

    products = []
    for row in rows:
        products.append({
            "id": row[0],
            "title": row[1],
            "category": row[2],
            "price": row[3],
            "condition": row[4],
            "location": row[5],
            "phone": row[6]
        })
    return products

# --- ADD PRODUCT ---
@app.post("/api/products")
def create_product(product: ProductCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO products (seller_id, title, description, category, price, condition, location, phone, image_url)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        product.seller_id,
        product.title,
        product.description,
        product.category,
        product.price,
        product.condition,
        product.location,
        product.phone,
        product.image_url
    ))
    conn.commit()
    product_id = cursor.lastrowid
    conn.close()
    return {"message": "Bidhaa imeongezwa kikamilifu", "id": product_id}

# --- GET PRODUCTS ---
@app.get("/api/products")
def get_products():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, seller_id, title, description, category, price, condition, location, phone, image_url FROM products ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    
    products = []
    for row in rows:
        products.append({
            "id": row[0],
            "seller_id": row[1],
            "title": row[2],
            "description": row[3],
            "category": row[4],
            "price": row[5],
            "condition": row[6],
            "location": row[7],
            "phone": row[8],
            "image_url": row[9]
        })
    return products
# 3. COMMUNITY FORUM ENDPOINTS (Sehemu ya Wafanyabiashara)
@app.get("/api/community")
# --- FUTA BIDHAA (DELETE PRODUCT) ---
@app.delete("/api/products/{product_id}")
def delete_product(product_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Bidhaa imefutwa kikamilifu"}

# --- MARK AS SOLD (UPDATE STATUS) ---
@app.put("/api/products/{product_id}/sold")
def mark_product_as_sold(product_id: int):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET title = '[IMEHAUZWA] ' || title WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    return {"message": "Bidhaa imewekwa alama ya kuuzwa"}
def get_community_posts():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, author_name, title, content, created_at FROM community_posts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    posts = []
    for row in rows:
        posts.append({
            "id": row[0],
            "author": row[1],
            "title": row[2],
            "content": row[3],
            "created_at": row[4]
        })
    return posts

@app.post("/api/community")
def create_community_post(post: CommunityPostCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO community_posts (author_id, author_name, title, content) VALUES (?, ?, ?, ?)",
        (post.author_id, post.author_name, post.title, post.content)
    )
    conn.commit()
    conn.close()
    return {"message": "Mada yako imechapishwa kwenye Community Forum!"}
