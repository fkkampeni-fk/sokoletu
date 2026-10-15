import sqlite3
import hashlib
from typing import List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(
    title="Soko la Mtaa API",
    description="Backend API kwa ajili ya Mobile App ya Soko la Mtaa na Community Forum",
    version="1.0.0"
)

# --- DATABASE INITIALIZATION ---
DB_NAME = "local_market.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Meza ya Watumiaji
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            phone TEXT NOT NULL,
            location TEXT NOT NULL
        )
    """)
    
    # Meza ya Bidhaa
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            condition TEXT NOT NULL,
            location TEXT NOT NULL,
            phone TEXT NOT NULL,
            status TEXT DEFAULT 'Available',
            FOREIGN KEY (seller_id) REFERENCES users (id)
        )
    """)
    
    # Meza ya Jukwaa la Jamii (Community Posts)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            author_name TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# --- PYDANTIC SCHEMAS (Data Validation) ---
class UserRegister(BaseModel):
    username: str
    password: str
    phone: str
    location: str

class UserLogin(BaseModel):
    username: str
    password: str

class ProductCreate(BaseModel):
    seller_id: int
    title: str
    category: str
    price: float
    condition: str
    location: str
    phone: str

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

@app.post("/api/products")
def create_product(product: ProductCreate):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (seller_id, title, category, price, condition, location, phone, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'Available')",
        (product.seller_id, product.title, product.category, product.price, product.condition, product.location, product.phone)
    )
    conn.commit()
    conn.close()
    return {"message": "Bidhaa imeonyeshwa sokoni kikamilifu!"}

# 3. COMMUNITY FORUM ENDPOINTS (Sehemu ya Wafanyabiashara)
@app.get("/api/community")
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
