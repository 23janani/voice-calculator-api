from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import jwt
import datetime
import bcrypt

# 1. Initialize App & Security Setup
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "my_super_secret_developer_key"

def init_db():
    conn = sqlite3.connect("calculations.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT, input TEXT, expr TEXT, res TEXT)''')
    conn.commit()
    conn.close()

init_db()

class UserCredentials(BaseModel):
    email: str
    password: str

class Calculation(BaseModel):
    type: str
    input: str
    expr: str
    res: str

# --- THE BOUNCER ---
def get_current_user_id(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        
        # Pull out the ID safely
        user_id_str = payload.get("sub")
        
        # If the ID is missing entirely, throw it in the trash
        if user_id_str is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        # If it exists, safely turn it into an integer!
        return int(user_id_str)
        
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

# 4. API Endpoints
@app.post("/register")
def register_user(user: UserCredentials):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), salt).decode('utf-8')
    
    conn = sqlite3.connect("calculations.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (user.email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered")
    
    conn.close()
    return {"message": "Account created successfully!"}

@app.post("/login")
def login_user(user: UserCredentials):
    conn = sqlite3.connect("calculations.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE email = ?", (user.email,))
    db_user = cursor.fetchone()
    conn.close()

    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user[1].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    # THE FIX: Convert the database integer into a string for the JWT token!
    user_id = str(db_user[0]) 
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    token = jwt.encode({"sub": user_id, "exp": expiration}, SECRET_KEY, algorithm="HS256")
    
    return {"token": token, "email": user.email}

@app.get("/history")
def get_history(user_id: int = Depends(get_current_user_id)):
    conn = sqlite3.connect("calculations.db")
    cursor = conn.cursor()
    cursor.execute("SELECT type, input, expr, res FROM history WHERE user_id = ? ORDER BY id DESC LIMIT 5", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    
    return [{"type": row[0], "input": row[1], "expr": row[2], "res": row[3]} for row in rows]

@app.post("/history")
def save_calculation(calc: Calculation, user_id: int = Depends(get_current_user_id)):
    conn = sqlite3.connect("calculations.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO history (user_id, type, input, expr, res) VALUES (?, ?, ?, ?, ?)",
        (user_id, calc.type, calc.input, calc.expr, calc.res)
    )
    conn.commit()
    conn.close()
    return {"message": "Saved successfully!"}
