from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime, timedelta
from typing import List, Optional
import os
import logging
import bcrypt
import jwt
import secrets

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Notes API")

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB
MONGO_URL = os.getenv("MONGO_URL") or os.getenv("MONGODB_URL")
if not MONGO_URL:
    raise RuntimeError("MONGO_URL or MONGODB_URL environment variable not set")

logger.info(f"Connecting to MongoDB...")
client = AsyncIOMotorClient(MONGO_URL)
database = client.secure_notes
notes_collection = database.notes
users_collection = database.users

# Models
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str

class NoteCreate(BaseModel):
    title: str
    encrypted_content: str
    salt: str
    iv: str

class NoteResponse(BaseModel):
    id: str
    title: str
    encrypted_content: str
    salt: str
    iv: str
    created_at: datetime
    updated_at: datetime
    username: str

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    encrypted_content: Optional[str] = None
    salt: Optional[str] = None
    iv: Optional[str] = None

# Authentication functions
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_jwt_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    return verify_jwt_token(credentials.credentials)

# Static frontend - with error handling
static_path = os.path.join(os.path.dirname(__file__), "static")
logger.info(f"Static path: {static_path}")
logger.info(f"Static path exists: {os.path.exists(static_path)}")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")
    logger.info("Static files mounted successfully")
else:
    logger.error(f"Static directory not found at: {static_path}")

@app.get("/")
async def serve_frontend():
    index_path = os.path.join(static_path, "index.html")
    logger.info(f"Attempting to serve: {index_path}")
    logger.info(f"Index file exists: {os.path.exists(index_path)}")
    
    if not os.path.exists(index_path):
        logger.error(f"index.html not found at: {index_path}")
        return {"error": "Frontend not found", "path": index_path}
    
    return FileResponse(index_path)

# Authentication Endpoints
@app.post("/api/auth/register", response_model=TokenResponse)
async def register_user(user: UserCreate):
    try:
        # Check if user already exists
        existing_user = await users_collection.find_one({"username": user.username})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already exists"
            )
        
        # Hash password and create user
        hashed_password = hash_password(user.password)
        user_dict = {
            "username": user.username,
            "password": hashed_password,
            "created_at": datetime.utcnow()
        }
        
        result = await users_collection.insert_one(user_dict)
        if not result.inserted_id:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
        
        # Generate token
        token = create_jwt_token(user.username)
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            username=user.username
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/api/auth/login", response_model=TokenResponse)
async def login_user(user: UserLogin):
    try:
        # Find user
        db_user = await users_collection.find_one({"username": user.username})
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Verify password
        if not verify_password(user.password, db_user["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        # Generate token
        token = create_jwt_token(user.username)
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            username=user.username
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error logging in user: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.get("/api/auth/me")
async def get_current_user_info(current_user: str = Depends(get_current_user)):
    return {"username": current_user}

# Add a simple test endpoint
@app.get("/api/test")
async def test_endpoint():
    return {"message": "API is working!", "mongodb_connected": True}

# Notes API Endpoints (Updated with authentication)
@app.post("/api/notes", response_model=NoteResponse)
async def create_note(note: NoteCreate, current_user: str = Depends(get_current_user)):
    try:
        note_dict = {
            "title": note.title,
            "encrypted_content": note.encrypted_content,
            "salt": note.salt,
            "iv": note.iv,
            "username": current_user,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        result = await notes_collection.insert_one(note_dict)
        note_dict["id"] = str(result.inserted_id)
        note_dict.pop("_id", None)
        return NoteResponse(**note_dict)
    except Exception as e:
        logger.error(f"Error creating note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/notes", response_model=List[NoteResponse])
async def get_notes(current_user: str = Depends(get_current_user)):
    try:
        notes = []
        # Only get notes for the current user
        async for note in notes_collection.find({"username": current_user}):
            note["id"] = str(note["_id"])
            note.pop("_id", None)
            notes.append(NoteResponse(**note))
        return notes
    except Exception as e:
        logger.error(f"Error getting notes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str, current_user: str = Depends(get_current_user)):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    try:
        # Only get note if it belongs to the current user
        note = await notes_collection.find_one({"_id": object_id, "username": current_user})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        return NoteResponse(**note)
    except Exception as e:
        logger.error(f"Error getting note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/notes/{note_id}", response_model=NoteResponse)
async def update_note(note_id: str, note_update: NoteUpdate, current_user: str = Depends(get_current_user)):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    try:
        update_dict = {"updated_at": datetime.utcnow()}
        if note_update.title is not None:
            update_dict["title"] = note_update.title
        if note_update.encrypted_content is not None:
            update_dict["encrypted_content"] = note_update.encrypted_content
        if note_update.salt is not None:
            update_dict["salt"] = note_update.salt
        if note_update.iv is not None:
            update_dict["iv"] = note_update.iv
        
        # Only update note if it belongs to the current user
        result = await notes_collection.update_one(
            {"_id": object_id, "username": current_user}, 
            {"$set": update_dict}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Note not found")
        
        note = await notes_collection.find_one({"_id": object_id, "username": current_user})
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        return NoteResponse(**note)
    except Exception as e:
        logger.error(f"Error updating note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/notes/{note_id}")
async def delete_note(note_id: str, current_user: str = Depends(get_current_user)):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    try:
        # Only delete note if it belongs to the current user
        result = await notes_collection.delete_one({"_id": object_id, "username": current_user})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Note not found")
        return {"message": "Note deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "message": "API is running"}

@app.get("/api/health/db")
async def health_check_db():
    try:
        # Test MongoDB connection with timeout
        await database.command("ping")
        return {"status": "healthy", "mongodb": "connected"}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")

# Startup event
@app.on_event("startup")
async def startup_event():
    logger.info("Application starting up...")
    logger.info(f"Current working directory: {os.getcwd()}")
    logger.info(f"Files in current directory: {os.listdir('.')}")
    if os.path.exists('static'):
        logger.info(f"Files in static directory: {os.listdir('static')}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting server on port: {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
