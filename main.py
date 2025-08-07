from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime
from typing import List, Optional
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Notes API")

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

# Models
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

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    encrypted_content: Optional[str] = None
    salt: Optional[str] = None
    iv: Optional[str] = None

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

# Add a simple test endpoint
@app.get("/api/test")
async def test_endpoint():
    return {"message": "API is working!", "mongodb_connected": True}

# API Endpoints
@app.post("/api/notes", response_model=NoteResponse)
async def create_note(note: NoteCreate):
    try:
        note_dict = {
            "title": note.title,
            "encrypted_content": note.encrypted_content,
            "salt": note.salt,
            "iv": note.iv,
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
async def get_notes():
    try:
        notes = []
        async for note in notes_collection.find():
            note["id"] = str(note["_id"])
            note.pop("_id", None)
            notes.append(NoteResponse(**note))
        return notes
    except Exception as e:
        logger.error(f"Error getting notes: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    try:
        note = await notes_collection.find_one({"_id": object_id})
        if not note:
            raise HTTPException(status_code=404, detail="Note not found")
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        return NoteResponse(**note)
    except Exception as e:
        logger.error(f"Error getting note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/notes/{note_id}", response_model=NoteResponse)
async def update_note(note_id: str, note_update: NoteUpdate):
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
        
        result = await notes_collection.update_one({"_id": object_id}, {"$set": update_dict})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Note not found")
        
        note = await notes_collection.find_one({"_id": object_id})
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        return NoteResponse(**note)
    except Exception as e:
        logger.error(f"Error updating note: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/notes/{note_id}")
async def delete_note(note_id: str):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    try:
        result = await notes_collection.delete_one({"_id": object_id})
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
