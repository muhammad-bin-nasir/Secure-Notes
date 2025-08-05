from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson.objectid import ObjectId
from datetime import datetime
from typing import List, Optional
import os

app = FastAPI(title="Secure Notes API")

# CORS middleware for frontend (change '*' to your frontend URL in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to your frontend domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGODB_URL)
database = client.secure_notes
notes_collection = database.notes

# Pydantic models
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

# Serve static files if directory exists
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_frontend():
    index_path = os.path.join("static", "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="Frontend not found")

@app.post("/api/notes", response_model=NoteResponse)
async def create_note(note: NoteCreate):
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
    return NoteResponse(**note_dict)

@app.get("/api/notes", response_model=List[NoteResponse])
async def get_notes():
    notes = []
    async for note in notes_collection.find():
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        notes.append(NoteResponse(**note))
    return notes

@app.get("/api/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    note = await notes_collection.find_one({"_id": object_id})
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    
    note["id"] = str(note["_id"])
    note.pop("_id", None)
    return NoteResponse(**note)

@app.put("/api/notes/{note_id}", response_model=NoteResponse)
async def update_note(note_id: str, note_update: NoteUpdate):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    update_dict = {"updated_at": datetime.utcnow()}
    if note_update.title is not None:
        update_dict["title"] = note_update.title
    if note_update.encrypted_content is not None:
        update_dict["encrypted_content"] = note_update.encrypted_content
    if note_update.salt is not None:
        update_dict["salt"] = note_update.salt
    if note_update.iv is not None:
        update_dict["iv"] = note_update.iv
    
    result = await notes_collection.update_one(
        {"_id": object_id},
        {"$set": update_dict}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    
    note = await notes_collection.find_one({"_id": object_id})
    note["id"] = str(note["_id"])
    note.pop("_id", None)
    return NoteResponse(**note)

@app.delete("/api/notes/{note_id}")
async def delete_note(note_id: str):
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    result = await notes_collection.delete_one({"_id": object_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")
    
    return {"message": "Note deleted successfully"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy"}
