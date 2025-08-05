from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from datetime import datetime
from typing import List, Optional
import os

app = FastAPI(title="Secure Notes API")

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
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
    encrypted_content: str  # This will be the encrypted note content
    salt: str  # Salt used for key derivation
    iv: str   # Initialization vector for AES encryption

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

# Serve static files (our frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")

@app.post("/api/notes", response_model=NoteResponse)
async def create_note(note: NoteCreate):
    """Create a new encrypted note"""
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

@app.get("/api/notes", response_model=List[NoteResponse])
async def get_notes():
    """Get all notes (titles and encrypted content)"""
    notes = []
    async for note in notes_collection.find():
        note["id"] = str(note["_id"])
        note.pop("_id", None)
        notes.append(NoteResponse(**note))
    
    return notes

@app.get("/api/notes/{note_id}", response_model=NoteResponse)
async def get_note(note_id: str):
    """Get a specific note by ID"""
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
    """Update an existing note"""
    try:
        object_id = ObjectId(note_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid note ID format")
    
    # Build update document
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
    
    # Return updated note
    note = await notes_collection.find_one({"_id": object_id})
    note["id"] = str(note["_id"])
    note.pop("_id", None)
    
    return NoteResponse(**note)

@app.delete("/api/notes/{note_id}")
async def delete_note(note_id: str):
    """Delete a note"""
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
    """Health check endpoint"""
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)