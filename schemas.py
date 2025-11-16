"""
Database Schemas for BlueFlame Tasks

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercased class name. Example: class User -> collection "user".
"""
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr

class User(BaseModel):
    """
    Users collection schema
    Collection: "user"
    """
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    username: str = Field(..., min_length=3, max_length=24, description="Unique public username")
    display_name: str = Field(..., min_length=1, max_length=60)
    bio: Optional[str] = Field(None, max_length=280)
    avatar_url: Optional[str] = None
    is_public: bool = Field(default=False, description="Whether profile and tasks are public")
    theme: str = Field(default="blueflame", description="Theme preference")

class Task(BaseModel):
    """
    Tasks collection schema
    Collection: "task"
    """
    user_id: str = Field(..., description="Owner user id (stringified ObjectId)")
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = Field(None, max_length=2000)
    completed: bool = Field(default=False)
    order: int = Field(default=0, description="Ordering index for drag & drop")

# Additional models used for responses/requests (not collections)
class PublicProfile(BaseModel):
    username: str
    display_name: str
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    is_public: bool = True
    theme: str = "blueflame"
    tasks: List[dict] = []
