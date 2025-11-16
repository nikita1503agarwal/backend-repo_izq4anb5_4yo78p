import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document
from schemas import User, Task, PublicProfile

# App setup
app = FastAPI(title="BlueFlame Tasks API", version="0.1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Helper functions
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Utility to find single document
from bson.objectid import ObjectId

def find_one(collection: str, filter_dict: dict):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return db[collection].find_one(filter_dict)


# Dependencies
class CurrentUser(BaseModel):
    id: str
    email: EmailStr
    username: str


def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = find_one("user", {"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception

    return CurrentUser(id=str(user["_id"]), email=user["email"], username=user["username"]) 


# Routes
@app.get("/")
def read_root():
    return {"message": "BlueFlame Tasks API running"}


@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# Auth Endpoints
class SignupPayload(BaseModel):
    email: EmailStr
    password: str
    username: str
    display_name: str


@app.post("/auth/signup", response_model=Token)
def signup(payload: SignupPayload):
    # Ensure unique email and username
    if find_one("user", {"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if find_one("user", {"username": payload.username}):
        raise HTTPException(status_code=400, detail="Username already taken")

    user_doc = User(
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        username=payload.username,
        display_name=payload.display_name,
        bio=None,
        avatar_url=None,
        is_public=False,
        theme="blueflame",
    )
    user_id = create_document("user", user_doc)

    token = create_access_token({"sub": user_id})
    return Token(access_token=token)


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


@app.post("/auth/login", response_model=Token)
def login(payload: LoginPayload):
    user = find_one("user", {"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


# Profile Endpoints
class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    is_public: Optional[bool] = None
    theme: Optional[str] = None


@app.get("/user/profile")
def get_profile(current: CurrentUser = Depends(get_current_user)):
    user = find_one("user", {"_id": ObjectId(current.id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["_id"] = str(user["_id"]) 
    user.pop("password_hash", None)
    return user


@app.post("/user/profile")
def update_profile(data: ProfileUpdate, current: CurrentUser = Depends(get_current_user)):
    updates = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    if not updates:
        return {"updated": False}
    result = db["user"].update_one({"_id": ObjectId(current.id)}, {"$set": updates, "$currentDate": {"updated_at": True}})
    return {"updated": result.modified_count > 0}


# Task Endpoints
class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None
    order: Optional[int] = None


def serialize_task(doc: dict):
    return {
        "id": str(doc["_id"]),
        "title": doc.get("title"),
        "description": doc.get("description"),
        "completed": doc.get("completed", False),
        "order": doc.get("order", 0),
    }


@app.get("/tasks")
def list_tasks(current: CurrentUser = Depends(get_current_user)):
    docs = db["task"].find({"user_id": current.id}).sort("order", 1)
    return [serialize_task(d) for d in docs]


@app.post("/tasks")
def create_task(data: TaskCreate, current: CurrentUser = Depends(get_current_user)):
    doc = Task(user_id=current.id, title=data.title, description=data.description or None, completed=False, order=int(datetime.now().timestamp()))
    inserted_id = create_document("task", doc)
    created = db["task"].find_one({"_id": ObjectId(inserted_id)})
    return serialize_task(created)


@app.patch("/tasks/{task_id}")
def update_task(task_id: str, data: TaskUpdate, current: CurrentUser = Depends(get_current_user)):
    updates = {k: v for k, v in data.model_dump(exclude_none=True).items()}
    res = db["task"].update_one({"_id": ObjectId(task_id), "user_id": current.id}, {"$set": updates, "$currentDate": {"updated_at": True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    doc = db["task"].find_one({"_id": ObjectId(task_id)})
    return serialize_task(doc)


@app.delete("/tasks/{task_id}")
def delete_task(task_id: str, current: CurrentUser = Depends(get_current_user)):
    res = db["task"].delete_one({"_id": ObjectId(task_id), "user_id": current.id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"deleted": True}


# Public profile
@app.get("/public/{username}", response_model=PublicProfile)
def public_profile(username: str):
    user = find_one("user", {"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.get("is_public", False):
        raise HTTPException(status_code=403, detail="This profile is private")

    tasks = db["task"].find({"user_id": str(user["_id"]) , "completed": {"$in": [True, False]}}).sort("order", 1)
    public_tasks = [
        {"title": t.get("title"), "description": t.get("description"), "completed": t.get("completed", False)}
        for t in tasks
    ]
    return PublicProfile(
        username=user["username"],
        display_name=user.get("display_name", user["username"]),
        bio=user.get("bio"),
        avatar_url=user.get("avatar_url"),
        is_public=True,
        theme=user.get("theme", "blueflame"),
        tasks=public_tasks,
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
