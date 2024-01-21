import os
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from neurons.api import neuron

# Constants and Security Configurations
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"  # Replace with environment variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize FastAPI app
app = FastAPI()

# Initialize Password Context for hashing and verifying
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User Model and Database
class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str
    seed: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# In-memory database (Replace with a real database in production)
fake_user_db: Dict[str, UserInDB] = {
    "johndoe": UserInDB(username="johndoe", hashed_password=pwd_context.hash("example"))  # Replace with actual hashed password
}

# User management functions
def get_user(db, username: str):
    return db.get(username)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def generate_seed():
    # Generate a random 32-byte seed and return its hash
    return pwd_context.hash(os.urandom(32))

# OAuth2 and JWT Token Management
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User Authentication Functions
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = get_user(fake_user_db, username)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# User Registration Endpoint
@app.post("/register/")
async def register_user(username: str, password: str):
    if get_user(fake_user_db, username):
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    seed = generate_seed()
    fake_user_db[username] = UserInDB(username=username, hashed_password=hashed_password, seed=seed)
    return {"message": "User registered successfully"}

# User Login and Token Generation Endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(fake_user_db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Protected User Data Endpoint
@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# Instantiate your neuron class
neuron_instance = neuron()

# File Upload Endpoint
@app.post("/uploadfiles/")
async def create_upload_files(files: List[UploadFile] = File(...)):
    responses = []
    for file in files:
        contents = await file.read()
        response = await neuron_instance.store_user_data(synapse=contents)  # Ensure this method is correctly implemented
        responses.append({"filename": file.filename, "response": response})
    return responses

# File Retrieval Endpoint
@app.get("/retrieve/{data_hash}")
async def retrieve_user_data(data_hash: str):
    try:
        response = await neuron_instance.retrieve_user_data(data_hash)  # Ensure this method is correctly implemented
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
