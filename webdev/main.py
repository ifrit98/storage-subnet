import os
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import base64
import bittensor as bt
from storage.validator.encryption import encrypt_data, decrypt_data_with_private_key
from storage import StoreUserAPI, RetrieveUserAPI, get_query_api_axons

# Constants and Security Configurations
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" # Replace with environment variable in production
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
    wallet_name: str
    wallet_hotkey: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# In-memory database (Replace with a real database in production)
fake_user_db: Dict[str, UserInDB] = {
    "johndoe": UserInDB(username="johndoe", 
                        hashed_password=pwd_context.hash("example"), 
                        seed="a6825ec6168f72e90b1244b1d2307433ad8394ad65b7ef4af10966bc103a39ae", 
                        wallet_name = 'abcd', 
                        wallet_hotkey = 'efghijk', 
                        )
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

# User Registration Endpoint
@app.post("/register/")
async def register_user(username: str, password: str):
    if get_user(fake_user_db, username):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Generate wallet
    user_wallet = bt.wallet()

    # Hash the password and generate a seed for the user
    hashed_password = get_password_hash(password)
    seed = generate_seed()
    name = user_wallet.name
    hotkey = user_wallet.hotkey.ss58_address

    # Store the user details in the database
    fake_user_db[username] = UserInDB(username=username, 
                                      hashed_password=hashed_password, 
                                      seed=seed, 
                                      wallet_name = name, 
                                      wallet_hotkey = hotkey, 
                                      )
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
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# File Upload Endpoint
@app.post("/uploadfiles/")
async def create_upload_files(files: List[UploadFile] = File(...), current_user: User = Depends(get_current_user)):
    
    # Access wallet_name and wallet_hotkey from current_user
    wallet_name = current_user.wallet_name
    wallet_hotkey = current_user.wallet_hotkey
    user_wallet = bt.wallet(name = wallet_name, hotkey = wallet_hotkey)

    # storage handler
    store_handler = StoreUserAPI(user_wallet)

    # Fetch the axons of the available API nodes, or specify UIDs directly
    metagraph = bt.subtensor("test").metagraph(netuid=22)
    axons = await get_query_api_axons(wallet=user_wallet, metagraph=metagraph, uids=[5, 7])

    for file in files:
        raw_data = await file.read()

        cid = await store_handler(
        axons=axons,
        # any arguments for the proper synapse
        data=raw_data,
        encrypt=False, # optionally encrypt the data with your bittensor wallet
        ttl=60 * 60 * 24 * 30,
        encoding="utf-8",
        uid=None,
        timeout=60,
        )

    return cid

# File Retrieval Endpoint
@app.get("/retrieve/{data_hash}")
async def retrieve_user_data(cid: str, outpath: str, current_user: User = Depends(get_current_user)):
    
    # Access wallet_name and wallet_hotkey from current_user
    wallet_name = current_user.wallet_name
    wallet_hotkey = current_user.wallet_hotkey
    user_wallet = bt.wallet(name = wallet_name, hotkey = wallet_hotkey)

    # retriever handler
    retrieve_handler = RetrieveUserAPI(user_wallet)

    # Fetch the axons of the available API nodes, or specify UIDs directly
    metagraph = bt.subtensor("test").metagraph(netuid=22)
    axons = await get_query_api_axons(wallet=user_wallet, metagraph=metagraph, uids=[5, 7])

    try:
        responses = await retrieve_handler(
            axons=axons,
            # Arugmnts for the proper synapse
            cid=cid, 
            timeout=60
        )
        
        for response in responses:
            # bittensor.logging.trace(f"response: {response.dendrite.dict()}")
            if (
                response.dendrite.status_code != 200
                or response.encrypted_data == None
            ):
                continue

            # Decrypt the response
            encrypted_data = base64.b64decode(response.encrypted_data)
            
            if (
                response.encryption_payload == None
                or response.encryption_payload == ""
                or response.encryption_payload == "{}"
            ):
                decrypted_data = encrypted_data
            else:
                decrypted_data = decrypt_data_with_private_key(
                    encrypted_data,
                    response.encryption_payload,
                    bytes(user_wallet.coldkey.private_key.hex(), "utf-8"),
                )
            success = True
            break  # No need to keep going if we returned data.

        if success:
            # Save the data
            with open(outpath, "wb") as f:
                f.write(decrypted_data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
