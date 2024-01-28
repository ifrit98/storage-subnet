import os
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import List, Optional, Dict
import torch
import storage, bittensor, base64, argparse
from storage.cli import create_config
from storage.validator.encryption import encrypt_data, decrypt_data_with_private_key
from storage.validator.utils import get_all_validators

# Constants and Security Configurations
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" # Replace with environment variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Initialize FastAPI app
app = FastAPI()

# Provide args to create the config
args = argparse.Namespace()
args.wallet_name = 'wallet_name'
args.wallet_hotkey = 'hotkey'
args.subtensor_network = 'subtensor_network'
args.stake_limit = 'stake_limit'
args.data_hash = 'data_hash'
# Call the create_config function from the cli class
config = create_config(args)

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
    "johndoe": UserInDB(username="johndoe", hashed_password=pwd_context.hash("example"), seed="a6825ec6168f72e90b1244b1d2307433ad8394ad65b7ef4af10966bc103a39ae")  # Replace with actual hashed password
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

# load the wallet
wallet = bittensor.wallet(
    name=config.wallet.name, hotkey=config.wallet.hotkey
)

# instantiate dendrite and metagraph
dendrite = bittensor.dendrite(wallet=wallet)

# create subtensor instance
subtensor = bittensor.subtensor(network=config.subtensor.network)
mg = subtensor.metagraph(config.netuid)

self = argparse.Namespace()
self.config = config
self.metagraph = mg

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

# File Upload Endpoint
@app.post("/uploadfiles/")
async def create_upload_files(files: List[UploadFile] = File(...)):
    responses = []
    for file in files:
        raw_data = await file.read()

        # encrypt using the bittensor wallet
        encrypted_data, encryption_payload = encrypt_data(
            bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data,
            wallet,
        )

        # Encode the encrypted data
        encoded_data = base64.b64encode(encrypted_data)

        # create our synapse wrapper
        synapse = storage.protocol.StoreUser(
            encrypted_data=encoded_data,
            encryption_payload=encryption_payload,
        )

        # grab validators to query for storage
        query_uids = get_all_validators(self)
        bittensor.logging.debug("query uids:", query_uids)
        axons = [mg.axons[uid] for uid in query_uids]
        bittensor.logging.debug("query axons:", axons)

        # Post request to the decentralized storage network
        response = dendrite.query(axons, synapse, timeout=270, deserialize=False)
        responses.append({"filename": file.filename, "response": response})

    return responses

# File Retrieval Endpoint
@app.get("/retrieve/{data_hash}")
async def retrieve_user_data(data_hash: str, outpath: str):
    try:
        # Determine axons to query from metagraph for retrieval
        vpermits = mg.validator_permit
        vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
        vpermit_uids = torch.where(vpermits)[0]

        query_uids = torch.where(mg.S[vpermit_uids] > config.stake_limit)[0]
        axons = [mg.axons[uid] for uid in query_uids]

        synapse = storage.protocol.RetrieveUser(data_hash=config.data_hash)

        # Query axons
        responses = dendrite.query(axons, synapse, timeout=270, deserialize=False)
        success = False
        for response in responses:
            bittensor.logging.trace(f"response: {response.dendrite.dict()}")
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
                    bytes(wallet.coldkey.private_key.hex(), "utf-8"),
                )
            success = True
            break  # No need to keep going if we returned data.

        if success:
            # Save the data
            with open(outpath, "wb") as f:
                f.write(decrypted_data)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
