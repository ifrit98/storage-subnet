import json
import torch
import bittensor as bt

import os
from os import getenv
from redis import StrictRedis
from datetime import datetime
from pydantic import BaseModel
from typing import Optional, Union, List

redis_db = None

os.environ["REDIS_URL"] = "localhost"
os.environ["REDIS_DB"] = "2"
os.environ["REDIS_PORT"] = "6379"

METAGRAPH_ATTRIBUTES = [
    "n",
    "block",
    "stake",
    "total_stake",
    "ranks",
    "trust",
    "consensus",
    "validator_trust",
    "incentive",
    "emission",
    "dividends",
    "active",
    "last_update",
    "validator_permit",
    "weights",
    "bonds",
    "uids"
]

def get_database() -> StrictRedis:
    return StrictRedis(host=getenv("REDIS_HOST"), port=getenv("REDIS_PORT"), db=getenv("REDIS_DB")) if redis_db == None else redis_db

def startup():
    global redis_db
    redis_db = get_database()
    if redis_db.get("service:has_launched") == None:
        redis_db.set("service:service", "UserDatabase")
        redis_db.set("service:userCount", "0")
        redis_db.set("service:totalFiles", "0")
        redis_db.set("service:has_launched", "True")

    redis_db.set("service:started", datetime.today().ctime())

def get_server_wallet():
    server_wallet = bt.wallet(name="server", hotkey="default")
    if redis_db.hget("server_wallet", "name") is None:
        server_wallet.create(coldkey_use_password=False, hotkey_use_password=False)
        redis_db.hset("server_wallet", "name", server_wallet.name)
        redis_db.hset("server_wallet", "hotkey", server_wallet.hotkey.ss58_address)
        redis_db.hset("server_wallet", "mnemonic", server_wallet.coldkey.mnemonic)

    return server_wallet

# User Model and Database
class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str
    seed: str
    wallet_name: str
    wallet_hotkey: str
    wallet_mnemonic: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def serialize_model(model: BaseModel) -> str:
    """Serialize Pydantic model to JSON string."""
    return model.json()

def deserialize_model(model_str: str, model_class: type) -> BaseModel:
    """Deserialize JSON string back into Pydantic model."""
    return model_class.parse_raw(model_str)

def get_user(username: str) -> Optional[UserInDB]:
    user_str = redis_db.get(username)
    if user_str:
        return deserialize_model(user_str, UserInDB)
    return None

def create_user(user: UserInDB):
    username = user.username
    user_str = serialize_model(user)
    redis_db.set(username, user_str)

def store_file_metadata(filename: str, cid: str, hotkeys: List[str], payload: dict):
    redis_db.set(filename, json.dumps({"cid": cid, "hotkeys": hotkeys, "encryption_payload": payload}))

def get_file_metadata(filename: str) -> Optional[dict]:
    if redis_db.get(filename) is None:
        return None
    return json.loads(redis_db.get(filename))

def get_metagraph(netuid: int = 22, network: str = "test") -> bt.metagraph:
    metagraph_str = redis_db.get(f"metagraph:{netuid}")
    if metagraph_str:
        metagraph = deserialize_metagraph(metagraph_str.decode())
        last_block = metagraph.block.item()
        current_block = bt.subtensor(network).get_current_block()
        if current_block - last_block < 100:
            return metagraph

    metagraph = bt.subtensor(network).metagraph(netuid)
    metagraph_str = serialize_metagraph(metagraph, dump=True)
    redis_db.set(f"metagraph:{netuid}", metagraph_str)
    return metagraph

def serialize_metagraph(metagraph_obj: bt.metagraph, dump=False) -> Union[str, dict]:
    serialized_data = {}
    for attr in METAGRAPH_ATTRIBUTES:
        tensor = getattr(metagraph_obj, attr, None)
        if tensor is not None:
            serialized_data[attr] = tensor.cpu().numpy().tolist()

    serialized_data["netuid"] = metagraph_obj.netuid
    serialized_data["network"] = metagraph_obj.network
    serialized_data["version"] = metagraph_obj.version.item()
    serialized_data["axons"] = [axon.to_string() for axon in metagraph_obj.axons]
    serialized_data["netuid"] = metagraph_obj.netuid

    return json.dumps(serialized_data) if dump else serialized_data

def deserialize_metagraph(serialized_str):
    if isinstance(serialized_str, str):
        data = json.loads(serialized_str)
    else:
        data = serialized_str
    metagraph_obj = bt.metagraph(
        netuid=data["netuid"], network=data["network"], lite=False, sync=False
    )
    metagraph_obj.version = torch.nn.Parameter(
        torch.tensor([data["version"]], dtype=torch.int64), requires_grad=False
    )

    for attr in METAGRAPH_ATTRIBUTES:
        if attr in data:
            setattr(
                metagraph_obj,
                attr,
                torch.nn.Parameter(torch.tensor(data[attr]), requires_grad=False),
            )

    metagraph_obj.axons = [
        bt.chain_data.AxonInfo.from_string(axon_data) for axon_data in data["axons"]
    ]

    return metagraph_obj