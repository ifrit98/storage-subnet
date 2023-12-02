# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 philanthrope

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import json
import redis
import asyncio
import bittensor as bt
from typing import Dict, List, Any, Union, Optional, Tuple


# Function to add metadata to a hash in Redis
def add_metadata_to_hotkey(
    ss58_address: str, data_hash: str, metadata: Dict, database: redis.Redis
):
    """
    Associates a data hash and its metadata with a hotkey in Redis.

    Parameters:
        ss58_address (str): The primary key representing the hotkey.
        data_hash (str): The subkey representing the data hash.
        metadata (dict): The metadata to associate with the data hash.
        database (redis.Redis): The Redis client instance.
    """
    # Serialize the metadata as a JSON string
    metadata_json = json.dumps(metadata)
    # Use HSET to associate the data hash with the hotkey
    key = f"hotkey:{ss58_address}"
    database.hset(key, data_hash, metadata_json)
    bt.logging.trace(f"Associated data hash {data_hash} with hotkey {ss58_address}.")


def get_metadata_for_hotkey(
    ss58_address: str, database: redis.Redis
) -> Dict[str, dict]:
    """
    Retrieves all data hashes and their metadata for a given hotkey.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are the associated metadata.
    """
    # Fetch all fields (data hashes) and values (metadata) for the hotkey
    all_data_hashes = database.hgetall(f"hotkey:{ss58_address}")

    # Deserialize the metadata for each data hash
    return {
        data_hash.decode("utf-8"): json.loads(metadata.decode("utf-8"))
        for data_hash, metadata in all_data_hashes.items()
    }


def get_hashes_for_hotkey(ss58_address: str, database: redis.Redis) -> List[str]:
    """
    Retrieves all data hashes and their metadata for a given hotkey.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are the associated metadata.
    """
    # Fetch all fields (data hashes) and values (metadata) for the hotkey
    all_data_hashes = database.hgetall(f"hotkey:{ss58_address}")

    # Deserialize the metadata for each data hash
    return [
        data_hash.decode("utf-8") for data_hash, metadata in all_data_hashes.items()
    ]


def update_metadata_for_data_hash(
    ss58_address: str, data_hash: str, new_metadata: dict, database: redis.Redis
):
    """
    Updates the metadata for a specific data hash associated with a hotkey.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        data_hash (str): The subkey representing the data hash to update.
        new_metadata (dict): The new metadata to associate with the data hash.
        database (redis.Redis): The Redis client instance.
    """
    # Serialize the new metadata as a JSON string
    new_metadata_json = json.dumps(new_metadata)
    # Update the field in the hash with the new metadata
    database.hset(f"hotkey:{ss58_address}", data_hash, new_metadata_json)
    bt.logging.trace(
        f"Updated metadata for data hash {data_hash} under hotkey {ss58_address}."
    )


def get_metadata_for_hotkey_and_hash(
    ss58_address: str, data_hash: str, database: redis.Redis, verbose: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Retrieves specific metadata from a hash in Redis for the given field_key.

    Parameters:
        ss58_address (str): The hotkey assoicated.
        data_hash (str): The data hash associated.
        databse (redis.Redis): The Redis client instance.

    Returns:
        The deserialized metadata as a dictionary, or None if not found.
    """
    # Get the JSON string from Redis
    metadata_json = database.hget(f"hotkey:{ss58_address}", data_hash)
    if verbose:
        bt.logging.trace(
            f"hotkey {ss58_address[:16]} | data_hash {data_hash[:16]} | metadata_json {metadata_json}"
        )
    if metadata_json:
        # Deserialize the JSON string to a Python dictionary
        metadata = json.loads(metadata_json)
        return metadata
    else:
        bt.logging.trace(f"No metadata found for {data_hash} in hash {ss58_address}.")
        return None


def get_all_chunk_hashes(database: redis.Redis) -> Dict[str, List[str]]:
    """
    Retrieves all chunk hashes and associated metadata from the Redis instance.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are chunk hashes and values are lists of hotkeys associated with each chunk hash.
    """
    # Initialize an empty dictionary to store the inverse map
    chunk_hash_hotkeys = {}

    # Retrieve all hotkeys (assuming keys are named with a 'hotkey:' prefix)
    for hotkey in database.scan_iter("*"):
        if not hotkey.startswith(b"hotkey:"):
            continue
        # Fetch all fields (data hashes) for the current hotkey
        data_hashes = database.hkeys(hotkey)
        # Iterate over each data hash and append the hotkey to the corresponding list
        for data_hash in data_hashes:
            data_hash = data_hash.decode("utf-8")
            if data_hash not in chunk_hash_hotkeys:
                chunk_hash_hotkeys[data_hash] = []
            chunk_hash_hotkeys[data_hash].append(hotkey.decode("utf-8").split(":")[1])

    return chunk_hash_hotkeys


def get_all_full_hashes(database: redis.Redis) -> List[str]:
    """
    Retrieves all data hashes and their corresponding hotkeys from the Redis instance.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are lists of hotkeys associated with each data hash.
    """
    data_hashes = []
    for key in database.scan_iter("*"):
        if not key.startswith(b"file:"):
            continue
        data_hashes.append(key.decode("utf-8").split(":")[1])

    return data_hashes


def get_all_hotkeys_for_data_hash(data_hash: str, database: redis.Redis) -> List[str]:
    """
    Retrieves all hotkeys associated with a specific data hash.

    Parameters:
        data_hash (str): The data hash to look up.
        database (redis.Redis): The Redis client instance.

    Returns:
        A list of hotkeys associated with the data hash.
    """
    # Initialize an empty list to store the hotkeys
    hotkeys = []

    # Retrieve all hotkeys (assuming keys are named with a 'hotkey:' prefix)
    for hotkey in database.scan_iter("*"):
        # Check if the data hash exists within the hash of the hotkey
        if database.hexists(hotkey, data_hash):
            hotkey = hotkey.decode("utf-8") if isinstance(hotkey, bytes) else hotkey
            hotkeys.append(hotkey)

    return hotkeys


def total_hotkey_storage(hotkey: str, database: redis.Redis) -> int:
    """
    Calculates the total storage used by a hotkey in the database.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        The total storage used by the hotkey in bytes.
    """
    total_storage = 0
    for data_hash in database.hkeys(f"hotkey:{hotkey}"):
        # Get the metadata for the current data hash
        metadata = get_metadata_for_hotkey_and_hash(hotkey, data_hash, database)
        if metadata:
            # Add the size of the data to the total storage
            total_storage += metadata["size"]
    bt.logging.trace(f"total_hotkey_storage {total_storage} | hotkey {hotkey}")
    return total_storage


def hotkey_at_capacity(hotkey: str, database: redis.Redis) -> bool:
    """
    Checks if the hotkey is at capacity.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        True if the hotkey is at capacity, False otherwise.
    """
    # Get the total storage used by the hotkey
    total_storage = total_hotkey_storage(hotkey, database)
    # Check if the hotkey is at capacity
    byte_limit = database.hget(f"stats:{hotkey}", "storage_limit")
    if byte_limit is None:
        bt.logging.warning(f"Could not find storage limit for {hotkey}.")
        return False
    try:
        limit = int(byte_limit)
    except Exception as e:
        bt.logging.warning(f"Could not parse storage limit for {hotkey} | {e}.")
        return False
    if total_storage >= limit:
        bt.logging.trace(f"Hotkey {hotkey} is at max capacity {limit // 10**9} GB.")
        return True
    else:
        bt.logging.trace(
            f"Hotkey {hotkey} has {(limit - total_storage) // 10**9} GB free."
        )
        return False


def total_network_storage(database: redis.Redis) -> int:
    """
    Calculates the total storage used by all hotkeys in the database.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        The total storage used by all hotkeys in the database in bytes.
    """
    total_storage = 0
    # Iterate over all hotkeys
    for hotkey in database.scan_iter("*"):
        if not hotkey.startswith(b"hotkey:"):
            continue
        # Grab storage for that hotkey
        total_storage += total_hotkey_storage(hotkey.decode().split(":")[1], database)
    return total_storage


def get_miner_statistics(database: redis.Redis) -> Dict[str, Dict[str, str]]:
    """
    Retrieves statistics for all miners in the database.
    Parameters:
        database (redis.Redis): The Redis client instance.
    Returns:
        A dictionary where keys are hotkeys and values are dictionaries containing the statistics for each hotkey.
    """
    return {
        key.decode("utf-8").split(":")[-1]: {
            k.decode("utf-8"): v.decode("utf-8")
            for k, v in database.hgetall(key).items()
        }
        for key in database.scan_iter(b"stats:*")
    }


def get_single_miner_statistics(
    ss58_address: str, database: redis.Redis
) -> Dict[str, Dict[str, str]]:
    """
    Retrieves statistics for all miners in the database.
    Parameters:
        database (redis.Redis): The Redis client instance.
    Returns:
        A dictionary where keys are hotkeys and values are dictionaries containing the statistics for each hotkey.
    """
    return {
        k.decode("utf-8"): v.decode("utf-8")
        for k, v in database.hgetall(f"stats:{ss58_address}").items()
    }


def get_redis_db_size(database: redis.Redis) -> int:
    """
    Calculates the total approximate size of all keys in a Redis database.
    Parameters:
        database (int): Redis database
    Returns:
        int: Total size of all keys in bytes
    """
    total_size = 0
    for key in database.scan_iter("*"):
        size = database.execute_command("MEMORY USAGE", key)
        if size:
            total_size += size
    return total_size


def store_file_chunk_mapping_ordered(
    full_hash: str,
    chunk_hashes: List[str],
    chunk_indices: List[str],
    database: redis.Redis,
):
    """
    Store an ordered mapping of file chunks in the database.

    This function takes a file's full hash and the hashes of its individual chunks, along with their
    respective indices, and stores them in a sorted set in the Redis database. The order is preserved
    based on the chunk index.

    Parameters:
    - full_hash (str): The full hash of the file.
    - chunk_hashes (List[str]): A list of hashes for the individual chunks of the file.
    - chunk_indices (List[int]): A list of indices corresponding to each chunk hash.
    - database (redis.Redis): An instance of the Redis database.
    """
    key = f"file:{full_hash}"
    for chunk_index, chunk_hash in zip(chunk_indices, chunk_hashes):
        database.zadd(key, {chunk_hash: chunk_index})


def get_all_chunks_for_file(
    file_hash: str, database: redis.Redis
) -> Optional[Dict[int, Dict[str, Union[str, List[str], int]]]]:
    """
    Retrieve all chunk hashes and their metadata for a given file hash.

    This function fetches the hashes and metadata of all chunks associated with a particular file hash.
    The data is retrieved from a sorted set and returned in a dictionary with the chunk index as the key.

    Parameters:
    - file_hash (str): The full hash of the file whose chunks are to be retrieved.
    - database (redis.Redis): An instance of the Redis database.

    Returns:
    - dict: A dictionary where keys are chunk indices, and values are dictionaries with chunk metadata.
      Returns None if no chunks are found.
    """
    file_chunks_key = f"file:{file_hash}"
    chunk_hashes_with_index = database.zrange(file_chunks_key, 0, -1, withscores=True)
    if not chunk_hashes_with_index:
        return None

    chunks_info = {}
    for chunk_hash_bytes, index in chunk_hashes_with_index:
        chunk_hash = chunk_hash_bytes.decode()
        chunk_metadata = database.hgetall(f"chunk:{chunk_hash}")
        if chunk_metadata:
            chunks_info[int(index)] = {
                "chunk_hash": chunk_hash,
                "hotkeys": chunk_metadata[b"hotkeys"].decode().split(","),
                "size": int(chunk_metadata[b"size"]),
            }
    return chunks_info


def get_hotkeys_for_hash(
    hash_value: str, database: redis.Redis, is_full_hash: bool = False
):
    """
    Fetch all hotkeys associated with a given hash, which can be a full file hash or a chunk hash.

    Parameters:
    - hash_value (str): The hash value of the file or chunk.
    - database (redis.Redis): An instance of the Redis database.
    - is_full_hash (bool): A flag indicating if the hash_value is a full file hash.

    Returns:
    - List[str]: A list of hotkeys associated with the hash.
      Returns None if no hotkeys are found.
    """
    all_hotkeys = set()

    if is_full_hash:
        # Get UIDs for all chunks under the full hash
        chunks_info = get_all_chunks_for_file(hash_value, database)
        if chunks_info is None:
            return None
        for chunk_info in chunks_info.values():
            all_hotkeys.update(chunk_info["hotkeys"])
    else:
        # Get UIDs for a single chunk hash
        chunk_metadata = database.hgetall(f"chunk:{hash_value}")
        if chunk_metadata:
            hotkeys = chunk_metadata.get(b"hotkeys")
            if hotkeys:
                all_hotkeys.update(hotkeys.decode().split(","))

    return list(all_hotkeys)


def add_hotkey_to_chunk(chunk_hash: str, hotkey: str, database: redis.Redis):
    """
    Add a hotkey to the metadata of a specific chunk.

    This function updates the chunk's metadata to include the given hotkey. If the hotkey is already
    associated with the chunk, no changes are made.

    Parameters:
    - chunk_hash (str): The hash of the chunk to which the hotkey is to be added.
    - hotkey (str): The hotkey to add to the chunk's metadata.
    - database (redis.Redis): An instance of the Redis database.
    """
    chunk_metadata_key = f"chunk:{chunk_hash}"

    # Fetch existing UIDs for the chunk
    existing_metadata = database.hget(chunk_metadata_key, "hotkeys")
    if existing_metadata:
        existing_hotkeys = existing_metadata.decode().split(",")

        # Add new UID if it's not already in the list
        if hotkey not in existing_hotkeys:
            updated_hotkeys = existing_hotkeys + [hotkey]
            database.hset(chunk_metadata_key, "hotkeys", ",".join(updated_hotkeys))
            print(f"UID {hotkey} added to chunk {chunk_hash}.")
        else:
            print(f"UID {hotkey} already exists for chunk {chunk_hash}.")
    else:
        # If no UIDs are associated with this chunk, create a new entry
        database.hmset(chunk_metadata_key, {"hotkeys": hotkey})
        print(f"UID {hotkey} set for new chunk {chunk_hash}.")


def store_chunk_metadata(
    full_hash: str,
    chunk_hash: str,
    hotkeys: List[str],
    chunk_size: int,
    database: redis.Redis,
):
    """
    Store metadata for a specific file chunk.

    This function creates or updates the metadata for a chunk, including the associated hotkeys and chunk size.

    Parameters:
    - full_hash (str): The full hash of the file that the chunk belongs to.
    - chunk_hash (str): The hash of the chunk whose metadata is to be stored.
    - hotkeys (List[str]): A list of hotkeys associated with the chunk.
    - chunk_size (int): The size of the chunk in bytes.
    - database (redis.Redis): An instance of the Redis database.
    """
    chunk_metadata_key = f"chunk:{chunk_hash}"
    existing_metadata = database.hget(chunk_metadata_key, "hotkeys")
    if existing_metadata:
        existing_hotkeys = existing_metadata.decode().split(",")
        hotkeys = set(existing_hotkeys + hotkeys)
    metadata = {"hotkeys": ",".join(hotkeys), "size": chunk_size}

    database.hmset(chunk_metadata_key, metadata)


def get_ordered_metadata(
    file_hash: str, database: redis.Redis
) -> List[Dict[str, Union[str, List[str], int]]]:
    """
    Retrieve the metadata for all chunks of a file in the order of their indices.

    This function calls `get_all_chunks_for_file` to fetch all chunks' metadata and then sorts
    them based on their indices to maintain the original file order.

    Parameters:
    - file_hash (str): The full hash of the file whose ordered metadata is to be retrieved.
    - database (redis.Redis): An instance of the Redis database.

    Returns:
    - List[dict]: A list of metadata dictionaries for each chunk, ordered by their chunk index.
      Returns None if no chunks are found.
    """
    chunks_info = get_all_chunks_for_file(file_hash, database)
    if chunks_info is None:
        return None

    ordered_chunks = sorted(chunks_info.items(), key=lambda x: x[0])
    return [chunk_info for _, chunk_info in ordered_chunks]


# Function to grab mutually exclusiv UIDs for a specific full_hash (get chunks of non-overlapping UIDs)
def retrieve_mutually_exclusive_hotkeys_full_hash(
    full_hash: str, database: redis.Redis
) -> Dict[str, List[str]]:
    """
    Retrieve a list of mutually exclusive hotkeys for a specific full hash.

    This function retrieves the metadata for all chunks of a file and then sorts them based on their
    indices to maintain the original file order. It then iterates over the chunks and adds the hotkeys
    of each chunk to the dict of chunk hash <> mutually exclusive hotkey mappings if not already present.

    Parameters:
    - full_hash (str): The full hash of the file whose ordered metadata is to be retrieved.
    - database (redis.Redis): An instance of the Redis database.

    Returns:
    - Dict[str, List[str]]: A dict of mutually exclusive hotkeys for each corresponding hash.
      Returns None if no chunks are found.
    """
    chunks_info = get_all_chunks_for_file(full_hash, database)
    if chunks_info is None:
        return None

    ordered_chunks = sorted(chunks_info.items(), key=lambda x: x[0])
    mutually_exclusive_hotkeys = {}
    for _, chunk_info in ordered_chunks:
        if chunk_info["chunk_hash"] not in mutually_exclusive_hotkeys:
            mutually_exclusive_hotkeys[chunk_info["chunk_hash"]] = []
        for hotkey in chunk_info["hotkeys"]:
            if hotkey not in mutually_exclusive_hotkeys[chunk_info["chunk_hash"]]:
                mutually_exclusive_hotkeys[chunk_info["chunk_hash"]].append(hotkey)

    return mutually_exclusive_hotkeys
