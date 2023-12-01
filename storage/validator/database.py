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
def add_metadata_to_hotkey(ss58_address, data_hash, metadata, database):
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
    database.hset(ss58_address, data_hash, metadata_json)
    bt.logging.trace(f"Associated data hash {data_hash} with hotkey {ss58_address}.")


def get_all_data_for_hotkey(ss58_address, database, return_hashes=False):
    """
    Retrieves all data hashes and their metadata for a given hotkey.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are the associated metadata.
    """
    # Fetch all fields (data hashes) and values (metadata) for the hotkey
    all_data_hashes = database.hgetall(ss58_address)

    # Return only the hashes themselves if specified
    if return_hashes:
        return all_data_hashes

    # Deserialize the metadata for each data hash
    return {
        data_hash.decode("utf-8"): json.loads(metadata.decode("utf-8"))
        for data_hash, metadata in all_data_hashes.items()
    }


def update_metadata_for_data_hash(ss58_address, data_hash, new_metadata, database):
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
    database.hset(ss58_address, data_hash, new_metadata_json)
    bt.logging.trace(
        f"Updated metadata for data hash {data_hash} under hotkey {ss58_address}."
    )


def get_metadata_from_hash(ss58_address, data_hash, database):
    """
    Retrieves metadata from a hash in Redis for the given field_key.

    Parameters:
        hash_key (str): The hash key in Redis.
        field_key (str): The field key within the hash.
        databse (redis.Redis): The Redis client instance.

    Returns:
        The deserialized metadata as a dictionary, or None if not found.
    """
    # Get the JSON string from Redis
    metadata_json = database.hget(ss58_address, data_hash)
    bt.logging.debug(
        f"hotkey {ss58_address} | data_hash {data_hash} | metadata_json {metadata_json}"
    )
    if metadata_json:
        # Deserialize the JSON string to a Python dictionary
        metadata = json.loads(metadata_json)
        return metadata
    else:
        bt.logging.trace(f"No metadata found for {data_hash} in hash {ss58_address}.")
        return None


def get_all_data_hashes(database):
    """
    Retrieves all data hashes and their corresponding hotkeys from the Redis instance.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are lists of hotkeys associated with each data hash.
    """
    # Initialize an empty dictionary to store the inverse map
    data_hash_to_hotkeys = {}

    # Retrieve all hotkeys (assuming keys are named with a 'hotkey:' prefix)
    for hotkey in database.scan_iter("*"):
        if hotkey.decode().startswith("stats:"):
            continue
        # Fetch all fields (data hashes) for the current hotkey
        data_hashes = database.hkeys(hotkey)
        # Iterate over each data hash and append the hotkey to the corresponding list
        for data_hash in data_hashes:
            data_hash = data_hash.decode("utf-8")
            if data_hash not in data_hash_to_hotkeys:
                data_hash_to_hotkeys[data_hash] = []
            data_hash_to_hotkeys[data_hash].append(hotkey.decode("utf-8"))

    return data_hash_to_hotkeys


def get_all_hotkeys_for_data_hash(data_hash, database):
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


def calculate_total_hotkey_storage(hotkey, database):
    """
    Calculates the total storage used by a hotkey in the database.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        The total storage used by the hotkey in bytes.
    """
    total_storage = 0
    for data_hash in database.hkeys(hotkey):
        bt.logging.debug(
            f"total_hotkey_storage: hotkey {hotkey} | data_hash {data_hash}"
        )
        # Get the metadata for the current data hash
        metadata = get_metadata_from_hash(hotkey, data_hash, database)
        if metadata:
            # Add the size of the data to the total storage
            total_storage += metadata["size"]
    return total_storage


def hotkey_at_capacity(hotkey, database):
    """
    Checks if the hotkey is at capacity.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        True if the hotkey is at capacity, False otherwise.
    """
    # Get the total storage used by the hotkey
    total_storage = calculate_total_hotkey_storage(hotkey, database)
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
        bt.logging.debug(f"Hotkey {hotkey} is at max capacity {limit // 10**9} GB.")
        return True
    else:
        return False


def calculate_total_network_storage(database):
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
        if hotkey.startswith(b"stats:") or hotkey.startswith("chunk:"):
            continue
        # Grab storage for that hotkey
        total_storage += calculate_total_hotkey_storage(hotkey, database)
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


def store_file_chunk_mapping_ordered(full_hash, chunk_hashes, chunk_indices, database):
    key = f"file:{full_hash}"
    for chunk_index, chunk_hash in zip(chunk_indices, chunk_hashes):
        database.zadd(key, {chunk_hash: chunk_index})


def get_all_chunks_for_file(file_hash, database):
    file_chunks_key = f"file:{file_hash}"
    chunk_hashes_with_index = database.zrange(file_chunks_key, 0, -1, withscores=True)
    if not chunk_hashes_with_index:
        return None

    chunks_info = {}
    for chunk_hash_bytes, index in chunk_hashes_with_index:
        chunk_hash = chunk_hash_bytes.decode()  # Decode bytes to string
        chunk_metadata = database.hgetall(f"chunk:{chunk_hash}")
        if chunk_metadata:
            chunks_info[int(index)] = {
                "chunk_hash": chunk_hash,
                # "file_hash": chunk_metadata[b'file_hash'].decode(),
                "uids": chunk_metadata[b"uids"].decode().split(","),
                "size": int(chunk_metadata[b"size"]),
                # "seed": chunk_metadata[b'seed'].decode()
            }
    return chunks_info


def get_uids_for_hash(hash_value, database, is_full_hash=False):
    all_uids = set()

    if is_full_hash:
        # Get UIDs for all chunks under the full hash
        chunks_info = get_all_chunks_for_file(hash_value, database)
        if chunks_info is None:
            return None
        for chunk_info in chunks_info.values():
            all_uids.update(chunk_info["uids"])
    else:
        # Get UIDs for a single chunk hash
        chunk_metadata = database.hgetall(f"chunk:{hash_value}")
        if chunk_metadata:
            uids = chunk_metadata.get(b"uids")
            if uids:
                all_uids.update(uids.decode().split(","))

    return list(all_uids)


def add_uid_to_chunk(chunk_hash, uid, database):
    chunk_metadata_key = f"chunk:{chunk_hash}"

    # Fetch existing UIDs for the chunk
    existing_metadata = database.hget(chunk_metadata_key, "uids")
    if existing_metadata:
        existing_uids = existing_metadata.decode().split(",")

        # Add new UID if it's not already in the list
        if uid not in existing_uids:
            updated_uids = existing_uids + [uid]
            database.hset(chunk_metadata_key, "uids", ",".join(updated_uids))
            print(f"UID {uid} added to chunk {chunk_hash}.")
        else:
            print(f"UID {uid} already exists for chunk {chunk_hash}.")
    else:
        # If no UIDs are associated with this chunk, create a new entry
        database.hmset(chunk_metadata_key, {"uids": uid})
        print(f"UID {uid} set for new chunk {chunk_hash}.")


def store_chunk_metadata(full_hash, chunk_hash, uids, chunk_size, database):
    chunk_metadata_key = f"chunk:{chunk_hash}"
    existing_metadata = database.hget(chunk_metadata_key, "uids")
    if existing_metadata:
        existing_uids = existing_metadata.decode().split(",")
        uids = set(existing_uids + uids)
    metadata = {"uids": ",".join(uids), "size": chunk_size}

    database.hmset(chunk_metadata_key, metadata)


def get_ordered_metadata(file_hash, database):
    chunks_info = get_all_chunks_for_file(file_hash, database)
    if chunks_info is None:
        return None

    ordered_chunks = sorted(chunks_info.items(), key=lambda x: x[0])
    return [chunk_info for _, chunk_info in ordered_chunks]
