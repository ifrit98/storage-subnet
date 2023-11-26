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

import os
import sys
import json
import redis
import random
import asyncio
import hashlib
import bittensor as bt
from typing import Dict, List, Any, Union, Optional, Tuple

MAXCHUNKSIZE = 64

def chunk(data, chunksize=MAXCHUNKSIZE):
    if sys.getsizeof(data) <= chunksize:
        yield data
        return

    for i in range(0, len(data), chunksize):
        yield data[i : i + chunksize]

def hash_data(data):
    if not isinstance(data, (bytes, bytearray)):
        data_str = str(data)
        data = data_str.encode()
    h = hashlib.sha3_256(data).hexdigest()
    return int(h, 16)

def generate_uid_combinations(UIDs, UID_redundancy_factor):
    # Generate all unique combinations of UIDs
    return list(itertools.combinations(UIDs, UID_redundancy_factor))

def assign_combinations_to_hashes(hashes, combinations):
    if len(hashes) > len(combinations):
        raise ValueError("Not enough unique UID combinations for the given redundancy factor and number of hashes.")

    # Shuffle once and then iterate in order for assignment
    random.shuffle(combinations)
    return {hash_val: combinations[i] for i, hash_val in enumerate(hashes)}

def create_validator_distribution_optimized(hashes, UIDs, validator_hotkeys, UID_redundancy_factor, validator_redundancy_factor):
    combinations = generate_uid_combinations(UIDs, UID_redundancy_factor)
    hash_distribution = assign_combinations_to_hashes(hashes, combinations)
    
    # Select validators efficiently
    selected_validators = random.sample(validator_hotkeys, validator_redundancy_factor)
    # Direct reference assignment as hash distributions are immutable and not modified
    return {validator: hash_distribution for validator in selected_validators}

def split_and_store(data, db, metagraph = None, miner_redundancy: int = 3, validator_redundancy: int = 2):
    full_hash = hash_data(data)
    hashes = [hash_data(chunk) for chunk in chunk(data, MAXCHUNKSIZE)]
    miner_hotkeys = get_miner_hotkeys(metagraph)
    validator_hotkeys = get_validator_hotkeys(metagraph)

    try:
        distribution = create_validator_distribution_optimized(
            hashes, miner_hotkeys, validator_hotkeys, miner_redundancy, validator_redundancy)
        for validator, dist in distribution.items():
            print(f"Validator {validator}: {dist}")
    except ValueError as e:
        print(e)

    store_validator_data(r10, final_distribution, full_hash, hashes)
    store_global_index_direct_with_order(r10, final_distribution, full_hash, hashes)
    store_global_index_indirect_with_order(r10, final_distribution, full_hash, hashes)

    return full_hash, hashes, distribution

def store_validator_data(r, validator_data, full_hash, chunk_hashes):
    full_hash_key = f"fullhash:{full_hash}"
    chunk_order = 0
    for chunk_hash in chunk_hashes:
        r.zadd(full_hash_key, {str(chunk_hash): chunk_order})
        chunk_order += 1

    for validator, chunks in validator_data.items():
        validator_key = f"validator:{validator}"
        for chunk_hash, uids in chunks.items():
            r.hset(validator_key, str(chunk_hash), ','.join(uids))

def store_validator_data_with_size(r, validator_data, full_hash, chunk_hashes, size_in_bytes):
    full_hash_key = f"fullhash:{full_hash}"
    chunk_order = 0
    for chunk_hash in chunk_hashes:
        r.zadd(full_hash_key, {str(chunk_hash): chunk_order})
        chunk_order += 1

    for validator, chunks in validator_data.items():
        validator_key = f"validator:{validator}"
        for chunk_hash, uids in chunks.items():
            r.hset(validator_key, str(chunk_hash), ','.join(uids))

    # Store the size of the data
    full_hash_size_key = f"fullhash:size:{full_hash}"
    r.set(full_hash_size_key, size_in_bytes)

def store_global_index_indirect_with_order(r, distribution, full_hash, chunk_hashes):
    global_index_key = f"global:indirect:{full_hash}"

    for order, chunk_hash in enumerate(chunk_hashes):
        for validator in distribution:
            # Add the validator to the set of validators for this chunk_hash
            r.zadd(f"{global_index_key}:{chunk_hash}", {validator: order})

def get_miner_hotkeys_from_full_hash(r, full_hash):
    full_hash_key = f"fullhash:{full_hash}"
    ordered_chunk_hashes = r.zrange(full_hash_key, 0, -1, withscores=False)

    miner_hotkeys_by_chunk = {}
    for chunk_hash_bytes in ordered_chunk_hashes:
        chunk_hash = chunk_hash_bytes.decode('utf-8')
        miner_hotkeys = set()
        for validator_key in r.scan_iter("validator:*"):
            uids = r.hget(validator_key, chunk_hash)
            if uids:
                miner_hotkeys.update(uids.decode('utf-8').split(','))

        miner_hotkeys_by_chunk[chunk_hash] = list(miner_hotkeys)

    return miner_hotkeys_by_chunk

def get_validator_hotkeys_from_full_hash(r, full_hash):
    full_hash_key = f"fullhash:{full_hash}"
    ordered_chunk_hashes = r.zrange(full_hash_key, 0, -1, withscores=False)

    validator_hotkeys_by_chunk = {}
    for chunk_hash_bytes in ordered_chunk_hashes:
        chunk_hash = chunk_hash_bytes.decode('utf-8')
        chunk_key = f"global:indirect:{full_hash}:{chunk_hash}"
        validator_hotkeys = r.zrange(chunk_key, 0, -1, withscores=False)

        validator_hotkeys_by_chunk[chunk_hash] = [v.decode('utf-8') for v in validator_hotkeys]

    return validator_hotkeys_by_chunk

def get_all_full_hashes(r):
    return [k.decode('utf-8').split(':')[1] for k in r.scan_iter("fullhash:*")]

def get_all_chunk_hashes(r, full_hash):
    full_hash_key = f"fullhash:{full_hash}"
    ordered_chunk_hashes = r.zrange(full_hash_key, 0, -1, withscores=False)
    return [chunk_hash.decode('utf-8') for chunk_hash in ordered_chunk_hashes]

    return [v.decode('utf-8') for v in r.zrange(chunk_key, 0, -1, withscores=False)]

def get_all_validator_hotkeys_for_chunk_hash(r, full_hash, chunk_hash):
    validator_hotkeys = set()
    for validator_key in r.scan_iter("validator:*"):
        uids = r.hget(validator_key, chunk_hash)
        if uids:
            validator_hotkeys.update(uids.decode('utf-8').split(','))

    return list(validator_hotkeys)

def get_all_miner_hotkeys_for_chunk_hash_only(r, chunk_hash):
    miner_hotkeys = set()
    for validator_key in r.scan_iter("validator:*"):
        uids = r.hget(validator_key, chunk_hash)
        if uids:
            miner_hotkeys.update(uids.decode('utf-8').split(','))

    return list(miner_hotkeys)

def get_all_validator_hotkeys_for_chunk_hash_only(r, chunk_hash):
    validator_hotkeys = set()
    for validator_key in r.scan_iter("validator:*"):
        uids = r.hget(validator_key, chunk_hash)
        if uids:
            validator_hotkeys.add(validator_key.decode('utf-8').split(':')[1])

    return list(validator_hotkeys)

def delete_full_hash(r, full_hash):
    # Delete full hash key
    full_hash_key = f"fullhash:{full_hash}"
    r.delete(full_hash_key)

    # Delete validator data
    for validator_key in r.scan_iter(f"validator:*"):
        r.hdel(validator_key, full_hash)

    # Delete global index data
    for chunk_key in r.scan_iter(f"global:indirect:{full_hash}:*"):
        r.delete(chunk_key)

def get_redis_db_size(r):
    return r.info('memory')['used_memory']

def calculate_total_network_storage(r):
    total_storage = 0
    for full_hash_key in r.scan_iter("fullhash:size:*"):
        size = r.get(full_hash_key)
        if size:
            total_storage += int(size)
    return total_storage


def calculate_total_hotkey_storage(hotkey, database):
    """
    Calculates the total storage used by a hotkey in the database.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        The total storage used by the hotkey in bytes.
    """
    # TODO: update this for redeisgn and miner-specific storage limits
    # Should only be needed by sub-validators
    total_storage = 0
    for data_hash in database.hkeys(hotkey):
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
    # TODO: update this for redesign and miner-only
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

def get_miner_statistics(database: redis.Redis) -> Dict[str, Dict[str, str]]:
    """
    Retrieves statistics for all miners in the database.
    Parameters:
        database (redis.Redis): The Redis client instance.
    Returns:
        A dictionary where keys are hotkeys and values are dictionaries containing the statistics for each hotkey.
    """
    # TODO: update this to new redesign
    return {
        key.decode("utf-8").split(":")[-1]: {
            k.decode("utf-8"): v.decode("utf-8")
            for k, v in database.hgetall(key).items()
        }
        for key in database.scan_iter(b"stats:*")
    }
