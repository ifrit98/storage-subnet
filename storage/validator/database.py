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
import asyncio
import bittensor as bt

import redis

database = db = redis.StrictRedis("localhost", 6379, 1)
hotkey = ss58_address = "5H1CaMTf6XvzSYLcLe4AhnXwttQ4z3ry6fy9XzS9wrxV5vFA"
updater_hotkey = "5DU7XMB42qnZF2GxXdkW6Cr8dho734ue1PrfKDBUcUAqEKBY"
data_hash = (
    "30207882824849456500512637190778999913565856759543620533747899842526447165760"
)
data_hash2 = "123456789"

metadata = {
    "prev_seed": "c678132a237505ee773aaee733fdfc3ed99f59310ad6a86e7ee4feab92e823e3",
    "size": 161851493,
    "version": 0,
    "encryption_payload": {
        "nonce": "82bd50b0ff44c408b78b0c67c407b48c470d8f24626f9c22",
        "ciphertext": "cf3092fcc88cf838154d23d39f2e946cc91ce49613411b85f64a520b766ce00fb2fa69e1fcd0faa2ffacc9afc321a5fcdc4bedce69e007edf7fb04c997e8f08c038931daceba92a2572d3b9363ca99c5ae03f219f99e39bb134ffeea622d91784e57d5782d876df72b030ecdc9f7c88dbda0a67c5b05dfe8ff00c82db9907ba4f7d0ab2033fb644a6bcef1e47db59448e2c2e2d3c9996f604fcf6ee3978a11edf39fa9a57114daf0601aee4af0124622235c8fdadd4b0b",
    },
    "updated_by": "5C86aJ2uQawR6P6veaJQXNK9HaWh6NMbUhTiLs65kq4ZW3NH",
}


def add_metadata_to_hotkey(ss58_address, data_hash, metadata, database):
    """
    Associates a data hash and its metadata with a hotkey in Redis, with versioning.

    Parameters:
        ss58_address (str): The primary key representing the hotkey.
        data_hash (str): The subkey representing the data hash.
        metadata (dict): The metadata to associate with the data hash.
        database (redis.Redis): The Redis client instance.
    """
    # Get the current latest version number
    current_version = database.hlen(f"{ss58_address}:{data_hash}")
    new_version = current_version + 1

    # Serialize the metadata as a JSON string
    metadata_json = json.dumps(metadata)

    # Use HSET to associate the new version with the data hash
    database.hset(f"{ss58_address}:{data_hash}", str(new_version), metadata_json)
    bt.logging.debug(
        f"Associated data hash {data_hash} with version {new_version} under hotkey {ss58_address}."
    )


def get_latest_metadata(ss58_address, data_hash, database):
    """
    Retrieves the latest version of metadata for a given data hash.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        data_hash (str): The data hash to look up.
        database (redis.Redis): The Redis client instance.

    Returns:
        The deserialized metadata as a dictionary for the latest version, or None if not found.
    """
    versioned_hash = f"{ss58_address}:{data_hash}"
    latest_version = database.hgetall(versioned_hash)
    if latest_version:
        # Get the highest version key
        highest_version_key = max(latest_version, key=int)
        metadata_json = latest_version[highest_version_key]
        return json.loads(metadata_json.decode("utf-8"))
    else:
        return None


def get_all_data_for_hotkey(
    ss58_address, database, return_only_hashes=False, return_all_versions=False
):
    data = {}
    if return_all_versions:
        for key in database.scan_iter(f"{ss58_address}:*"):
            # Extract data_hash from the key
            _, data_hash = key.decode().split(":", 1)
            versions = database.hgetall(key)
            if not versions:
                continue
            all_versions_data = {
                v.decode("utf-8"): json.loads(metadata.decode("utf-8"))
                for v, metadata in versions.items()
            }
            data[data_hash] = all_versions_data
    else:
        for key in database.scan_iter(f"{ss58_address}:*"):
            # Extract data_hash from the key
            _, data_hash = key.decode().split(":", 1)
            latest_version = get_latest_metadata(ss58_address, data_hash, database)
            if not latest_version:
                continue
            data[data_hash] = latest_version

    if return_only_hashes:
        return list(_data.keys())

    return data


def get_metadata_from_hash(ss58_address, data_hash, database, version=None):
    versioned_hash = f"{ss58_address}:{data_hash}"
    if version is None:
        # If version not specified, get the latest
        versions = database.hgetall(versioned_hash)
        if not versions:
            return None
        latest_version = max(versions.keys(), key=lambda k: int(k.decode("utf-8")))
        metadata = versions[latest_version]
    else:
        # Get specified version
        metadata = database.hget(versioned_hash, str(version))

    return json.loads(metadata.decode("utf-8")) if metadata else None


def calculate_total_hotkey_storage(hotkey, database):
    total_storage = 0
    for key in database.scan_iter(f"{hotkey}:*"):
        versions = database.hgetall(key)
        if not versions:
            continue
        latest_version = max(versions.keys(), key=lambda k: int(k.decode("utf-8")))
        latest_metadata = json.loads(versions[latest_version].decode("utf-8"))
        total_storage += latest_metadata.get("size", 0)
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
    try:
        limit = int(byte_limit)
    except Exception as e:
        bt.logging.error(f"Could not parse storage limit for {hotkey} | {e}.")
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
        if hotkey.startswith("stats:"):
            continue
        # Grab storage for that hotkey
        total_storage += calculate_total_hotkey_storage(database, hotkey)
    return total_storage
