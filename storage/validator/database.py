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
from typing import Dict, List, Optional, Tuple, Union


def add_metadata_to_hotkey(
    ss58_address: str,
    data_hash: str,
    updater_hotkey: str,
    metadata: dict,
    database: redis.Redis,
):
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

    # Update the metadata with last updater hotkey and version number
    metadata["updated_by"] = updater_hotkey
    new_version = current_version + 1

    # Serialize the metadata as a JSON string
    metadata_json = json.dumps(metadata)

    # Use HSET to associate the new version with the data hash
    database.hset(f"{ss58_address}:{data_hash}", str(new_version), metadata_json)
    bt.logging.debug(
        f"Associated data hash {data_hash} with version {new_version} under hotkey {ss58_address}."
    )


def get_latest_metadata(
    ss58_address: str, data_hash: str, database: redis.Redis
) -> Union[Dict[str, str], None]:
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
    ss58_address: str,
    database: redis.Redis,
    return_only_hashes: bool = False,
    return_all_versions: bool = False,
) -> Union[Dict[str, Dict[str, str]], List[str]]:
    """
    Retrieves all data associated with a specific hotkey, optionally including all versions of each data hash.

    This function is designed to fetch all data hashes stored under a given hotkey in the Redis database. It can return either the latest version of the metadata for each data hash or all versions of the metadata, based on the provided flags. This functionality is essential for auditing and data tracking purposes, particularly in systems where data versioning and history are important.

    Parameters:
        ss58_address (str): The hotkey whose associated data hashes are to be retrieved.
        database (redis.Redis): An instance of the Redis client connected to the database.
        return_only_hashes (bool, optional): If set to True, the function returns only the list of data hashes without their corresponding metadata. Defaults to False.
        return_all_versions (bool, optional): If set to True, the function returns metadata for all versions of each data hash. Otherwise, it returns only the latest metadata. Defaults to False.

    Returns:
        dict: A dictionary where each key is a data hash and its value is the associated metadata. If 'return_only_hashes' is True, a list of data hashes is returned instead. If 'return_all_versions' is True, the value is a nested dictionary containing all versions of the metadata for each data hash.
    """
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
        return list(data.keys())

    return data


def get_metadata_from_hash(
    ss58_address: str, data_hash: str, database: redis.Redis, version: int = None
) -> Union[Dict[str, str], None]:
    """
    Retrieves the metadata associated with a specific version of a data hash for a given hotkey. If the version number is not specified, the function returns the metadata for the latest version.

    This function is crucial for accessing the metadata of a data hash, allowing users to understand the properties and history of the data stored under a specific hotkey. It supports version control by allowing access to different versions of the metadata.

    Parameters:
        ss58_address (str): The key representing the hotkey associated with the data hash.
        data_hash (str): The data hash whose metadata is to be retrieved.
        database (redis.Redis): An instance of the Redis client connected to the database.
        version (int, optional): The specific version number of the data hash's metadata to retrieve. If not provided, the latest version's metadata is returned.

    Returns:
        dict: A dictionary containing the metadata of the specified version of the data hash. Returns `None` if no metadata is found for the specified version or data hash.
    """
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


def calculate_total_hotkey_storage(hotkey: str, database: redis.Redis) -> int:
    """
    Calculates the total storage used by a hotkey in the database.

    Parameters:
        database (redis.Redis): The Redis client instance.
        hotkey (str): The key representing the hotkey.

    Returns:
        The total storage used by the hotkey in bytes.
    """
    hotkey = hotkey.decode() if isinstance(hotkey, bytes) else hotkey
    total_storage = 0
    for key in database.scan_iter(f"{hotkey}:*"):
        versions = database.hgetall(key)
        if not versions:
            continue
        latest_version = max(versions.keys(), key=lambda k: int(k.decode("utf-8")))
        latest_metadata = json.loads(versions[latest_version].decode("utf-8"))
        total_storage += latest_metadata.get("size", 0)
    return total_storage


def get_all_data_hashes(database: redis.Redis) -> List[str]:
    """
    Retrieves all unique data hashes and their corresponding hotkeys from the Redis instance.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        dict: A dictionary where keys are unique data hashes and values are lists of hotkeys associated with each data hash.
    """
    data_hash_to_hotkeys = {}

    # Retrieve all keys in the format 'hotkey:data_hash'
    for key in database.scan_iter("*:*"):
        hotkey, data_hash = key.decode().split(":")
        if hotkey.startswith("stats"):
            continue

        # Remove version information from the data hash if present
        data_hash = data_hash.split("_v")[0]

        if data_hash not in data_hash_to_hotkeys:
            data_hash_to_hotkeys[data_hash] = []
        if hotkey not in data_hash_to_hotkeys[data_hash]:
            data_hash_to_hotkeys[data_hash].append(hotkey)

    return data_hash_to_hotkeys


def get_all_hotkeys_for_data_hash(data_hash: str, database: redis.Redis) -> set:
    """
    Retrieves a list of all hotkeys that are associated with a specific data hash within the database.

    This function scans through the Redis database and checks each hotkey to determine if it contains the specified data hash.
    It's useful for identifying all the hotkeys that are linked to a particular piece of data, which can be important for data management and auditing purposes.

    Parameters:
        data_hash (str): The specific data hash for which associated hotkeys are to be retrieved.
        database (redis.Redis): An instance of the Redis client connected to the database.

    Returns:
        set: A set of strings, where each string is a hotkey that is associated with the specified data hash.
             If no hotkeys are found for the given data hash, an empty set is returned.
    """
    hotkeys = set()

    # Retrieve all keys in the format 'hotkey:data_hash:version'
    for key in database.scan_iter(f"*:{data_hash}"):
        hotkey, _ = key.decode().split(":")
        hotkeys.add(hotkey)

    return hotkeys


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
    total_storage = calculate_total_hotkey_storage(hotkey, database)

    # Check if the hotkey is at capacity
    hotkey = hotkey.decode() if isinstance(hotkey, bytes) else hotkey
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


def get_all_unique_hotkeys(database: redis.Redis) -> set:
    """
    Retrieves all unique hotkeys present in the Redis database.

    This method scans the Redis database for keys and extracts the unique hotkeys from them.
    It assumes that the keys are in the format 'hotkey:rest_of_the_key'.

    Parameters:
        database (redis.Redis): The Redis client instance.

    Returns:
        set: A set of unique hotkeys found in the database.
    """
    unique_hotkeys = set()

    # Scan through all keys in the database
    for key in database.scan_iter("*:*"):
        # Split the key at the colon and take the first part as the hotkey
        hotkey = key.decode().split(":")[0]
        unique_hotkeys.add(hotkey)

    if "stats" in unique_hotkeys:
        unique_hotkeys.remove("stats")

    return unique_hotkeys


def calculate_total_network_storage(
    database: redis.Redis, return_gb: bool = False
) -> int:
    """
    Calculates the total storage used by all hotkeys in the database.

    If return_gb is set to True, the storage is returned in GB, otherwise in bytes.

    Parameters:
        database (redis.Redis): The Redis client instance.
        return_gb (bool): Whether to return the storage in GB or bytes.

    Returns:
        The total storage used by all hotkeys in the database in bytes.
    """
    total_storage = 0
    # Iterate over all hotkeys
    for hotkey in get_all_unique_hotkeys(database):
        # Grab storage for that hotkey
        total_storage += calculate_total_hotkey_storage(hotkey, database)
    return total_storage / 1e9 if return_gb else total_storage


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
        for key in database.scan_iter(f"stats:*")
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
