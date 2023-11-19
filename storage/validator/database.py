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


# Constants for storage limits in bytes
STORAGE_LIMIT_DIAMOND = 100000 * 10**9  # 100000 GB in bytes
STORAGE_LIMIT_GOLD = 10000 * 10**9  # 10000 GB in bytes
STORAGE_LIMIT_SILVER = 1000 * 10**9  # 1000 GB in bytes
STORAGE_LIMIT_BRONZE = 100 * 10**9  # 100 GB in bytes

DIAMOND_STORE_SUCCESS_RATE = 0.995  # 1/200 chance of failure
DIAMOND_RETRIEVAL_SUCCESS_RATE = 0.9999  # 1/100000 chance of failure
DIAMOND_CHALLENGE_SUCCESS_RATE = 0.999  # 1/1000 chance of failure

GOLD_STORE_SUCCESS_RATE = 0.99  # 1/100 chance of failure
GOLD_RETRIEVAL_SUCCESS_RATE = 0.999  # 1/1000 chance of failure
GOLD_CHALLENGE_SUCCESS_RATE = 0.99  # 1/100 chance of failure

SILVER_STORE_SUCCESS_RATE = 0.98  # 1/50 chance of failure
SILVER_RETRIEVAL_SUCCESS_RATE = 0.999  # 1/1000 chance of failure
SILVER_CHALLENGE_SUCCESS_RATE = 0.999  # 1/1000 chance of failure

DIAMOND_TIER_REWARD_FACTOR = 1.0
GOLD_TIER_REWARD_FACTOR = 0.5
SILVER_TIER_REWARD_FACTOR = 0.25
BRONZE_TIER_REWARD_FACTOR = 0.1

DIAMOND_TIER_TOTAL_SUCCESSES = 10**11
GOLD_TIER_TOTAL_SUCCESSES = 10**9
SILVER_TIER_TOTAL_SUCCESSES = 10**7


# Functioßn to add metadata to a hash in Redis
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
    bt.logging.debug(
        f"Associated data hash {data_hash} and metadata with hotkey {ss58_address}."
    )


def miner_is_registered(ss58_address, database):
    """
    Checks if a miner is registered in the database.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        True if the miner is registered, False otherwise.
    """
    return database.exists(f"stats:{ss58_address}")


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
    bt.logging.debug(
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
    if metadata_json:
        # Deserialize the JSON string to a Python dictionary
        metadata = json.loads(metadata_json)
        return metadata
    else:
        bt.logging.debug(f"No metadata found for {data_hash} in hash {ss58_address}.")
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
        # Fetch all fields (data hashes) for the current hotkey
        data_hashes = database.hkeys(hotkey)
        # Iterate over each data hash and append the hotkey to the corresponding list
        for data_hash in data_hashes:
            data_hash = data_hash.decode("utf-8")
            if data_hash not in data_hash_to_hotkeys:
                data_hash_to_hotkeys[data_hash] = []
            data_hash_to_hotkeys[data_hash].append(hotkey)

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


def register_miner(ss58_address, database):
    # Initialize statistics for a new miner in a separate hash
    database.hmset(
        f"stats:{ss58_address}",
        {
            "store_attempts": 0,
            "store_successes": 0,
            "challenge_successes": 0,
            "challenge_attempts": 0,
            "retrieval_successes": 0,
            "retrieval_attempts": 0,
            "tier": "Bronze",  # Init to bronze status
            "storage_limit": STORAGE_LIMIT_BRONZE,  # in GB
        },
    )


def get_tier_factor(ss58_address, database):
    tier = database.hget(f"stats:{ss58_address}", "tier")
    if tier == b"Diamond":
        return DIAMOND_TIER_REWARD_FACTOR
    elif tier == b"Gold":
        return GOLD_TIER_REWARD_FACTOR
    elif tier == b"Silver":
        return SILVER_TIER_REWARD_FACTOR
    else:
        return BRONZE_TIER_REWARD_FACTOR


def update_statistics(ss58_address, success, task_type, database):
    # Check and see if this miner is registered.
    if not miner_is_registered(ss58_address, database):
        register_miner(ss58_address, database)

    # Update statistics in the stats hash
    stats_key = f"stats:{ss58_address}"
    database.hincrby(stats_key, "store_attempts", 1)

    if task_type == "store":
        database.hincrby(stats_key, "store_attempts", 1)
        if success:
            database.hincrby(stats_key, "store_successes", 1)
    elif task_type == "challenge":
        database.hincrby(stats_key, "challenge_attempts", 1)
        if success:
            database.hincrby(stats_key, "challenge_successes", 1)
    elif task_type == "retrieval":
        database.hincrby(stats_key, "retrieval_attempts", 1)
        if success:
            database.hincrby(stats_key, "retrieval_successes", 1)
    else:
        bt.logging.error(f"Invalid task type {task_type}.")


async def compute_tier(stats_key, database):
    data = database.hgetall(stats_key)

    registered = miner_is_registered(stats_key, database)
    if not data:
        bt.logging.warning(f"No statistics data found for {stats_key}! Skipping...")
        return

    bt.logging.trace(f"Data for {stats_key}: {data}")
    bt.logging.trace(f"Computing tier for {stats_key}.")

    # Get the number of successful challenges
    challenge_successes = int(database.hget(stats_key, "challenge_successes"))
    # Get the number of successful retrievals
    retrieval_successes = int(database.hget(stats_key, "retrieval_successes"))
    # Get the number of successful stores
    store_successes = int(database.hget(stats_key, "store_successes"))
    # Get the number of total challenges
    challenge_attempts = int(database.hget(stats_key, "challenge_attempts"))
    # Get the number of total retrievals
    retrieval_attempts = int(database.hget(stats_key, "retrieval_attempts"))
    # Get the number of total stores
    store_attempts = int(database.hget(stats_key, "store_attempts"))

    # Compute the success rate for each task type
    challenge_success_rate = (
        challenge_successes / challenge_attempts if challenge_attempts > 0 else 0
    )
    retrieval_success_rate = (
        retrieval_successes / retrieval_attempts if retrieval_attempts > 0 else 0
    )
    store_success_rate = store_successes / store_attempts
    total_successes = challenge_successes + retrieval_successes + store_successes

    if (
        challenge_success_rate >= DIAMOND_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= DIAMOND_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= DIAMOND_STORE_SUCCESS_RATE
        and total_successes >= DIAMOND_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Diamond"
    elif (
        challenge_success_rate >= GOLD_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= GOLD_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= GOLD_STORE_SUCCESS_RATE
        and total_successes >= GOLD_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Gold"
    elif (
        challenge_success_rate >= SILVER_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= SILVER_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= SILVER_STORE_SUCCESS_RATE
        and total_successes >= SILVER_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Silver"
    else:
        tier = b"Bronze"

    # (Potentially) set the new tier in the stats hash
    current_tier = database.hget(stats_key, "tier")
    if tier != current_tier:
        database.hset(stats_key, "tier", tier)
        bt.logging.debug(f"Updated tier for {stats_key} from {current_tier} to {tier}.")

        # Update the storage limit
        if tier == b"Diamond":
            storage_limit = STORAGE_LIMIT_DIAMOND
        elif tier == b"Gold":
            storage_limit = STORAGE_LIMIT_GOLD
        elif tier == b"Silver":
            storage_limit = STORAGE_LIMIT_SILVER
        else:
            storage_limit = STORAGE_LIMIT_BRONZE

        current_limit = database.hget(stats_key, "storage_limit")
        database.hset(stats_key, "storage_limit", storage_limit)
        bt.logging.debug(
            f"Storage limit for {stats_key} set from {current_limit} -> {storage_limit} bytes."
        )


async def compute_all_tiers(database):
    # Iterate over all miners
    """
    Computes the tier for all miners in the database.

    This function should be called periodically to update the tier for all miners.
    """
    miners = [miner for miner in database.scan_iter("stats:*")]
    tasks = [compute_tier(miner, database) for miner in miners]
    await asyncio.gather(*tasks)
