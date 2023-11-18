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
import bittensor as bt


# Function to add metadata to a hash in Redis
def add_metadata_to_hotkey(hotkey, data_hash, metadata, database):
    """
    Associates a data hash and its metadata with a hotkey in Redis.

    Parameters:
        hotkey (str): The primary key representing the hotkey.
        data_hash (str): The subkey representing the data hash.
        metadata (dict): The metadata to associate with the data hash.
        database (redis.Redis): The Redis client instance.
    """
    # Serialize the metadata as a JSON string
    metadata_json = json.dumps(metadata)
    # Use HSET to associate the data hash with the hotkey
    database.hset(hotkey, data_hash, metadata_json)
    bt.logging.debug(
        f"Associated data hash {data_hash} and metadata with hotkey {hotkey}."
    )


def get_all_data_for_hotkey(hotkey, database, return_hashes=False):
    """
    Retrieves all data hashes and their metadata for a given hotkey.

    Parameters:
        hotkey (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are the associated metadata.
    """
    # Fetch all fields (data hashes) and values (metadata) for the hotkey
    all_data_hashes = database.hgetall(hotkey)

    # Return only the hashes themselves if specified
    if return_hashes:
        return all_data_hashes

    # Deserialize the metadata for each data hash
    return {
        data_hash.decode("utf-8"): json.loads(metadata.decode("utf-8"))
        for data_hash, metadata in all_data_hashes.items()
    }


def update_metadata_for_data_hash(hotkey, data_hash, new_metadata, database):
    """
    Updates the metadata for a specific data hash associated with a hotkey.

    Parameters:
        hotkey (str): The key representing the hotkey.
        data_hash (str): The subkey representing the data hash to update.
        new_metadata (dict): The new metadata to associate with the data hash.
        database (redis.Redis): The Redis client instance.
    """
    # Serialize the new metadata as a JSON string
    new_metadata_json = json.dumps(new_metadata)
    # Update the field in the hash with the new metadata
    database.hset(hotkey, data_hash, new_metadata_json)
    bt.logging.debug(
        f"Updated metadata for data hash {data_hash} under hotkey {hotkey}."
    )


def get_metadata_from_hash(hotkey, data_hash, database):
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
    metadata_json = database.hget(hotkey, data_hash)
    if metadata_json:
        # Deserialize the JSON string to a Python dictionary
        metadata = json.loads(metadata_json)
        return metadata
    else:
        bt.logging.debug(f"No metadata found for {data_hash} in hash {hotkey}.")
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


def update_ranking_data(hotkey, rankings, database):
    """
    Updates the ranking data for a specific hotkey.

    Parameters:
        hotkey (str): The key representing the hotkey.
        rankings (dict): The new ranking data to associate with the hotkey.
        database (redis.Redis): The Redis client instance.
    """
    # Serialize the new ranking data as a JSON string
    rankings_json = json.dumps(rankings)
    # Update the field in the hash with the new ranking data
    database.hset(hotkey, "rankings", rankings_json)
    bt.logging.debug(f"Updated ranking data for hotkey {hotkey}.")


def retrieve_ranking_data(hotkey, database):
    """
    Retrieves ranking data from a hash in Redis for the given hotkey.

    Parameters:
        hotkey (str): The key representing the hotkey.
        databse (redis.Redis): The Redis client instance.

    Returns:
        The deserialized ranking data as a dictionary, or None if not found.
    """
    # Get the JSON string from Redis
    rankings_json = database.hget(hotkey, "rankings")
    if rankings_json:
        # Deserialize the JSON string to a Python dictionary
        rankings = json.loads(rankings_json)
        return rankings
    else:
        bt.logging.debug(f"No ranking data found for {hotkey}.")
        return None
