import json
import redis


def store_chunk_metadata(r, chunk_hash, filepath, size, seed):
    """
    Stores the metadata of a chunk in a Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        filepath (str): The file path associated with the chunk.
        size (int): The size of the chunk.
        seed (str): The seed associated with the chunk.

    This function stores the filepath, size (as a string), and seed for the given chunk hash.
    """
    # Ensure that all data are in the correct format
    metadata = {
        "filepath": filepath,
        "size": str(size),  # Convert size to string
        "seed": seed,  # Store seed directly
    }

    # Use hmset (or hset which is its modern equivalent) to store the hash
    for key, value in metadata.items():
        r.hset(chunk_hash, key, value)


def store_or_update_chunk_metadata(r, chunk_hash, filepath, size, seed):
    """
    Stores or updates the metadata of a chunk in a Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        filepath (str): The file path associated with the chunk.
        size (int): The size of the chunk.
        seed (str): The seed associated with the chunk.

    This function checks if the chunk hash already exists in the database. If it does,
    it updates the existing entry with the new seed information. If not, it stores the new metadata.
    """
    if r.exists(chunk_hash):
        # Update the existing entry with new seed information
        update_seed_info(r, chunk_hash, seed)
    else:
        # Add new entry
        store_chunk_metadata(r, chunk_hash, filepath, size, seed)


def update_seed_info(r, chunk_hash, seed):
    """
    Updates the seed information for a specific chunk in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        seed (str): The new seed value to be updated.

    This function updates the seed information for the specified chunk hash.
    """
    # Update the existing seed information
    r.hset(chunk_hash, "seed", seed)


def get_chunk_metadata(r, chunk_hash):
    """
    Retrieves the metadata for a specific chunk from the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.

    Returns:
        dict: A dictionary containing the chunk's metadata, including filepath, size, and seed.
              Size is converted to an integer, and seed is decoded from bytes to a string.
    """
    metadata = r.hgetall(chunk_hash)
    if metadata:
        metadata[b"size"] = int(metadata[b"size"])
        metadata[b"seed"] = metadata[b"seed"].decode("utf-8")
    return metadata


def get_all_filepaths(r):
    """
    Retrieves the filepaths for all chunks stored in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.

    Returns:
        dict: A dictionary mapping chunk hashes to their corresponding filepaths.
    """
    filepaths = {}
    for key in r.scan_iter("*"):
        filepath = r.hget(key, b"filepath")
        if filepath:
            filepaths[key.decode("utf-8")] = filepath.decode("utf-8")
    return filepaths


def get_total_storage_used(r):
    """
    Calculates the total storage used by all chunks in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.

    Returns:
        int: The total size of all chunks stored in the database.
    """
    total_size = 0
    for key in r.scan_iter("*"):
        size = r.hget(key, b"size")
        if size:
            total_size += int(size)
    return total_size
