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
import json
import redis
import aioredis
import bittensor as bt


async def store_chunk_metadata(r, chunk_hash, filepath, size, seed):
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
        await r.hset(chunk_hash, key, value)


async def store_or_update_chunk_metadata(r, chunk_hash, filepath, size, seed):
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
    if await r.exists(chunk_hash):
        # Update the existing entry with new seed information
        await update_seed_info(r, chunk_hash, seed)
    else:
        # Add new entry
        await store_chunk_metadata(r, chunk_hash, filepath, size, seed)


async def update_seed_info(r, chunk_hash, seed):
    """
    Updates the seed information for a specific chunk in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        seed (str): The new seed value to be updated.

    This function updates the seed information for the specified chunk hash.
    """
    # Update the existing seed information
    await r.hset(chunk_hash, "seed", seed)


async def get_chunk_metadata(r, chunk_hash):
    """
    Retrieves the metadata for a specific chunk from the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.

    Returns:
        dict: A dictionary containing the chunk's metadata, including filepath, size, and seed.
              Size is converted to an integer, and seed is decoded from bytes to a string.
    """
    metadata = await r.hgetall(chunk_hash)
    if metadata:
        metadata[b"size"] = int(metadata[b"size"])
        metadata[b"seed"] = metadata[b"seed"].decode("utf-8")
    return metadata


async def get_all_filepaths(r):
    """
    Retrieves the filepaths for all chunks stored in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.

    Returns:
        dict: A dictionary mapping chunk hashes to their corresponding filepaths.
    """
    filepaths = {}
    async for key in r.scan_iter("*"):
        filepath = await r.hget(key, b"filepath")
        if filepath:
            filepaths[key.decode("utf-8")] = filepath.decode("utf-8")
    return filepaths


async def get_total_storage_used(r):
    """
    Calculates the total storage used by all chunks in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.

    Returns:
        int: The total size of all chunks stored in the database.
    """
    total_size = 0
    async for key in r.scan_iter("*"):
        size = await r.hget(key, b"size")
        if size:
            total_size += int(size)
    return total_size


async def migrate_data_directory(r, new_base_directory, return_failures=False):
    failed_filepaths = []

    async for key in r.scan_iter("*"):
        filepath = await r.hget(key, b"filepath")

        if filepath:
            filepath = filepath.decode("utf-8")
            data_hash = key.decode("utf-8")
            new_filepath = os.path.join(new_base_directory, data_hash)

            if not os.path.exists(new_filepath):
                bt.logging.debug(
                    f"Data does not exist in new path {new_filepath}. Skipping..."
                )
                failed_filepaths.append(new_filepath)
                continue

            await r.hset(key, "filepath", new_filepath)

    return failed_filepaths if return_failures else None
