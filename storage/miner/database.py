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
import time
import bittensor as bt
from typing import Optional, Dict, Any, Union, List
from redis import asyncio as aioredis
from traceback import print_exception


async def store_chunk_metadata(
    r: "aioredis.Strictredis",
    chunk_hash: str,
    filepath: str,
    hotkey: str,
    size: int,
    seed: str,
    ttl: int = None,
):
    """
    Stores the metadata of a chunk in a Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        hotkey (str): Miner hotkey associated with the chunk.
        size (int): The size of the chunk.
        seed (str): The seed associated with the chunk.
        ttl (int, optional): The time-to-live for the chunk. Defaults to 30 days.

    This function stores the filepath, size (as a string), seed, and ttl for the given chunk hash.
    """

    # Ensure that all data are in the correct format
    metadata = {
        "filepath": filepath,
        "size": str(size),  # Convert size to string
        "seed": seed,  # Store seed directly
        "ttl": ttl or 60 * 60 * 24 * 30,  # Default to 30 days if not provided
        "generated": time.time(),
    }
    metadata_str = json.dumps(metadata)

    # Use hmset (or hset which is its modern equivalent) to store the metadata dict
    await r.hset(chunk_hash, hotkey, metadata_str)


async def convert_to_new_format(
    r: "aioredis.Strictredis", chunk_hash: str, hotkey: str = None
):
    """
    Stores the metadata of a chunk in a Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        hotkey (str): Miner hotkey associated with the chunk.

    This function stores the filepath, size (as a string), and seed for the given chunk hash.
    """
    bt.logging.debug(
        f"Converting chunk {chunk_hash} to new format with hotkey {hotkey}"
    )
    old_md = await r.hgetall(chunk_hash)
    try:
        old_hotkey = old_md.pop(b"hotkey")
    except KeyError:
        bt.logging.trace(f"Key not found in metadata {old_md}. New format.")
        return
    new_md = {k.decode("utf-8"): v.decode("utf-8") for k, v in old_md.items()}
    if hotkey is not None:
        if hotkey != old_hotkey:
            # Save both separately for safety/reverse compatibility
            await r.hset(chunk_hash, old_hotkey, json.dumps(new_md))
    else:
        hotkey = old_hotkey
    new_md = json.dumps(new_md)
    await r.delete(chunk_hash)
    await r.hset(chunk_hash, hotkey, new_md)


async def store_or_update_chunk_metadata(
    r: "aioredis.Strictredis",
    chunk_hash: str,
    filepath: str,
    hotkey: str,
    size: int,
    seed: str,
    ttl: Optional[int] = None,
):
    """
    Stores or updates the metadata of a chunk in a Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        hotkey (str): Miner hotkey associated with the chunk.
        size (int): The size of the chunk.
        seed (str): The seed associated with the chunk.
        ttl (int, optional): The time-to-live for the chunk. Defaults to 30 days.

    This function checks if the chunk hash already exists in the database. If it does,
    it updates the existing entry with the new seed information. If not, it stores the new metadata.
    """
    if await r.exists(chunk_hash):
        if not await r.hget(chunk_hash, hotkey):
            # It exists in old format only, convert to new format and delete old key
            await convert_to_new_format(r, chunk_hash)
        # Update the existing entry with new seed information
        await update_seed_info(r, chunk_hash, hotkey, seed)
    else:
        # Add new entry in new format
        await store_chunk_metadata(r, chunk_hash, filepath, hotkey, size, seed, ttl)


async def update_seed_info(
    r: "aioredis.Strictredis", chunk_hash: str, hotkey: str, seed: str
):
    """
    Updates the seed information for a specific chunk in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
        hotkey (str): The caller hotkey value to be updated.
        seed (str): The new seed value to be updated.

    This function updates the seed information for the specified chunk hash.
    """
    try:
        # Check if we are legacy and convert if necessary
        if await is_old_version(r, chunk_hash, hotkey):
            await convert_to_new_format(r, chunk_hash, hotkey)
        # Grab the meta dict
        metadata = await r.hget(chunk_hash, hotkey)
        # Store the metadata if it does not exist for some reason
        if metadata is None:
            metadata = {
                "filepath": "",            # Unknown filepath, will attempt reconstruction on load
                "size": str(0),            # Unknown size
                "seed": seed,              # Store seed directly
                "ttl": 60 * 60 * 24 * 30,  # Default to 30 days
                "generated": time.time(),
            }
        else:
            # Convert to dict
            metadata = json.loads(metadata)
        # Update the seed value
        metadata["seed"] = seed
        # Convert back to string
        metadata = json.dumps(metadata)
        # Store the updated metadata
        await r.hset(chunk_hash, hotkey, metadata)
    except BaseException as e:
        print_exception(e)


async def is_old_version(
    r: "aioredis.Strictredis", chunk_hash: str, hotkey: str = None
) -> bool:
    if hotkey is None:
        try:
            md = await r.hgetall(chunk_hash)
            hotkey = md.pop(b"hotkey")
        except Exception as e:
            # No hotkey found, assume new version
            return False
    # If it's the new version, will have the subkey == to hotkey, else old version
    return await r.hgetall(chunk_hash) and not await r.hget(chunk_hash, hotkey)


async def get_chunk_metadata(
    r: "aioredis.Strictredis", chunk_hash: str, hotkey: str
) -> Optional[Dict[str, Any]]:
    """
    Retrieves the metadata for a specific chunk from the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.

    Returns:
        dict: A dictionary containing the chunk's metadata, including filepath, size, and seed.
              Size is converted to an integer, and seed is decoded from bytes to a string.
    """

    # Legacy support for old format (convert to new format if necessary)
    if await r.hgetall(chunk_hash) and not await r.hget(chunk_hash, hotkey):
        await convert_to_new_format(r, chunk_hash, hotkey)

    metadata = await r.hget(chunk_hash, hotkey)
    if metadata:
        # New key structure as of 1.5.3
        try:
            metadata = json.loads(metadata)
            metadata["size"] = int(metadata.get("size", 0))
            metadata["ttl"] = int(metadata.get("ttl", 60 * 60 * 24 * 30))
            metadata["seed"] = metadata.get("seed", "")
            metadata["generated"] = float(metadata.get("generated", 0))
        except json.JSONDecodeError as e:
            bt.logging.error(f"Error decoding metadata for {chunk_hash}: {e}")
            metadata = None
        except Exception as e:
            bt.logging.error(f"Error getting metadata for {chunk_hash}: {e}")
            metadata = None
    else:
        # attempt to fetch via old key structure for reverse compatibility < 1.5.3
        metadata = await r.hgetall(chunk_hash)
        if metadata:
            try:
                metadata = {k.decode("utf-8"): v.decode("utf-8") for k, v in metadata.items()}
                metadata["size"] = int(metadata.get("size", 0))
            except Exception as e:
                bt.logging.error(f"Error getting metadata for {chunk_hash}: {e}")
                metadata = None
    return metadata


async def safe_remove_old_keys(r, chunk_hash: str):
    """
    Removes outdated schema keys for the specific hash.

    Args:
        r (redis.Redis): The Redis connection instance.
        chunk_hash (str): The unique hash identifying the chunk.
    """
    metadata_dict = await r.hgetall(chunk_hash)
    if b"hotkey" in metadata_dict:
        await r.hdel(chunk_hash, b"hotkey")
    if b"seed" in metadata_dict:
        await r.hdel(chunk_hash, b"seed")
    if b"filepath" in metadata_dict:
        await r.hdel(chunk_hash, b"filepath")
    if b"size" in metadata_dict:
        await r.hdel(chunk_hash, b"size")
    if b"ttl" in metadata_dict:
        await r.hdel(chunk_hash, b"ttl")
    if b"generated" in metadata_dict:
        await r.hdel(chunk_hash, b"generated")


async def safe_remove_all_old_keys(r):
    """
    Removes all outdated schema keys from the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.
    """
    async for key in r.scan_iter("*"):
        try:
            await safe_remove_old_keys(r, key)
        except Exception as e:
            bt.logging.error(f"Could not remove old key {key} with error: {e}")


async def convert_all_to_hotkey_format(r: "aioredis.Strictredis"):
    """
    Converts all chunk metadata in the Redis database to the new format using caller as subkey.

    Args:
        r (redis.Redis): The Redis connection instance.
    """
    async for key in r.scan_iter("*"):
        try:
            if await is_old_version(r, key):
                await convert_to_new_format(r, key)
        except Exception as e:
            bt.logging.error(f"Error converting {key} with error: {e}")


async def get_total_storage_used(r: "aioredis.Strictredis") -> int:
    """
    Calculates the total storage used by all chunks in the Redis database.

    Args:
        r (redis.Redis): The Redis connection instance.

    Returns:
        int: The total size of all chunks stored in the database.
    """
    total_size = 0
    async for key in r.scan_iter("*"):
        try:
            if await is_old_version(r, key):
                size = await r.hget(key, b"size")
            else:
                metadata_dict = await r.hgetall(key)
                first_key = list(metadata_dict)[0]
                metadata = json.loads(metadata_dict[first_key])
                size = metadata.get("size", 0)
        except Exception as e:
            size = 0
        if size:
            total_size += int(size)
    return total_size


async def get_filepath(r: "aioredis.StrictRedis", chunk_hash: str, hotkey: str) -> str:
    """
    Retrieves the filepath for a specific chunk from the Redis database.

    Args:
        chunk_hash (str): The unique hash identifying the chunk.
        hotkey (str): The hotkey associated with the chunk.
        r (redis.Redis): The Redis connection instance.

    Returns:
        str: The filepath of the chunk.
    """

    filepath = ""
    metadata_str = await r.hget(chunk_hash, hotkey)
    if metadata_str is not None:
        metadata = json.loads(metadata_str)
        filepath = metadata.get("filepath")
    return filepath


async def migrate_data_directory(
    r: "aioredis.Strictredis", new_base_directory: str, return_failures: bool = False
) -> Optional[List[str]]:
    try:
        async for key in r.scan_iter("*"):
            if await is_old_version(key):
                filepath = await r.hget(key, b"filepath")
                filepath = filepath.decode("utf-8")
            else:
                hotkey = (await r.hkeys(key))[0]
                metadata = json.loads(await r.hget(key, hotkey))
                filepath = metadata.get("filepath")
            old_base_directory = os.path.dirname(filepath)
            break
    except Exception as e:
        bt.logging.error(f"Error getting old base directory: {e}")
        return

    new_base_directory = os.path.expanduser(new_base_directory)
    bt.logging.info(
        f"Migrating filepaths for all hashes in Redis index from old base {old_base_directory} to new {new_base_directory}"
    )

    if not os.path.exists(new_base_directory):
        bt.logging.info(
            f"New base directory {new_base_directory} does not exist. Creating..."
        )
        os.makedirs(new_base_directory)

    failed_filepaths = []
    async for key in r.scan_iter("*"):
        # In case we still have laggards, convert to the new format
        if await is_old_version(key):
            await convert_to_new_format(r, key)

        async for hotkey in await r.hkeys(key):
            metadata = json.loads(await r.hget(key, hotkey))
            filepath = metadata.get("filepath")

            if filepath:
                data_hash = key.decode("utf-8")
                new_filepath = os.path.join(new_base_directory, data_hash)

                if not os.path.isfile(new_filepath):
                    bt.logging.trace(
                        f"Data does not exist in new path {new_filepath}. Skipping..."
                    )
                    if (
                        new_filepath not in failed_filepaths
                    ):  # don't double add filepaths for different hotkeys
                        failed_filepaths.append(new_filepath)
                    continue

                # update metadata and restore as hash key
                metadata["filepath"] = new_filepath
                await r.hset(key, hotkey, json.dumps(metadata))

    if len(failed_filepaths):
        if not os.path.exists("migration_log"):
            os.makedirs("migration_log")
        with open("migration_log/failed_filepaths.json", "w") as f:
            json.dump(failed_filepaths, f)
        bt.logging.error(
            f"Failed to migrate {len(failed_filepaths)} files. These were skipped and may need to be migrated manually."
        )
        bt.logging.error(
            f"Please see {os.path.abspath('logs/failed_migration_filepaths.json')} for a complete list of failed filepaths."
        )
    else:
        bt.logging.success("Successfully migrated all filepaths.")

    return failed_filepaths if return_failures else None
