import json
import redis


def store_chunk_metadata(r, chunk_hash, filepath, size, seed):
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
    if r.exists(chunk_hash):
        # Update the existing entry with new seed information
        update_seed_info(r, chunk_hash, seed)
    else:
        # Add new entry
        store_chunk_metadata(r, chunk_hash, filepath, size, seed)


def update_seed_info(r, chunk_hash, seed):
    # Update the existing seed information
    r.hset(chunk_hash, "seed", seed)


def get_chunk_metadata(r, chunk_hash):
    metadata = r.hgetall(chunk_hash)
    if metadata:
        metadata[b"size"] = int(metadata[b"size"])
        metadata[b"seed"] = metadata[b"seed"].decode("utf-8")
    return metadata


def get_all_filepaths(r):
    filepaths = {}
    for key in r.scan_iter("*"):
        filepath = r.hget(key, b"filepath")
        if filepath:
            filepaths[key.decode("utf-8")] = filepath.decode("utf-8")
    return filepaths


def get_total_storage_used(r):
    total_size = 0
    for key in r.scan_iter("*"):
        size = r.hget(key, b"size")
        if size:
            total_size += int(size)
    return total_size
