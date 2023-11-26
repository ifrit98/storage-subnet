import json
import redis


def store_chunk_metadata(r, chunk_hash, filepath, size, validator_seeds):
    # Ensure that all data are in the correct format
    metadata = {
        "filepath": filepath,
        "size": str(size),  # Convert size to string
        "seeds": json.dumps(validator_seeds)  # Convert seeds dict to JSON string
    }

    # Use hmset (or hset which is its modern equivalent) to store the hash
    for key, value in metadata.items():
        r.hset(chunk_hash, key, value)

def store_or_update_chunk_metadata(r, chunk_hash, filepath, size, validator_hotkey, seed):
    if r.exists(chunk_hash):
        # Update the existing entry with new validator seed information
        update_seed_info(r, chunk_hash, validator_hotkey, seed)
    else:
        # Add new entry
        validator_seeds = {validator_hotkey: {"prev_seed": seed}}
        store_chunk_metadata(r, chunk_hash, filepath, size, validator_seeds)

def update_seed_info(r, chunk_hash, validator_hotkey, seed):
    # Retrieve and update the existing seeds information
    seeds_json = r.hget(chunk_hash, "seeds").decode('utf-8')
    seeds = json.loads(seeds_json) if seeds_json else {}
    seeds[validator_hotkey] = {"prev_seed": seed}
    r.hset(chunk_hash, "seeds", json.dumps(seeds))

def get_chunk_metadata(r, chunk_hash):
    metadata = r.hgetall(chunk_hash)
    if metadata:
        metadata[b'size'] = int(metadata[b'size'])
        metadata[b'seeds'] = json.loads(metadata[b'seeds'].decode('utf-8'))
    return metadata

def get_chunks_for_validator(r, validator_hotkey):
    chunk_hashes = []
    for key in r.scan_iter("*"):
        seeds_json = r.hget(key, b"seeds")
        if seeds_json:
            seeds = json.loads(seeds_json.decode('utf-8'))
            if validator_hotkey in seeds:
                chunk_hashes.append(key.decode('utf-8'))
    return chunk_hashes

def get_all_filepaths(r):
    filepaths = {}
    for key in r.scan_iter("*"):
        filepath = r.hget(key, b"filepath")
        if filepath:
            filepaths[key.decode('utf-8')] = filepath.decode('utf-8')
    return filepaths

def get_total_storage_used(r):
    total_size = 0
    for key in r.scan_iter("*"):
        size = r.hget(key, b"size")
        if size:
            total_size += int(size)
    return total_size
