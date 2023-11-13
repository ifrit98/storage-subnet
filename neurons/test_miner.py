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

import sys
import json
import redis
import base64
import storage
import bittensor as bt

from Crypto.Random import get_random_bytes, random

from storage.shared.ecc import (
    hash_data,
    setup_CRS,
    ECCommitment,
    ecc_point_to_hex,
    hex_to_ecc_point,
)

from storage.validator.verify import (
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)

from storage.validator.encryption import (
    decrypt_data,
    encrypt_data,
)

from storage.validator.utils import (
    make_random_file,
    get_random_chunksize,
)

from storage.shared.utils import (
    b64_encode,
    b64_decode,
    chunk_data,
)


def GetSynapse(curve, maxsize, wallet):
    # Setup CRS for this round of validation
    g, h = setup_CRS(curve=curve)

    # Make a random bytes file to test the miner
    random_data = b"this is a random bytestring, long enough to be chunked into segments and reconstructed at the end"
    # random_data = make_random_file(maxsize=maxsize)

    # Encrypt the data
    encrypted_data, encryption_payload = encrypt_data(random_data, wallet)

    # Convert to base64 for compactness
    b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

    # Hash the encrypted datad
    data_hash = hash_data(encrypted_data)

    syn = synapse = storage.protocol.Store(
        data_hash=data_hash,
        encrypted_data=b64_encrypted_data,
        curve=curve,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        seed=get_random_bytes(32).hex(),
    )
    return synapse, encryption_payload, random_data


# Function to add metadata to a hash in Redis
def add_data_to_hotkey(hotkey, data_hash, metadata, database):
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
    print(f"Associated data hash {data_hash} with hotkey {hotkey}.")


def get_all_data_for_hotkey(hotkey, database):
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
    print(f"Updated metadata for data hash {data_hash} under hotkey {hotkey}.")


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
        print(f"No metadata found for {data_hash} in hash {hotkey}.")
        return None


def get_all_data_hashes(redis_client):
    """
    Retrieves all data hashes and their corresponding hotkeys from the Redis instance.

    Parameters:
        redis_client (redis.Redis): The Redis client instance.

    Returns:
        A dictionary where keys are data hashes and values are lists of hotkeys associated with each data hash.
    """
    # Initialize an empty dictionary to store the inverse map
    data_hash_to_hotkeys = {}

    # Retrieve all hotkeys (assuming keys are named with a 'hotkey:' prefix)
    for hotkey in redis_client.scan_iter("*"):
        # Remove the 'hotkey:' prefix to get the actual hotkey value
        hotkey = hotkey.decode("utf-8")
        # Fetch all fields (data hashes) for the current hotkey
        data_hashes = redis_client.hkeys(hotkey)
        # Iterate over each data hash and append the hotkey to the corresponding list
        for data_hash in data_hashes:
            data_hash = data_hash.decode("utf-8")
            if data_hash not in data_hash_to_hotkeys:
                data_hash_to_hotkeys[data_hash] = []
            data_hash_to_hotkeys[data_hash].append(hotkey)

    return data_hash_to_hotkeys


def test(miner):
    validator_db = redis.StrictRedis(host="localhost", port=6379, db=1)
    bt.logging.debug("\n\nstore phase------------------------".upper())
    syn, encryption_payload, random_data = GetSynapse("P-256", 128, wallet=miner.wallet)
    bt.logging.debug("\nsynapse:", syn)
    response_store = miner.store(syn)

    # Verify the initial store
    bt.logging.debug("\nresponse store:")
    bt.logging.debug(response_store.dict())
    verified = verify_store_with_seed(response_store)
    bt.logging.debug(f"Store verified: {verified}")

    encrypted_byte_data = base64.b64decode(syn.encrypted_data)
    response_store.axon.hotkey = miner.wallet.hotkey.ss58_address
    validator_store = {
        "prev_seed": response_store.seed,
        "size": sys.getsizeof(encrypted_byte_data),
        "counter": 0,
        "encryption_payload": encryption_payload,
    }

    # Add metadata to Redis (hash, hotkey) pair
    data_hash = hash_data(encrypted_byte_data)
    hotkey = str(response_store.axon.hotkey)
    add_data_to_hotkey(hotkey, data_hash, validator_store, validator_db)

    bt.logging.debug("\n\nchallenge phase------------------------".upper())
    bt.logging.debug(f"key selected: {data_hash} {hotkey}")
    data = get_metadata_from_hash(hotkey, data_hash, validator_db)
    bt.logging.debug("data:", data)
    bt.logging.debug(f"data size: {data['size']}")

    # Get random chunksize given total size
    chunk_size = (
        get_random_chunksize(data["size"]) // 4
    )  # at least 4 chunks # TODO make this a hyperparam

    if chunk_size == 0:
        chunk_size = 10  # safe default
    bt.logging.debug("chunksize:", chunk_size)

    # Calculate number of chunks
    num_chunks = data["size"] // chunk_size
    bt.logging.debug(f"num chunks {num_chunks}")

    # Get setup params
    g, h = setup_CRS()
    syn = storage.protocol.Challenge(
        challenge_hash=data_hash,
        chunk_size=chunk_size,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        curve="P-256",
        challenge_index=random.choice(range(num_chunks)),
        seed=get_random_bytes(32).hex(),
    )
    bt.logging.debug("\nChallenge synapse:", syn)
    response_challenge = miner.challenge(syn)
    bt.logging.debug("\nchallenge response:")
    bt.logging.debug(response_challenge.dict())
    verified = verify_challenge_with_seed(response_challenge)
    bt.logging.debug(f"Is verified: {verified}")
    # Update validator storage
    data["prev_seed"] = response_challenge.seed
    data["counter"] += 1
    bt.logging.debug(
        f"updating validator database for key {data_hash} | {hotkey} with: {data}"
    )
    update_metadata_for_data_hash(hotkey, data_hash, data, validator_db)

    # Challenge a 2nd time to verify the chain of proofs
    bt.logging.debug("\n\n2nd challenge phase------------------------".upper())
    g, h = setup_CRS()
    syn = storage.protocol.Challenge(
        challenge_hash=data_hash,
        chunk_size=chunk_size,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        curve="P-256",
        challenge_index=random.choice(range(num_chunks)),
        seed=get_random_bytes(32).hex(),  # data["seed"], # should be a NEW seed
    )
    bt.logging.debug("\nChallenge 2 synapse:", syn)
    response_challenge = miner.challenge(syn)
    bt.logging.debug("\nchallenge 2 response:")
    bt.logging.debug(response_challenge.dict())
    verified = verify_challenge_with_seed(response_challenge)
    bt.logging.debug(f"Is verified 2: {verified}")
    # Update validator storage
    data["prev_seed"] = response_challenge.seed
    data["counter"] += 1
    bt.logging.debug(
        f"updating validator database for key {data_hash} | {hotkey} with: {data}"
    )
    update_metadata_for_data_hash(hotkey, data_hash, data, validator_db)

    bt.logging.debug("\n\nretrieve phase------------------------".upper())
    ryn = storage.protocol.Retrieve(
        data_hash=data_hash, seed=get_random_bytes(32).hex()
    )
    bt.logging.debug("receive synapse:", ryn)
    rdata = miner.retrieve(ryn)

    verified = verify_retrieve_with_seed(rdata)
    bt.logging.debug(f"Retreive is verified: {verified}")

    bt.logging.debug("retrieved data:", rdata)
    decoded = base64.b64decode(rdata.data)
    bt.logging.debug("decoded base64 data:", decoded)
    encryption_payload = data[
        "encryption_payload"
    ]  # json.loads(data["encryption_payload"])
    bt.logging.debug(f"encryption payload: {encryption_payload}")
    unencrypted = decrypt_data(decoded, encryption_payload, wallet=miner.wallet)
    bt.logging.debug("decrypted data:", unencrypted)

    # Update validator storage
    data["prev_seed"] = ryn.seed
    data["counter"] += 1

    bt.logging.debug(
        f"updating validator database for key {data_hash} | {hotkey} with: {data}"
    )
    update_metadata_for_data_hash(hotkey, data_hash, data, validator_db)

    print(
        "final validator store:",
        get_metadata_from_hash(hotkey, data_hash, validator_db),
    )

    try:
        # Check if the data is the same
        assert random_data == unencrypted, "Data is not the same!"
    except Exception as e:
        print(e)
        return False

    print("Verified successully!")

    hash_map = get_all_data_hashes(validator_db)
    import pdb

    pdb.set_trace()
    return True
