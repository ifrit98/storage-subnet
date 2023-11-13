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


def test(miner):
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
    lookup_key = f"{hash_data(encrypted_byte_data)}.{response_store.axon.hotkey}"
    bt.logging.debug(f"lookup key: {lookup_key}")
    validator_store = {
        "prev_seed": response_store.seed,
        "size": sys.getsizeof(encrypted_byte_data),
        "counter": 0,
        "encryption_payload": encryption_payload,
    }
    dump = json.dumps(validator_store).encode()
    miner.database.set(lookup_key, dump)
    retrv = miner.database.get(lookup_key)
    bt.logging.debug("\nretrv:", retrv)
    bt.logging.debug("\nretrv decoded:", json.loads(retrv.decode("utf-8")))

    bt.logging.debug("\n\nchallenge phase------------------------".upper())
    bt.logging.debug(f"key selected: {lookup_key}")
    data_hash = lookup_key.split(".")[0]
    bt.logging.debug("data_hash:", data_hash)
    data = miner.database.get(lookup_key)
    bt.logging.debug("data:", data)
    data = json.loads(data.decode("utf-8"))
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
    dump = json.dumps(data).encode()
    miner.database.set(lookup_key, dump)

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
    dump = json.dumps(data).encode()
    miner.database.set(lookup_key, dump)

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
    dump = json.dumps(data).encode()
    miner.database.set(lookup_key, dump)

    print("final validator store:", miner.database.get(lookup_key))

    try:
        # Check if the data is the same
        assert random_data == unencrypted, "Data is not the same!"
    except Exception as e:
        print(e)
        return False

    print("Verified successully!")

    return True
