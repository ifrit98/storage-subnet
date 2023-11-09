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

# Bittensor Miner Template:

# Step 1: Import necessary libraries and modules
import os
import sys
import copy
import json
import time
import redis
import typing
import base64
import argparse
import traceback
import bittensor as bt
from collections import defaultdict
from Crypto.Random import get_random_bytes

from pprint import pprint, pformat

# import this repo
import storage
from storage.utils import (
    hash_data,
    setup_CRS,
    chunk_data,
    MerkleTree,
    ECCommitment,
    ecc_point_to_hex,
    hex_to_ecc_point,
    b64_encode,
    b64_decode,
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)


def get_config():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--custom", default="my_custom_value", help="Adds a custom value to the parser."
    )
    parser.add_argument(
        "--curve",
        default="P-256",
        help="Curve for elliptic curve cryptography.",
        choices=["P-256"],  # TODO: expand this list
    )
    parser.add_argument(
        "--maxsize",
        default=128,
        type=int,
        help="Maximum size of random data to store.",
    )
    parser.add_argument("--test", default=False, action="store_true")
    parser.add_argument("--netuid", type=int, default=21, help="The chain subnet uid.")
    parser.add_argument(
        "--databse_host", default="localhost", help="The host of the redis database."
    )
    parser.add_argument(
        "--database_port",
        type=int,
        default=6379,
        help="The port of the redis database.",
    )
    parser.add_argument(
        "--database_index",
        type=int,
        default=0,
        help="The index of the redis database.",
    )
    bt.subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.wallet.add_args(parser)
    bt.axon.add_args(parser)
    config = bt.config(parser)
    config.full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            "miner",
        )
    )
    if not os.path.exists(config.full_path):
        os.makedirs(config.full_path, exist_ok=True)
    return config


def commit_data_with_seed(committer, data_chunks, n_chunks, seed):
    merkle_tree = MerkleTree()

    # Commit each chunk of data
    randomness, chunks, points = [None] * n_chunks, [None] * n_chunks, [None] * n_chunks
    bt.logging.debug("n_chunks:", n_chunks)
    for index, chunk in enumerate(data_chunks):
        bt.logging.debug("index:", index)
        c, m_val, r = committer.commit(chunk + str(seed).encode())
        c_hex = ecc_point_to_hex(c)
        randomness[index] = r
        chunks[index] = chunk
        points[index] = c_hex
        merkle_tree.add_leaf(c_hex)

    # Create the tree from the leaves
    merkle_tree.make_tree()
    return randomness, chunks, points, merkle_tree


def main(config):
    bt.logging(config=config, logging_dir=config.full_path)
    bt.logging.info(config)

    bt.logging.info("Setting up bittensor objects.")

    wallet = bt.wallet(config=config)
    bt.logging.info(f"Wallet: {wallet}")

    subtensor = bt.subtensor(config=config)
    bt.logging.info(f"Subtensor: {subtensor}")

    metagraph = subtensor.metagraph(config.netuid)
    bt.logging.info(f"Metagraph: {metagraph}")

    if wallet.hotkey.ss58_address not in metagraph.hotkeys:
        bt.logging.error(
            f"\nYour miner: {wallet} is not registered to chain connection: {subtensor} \nRun btcli register and try again. "
        )
        exit()

    bt.logging.info(
        f"Running miner for subnet: {config.netuid} on network: {subtensor.chain_endpoint} with config:"
    )

    my_subnet_uid = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
    bt.logging.info(f"Running miner on uid: {my_subnet_uid}")

    database = redis.StrictRedis(
        host=config.database_host, port=config.database_port, db=config.database_index
    )

    def blacklist_fn(
        synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> typing.Tuple[bool, str]:
        if synapse.dendrite.hotkey not in metagraph.hotkeys:
            # Ignore requests from unrecognized entities.
            bt.logging.trace(
                f"Blacklisting unrecognized hotkey {synapse.dendrite.hotkey}"
            )
            return True, "Unrecognized hotkey"
        bt.logging.trace(
            f"Not Blacklisting recognized hotkey {synapse.dendrite.hotkey}"
        )
        return False, "Hotkey recognized!"

    def priority_fn(
        synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> float:
        caller_uid = metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        prirority = float(metagraph.S[caller_uid])  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", prirority
        )
        return prirority

    def total_storage(database):
        # Fetch all keys from Redis
        all_keys = database.keys("*")

        # Filter out keys that contain a period
        filtered_keys = [key for key in all_keys if b"." not in key]
        bt.logging.debug("filtered_keys:", filtered_keys)

        # Get the size of each key and sum them up
        total_size = sum([database.memory_usage(key) for key in filtered_keys])
        return total_size

    def compute_subsequent_commitment(data, previous_seed, new_seed, verbose=False):
        """Compute a subsequent commitment based on the original data, previous seed, and new seed."""
        if verbose:
            print("IN COMPUTE SUBESEQUENT COMMITMENT")
            print("type of data     :", type(data))
            print("type of prev_seed:", type(previous_seed))
            print("type of new_seed :", type(new_seed))
        proof = hash_data(data + previous_seed)
        return hash_data(str(proof).encode("utf-8") + new_seed), proof

    # This is the core miner function, which decides the miner's response to a valid, high-priority request.
    def store(synapse: storage.protocol.Store) -> storage.protocol.Store:
        # Decode the data from base64 to raw bytes
        encrypted_byte_data = base64.b64decode(synapse.encrypted_data)

        # Commit to the entire data block
        committer = ECCommitment(
            hex_to_ecc_point(synapse.g, synapse.curve),
            hex_to_ecc_point(synapse.h, synapse.curve),
        )
        bt.logging.debug(f"committer: {committer}")
        bt.logging.debug(f"encrypted_byte_data: {encrypted_byte_data}")
        c, m_val, r = committer.commit(encrypted_byte_data + str(synapse.seed).encode())
        bt.logging.debug(f"c: {c}")
        bt.logging.debug(f"m_val: {m_val}")
        bt.logging.debug(f"r: {r}")

        # Store the data with the hash as the key
        miner_store = {
            "data": synapse.encrypted_data,
            "prev_seed": str(synapse.seed),
            "size": sys.getsizeof(encrypted_byte_data),
        }

        dumped = json.dumps(miner_store).encode()
        bt.logging.debug(f"dumped: {dumped}")
        data_hash = hash_data(encrypted_byte_data)
        bt.logging.debug(f"data_hash: {data_hash}")
        database.set(data_hash, dumped)
        bt.logging.debug(f"set in database!")

        # Send back some proof that we stored the data
        synapse.randomness = r
        synapse.commitment = ecc_point_to_hex(c)

        # NOTE: Does this add anything of value?
        synapse.signature = wallet.hotkey.sign(str(m_val)).hex()
        bt.logging.debug(f"signed m_val: {synapse.signature}")

        # CONCAT METHOD INITIAlIZE CHAIN
        print(f"type(seed): {type(synapse.seed)}")
        synapse.commitment_hash = str(m_val)
        bt.logging.debug(f"initial commitment_hash: {synapse.commitment_hash}")

        bt.logging.debug(f"returning synapse: {synapse}")
        return synapse

    def challenge(
        synapse: storage.protocol.Challenge, verbose=False
    ) -> storage.protocol.Challenge:
        # Retrieve the data itself from miner storage
        bt.logging.debug(f"challenge hash: {synapse.challenge_hash}")
        data = database.get(synapse.challenge_hash)
        if data is None:
            bt.logging.error(f"No data found for {synapse.challenge_hash}")
            bt.logging.error(f"keys found: {database.keys('*')}")
            return synapse

        decoded = json.loads(data.decode("utf-8"))
        bt.logging.debug(f"decoded data: {decoded}")

        # Chunk the data according to the specified (random) chunk size
        encrypted_data_bytes = base64.b64decode(decoded["data"])
        bt.logging.debug(f"encrypted_data_bytes: {encrypted_data_bytes}")

        # Construct the next commitment hash using previous commitment and hash
        # of the data to prove storage over time
        prev_seed = decoded["prev_seed"].encode()
        new_seed = synapse.seed.encode()
        next_commitment, proof = compute_subsequent_commitment(
            encrypted_data_bytes, prev_seed, new_seed
        )
        if verbose:
            print(
                f"types: prev_seed {str(type(prev_seed))}, new_seed {str(type(new_seed))}, proof {str(type(proof))}"
            )
            print(f"prev seed : {prev_seed}")
            print(f"new seed  : {new_seed}")
            print(f"proof     : {proof}")
            print(f"commitment: {next_commitment}\n")
        synapse.commitment_hash = next_commitment
        synapse.commitment_proof = proof

        # TODO: update the commitment seed challenge hash in storage
        # - previous seed (S-1)
        decoded["prev_seed"] = new_seed.decode("utf-8")
        database.set(synapse.challenge_hash, json.dumps(decoded).encode())
        bt.logging.debug(f"udpated miner storage: {decoded}")

        data_chunks = chunk_data(encrypted_data_bytes, synapse.chunk_size)
        bt.logging.debug(f"data_chunks: {data_chunks}")

        # Extract setup params
        g = hex_to_ecc_point(synapse.g, synapse.curve)
        h = hex_to_ecc_point(synapse.h, synapse.curve)

        # Commit the data chunks based on the provided curve points
        committer = ECCommitment(g, h)
        randomness, chunks, commitments, merkle_tree = commit_data_with_seed(
            committer,
            data_chunks,
            sys.getsizeof(encrypted_data_bytes) // synapse.chunk_size + 1,
            synapse.seed,
        )
        bt.logging.debug(f"merkle_tree: {merkle_tree}")

        # Prepare return values to validator
        synapse.commitment = commitments[synapse.challenge_index]
        bt.logging.debug(f"commitment: {synapse.commitment}")
        synapse.data_chunk = base64.b64encode(chunks[synapse.challenge_index])
        bt.logging.debug(f"data_chunk: {synapse.data_chunk}")
        synapse.randomness = randomness[synapse.challenge_index]
        bt.logging.debug(f"randomness: {synapse.randomness}")
        synapse.merkle_proof = b64_encode(
            merkle_tree.get_proof(synapse.challenge_index)
        )
        bt.logging.debug(f"merkle_proof: {synapse.merkle_proof}")
        synapse.merkle_root = merkle_tree.get_merkle_root()
        bt.logging.debug(f"merkle_root: {synapse.merkle_root}")
        return synapse

    def retrieve(synapse: storage.protocol.Retrieve) -> storage.protocol.Retrieve:
        # Fetch the data from the miner database
        data = database.get(synapse.data_hash)
        bt.logging.debug("retireved data:", data)

        # Decode the data + metadata from bytes to json
        decoded = json.loads(data.decode("utf-8"))
        bt.logging.debug("retrieve decoded data:", decoded)

        # incorporate a final seed challenge to verify they still have the data at retrieval time
        commitment, proof = compute_subsequent_commitment(
            base64.b64decode(decoded["data"]),
            decoded["prev_seed"].encode(),
            synapse.seed.encode(),
        )
        synapse.commitment_hash = commitment
        synapse.commitment_proof = proof

        # TODO: restore new seed
        decoded["prev_seed"] = synapse.seed
        database.set(synapse.data_hash, json.dumps(decoded).encode())
        bt.logging.debug(f"udpated retrieve miner storage: {decoded}")

        # Return base64 data (no need to decode here)
        synapse.data = decoded["data"]
        return synapse

    def test(config):
        bt.logging.debug("\n\nstore phase------------------------".upper())
        syn, (encryption_key, nonce, tag) = GetSynapse(
            config.curve, config.maxsize, key=wallet.hotkey.public_key
        )
        bt.logging.debug("\nsynapse:", syn)
        response_store = store(syn)
        # TODO: Verify the initial store
        bt.logging.debug("\nresponse store:")
        bt.logging.debug(response_store.dict())
        verified = verify_store_with_seed(response_store)
        bt.logging.debug(f"\nStore verified: {verified}")

        encrypted_byte_data = base64.b64decode(syn.encrypted_data)
        response_store.axon.hotkey = wallet.hotkey.ss58_address
        lookup_key = f"{hash_data(encrypted_byte_data)}.{response_store.axon.hotkey}"
        bt.logging.debug(f"lookup key: {lookup_key}")
        validator_store = {
            "seed": response_store.seed,
            "size": sys.getsizeof(encrypted_byte_data),
            "commitment_hash": response_store.commitment_hash,
            "encryption_key": encryption_key.hex(),
            "encryption_nonce": nonce.hex(),
            "encryption_tag": tag.hex(),
        }
        dump = json.dumps(validator_store).encode()
        database.set(lookup_key, dump)
        retrv = database.get(lookup_key)
        bt.logging.debug("\nretrv:", retrv)
        bt.logging.debug("\nretrv decoded:", json.loads(retrv.decode("utf-8")))

        bt.logging.debug("\n\nchallenge phase------------------------".upper())
        bt.logging.debug(f"key selected: {lookup_key}")
        data_hash = lookup_key.split(".")[0]
        bt.logging.debug("data_hash:", data_hash)
        data = database.get(lookup_key)
        bt.logging.debug("data:", data)
        bt.logging.debug("data size:", sys.getsizeof(data))
        data = json.loads(data.decode("utf-8"))
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
            curve=config.curve,
            challenge_index=random.choice(range(num_chunks)),
            seed=get_random_bytes(32).hex(),  # data["seed"], # should be a NEW seed
        )
        bt.logging.debug("\nChallenge synapse:", syn)
        response_challenge = challenge(syn)
        bt.logging.debug("\nchallenge response:")
        bt.logging.debug(response_challenge.dict())
        verified = verify_challenge_with_seed(response_challenge)
        bt.logging.debug(f"Is verified: {verified}")

        # Challenge a 2nd time to verify the chain of proofs
        bt.logging.debug("\n\n2nd challenge phase------------------------".upper())
        g, h = setup_CRS()
        syn = storage.protocol.Challenge(
            challenge_hash=data_hash,
            chunk_size=chunk_size,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            curve=config.curve,
            challenge_index=random.choice(range(num_chunks)),
            seed=get_random_bytes(32).hex(),  # data["seed"], # should be a NEW seed
        )
        bt.logging.debug("\nChallenge 2 synapse:", syn)
        response_challenge = challenge(syn)
        bt.logging.debug("\nchallenge 2 response:")
        bt.logging.debug(response_challenge.dict())
        verified = verify_challenge_with_seed(response_challenge)
        bt.logging.debug(f"Is verified 2: {verified}")

        bt.logging.debug("\n\nretrieve phase------------------------".upper())
        ryn = storage.protocol.Retrieve(
            data_hash=data_hash, seed=get_random_bytes(32).hex()
        )
        bt.logging.debug("receive synapse:", ryn)
        rdata = retrieve(ryn)

        verified = verify_retrieve_with_seed(rdata)
        bt.logging.debug(f"Retreive is verified: {verified}")

        bt.logging.debug("retrieved data:", rdata)
        decoded = base64.b64decode(rdata.data)
        bt.logging.debug("decoded base64 data:", decoded)
        unencrypted = decrypt_aes_gcm(decoded, encryption_key, nonce, tag)
        bt.logging.debug("decrypted data:", unencrypted)
        import pdb

        pdb.set_trace()

    if config.test:  # (debugging)
        import random
        from storage.utils import (
            GetSynapse,
            verify_store_with_seed,
            get_random_chunksize,
            decrypt_aes_gcm,
        )

        test(config)

    # TODO: Defensive programming and error-handling around all functions
    # TODO: GUNdb mechanism on validator side for shared database (or first approx/sqlite?)

    # Step 6: Build and link miner functions to the axon.
    # The axon handles request processing, allowing validators to send this process requests.
    axon = bt.axon(wallet=wallet, config=config)
    bt.logging.info(f"Axon {axon}")

    # Attach determiners which functions are called when servicing a request.
    bt.logging.info(f"Attaching forward function to axon.")
    axon.attach(
        forward_fn=store,
        # blacklist_fn=blacklist_fn,
        # priority_fn=priority_fn,
    ).attach(
        forward_fn=challenge,
        # blacklist_fn=blacklist_fn,
        # priority_fn=priority_fn,
    ).attach(
        forward_fn=retrieve,
    )

    # Serve passes the axon information to the network + netuid we are hosting on.
    # This will auto-update if the axon port of external ip have changed.
    bt.logging.info(
        f"Serving axon {store} on network: {subtensor.chain_endpoint} with netuid: {config.netuid}"
    )
    bt.logging.info(
        f"Serving axon {challenge} on network: {subtensor.chain_endpoint} with netuid: {config.netuid}"
    )
    bt.logging.info(
        f"Serving axon {retrieve} on network: {subtensor.chain_endpoint} with netuid: {config.netuid}"
    )
    axon.serve(netuid=config.netuid, subtensor=subtensor)

    # Start  starts the miner's axon, making it active on the network.
    bt.logging.info(f"Starting axon server on port: {config.axon.port}")
    axon.start()

    # Step 7: Keep the miner alive
    # This loop maintains the miner's operations until intentionally stopped.
    bt.logging.info(f"Starting main loop")
    step = 0
    while True:
        try:
            # TODO(developer): Define any additional operations to be performed by the miner.
            # Below: Periodically update our knowledge of the network graph.
            if step % 5 == 0:
                metagraph = subtensor.metagraph(config.netuid)
                log = (
                    f"Step:{step} | "
                    f"Block:{metagraph.block.item()} | "
                    f"Stake:{metagraph.S[my_subnet_uid]} | "
                    f"Rank:{metagraph.R[my_subnet_uid]} | "
                    f"Trust:{metagraph.T[my_subnet_uid]} | "
                    f"Consensus:{metagraph.C[my_subnet_uid] } | "
                    f"Incentive:{metagraph.I[my_subnet_uid]} | "
                    f"Emission:{metagraph.E[my_subnet_uid]}"
                )
                bt.logging.info(log)
            step += 1
            time.sleep(1)

        # If someone intentionally stops the miner, it'll safely terminate operations.
        except KeyboardInterrupt:
            axon.stop()
            bt.logging.success("Miner killed by keyboard interrupt.")
            break
        # In case of unforeseen errors, the miner will log the error and continue operations.
        except Exception as e:
            bt.logging.error(traceback.format_exc())
            continue


# This is the main function, which runs the miner.
if __name__ == "__main__":
    main(get_config())
