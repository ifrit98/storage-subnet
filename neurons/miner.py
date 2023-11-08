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
    verify_challenge_with_seed,
    xor_bytes,
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
    """
    Commits a list of data chunks to a new Merkle tree and generates the associated randomness and ECC points.

    This function takes a 'committer' object which should have a 'commit' method, a list of 'data_chunks', and
    an integer 'n_chunks' specifying the number of chunks to commit. It commits each chunk of data to the Merkle tree,
    collecting the ECC points and randomness values for each commitment, and then constructs the Merkle tree from
    all committed chunks.

    Args:
        committer: An object that has a 'commit' method for committing data chunks.
        data_chunks (list): A list of data chunks to be committed.
        n_chunks (int): The number of data chunks expected to be committed.

    Returns:
        tuple: A tuple containing four elements:
            - randomness (list): A list of randomness values for each committed chunk.
            - chunks (list): The original list of data chunks that were committed.
            - points (list): A list of hex strings representing the ECC points for each commitment.
            - merkle_tree (MerkleTree): A Merkle tree object that contains the commitments as leaves.

    Raises:
        ValueError: If the length of data_chunks is not equal to n_chunks.
    """
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

    # This is the core miner function, which decides the miner's response to a valid, high-priority request.
    def store(synapse: storage.protocol.Store) -> storage.protocol.Store:
        """
        Stores encrypted data chunks along with their commitments and the associated Merkle tree in the database.

        This function decodes the encrypted data provided in the synapse object, chunks it, and creates cryptographic
        commitments for each chunk using elliptic curve cryptography. The commitments and randomness values are stored
        along with a serialized Merkle tree. Finally, it verifies that the storage can be correctly retrieved and decoded,
        preparing the synapse object with necessary return values for the validator.

        Args:
            synapse (storage.protocol.Store): An object containing storage request parameters, including encrypted data,
                                            chunk size, curve information, and data hash for storage indexing.

        Returns:
            storage.protocol.Store: The updated synapse object containing the commitment of the stored data.

        Raises:
            Any exception raised by the underlying storage, encoding, or cryptographic functions will be propagated.
        """
        # Store the data
        miner_store = {
            "data": synapse.encrypted_data,
            "prev_seed": str(synapse.seed),
        }

        # Commit to the entire data block
        committer = ECCommitment(
            hex_to_ecc_point(synapse.g, synapse.curve),
            hex_to_ecc_point(synapse.h, synapse.curve),
        )
        bt.logging.debug(f"committer: {committer}")
        encrypted_byte_data = base64.b64decode(synapse.encrypted_data)
        bt.logging.debug(f"encrypted_byte_data: {encrypted_byte_data}")
        c, m_val, r = committer.commit(encrypted_byte_data + str(synapse.seed).encode())
        bt.logging.debug(f"c: {c}")
        bt.logging.debug(f"m_val: {m_val}")
        bt.logging.debug(f"r: {r}")

        # Store the data with the hash as the key
        miner_store["size"] = sys.getsizeof(encrypted_byte_data)

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

        # or equivalently hash_data(encrypted_byte_data + str(synapse.seed).encode())
        synapse.commitment_hash = str(m_val)
        bt.logging.debug(f"returning synapse: {synapse}")
        return synapse

    def challenge(synapse: storage.protocol.Challenge) -> storage.protocol.Challenge:
        """
        Responds to a challenge by providing a specific data chunk, its randomness, and a Merkle proof from the storage.

        When challenged, this function retrieves the stored commitments, selects the specified data chunk and its
        corresponding randomness value and Merkle proof based on the challenge index. It also re-commits to the data chunk,
        updates the miner storage with the new commitment and Merkle tree, and returns the challenge object with the
        necessary data for verification.

        Args:
            synapse (storage.protocol.Challenge): An object containing challenge parameters, including the challenge index,
                                                curve information, and the challenge hash for retrieving the stored data.

        Returns:
            storage.protocol.Challenge: The updated synapse object containing the requested chunk, its randomness value,
                                        the corresponding Merkle proof, and the updated commitment and Merkle root.

        Raises:
            Any exception raised by the underlying storage, encoding, or cryptographic functions will be propagated.

        Notes:
            The database update operation is a critical section of the code that ensures the miner's storage is up-to-date
            with the latest commitments, in case of concurrent challenge requests.
        """
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

        # TODO: update the commitment seed challenge hash
        # Needs:
        # - previous seed (S-1)
        # - current seed  (S)
        # - previous commitment hash (C-1)

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
        """
        Retrieves and decodes data associated with a given data hash from the miner database.

        The function expects a 'Retrieve' object from the 'storage.protocol' which contains
        a 'data_hash' attribute. It uses this hash to fetch the corresponding data from a
        database (which is a byte string). It then decodes the byte string into a JSON object.

        Note that the 'data' attribute of the 'Retrieve' object is updated with the base64-encoded
        data from the decoded JSON, without decoding it into a binary format. The modified 'Retrieve'
        object is then returned.

        Args:
            synapse (storage.protocol.Retrieve): An object that includes 'data_hash' used to
                retrieve data from the database.

        Returns:
            storage.protocol.Retrieve: The input 'Retrieve' object with the 'data' attribute
                updated to include the retrieved base64-encoded data.

        Raises:
            json.JSONDecodeError: If decoding the byte string to JSON fails.
            KeyError: If the key 'data' is not found in the decoded JSON object.
            Exception: If the retrieval from the database fails or other unspecified errors occur.
        """
        # Fetch the data from the miner database
        data = database.get(synapse.data_hash)
        bt.logging.debug("retireved data:", data)
        # Decode the data + metadata from bytes to json
        decoded = json.loads(data.decode("utf-8"))
        bt.logging.debug("retrieve decoded data:", decoded)
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
        bt.logging.debug("\nStore verified: ", verified)

        encrypted_byte_data = base64.b64decode(syn.encrypted_data)
        response_store.axon.hotkey = wallet.hotkey.ss58_address
        lookup_key = f"{hash_data(encrypted_byte_data)}.{response_store.axon.hotkey}"
        bt.logging.debug("lookup key:", lookup_key)
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
        bt.logging.debug("key selected:", lookup_key)
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
            seed=data["seed"],
        )
        bt.logging.debug("\nChallenge synapse:", syn)
        response_challenge = challenge(syn)
        bt.logging.debug("\nchallenge response:")
        bt.logging.debug(response_challenge.dict())
        verified = verify_challenge_with_seed(response_challenge)
        bt.logging.debug(f"Is verified: {verified}")

        bt.logging.debug("\n\nretrieve phase------------------------".upper())
        ryn = storage.protocol.Retrieve(data_hash=data_hash)
        bt.logging.debug("receive synapse:", ryn)
        rdata = retrieve(ryn)
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
