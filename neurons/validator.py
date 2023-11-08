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

# Bittensor Validator Template:

# Step 1: Import necessary libraries and modules
import os
import sys
import time
import redis
import torch
import base64
import argparse
import traceback
import bittensor as bt
from random import random_choice
from Crypto.Random import get_random_bytes

# import this repo
from storage import protocol
from storage.utils import (
    hash_data,
    setup_CRS,
    chunk_data,
    MerkleTree,
    encrypt_data,
    decrypt_aes_gcm,
    ECCommitment,
    make_random_file,
    get_random_chunksize,
    ecc_point_to_hex,
    hex_to_ecc_point,
    serialize_dict_with_bytes,
    deserialize_dict_with_bytes,
    verify_challenge_with_seed,
    verify_store_with_seed,
)


# TODO:
def Challenge(database):
    keys = database.keys("*")
    store_keys = [
        "abc.123",
        "def.123",
        "def.456",
        "hig.456",
        "lmn.456",
    ]

    key_by_miner = {}
    for key in keys:
        data_hash, hotkey = key.split(".")
        if hotkey not in key_by_miner:
            key_by_miner[hotkey] = []
        key_by_miner[hotkey].append(data_hash)

    # subtensor = bt.subtensor(network="test")
    # metagraph = subtensor.metagraph(8)
    # hotkeys = metagraph.hotkeys
    hotkeys = [
        None,
    ]  # "123", "456"]
    for hotkey in hotkeys:
        # Randomly select a storage_key from the database for this miner
        keys = key_by_miner[hotkey]
        hash = "103804754514487657733834309377505898919271919633571683238396104733193613812627"  # random_choice(keys)
        data = database.get(f"{hash}.{hotkey}")

        # Decode the storage data and create a challenge
        data = decode_storage(data)
        params = data["params"]
        merkle_root = data["merkle_root"]
        commitments = data["commitments"]

        # Choose a random commitment to challenge
        index = random_choice(range(len(commitments)))
        commitment = commitments[index]

        # Create the challenge
        synapse = protocol.Challenge(
            challenge_hash="91698717955530315133405947771692390048583575882025109729287710097208243039173",
            challenge_index=index,
        )
        # We want to get back from the miner:
        # - the data chunk itself (to prove they still have it)
        # - the random value to open the commitment
        # - the merkle proof for the data chunk

    # For each UID:
    # - fetch which data they have (list of hashes)
    # - randomly select a hash
    # - fetch the commitments for that hash
    # - randomly select a commitment/data_chunk
    # - send the challenge to the miner

    syn = protocol.Challenge(
        challenge_hash=key_.split(".")[0],
        commitment=commitment,
        merkle_root=merkle_root,
        params=params,
        index=index,
    )
    # We want to get back from the miner:
    # - the data chunk itself (to prove they still have it)
    # - the random value to open the commitment
    # - the merkle proof for the data chunk

    # TODO: maybe we additionally want a random challenge here on the original data?
    # Perhaps verify they signed the data chunk with their wallet? (e.g. dendrite signature and axon verify?)
    # Or a (data_chunk + <random_value|miner_key>) signature?
    # This way we have 3 layers of security:
    # - (1) the commitment + random value + original data to prove they have the data now
    # - (2) the merkle proof to prove they stored it originally
    # - (3) the data chunk signature to verify they also have the data (redundant with 1?)


# TODO: select a subset of miners to store given the redundancy factor N
def select_subset_uids(uids: list, N: int):
    return random.choices(uids, k=N)


def store_file_data(directory, metagraph):
    # TODO: write this to replace store_random_data
    # it will not be random but use real data from the validator filesystem
    # possibly textbooks, pdfs, audio files, pictures, etc. to mimick user data
    pass


def store_random_data(curve, maxsize, metagraph, redundacy=3, key=None):
    # Setup CRS for this round of validation
    g, h = setup_CRS(curve=curve)

    # Make a random bytes file to test the miner
    random_data = make_random_file(maxsize=maxsize)

    # Random encryption key for now (never will decrypt)
    encryption_key = key or get_random_bytes(32)

    # Encrypt the data
    encrypted_data, nonce, tag = encrypt_data(
        random_data,
        encryption_key,
    )

    # Convert to base64 for compactness
    b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

    synapse = protocol.Store(
        encrypted_data=b64_encrypted_data,
        curve=curve,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        seed=get_random_bytes(32).hex(),  # 256-bit seed
    )

    # Select subset of miners to query (e.g. redunancy factor of N)
    uids = select_subset_uids(metagraph.uids, N=redundancy)
    axons = [metagraph.axons[uid] for uid in uids]
    retry_uids = [None]

    while len(retry_uids):
        if retry_uids == [None]:
            # initial loop
            retry_uids = []

        # Broadcast the query to selected miners on the network.
        responses = dendrite.query(
            axons,
            synapse,
            deserialize=False,
        )

        # Log the results for monitoring purposes.
        bt.logging.info(f"Received responses: {responses}")

        # TEMP weights vector
        weights = [1.0] * len(metagraph.uids)
        for uid, response in enumerate(zip(uids, responses)):
            # Verify the commitment
            if not verify_challenge_with_seed(response):
                # TODO: flag this miner for 0 weight (or negative rewards?)
                weights[uid] = 0.0
                retry_uids.append(uid)
                continue
            # Store the hash->hotkey->size mapping in DB
            # TODO: update this to store by hotkey rather than pair so we can efficiently
            # lookup which miners have what data and query them
            # NOTE: this will become a problem when the size of the database grows too large
            key = f"{hash_data(encrypted_data)}.{response.axon.hotkey}"
            response_storage = {
                "size": sys.getsizeof(encrypted_data),
                "prev_seed": synapse.seed,
                "commitment_hash": response.commitment_hash,  # contains the seed
                # TODO: these will be private to the validator, not stored in decentralized GUN db
                "encryption_key": encryption_key.hex(),
                "encryption_nonce": nonce.hex(),
                "encryption_tag": tag.hex(),
            }
            bt.logging.debug(f"Storing data {response_storage}")
            # Store in the database according to the data hash and the miner hotkey
            database.set(key, json.dumps(response_storage).encode())
            bt.logging.debug(f"Stored data in database with key: {key}")

        # Get a new set of UIDs to query for those left behind
        if retry_uids != []:
            uids = select_subset_uids(retry_uids, N=len(retry_uids))
            axons = [metagraph.axons[uid] for uid in uids]


def challenge(metagraph):  #
    # TODO: come up with an algorithm for properly challenging miners and
    # ensure an even spread statistically of which miners are queried, and
    # which indices are queried (gaussian randomness?)

    # For each UID:
    # - fetch which data they have (list of hashes)
    # - randomly select a hash
    # - randomly select a commitment/data_chunk index
    # - send the challenge to the miner
    hotkeys = metagraph.hotkeys
    for hotkey in [None]:
        # Fetch the list of data hashes this miner has
        keys = database.keys(f"*.{hotkey}")
        print(f"all keys for hotkey {hotkey}\n{keys}")

        # Select a specific data hash to query
        # key = random.choice(keys).decode("utf-8")
        key = "36572423112117696224165833631177730849457409908727827954083586177537634882175.None"
        print("key selected:", key)
        data_hash = key.split(".")[0]
        print("data_hash:", data_hash)

        # Fetch the associated validator storage information (size, prev_seed, commitment_hash)
        data = database.get(key)
        print("data:", data)
        data = json.loads(data.decode("utf-8"))

        # Get random chunksize given total size
        chunk_size = (
            get_random_chunksize(data["size"]) // 4
        )  # at least 4 chunks # TODO make this a hyperparam
        print("chunksize:", chunksize)

        # Calculate number of chunks
        num_chunks = data["size"] // chunk_size

        # Get setup params
        g, h = setup_CRS()

        # Pre-fill the challenge synapse with required data
        synapse = protocol.Challenge(
            challenge_hash=data_hash,
            chunk_size=chunk_size,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            seed=get_random_bytes(32).hex(),  # 256-bit random seed
        )

        # Grab the UID to query
        uid = metagraph.hotkeys.index(hotkey)

        # Send the challenge to the miner
        response = dendrite.query(
            [metagraph.axons[uid]],
            synapse,
            deserialize=True,
        )

        # Verify the response
        verified = verify_challenge_with_seed(response)
        print(f"Is verified: {verified}")


def retrieve(dendrite, metagraph, data_hash):
    # fetch which miners have the data
    keys = database.keys(f"{data_hash}.*")
    axons_to_query = []
    for key in keys:
        hotkey = key.split(".")[1]
        uid = metagraph.hotkeys.index(hotkey)
        axons_to_query.append(metagraph.axons[uid])
        print("appending hotkey:", hotkey)

        # TODO: potentially issue a challenge to the miners to fetch the data
        # may be as simple as a query the commitment hash chain
        # C1 = hash(C0 || hash(data || current_seed)) ?
        # Check out scratch/XOR_scheme.py

    # query all N (from redundancy factor) with M challenges (x% of the total data)
    # TODO: see who returns the data fastest, and rank them highest
    responses = await dendrite(
        axons_to_query,
        protocol.Retrieve(
            data_hash=data_hash,
        ),
        deserialize=True,
    )

    for response in responses:
        print("response:", response)
        if hash_data(base64.b64decode(respnonse.data)) != data_hash:
            print("data hash does not match!")
            continue

        # Decrypt the data using the validator stored encryption keys
        response.data = decrypt_aes_gcm(
            base64.b64decode(response.data),
            bytes.fromhex(data["encryption_key"]),
            bytes.fromhex(data["encryption_nonce"]),
            bytes.fromhex(data["encryption_tag"]),
        )


# Step 2: Set up the configuration parser
# This function is responsible for setting up and parsing command-line arguments.
def get_config():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--alpha", default=0.9, type=float, help="The weight moving average scoring."
    )
    # TODO(developer): Adds your custom validator arguments to the parser.
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
    parser.add_argument(
        "--redundancy",
        type=int,
        default=3,
        help="Number of miners to store each piece of data on.",
    )
    parser.add_argument(
        "--databse_host", default="localhost", help="The host of the redis database."
    )
    parser.add_argument(
        "--databse_port", default=6379, help="The port of the redis database."
    )
    parser.add_argument(
        "--databse_index", default=0, help="The database number of the redis database."
    )
    # Adds override arguments for network and netuid.
    parser.add_argument("--netuid", type=int, default=1, help="The chain subnet uid.")
    # Adds subtensor specific arguments i.e. --subtensor.chain_endpoint ... --subtensor.network ...
    bt.subtensor.add_args(parser)
    # Adds logging specific arguments i.e. --logging.debug ..., --logging.trace .. or --logging.logging_dir ...
    bt.logging.add_args(parser)
    # Adds wallet specific arguments i.e. --wallet.name ..., --wallet.hotkey ./. or --wallet.path ...
    bt.wallet.add_args(parser)
    # Parse the config (will take command-line arguments if provided)
    # To print help message, run python3 template/validator.py --help
    config = bt.config(parser)

    # Step 3: Set up logging directory
    # Logging is crucial for monitoring and debugging purposes.
    config.full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            "validator",
        )
    )
    # Ensure the logging directory exists.
    if not os.path.exists(config.full_path):
        os.makedirs(config.full_path, exist_ok=True)

    # Return the parsed config.
    return config


def main(config):
    # Set up logging with the provided configuration and directory.
    bt.logging(config=config, logging_dir=config.full_path)
    bt.logging.info(
        f"Running validator for subnet: {config.netuid} on network: {config.subtensor.chain_endpoint} with config:"
    )
    # Log the configuration for reference.
    bt.logging.info(config)

    # Step 4: Build Bittensor validator objects
    # These are core Bittensor classes to interact with the network.
    bt.logging.info("Setting up bittensor objects.")

    # The wallet holds the cryptographic key pairs for the validator.
    wallet = bt.wallet(config=config)
    bt.logging.info(f"Wallet: {wallet}")

    # The subtensor is our connection to the Bittensor blockchain.
    subtensor = bt.subtensor(config=config)
    bt.logging.info(f"Subtensor: {subtensor}")

    # Dendrite is the RPC client; it lets us send messages to other nodes (axons) in the network.
    dendrite = bt.dendrite(wallet=wallet)
    bt.logging.info(f"Dendrite: {dendrite}")

    # The metagraph holds the state of the network, letting us know about other validators and miners.
    metagraph = subtensor.metagraph(config.netuid)
    bt.logging.info(f"Metagraph: {metagraph}")

    # Step 5: Connect the validator to the network
    if wallet.hotkey.ss58_address not in metagraph.hotkeys:
        bt.logging.error(
            f"\nYour validator: {wallet} if not registered to chain connection: {subtensor} \nRun btcli register and try again."
        )
        exit()

    # Setup database
    database = redis.StrictRedis(
        host=config.database_host, port=config.database_port, db=config.database_index
    )

    # Each validator gets a unique identity (UID) in the network for differentiation.
    my_subnet_uid = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
    bt.logging.info(f"Running validator on uid: {my_subnet_uid}")

    # Step 6: Set up initial scoring weights for validation
    bt.logging.info("Building validation weights.")
    scores = torch.ones_like(metagraph.S, dtype=torch.float32)
    bt.logging.info(f"Weights: {scores}")
    # Step 7: The Main Validation Loop
    bt.logging.info("Starting validator loop.")
    step = 0
    while True:
        try:
            # Setup CRS for this round of validation
            g, h = setup_CRS(curve=config.curve)

            # Make a random bytes file to test the miner
            random_data = make_random_file(maxsize=config.maxsize)

            # Encrypt the data
            encrypted_data, nonce, tag = encrypt_data(
                random_data,
                wallet.hotkey.secret,  # TODO: Use validator key as the encryption key?
            )

            # Convert to base64 for compactness
            b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

            # Hash the encrypted data
            data_hash = hash_data(encrypted_data)

            # Chunk the data
            chunksize = get_random_chunksize()
            # chunks = list(chunk_data(encrypted_data, chunksize))

            # Broadcast a query to all miners on the network.
            responses = dendrite.query(
                metagraph.axons,
                protocol.Store(
                    chunksize=chunksize,
                    encrypted_data=b64_encrypted_data,
                    data_hash=data_hash,
                    curve=config.curve,
                    g=ecc_point_to_hex(g),
                    h=ecc_point_to_hex(h),
                    size=sys.getsizeof(encrypted_data),
                ),
                deserialize=True,
            )

            # TODO: Store data params in Redis or GUNdb
            setup_params = {
                "g": g,
                "h": h,
                "curve": config.curve,
            }

            # Log the results for monitoring purposes.
            bt.logging.info(f"Received responses: {responses}")

            # TODO(developer): Define how the validator scores responses.
            # Adjust the scores based on responses from miners.
            for i, resp_i in enumerate(responses):
                # Check if the miner has provided the correct response by doubling the dummy input.
                # If correct, set their score for this round to 1. Otherwise, set it to 0.
                score = template.reward.dummy(step, resp_i)

                # Update the global score of the miner.
                # This score contributes to the miner's weight in the network.
                # A higher weight means that the miner has been consistently responding correctly.
                scores[i] = config.alpha * scores[i] + (1 - config.alpha) * score

            bt.logging.info(f"Scores: {scores}")
            # Periodically update the weights on the Bittensor blockchain.
            if (step + 1) % 10 == 0:
                # TODO(developer): Define how the validator normalizes scores before setting weights.
                weights = torch.nn.functional.normalize(scores, p=1.0, dim=0)
                bt.logging.info(f"Setting weights: {weights}")
                # This is a crucial step that updates the incentive mechanism on the Bittensor blockchain.
                # Miners with higher scores (or weights) receive a larger share of TAO rewards on this subnet.
                result = subtensor.set_weights(
                    netuid=config.netuid,  # Subnet to set weights on.
                    wallet=wallet,  # Wallet to sign set weights using hotkey.
                    uids=metagraph.uids,  # Uids of the miners to set weights for.
                    weights=weights,  # Weights to set for the miners.
                    wait_for_inclusion=True,
                )
                if result:
                    bt.logging.success("Successfully set weights.")
                else:
                    bt.logging.error("Failed to set weights.")

            # End the current step and prepare for the next iteration.
            step += 1
            # Resync our local state with the latest state from the blockchain.
            metagraph = subtensor.metagraph(config.netuid)
            # Sleep for a duration equivalent to the block time (i.e., time between successive blocks).
            time.sleep(bt.__blocktime__)

        # If we encounter an unexpected error, log it for debugging.
        except RuntimeError as e:
            bt.logging.error(e)
            traceback.print_exc()

        # If the user interrupts the program, gracefully exit.
        except KeyboardInterrupt:
            bt.logging.success("Keyboard interrupt detected. Exiting validator.")
            exit()


# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    # Parse the configuration.
    config = get_config()
    # Run the main function.
    main(config)
