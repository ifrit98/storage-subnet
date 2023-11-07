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
    encode_miner_storage,
    decode_miner_storage,
    verify_challenge,
)
from storage.utils import *


def get_config():
    # Step 2: Set up the configuration parser
    # This function initializes the necessary command-line arguments.
    # Using command-line arguments allows users to customize various miner settings.
    parser = argparse.ArgumentParser()
    # TODO(developer): Adds your custom miner arguments to the parser.
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
    # Adds override arguments for network and netuid.
    parser.add_argument("--netuid", type=int, default=1, help="The chain subnet uid.")
    # Adds subtensor specific arguments i.e. --subtensor.chain_endpoint ... --subtensor.network ...
    bt.subtensor.add_args(parser)
    # Adds logging specific arguments i.e. --logging.debug ..., --logging.trace .. or --logging.logging_dir ...
    bt.logging.add_args(parser)
    # Adds wallet specific arguments i.e. --wallet.name ..., --wallet.hotkey ./. or --wallet.path ...
    bt.wallet.add_args(parser)
    # Adds axon specific arguments i.e. --axon.port ...
    bt.axon.add_args(parser)
    # Activating the parser to read any command-line inputs.
    # To print help message, run python3 template/miner.py --help
    config = bt.config(parser)

    # Step 3: Set up logging directory
    # Logging captures events for diagnosis or understanding miner's behavior.
    config.full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            "miner",
        )
    )
    # Ensure the directory for logging exists, else create one.
    if not os.path.exists(config.full_path):
        os.makedirs(config.full_path, exist_ok=True)
    return config


def commit_data(committer, data_chunks, n_chunks):
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
    print("n_chunks:", n_chunks)
    for index, chunk in enumerate(data_chunks):
        print("index:", index)
        c, m_val, r = committer.commit(chunk)
        c_hex = ecc_point_to_hex(c)
        randomness[index] = r
        chunks[index] = chunk
        points[index] = c_hex
        merkle_tree.add_leaf(c_hex)

    # Create the tree from the leaves
    merkle_tree.make_tree()
    return randomness, chunks, points, merkle_tree


# Main takes the config and starts the miner.
def main(config):
    # Activating Bittensor's logging with the set configurations.
    bt.logging(config=config, logging_dir=config.full_path)

    # This logs the active configuration to the specified logging directory for review.
    bt.logging.info(config)

    # Step 4: Initialize Bittensor miner objects
    # These classes are vital to interact and function within the Bittensor network.
    bt.logging.info("Setting up bittensor objects.")

    # Wallet holds cryptographic information, ensuring secure transactions and communication.
    wallet = bt.wallet(config=config)
    bt.logging.info(f"Wallet: {wallet}")

    # subtensor manages the blockchain connection, facilitating interaction with the Bittensor blockchain.
    subtensor = bt.subtensor(config=config)
    bt.logging.info(f"Subtensor: {subtensor}")

    # metagraph provides the network's current state, holding state about other participants in a subnet.
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

    # Each miner gets a unique identity (UID) in the network for differentiation.
    my_subnet_uid = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
    bt.logging.info(f"Running miner on uid: {my_subnet_uid}")

    # Set up the miner's data storage.
    # This is where the miner will store the data it receives.
    database = redis.StrictRedis(host="localhost", port=6379, db=0)

    # Step 5: Set up miner functionalities
    # The following functions control the miner's response to incoming requests.
    # The blacklist function decides if a request should be ignored.
    def blacklist_fn(
        synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> typing.Tuple[bool, str]:
        # TODO(developer): Define how miners should blacklist requests. This Function
        # Runs before the synapse data has been deserialized (i.e. before synapse.data is available).
        # The synapse is instead contructed via the headers of the request. It is important to blacklist
        # requests before they are deserialized to avoid wasting resources on requests that will be ignored.
        # Below: Check that the hotkey is a registered entity in the metagraph.
        if synapse.dendrite.hotkey not in metagraph.hotkeys:
            # Ignore requests from unrecognized entities.
            bt.logging.trace(
                f"Blacklisting unrecognized hotkey {synapse.dendrite.hotkey}"
            )
            return True, "Unrecognized hotkey"
        # TODO(developer): In practice it would be wise to blacklist requests from entities that
        # are not validators, or do not have enough stake. This can be checked via metagraph.S
        # and metagraph.validator_permit. You can always attain the uid of the sender via a
        # metagraph.hotkeys.index( synapse.dendrite.hotkey ) call.
        # Otherwise, allow the request to be processed further.
        bt.logging.trace(
            f"Not Blacklisting recognized hotkey {synapse.dendrite.hotkey}"
        )
        return False, "Hotkey recognized!"

    # The priority function determines the order in which requests are handled.
    # More valuable or higher-priority requests are processed before others.
    def priority_fn(
        synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> float:
        # TODO(developer): Define how miners should prioritize requests.
        # Miners may recieve messages from multiple entities at once. This function
        # determines which request should be processed first. Higher values indicate
        # that the request should be processed first. Lower values indicate that the
        # request should be processed later.
        # Below: simple logic, prioritize requests from entities with more stake.
        caller_uid = metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        prirority = float(metagraph.S[caller_uid])  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", prirority
        )
        return prirority

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
            "g": synapse.g,
            "h": synapse.h,
            "curve": synapse.curve,
            "data": synapse.encrypted_data,
        }
        dumped = json.dumps(miner_store).encode()

        # Commit to the entire data block
        committer = ECCommitment(
            hex_to_ecc_point(synapse.g, synapse.curve),
            hex_to_ecc_point(synapse.h, synapse.curve),
        )
        encrypted_byte_data = base64.b64decode(synapse.encrypted_data)
        c, m_val, r = committer.commit(encrypted_byte_data)

        # Store the data with the hash as the key
        database.set(m_val, dumped)

        # Send back some proof that we stored the data
        synapse.randomness = r
        synapse.commitment = ecc_point_to_hex(c)
        synapse.signature = wallet.hotkey.sign(
            str(m_val)
        )  # NOTE: Does this add anything of value?

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
        data = database.get(synapse.challenge_hash)
        decoded = json.loads(data.decode("utf-8"))

        # Chunk the data according to the specified (random) chunk size
        encrypted_data_bytes = base64.b64decode(decoded["data"])
        data_chunks = chunk_data(encrypted_data_bytes, synapse.chunk_size)

        # Extract setup params
        g = hex_to_ecc_point(synapse.g, synapse.curve)
        h = hex_to_ecc_point(synapse.h, synapse.curve)

        # Commit the data chunks based on the provided curve points
        committer = ECCommitment(g, h)
        randomness, chunks, commitments, merkle_tree = commit_data(
            committer,
            data_chunks,
            sys.getsizeof(encrypted_data_bytes) // synapse.chunk_size + 1,
        )

        # Prepare return values to validator
        synapse.commitment = commitments[synapse.challenge_index]
        synapse.data_chunk = chunks[synapse.challenge_index]
        synapse.randomness = randomness[synapse.challenge_index]
        synapse.merkle_proof = b64_encode(
            merkle_tree.get_proof(synapse.challenge_index)
        )
        synapse.merkle_root = merkle_tree.get_merkle_root()
        return synapse

    # TODO: Validator code to update storage after challenge is successful
    # TODO: Encoding and decoding of merkle proofs on challenege
    # TODO: Defensive programming and error-handling around all functions
    # TODO: Test over the wire if you can query these endpoints and get the right responses
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
    )

    # Serve passes the axon information to the network + netuid we are hosting on.
    # This will auto-update if the axon port of external ip have changed.
    bt.logging.info(
        f"Serving axon {store} on network: {subtensor.chain_endpoint} with netuid: {config.netuid}"
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
