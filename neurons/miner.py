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
import torch
import redis
import typing
import base64
import asyncio
import argparse
import threading
import traceback
import bittensor as bt
from collections import defaultdict
from Crypto.Random import get_random_bytes

from pprint import pprint, pformat

from test_miner import test

# import this repo
import storage
from storage.shared.ecc import (
    hash_data,
    setup_CRS,
    ECCommitment,
    ecc_point_to_hex,
    hex_to_ecc_point,
)

from storage.shared.merkle import (
    MerkleTree,
)

from storage.shared.utils import (
    b64_encode,
    b64_decode,
    chunk_data,
)

from storage.miner import (
    run,
    set_weights,
)

from storage.miner.utils import (
    compute_subsequent_commitment,
    save_data_to_filesystem,
    load_from_filesystem,
    commit_data_with_seed,
)

from storage.miner.config import (
    config,
    check_config,
    add_args,
)


class miner:
    @classmethod
    def check_config(cls, config: "bt.Config"):
        """
        Adds neuron-specific arguments to the argument parser.

        Args:
            parser (argparse.ArgumentParser): Parser to add arguments to.

        This class method enriches the argument parser with options specific to the neuron's configuration.
        """
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        """
        Adds neuron-specific arguments to the argument parser.

        Args:
            parser (argparse.ArgumentParser): Parser to add arguments to.

        This class method enriches the argument parser with options specific to the neuron's configuration.
        """
        add_args(cls, parser)

    @classmethod
    def config(cls):
        """
        Retrieves the configuration for the neuron.

        Returns:
            bt.Config: The configuration object for the neuron.

        This class method returns the neuron's configuration, which is used throughout the neuron's lifecycle
        for various functionalities and operations.
        """
        return config(cls)

    subtensor: "bt.subtensor"
    wallet: "bt.wallet"
    metagraph: "bt.metagraph"

    def __init__(self):
        self.config = miner.config()
        self.check_config(self.config)
        bt.logging(config=self.config, logging_dir=self.config.miner.full_path)
        bt.logging.info(f"{self.config}")

        bt.logging.info("miner.__init__()")

        # Init device.
        bt.logging.debug("loading", "device")
        self.device = torch.device(self.config.miner.device)
        bt.logging.debug(str(self.device))

        # Init subtensor
        bt.logging.debug("loading", "subtensor")
        self.subtensor = bt.subtensor(config=self.config)
        bt.logging.debug(str(self.subtensor))

        # Init wallet.
        bt.logging.debug("loading", "wallet")
        self.wallet = bt.wallet(config=self.config)
        self.wallet.create_if_non_existent()
        if not self.config.wallet._mock:
            if not self.subtensor.is_hotkey_registered_on_subnet(
                hotkey_ss58=self.wallet.hotkey.ss58_address, netuid=self.config.netuid
            ):
                raise Exception(
                    f"Wallet not currently registered on netuid {self.config.netuid}, please first register wallet before running"
                )

        bt.logging.debug(f"wallet: {str(self.wallet)}")

        # Init metagraph.
        bt.logging.debug("loading", "metagraph")
        self.metagraph = bt.metagraph(
            netuid=self.config.netuid, network=self.subtensor.network, sync=False
        )  # Make sure not to sync without passing subtensor
        self.metagraph.sync(subtensor=self.subtensor)  # Sync metagraph with subtensor.
        self.hotkeys = copy.deepcopy(self.metagraph.hotkeys)
        bt.logging.debug(str(self.metagraph))

        # Setup database
        self.database = redis.StrictRedis(
            host=self.config.database.host,
            port=self.config.database.port,
            db=self.config.database.index,
        )

        self.my_subnet_uid = self.metagraph.hotkeys.index(
            self.wallet.hotkey.ss58_address
        )
        bt.logging.info(f"Running miner on uid: {self.my_subnet_uid}")

        # Init wandb.
        if not self.config.wandb.off:
            bt.logging.debug("loading", "wandb")
            init_wandb(self)

        # The axon handles request processing, allowing validators to send this process requests.
        self.axon = bt.axon(wallet=self.wallet, config=self.config)
        bt.logging.info(f"Axon {self.axon}")

        # Attach determiners which functions are called when servicing a request.
        bt.logging.info(f"Attaching forward functions to axon.")
        self.axon.attach(
            forward_fn=self.store,
            # blacklist_fn=blacklist_fn,
            # priority_fn=priority_fn,
        ).attach(
            forward_fn=self.challenge,
            # blacklist_fn=blacklist_fn,
            # priority_fn=priority_fn,
        ).attach(
            forward_fn=self.retrieve,
            # blacklist_fn=blacklist_fn,
            # priority_fn=priority_fn,
        )

        # Serve passes the axon information to the network + netuid we are hosting on.
        # This will auto-update if the axon port of external ip have changed.
        bt.logging.info(
            f"Serving axon {self.axon} on network: {self.subtensor.chain_endpoint} with netuid: {self.config.netuid}"
        )
        self.axon.serve(netuid=self.config.netuid, subtensor=self.subtensor)

        # Start  starts the miner's axon, making it active on the network.
        bt.logging.info(f"Starting axon server on port: {self.config.axon.port}")
        self.axon.start()

        # Init the event loop.
        self.loop = asyncio.get_event_loop()

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()
        self.request_timestamps: Dict = {}

        self.step = 0

        if self.config.test:  # (debugging)
            test(self)
            exit(0)

    @property
    def total_storage(self):
        """
        Calculates the total size of data stored by the miner.

        This method fetches all data keys from the Redis database and sums up the size of each data object.
        It provides an estimate of the total amount of data currently held by the miner.

        Returns:
            int: Total size of data (in bytes) stored by the miner.

        Example:
            >>> miner.total_storage()
            102400  # Example output indicating 102,400 bytes of data stored
        """
        # Fetch all keys from Redis
        all_keys = safe_key_search(database, "*")

        # Filter out keys that contain a period (temporary, remove later)
        filtered_keys = [key for key in all_keys if b"." not in key]
        bt.logging.debug("filtered_keys:", filtered_keys)

        # Get the size of each data object and sum them up
        total_size = sum(
            [
                json.loads(self.database.get(key).decode("utf-8")).get("size", 0)
                for key in filtered_keys
            ]
        )
        return total_size

    def blacklist_fn(
        self, synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> typing.Tuple[bool, str]:
        if synapse.dendrite.hotkey not in self.metagraph.hotkeys:
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
        self, synapse: typing.Union[storage.protocol.Store, storage.protocol.Challenge]
    ) -> float:
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        prirority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", prirority
        )
        return prirority

    # This is the core miner function, which decides the miner's response to a valid, high-priority request.
    def store(self, synapse: storage.protocol.Store) -> storage.protocol.Store:
        """
        Handles storing data requested by a synapse.

        This method commits to the entire data block provided by the synapse, stores it in the filesystem,
        and updates the Redis database with metadata about the stored data. It also generates a commitment
        proof to send back to the requesting entity as evidence of storage.

        Args:
            synapse (storage.protocol.Store): The Store synapse containing the data to be stored and associated metadata.

        Returns:
            storage.protocol.Store: The updated synapse with commitment proof and other storage details.
        """
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

        # Store the data with the hash as the key in the filesystem
        data_hash = hash_data(encrypted_byte_data)
        bt.logging.debug(f"data_hash: {data_hash}")
        filepath = save_data_to_filesystem(
            encrypted_byte_data, self.config.database.directory, str(data_hash)
        )
        bt.logging.debug(f"stored data in filepath: {filepath}")
        miner_store = {
            "filepath": filepath,
            "prev_seed": str(synapse.seed),
            "size": sys.getsizeof(encrypted_byte_data),
        }

        # Dump the metadata to json and store in redis
        dumped = json.dumps(miner_store).encode()
        bt.logging.debug(f"dumped: {dumped}")
        self.database.set(data_hash, dumped)
        bt.logging.debug(f"set in database!")

        # Send back some proof that we stored the data
        synapse.randomness = r
        synapse.commitment = ecc_point_to_hex(c)

        # NOTE: Does this add anything of value?
        synapse.signature = self.wallet.hotkey.sign(str(m_val)).hex()
        bt.logging.debug(f"signed m_val: {synapse.signature.hex()}")

        # CONCAT METHOD INITIAlIZE CHAIN
        print(f"type(seed): {type(synapse.seed)}")
        synapse.commitment_hash = str(m_val)
        bt.logging.debug(f"initial commitment_hash: {synapse.commitment_hash}")

        bt.logging.debug(f"returning synapse: {synapse}")
        return synapse

    def challenge(
        self, synapse: storage.protocol.Challenge
    ) -> storage.protocol.Challenge:
        """
        Responds to a challenge request by proving possession of the requested data chunk.

        This method fetches and chunks the data requested in the synapse. It computes the commitment to the data chunk
        based on the provided curve points and returns the chunk along with a merkle proof, root, and commitment
        as evidence of possession.

        Args:
            synapse (storage.protocol.Challenge): The Challenge synapse containing parameters for the data challenge.

        Returns:
            storage.protocol.Challenge: The updated synapse with the response to the data challenge.
        """
        # Retrieve the data itself from miner storage
        bt.logging.debug(f"challenge hash: {synapse.challenge_hash}")
        data = self.database.get(synapse.challenge_hash)
        if data is None:
            bt.logging.error(f"No data found for {synapse.challenge_hash}")
            bt.logging.error(f"keys found: {self.database.keys('*')}")
            return synapse

        decoded = json.loads(data.decode("utf-8"))
        bt.logging.debug(f"decoded data: {decoded}")

        # Chunk the data according to the specified (random) chunk size
        filepath = decoded["filepath"]
        encrypted_data_bytes = load_from_filesystem(filepath)
        bt.logging.debug(f"encrypted_data_bytes: {encrypted_data_bytes}")

        # Construct the next commitment hash using previous commitment and hash
        # of the data to prove storage over time
        prev_seed = decoded["prev_seed"].encode()
        new_seed = synapse.seed.encode()
        next_commitment, proof = compute_subsequent_commitment(
            encrypted_data_bytes, prev_seed, new_seed
        )
        if self.config.verbose:
            print(
                f"types: prev_seed {str(type(prev_seed))}, new_seed {str(type(new_seed))}, proof {str(type(proof))}"
            )
            print(f"prev seed : {prev_seed}")
            print(f"new seed  : {new_seed}")
            print(f"proof     : {proof}")
            print(f"commitment: {next_commitment}\n")
        synapse.commitment_hash = next_commitment
        synapse.commitment_proof = proof

        # update the commitment seed challenge hash in storage
        decoded["prev_seed"] = new_seed.decode("utf-8")
        self.database.set(synapse.challenge_hash, json.dumps(decoded).encode())
        bt.logging.debug(f"udpated miner storage: {decoded}")

        data_chunks = chunk_data(encrypted_data_bytes, synapse.chunk_size)
        bt.logging.debug(f"data_chunks: {pformat(data_chunks)}")

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

    def retrieve(self, synapse: storage.protocol.Retrieve) -> storage.protocol.Retrieve:
        """
        Retrieves data based on a given hash from the miner's storage.

        This method looks up the requested data in the Redis database using the provided hash. It then loads
        the data from the filesystem and includes a final seed challenge to verify continued possession
        of the data at retrieval time.

        Args:
            synapse (storage.protocol.Retrieve): The Retrieve synapse containing the hash of the data to be retrieved.

        Returns:
            storage.protocol.Retrieve: The updated synapse with the retrieved data and additional verification information.
        """
        # Fetch the data from the miner database
        data = self.database.get(synapse.data_hash)
        bt.logging.debug("retireved data:", data)

        # Decode the data + metadata from bytes to json
        decoded = json.loads(data.decode("utf-8"))
        bt.logging.debug("retrieve decoded data:", decoded)

        # load the data from the filesystem
        filepath = decoded["filepath"]
        encrypted_data_bytes = load_from_filesystem(filepath)

        # incorporate a final seed challenge to verify they still have the data at retrieval time
        commitment, proof = compute_subsequent_commitment(
            encrypted_data_bytes,
            decoded["prev_seed"].encode(),
            synapse.seed.encode(),
        )
        synapse.commitment_hash = commitment
        synapse.commitment_proof = proof

        # store new seed
        decoded["prev_seed"] = synapse.seed
        self.database.set(synapse.data_hash, json.dumps(decoded).encode())
        bt.logging.debug(f"udpated retrieve miner storage: {decoded}")

        # Return base64 data
        synapse.data = base64.b64encode(encrypted_data_bytes)
        return synapse

    def run(self):
        run(self)

    def run_in_background_thread(self):
        """
        Starts the miner's operations in a separate background thread.
        This is useful for non-blocking operations.
        """
        if not self.is_running:
            bt.logging.debug("Starting miner in background thread.")
            self.should_exit = False
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()
            self.is_running = True
            bt.logging.debug("Started")

    def stop_run_thread(self):
        """
        Stops the miner's operations that are running in the background thread.
        """
        if self.is_running:
            bt.logging.debug("Stopping miner in background thread.")
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            bt.logging.debug("Stopped")

    def __enter__(self):
        """
        Starts the miner's operations in a background thread upon entering the context.
        This method facilitates the use of the miner in a 'with' statement.
        """
        self.run_in_background_thread()

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Stops the miner's background operations upon exiting the context.
        This method facilitates the use of the miner in a 'with' statement.

        Args:
            exc_type: The type of the exception that caused the context to be exited.
                      None if the context was exited without an exception.
            exc_value: The instance of the exception that caused the context to be exited.
                       None if the context was exited without an exception.
            traceback: A traceback object encoding the stack trace.
                       None if the context was exited without an exception.
        """
        self.stop_run_thread()


def main():
    """
    Main function to run the neuron.

    This function initializes and runs the neuron. It handles the main loop, state management, and interaction
    with the Bittensor network.
    """
    miner().run()


if __name__ == "__main__":
    main()
