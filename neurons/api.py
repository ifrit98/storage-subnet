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
import sys
import copy
import json
import time
import torch
import base64
import typing
import asyncio
import aioredis
import argparse
import traceback
import websocket
import bittensor as bt

from typing import List, Optional, Tuple, Dict, Any
from loguru import logger
from pprint import pformat
from functools import partial
from traceback import print_exception
from Crypto.Random import get_random_bytes
from pyinstrument import Profiler

from storage import protocol
from storage.shared.ecc import hash_data
from storage.validator.utils import (
    get_available_query_miners,
    compute_chunk_distribution_mut_exclusive_numpy_reuse_uids,
)
from storage.shared.ecc import (
    hash_data,
    setup_CRS,
    ECCommitment,
    ecc_point_to_hex,
    hex_to_ecc_point,
)
from storage.validator.verify import (
    verify_store_with_seed,
    verify_retrieve_with_seed,
)
from storage.validator.encryption import decrypt_data_with_private_key
from storage.validator.config import config, check_config, add_args
from storage.validator.state import ttl_get_block, should_checkpoint
from storage.validator.reward import apply_reward_scores
from storage.validator.database import (
    add_metadata_to_hotkey,
    store_chunk_metadata,
    store_file_chunk_mapping_ordered,
    get_ordered_metadata,
    hotkey_at_capacity,
    retrieve_encryption_payload,
)
from storage.validator.bonding import update_statistics
from storage.validator.encryption import (
    decrypt_data,
    encrypt_data,
)


class neuron:
    """
    API node for storage network

    Attributes:
        subtensor (bt.subtensor): The interface to the Bittensor network's blockchain.
        wallet (bt.wallet): Cryptographic wallet containing keys for transactions and encryption.
        metagraph (bt.metagraph): Graph structure storing the state of the network.
        database (redis.StrictRedis): Database instance for storing metadata and proofs.
    """

    @classmethod
    def check_config(cls, config: "bt.Config"):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return config(cls)

    subtensor: "bt.subtensor"
    wallet: "bt.wallet"
    metagraph: "bt.metagraph"

    def __init__(self):
        self.config = neuron.config()
        self.check_config(self.config)
        bt.logging(config=self.config, logging_dir=self.config.neuron.full_path)
        print(self.config)
        bt.logging.info("neuron.__init__()")

        # Init device.
        bt.logging.debug("loading device")
        self.device = torch.device(self.config.neuron.device)
        bt.logging.debug(str(self.device))

        # Init subtensor
        bt.logging.debug("loading subtensor")
        self.subtensor = (
            bt.MockSubtensor()
            if self.config.neuron.mock_subtensor
            else bt.subtensor(config=self.config)
        )
        bt.logging.debug(str(self.subtensor))

        # Init wallet.
        bt.logging.debug("loading wallet")
        self.wallet = bt.wallet(config=self.config)
        self.wallet.coldkey  # Unlock for testing
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
        bt.logging.debug("loading metagraph")
        self.metagraph = bt.metagraph(
            netuid=self.config.netuid, network=self.subtensor.network, sync=False
        )  # Make sure not to sync without passing subtensor
        self.metagraph.sync(subtensor=self.subtensor)  # Sync metagraph with subtensor.
        bt.logging.debug(str(self.metagraph))

        # Setup database
        self.database = aioredis.StrictRedis(
            host=self.config.database.host,
            port=self.config.database.port,
            db=self.config.database.index,
        )
        self.db_semaphore = asyncio.Semaphore()

        # Init Weights.
        bt.logging.debug("loading moving_averaged_scores")
        self.moving_averaged_scores = torch.zeros((self.metagraph.n)).to(self.device)
        bt.logging.debug(str(self.moving_averaged_scores))

        self.my_subnet_uid = self.metagraph.hotkeys.index(
            self.wallet.hotkey.ss58_address
        )
        bt.logging.info(f"Running validator on uid: {self.my_subnet_uid}")

        bt.logging.debug("serving ip to chain...")
        try:
            self.axon = bt.axon(wallet=self.wallet, config=self.config)

            self.axon.attach(
                forward_fn=self.store_user_data,
                blacklist_fn=self.store_blacklist,
                priority_fn=self.store_priority,
            ).attach(
                forward_fn=self.retrieve_user_data,
                blacklist_fn=self.retrieve_blacklist,
                priority_fn=self.retrieve_priority,
            )

            try:
                self.subtensor.serve_axon(
                    netuid=self.config.netuid,
                    axon=self.axon,
                )
                self.axon.start()

            except Exception as e:
                bt.logging.error(f"Failed to serve Axon: {e}")
                pass

        except Exception as e:
            bt.logging.error(f"Failed to create Axon initialize: {e}")
            pass

        # Dendrite pool for querying the network.
        bt.logging.debug("loading dendrite_pool")
        if self.config.neuron.mock:
            self.dendrite = MockDendrite()  # TODO: fix this import error
        else:
            self.dendrite = bt.dendrite(wallet=self.wallet)
        bt.logging.debug(str(self.dendrite))

        # Init the event loop.
        self.loop = asyncio.get_event_loop()

        if self.config.neuron.challenge_sample_size == 0:
            self.config.neuron.challenge_sample_size = self.metagraph.n

        self.prev_step_block = ttl_get_block(self)

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()
        self.request_timestamps: Dict = {}

        self.step = 0

        self._top_n_validators = None
        self.get_top_n_validators()

    # TODO: Develop the agreement gossip protocol across validators to accept storage requests
    # and accept retrieve requests given agreement of top n % stake
    async def agreement_protocol(self):
        raise NotImplementedError

    def get_top_n_validators(self):
        """
        Retrieves a list of the top N validators based on the stake value from the metagraph.
        This list represents the top 10% of validators by stake.

        Returns:
            list: A list of UIDs (unique identifiers) for the top N validators.

        Note:
            - The method filters out the UID of the current instance (self) if it is in the top N list.
            - This function is typically used to identify validators with the highest stake in the network,
            which can be crucial for decision-making processes in a distributed system.
        """
        top_uids = torch.where(
            self.metagraph.S > torch.quantile(self.metagraph.S, 1 - 0.1)
        )[0].tolist()
        if self.my_subnet_uid in top_uids:
            top_uids.remove(self.my_subnet_uid)
        return top_uids

    @property
    def top_n_validators(self):
        """
        A property that provides access to the top N validators' UIDs. It calculates the top N validators
        if they have not been computed yet or if a checkpoint condition is met (indicated by the
        'should_checkpoint' function).

        Returns:
            list: A list of UIDs for the top N validators.

        Note:
            - This property employs lazy loading and caching to efficiently manage the retrieval of top N validators.
            - The cache is updated based on specific conditions, such as crossing a checkpoint in the network.
        """
        if self._top_n_validators == None or should_checkpoint(self):
            self._top_n_validators = self.get_top_n_validators()
        return self._top_n_validators

    async def store_user_data(self, synapse: protocol.StoreUser) -> protocol.StoreUser:
        """
        Asynchronously handles the storage of user data by processing a store user request. It stores the
        encrypted user data on the network and updates the request with the resulting data hash.

        Parameters:
            synapse (protocol.StoreUser): An instance of the StoreUser protocol class containing information
                                        about the data to be stored.

        Returns:
            protocol.StoreUser: The updated instance of the StoreUser protocol class with the data hash
                                of the stored data.

        Note:
            - This method is part of a larger protocol for storing data in a distributed network.
            - It relies on the 'store_broadband' method for actual storage and hash generation.
            - The method logs detailed information about the storage process for monitoring and debugging.
        """
        bt.logging.debug(f"store_user_data() {synapse.dendrite.dict()}")

        decoded_data = base64.b64decode(synapse.encrypted_data)
        decoded_data = (
            decoded_data.encode("utf-8")
            if isinstance(decoded_data, str)
            else decoded_data
        )
        validator_encrypted_data, validator_encryption_payload = encrypt_data(
            decoded_data, self.wallet
        )

        # Hash the original data to avoid data confusion
        data_hash = hash_data(decoded_data)

        if isinstance(validator_encryption_payload, dict):
            validator_encryption_payload = json.dumps(validator_encryption_payload)

        await self.database.set(
            f"payload:validator:{data_hash}", validator_encryption_payload
        )

        _ = await self.store_broadband(
            encrypted_data=validator_encrypted_data,
            encryption_payload=synapse.encryption_payload,
            data_hash=data_hash,
        )
        synapse.data_hash = data_hash
        return synapse

    async def store_blacklist(self, synapse: protocol.StoreUser) -> Tuple[bool, str]:
        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."
        # If a validator with top n% stake, allow.
        if synapse.dendrite.hotkey in self.top_n_validators:
            return False, f"Hotkey {synapse.dendrite.hotkey} in top n% stake."
        # Otherwise, reject.
        return False, "Debug all whitelisted"
        # return (
        #     True,
        #     f"Hotkey {synapse.dendrite.hotkey} not whitelisted or in top n% stake.",
        # )

    async def store_priority(self, synapse: protocol.StoreUser) -> float:
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", priority
        )
        return priority

    async def retrieve_user_data(
        self, synapse: protocol.RetrieveUser
    ) -> protocol.RetrieveUser:
        """
        Asynchronously handles the retrieval of user data from the network based on a given hash.
        It retrieves and verifies the data, then updates the synapse object with the retrieved data.

        Parameters:
            synapse (protocol.RetrieveUser): An instance of the RetrieveUser protocol class containing
                                            the hash of the data to be retrieved.

        Returns:
            protocol.RetrieveUser: The updated instance of the RetrieveUser protocol class with the
                                retrieved encrypted data and encryption payload.

        Note:
            - The function is part of a larger protocol for data retrieval in a distributed network.
            - It utilizes the 'retrieve_broadband' method to perform the actual data retrieval and
            verification based on the provided data hash.
            - The method logs the retrieval process and the resulting data for monitoring and debugging.
        """
        data, payload = await self.retrieve_broadband(synapse.data_hash)
        bt.logging.debug(f"returning user data: {data[:100]}")
        bt.logging.debug(f"returning user payload: {payload}")
        synapse.encrypted_data = base64.b64encode(data)
        synapse.encryption_payload = (
            json.dumps(payload) if isinstance(payload, dict) else payload
        )
        return synapse

    async def retrieve_blacklist(
        self, synapse: protocol.RetrieveUser
    ) -> Tuple[bool, str]:
        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."
        # If a validator with top n% stake, allow.
        if synapse.dendrite.hotkey in self.top_n_validators:
            return False, f"Hotkey {synapse.dendrite.hotkey} in top n% stake."
        # Otherwise, reject.
        return False, "Debug all whitelisted."
        # return (
        #     True,
        #     f"Hotkey {synapse.dendrite.hotkey} not whitelisted or in top n% stake.",
        # )

    async def retrieve_priority(self, synapse: protocol.RetrieveUser) -> float:
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", priority
        )
        return priority

    async def ping_uids(self, uids):
        """
        Ping a list of UIDs to check their availability.
        Returns a tuple with a list of successful UIDs and a list of failed UIDs.
        """
        axons = [self.metagraph.axons[uid] for uid in uids]
        responses = await self.dendrite(
            axons,
            bt.Synapse(),
            deserialize=False,
            timeout=self.config.api.ping_timeout,
        )
        successful_uids = [
            uid
            for uid, response in zip(uids, responses)
            if response.dendrite.status_code == 200
        ]
        failed_uids = [
            uid
            for uid, response in zip(uids, responses)
            if response.dendrite.status_code != 200
        ]
        bt.logging.trace("successful uids:", successful_uids)
        bt.logging.trace("failed uids    :", failed_uids)
        return successful_uids, failed_uids

    async def compute_and_ping_chunks(self, distributions):
        """
        Asynchronously evaluates the availability of miners for the given chunk distributions by pinging them.
        Rerolls the distribution to replace failed miners, ensuring exactly k successful miners are selected.

        Parameters:
            distributions (list of dicts): A list of chunk distribution dictionaries, each containing
                                        information about chunk indices and assigned miner UIDs.

        Returns:
            list of dicts: The updated list of chunk distributions with exactly k successful miner UIDs.

        Note:
            - This function is crucial for ensuring that data chunks are assigned to available and responsive miners.
            - Pings miners based on their UIDs and updates the distributions accordingly.
            - Logs the new set of UIDs and distributions for traceability.
        """
        max_retries = 3  # Define the maximum number of retries
        target_number_of_uids = len(
            distributions[0]["uids"]
        )  # Assuming k is the length of the uids in the first distribution

        for dist in distributions:
            retries = 0
            successful_uids = set()

            while (
                len(successful_uids) < target_number_of_uids and retries < max_retries
            ):
                # Ping all UIDs
                current_successful_uids, _ = await self.ping_uids(dist["uids"])
                successful_uids.update(current_successful_uids)

                # If enough UIDs are successful, select the first k items
                if len(successful_uids) >= target_number_of_uids:
                    dist["uids"] = tuple(
                        sorted(successful_uids)[:target_number_of_uids]
                    )
                    break

                # Reroll for k UIDs excluding the successful ones
                new_uids = await get_available_query_miners(
                    self, k=target_number_of_uids, exclude=successful_uids
                )
                bt.logging.trace("new uids:", new_uids)

                # Update the distribution with new UIDs
                dist["uids"] = tuple(new_uids)
                retries += 1

            # Log if the maximum retries are reached without enough successful UIDs
            if len(successful_uids) < target_number_of_uids:
                bt.logging.warning(
                    f"Insufficient successful UIDs for distribution: {dist}"
                )

        # Continue with your logic using the updated distributions
        bt.logging.trace("new distributions:", distributions)
        return distributions

    async def reroll_distribution(self, distribution, failed_uids):
        """
        Asynchronously rerolls a single data chunk distribution by replacing failed miner UIDs with new, available ones.
        This is part of the error handling process in data distribution to ensure that each chunk is reliably stored.

        Parameters:
            distribution (dict): The original chunk distribution dictionary, containing chunk information and miner UIDs.
            failed_uids (list of int): List of UIDs that failed in the original distribution and need replacement.

        Returns:
            dict: The updated chunk distribution with new miner UIDs replacing the failed ones.

        Note:
            - This function is typically used when certain miners are unresponsive or unable to store the chunk.
            - Ensures that each chunk has the required number of active miners for redundancy.
        """
        # Get new UIDs to replace the failed ones
        new_uids = await get_available_query_miners(
            self, k=len(failed_uids), exclude=failed_uids
        )
        distribution["uids"] = new_uids
        return distribution

    async def store_broadband(
        self, encrypted_data, encryption_payload, R=3, k=10, data_hash=None
    ):
        """
        Asynchronously stores encrypted data across a distributed network by splitting it into chunks and
        assigning these chunks to various miners for storage. This method ensures redundancy and efficient
        data distribution while handling network requests concurrently.

        The process includes chunking the data, selecting miners for storage, and verifying the integrity
        of stored data through response validation.

        Parameters:
            encrypted_data (bytes): The encrypted data to be stored across the network.
            encryption_payload (dict): Additional payload information required for encryption.
            R (int, optional): The redundancy factor, denoting how many times each chunk is replicated. Default is 3.
            k (int, optional): The number of miners to query for each chunk. Default is 10.
            data_hash (str, optional): The hash of the data to be stored. If not provided, compute it. Default is None.

        Returns:
            str: The hash of the full data, representing its unique identifier in the network.

        Raises:
            Exception: If the process of creating initial distributions fails after multiple retries.

        Note:
            - Uses a semaphore to limit the number of concurrent network requests.
            - Employs a retry mechanism for handling network and miner availability issues.
            - Logs various stages of the process for debugging and monitoring purposes.
        """
        if self.config.neuron.profile:
            # Create a profiler instance
            profiler = Profiler()
            profiler.start()

        semaphore = asyncio.Semaphore(self.config.neuron.semaphore_size)

        async def store_chunk_group(chunk_hash, chunk, uids):
            g, h = setup_CRS(curve=self.config.neuron.curve)

            bt.logging.debug(f"type(chunk): {type(chunk)}")
            bt.logging.debug(f"chunk: {chunk[:100]}")
            chunk = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
            b64_encoded_chunk = await asyncio.to_thread(base64.b64encode, chunk)
            b64_encoded_chunk = b64_encoded_chunk.decode("utf-8")
            bt.logging.debug(f"b64_encoded_chunk: {b64_encoded_chunk[:100]}")

            synapse = protocol.Store(
                encrypted_data=b64_encoded_chunk,
                curve=self.config.neuron.curve,
                g=ecc_point_to_hex(g),
                h=ecc_point_to_hex(h),
                seed=get_random_bytes(32).hex(),
            )

            uids = [
                uid
                for uid in uids
                if not await hotkey_at_capacity(
                    self.metagraph.hotkeys[uid], self.database
                )
            ]

            axons = [self.metagraph.axons[uid] for uid in uids]
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
                timeout=self.config.api.store_timeout,
            )

            chunk_size = sys.getsizeof(chunk)  # chunk size in bytes
            bt.logging.debug(f"chunk size: {chunk_size}")

            start = time.time()
            await store_chunk_metadata(
                full_hash,
                chunk_hash,
                [self.metagraph.hotkeys[uid] for uid in uids],
                chunk_size,  # this should be len(chunk) but we need to fix the chunking
                self.database,
            )
            end = time.time()
            bt.logging.debug(f"store_chunk_metadata time for uids {uids} : {end-start}")

            return responses

        async def handle_uid_operations(uid, response, chunk_hash, chunk_size):
            ss = time.time()
            start = time.time()

            # Offload the CPU-intensive verification to a separate thread
            verified = await asyncio.to_thread(verify_store_with_seed, response)

            end = time.time()
            bt.logging.debug(f"verify_store_with_seed time for uid {uid} : {end-start}")
            if verified:
                # Prepare storage for the data for particular miner
                response_storage = {
                    "prev_seed": response.seed,
                    "size": chunk_size,
                    "encryption_payload": encryption_payload,
                }
                start = time.time()
                # Store in the database according to the data hash and the miner hotkey
                await add_metadata_to_hotkey(
                    self.metagraph.hotkeys[uid],
                    chunk_hash,
                    response_storage,  # seed + size + encryption keys
                    self.database,
                )
                end = time.time()
                bt.logging.debug(
                    f"Stored data in database for uid: {uid} | {str(chunk_hash)}"
                )
            else:
                bt.logging.error(f"Failed to verify store commitment from UID: {uid}")

            # Update the storage statistics
            await update_statistics(
                ss58_address=self.metagraph.hotkeys[uid],
                success=verified,
                task_type="store",
                database=self.database,
            )
            bt.logging.debug(
                f"handle_uid_operations time for uid {uid} : {time.time()-ss}"
            )

            return {"chunk_hash": chunk_hash, "uid": uid, "verified": verified}

        async def semaphore_query_miners(distributions):
            tasks = []
            async with semaphore:
                for i, dist in enumerate(distributions):
                    bt.logging.trace(
                        f"Start index: {dist['start_idx']}, End index: {dist['end_idx']}"
                    )
                    chunk = encrypted_data[dist["start_idx"] : dist["end_idx"]]
                    bt.logging.trace(f"chunk: {chunk[:100]}")
                    dist["chunk_hash"] = hash_data(chunk)
                    bt.logging.debug(
                        f"Chunk {i} | uid distribution: {dist['uids']} | size: {dist['chunk_size']}"
                    )

                    # Create an asyncio task for each chunk processing
                    task = asyncio.create_task(
                        store_chunk_group(dist["chunk_hash"], chunk, dist["uids"])
                    )
                    tasks.append(task)

            bt.logging.debug(f"gathering broadband tasks: {pformat(tasks)}")
            responses_nested = await asyncio.gather(*tasks)

            # Update the distributions with respones
            for i, responses in enumerate(responses_nested):
                distributions[i]["responses"] = responses
            return distributions

        async def semaphore_query_uid_operations(distributions):
            tasks = []
            for dist in distributions:
                chunk_hash = dist["chunk_hash"]
                chunk_size = dist["chunk_size"]
                for uid, response in zip(dist["uids"], dist["responses"]):
                    task = asyncio.create_task(
                        handle_uid_operations(uid, response, chunk_hash, chunk_size)
                    )
                    tasks.append(task)
            uid_verified_dict_list = await asyncio.gather(*tasks)
            return uid_verified_dict_list

        async def create_initial_distributions(encrypted_data, R, k):
            dist_gen = compute_chunk_distribution_mut_exclusive_numpy_reuse_uids(
                self,
                sys.getsizeof(encrypted_data),
                R,
                k,
            )
            # Ping first to see if we need to reroll instead of waiting for the timeout
            distributions = [dist async for dist in dist_gen]
            distributions = await self.compute_and_ping_chunks(distributions)
            return distributions

        bt.logging.debug(f"store_broadband() {encrypted_data[:100]}")

        full_hash = data_hash or hash_data(encrypted_data)
        bt.logging.debug(f"full hash: {full_hash}")

        # Check and see if hash already exists, reject if so.
        if await get_ordered_metadata(full_hash, self.database):
            bt.logging.warning(f"Hash {full_hash} already exists on the network.")
            return full_hash

        full_size = sys.getsizeof(encrypted_data)
        bt.logging.debug(f"full size: {full_size}")

        # Sometimes this can fail, try/catch and retry for starters...
        # Compute the chunk distribution
        retries = 0
        while retries < 3:
            try:
                distributions = await create_initial_distributions(encrypted_data, R, k)
                break
            except websocket._exceptions.WebSocketConnectionClosedException:
                bt.logging.warning(
                    f"Failed to create initial distributions, retrying..."
                )
                retries += 1
            except Exception as e:
                bt.logging.warning(
                    f"Failed to create initial distributions: {e}, retrying..."
                )
                retries += 1

        bt.logging.trace(f"computed distributions: {pformat(distributions)}")

        chunk_hashes = []
        retry_dists = [None]  # sentinel for first iteration
        retries = 0
        while len(distributions) > 0 and retries < 3:
            async with semaphore:
                # Store on the network: query miners for each chunk
                # Updated distributions now contain responses from the network
                updated_distributions = await semaphore_query_miners(distributions)
                # Verify the responses and store the metadata for each verified response
                verifications = await semaphore_query_uid_operations(
                    updated_distributions
                )
                if (
                    chunk_hashes == []
                ):  # First time only. Grab all hashes in order after processed.
                    chunk_hashes.extend(
                        [dist["chunk_hash"] for dist in updated_distributions]
                    )

                # Process verification results and reroll failed distributions in a single loop
                distributions = (
                    []
                )  # reset original distributions to populate for next round
                for i, dist in enumerate(updated_distributions):
                    # Get verification status for the current distribution
                    bt.logging.trace(f"verifications: {pformat(verifications)}")

                    # Check if any UID in the distribution failed verification
                    if any(not v["verified"] for v in verifications):
                        # Extract failed UIDs
                        failed_uids = [
                            v["uid"] for v in verifications if not v["verified"]
                        ]
                        bt.logging.trace(f"failed uids: {pformat(failed_uids)}")
                        # Reroll distribution with failed UIDs
                        rerolled_dist = await self.reroll_distribution(
                            dist, failed_uids
                        )
                        bt.logging.trace(
                            f"rerolled uids: {pformat(rerolled_dist['uids'])}"
                        )
                        # Replace the original distribution with the rerolled one
                        distributions.append(rerolled_dist)

            retries += 1

        # Update the chunk hash mapping for this entire file
        await store_file_chunk_mapping_ordered(
            full_hash=full_hash,
            chunk_hashes=chunk_hashes,
            chunk_indices=list(range(len(chunk_hashes))),
            encryption_payload=encryption_payload,
            database=self.database,
        )

        if self.config.neuron.profile:
            # Stop the profiler
            profiler.stop()
            # Print the results
            print(profiler.output_text(unicode=True, color=True))

        return full_hash

    async def retrieve_broadband(self, full_hash: str):
        """
        Asynchronously retrieves and verifies data from the network based on a given hash, ensuring
        the integrity and correctness of the data. This method orchestrates the retrieval process across
        multiple miners, reconstructs the data from chunks, and verifies its integrity.

        Parameters:
            full_hash (str): The hash of the data to be retrieved, representing its unique identifier on the network.

        Returns:
            tuple: A tuple containing the reconstructed data and its associated encryption payload.

        Raises:
            Exception: If no metadata is found for the given hash or if there are issues during the retrieval process.

        Note:
            - This function is a critical component of data retrieval in a distributed storage system.
            - It handles concurrent requests to multiple miners and assembles the data chunks based on
            ordered metadata.
            - In case of discrepancies in data size, the function logs a warning for potential data integrity issues.
        """
        semaphore = asyncio.Semaphore(self.config.neuron.semaphore_size)

        async def retrieve_chunk_group(chunk_hash, uids):
            synapse = protocol.Retrieve(
                data_hash=chunk_hash,
                seed=get_random_bytes(32).hex(),
            )

            axons = [self.metagraph.axons[uid] for uid in uids]
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
                timeout=self.config.api.retrieve_timeout,
            )

            return responses

        # Get the chunks you need to reconstruct IN order
        ordered_metadata = await get_ordered_metadata(full_hash, self.database)
        if ordered_metadata == []:
            bt.logging.error(f"No metadata found for full hash: {full_hash}")
            return None

        # Get the hotkeys/uids to query
        tasks = []
        total_size = 0
        bt.logging.debug(f"ordered metadata: {pformat(ordered_metadata)}")
        # TODO: change this to use retrieve_mutually_exclusive_hotkeys_full_hash
        # to avoid possibly double querying miners for greater retrieval efficiency

        async with semaphore:
            for chunk_metadata in ordered_metadata:
                bt.logging.debug(f"chunk metadata: {chunk_metadata}")
                uids = [
                    self.metagraph.hotkeys.index(hotkey)
                    for hotkey in chunk_metadata["hotkeys"]
                ]
                total_size += chunk_metadata["size"]
                tasks.append(
                    asyncio.create_task(
                        retrieve_chunk_group(chunk_metadata["chunk_hash"], uids)
                    )
                )
            responses = await asyncio.gather(*tasks)

            chunks = {}
            for i, response_group in enumerate(responses):
                for response in response_group:
                    if response.dendrite.status_code != 200:
                        bt.logging.debug(f"failed response: {response.dendrite.dict()}")
                        continue
                    verified = verify_retrieve_with_seed(response)
                    if verified:
                        # Add to final chunks dict
                        if i not in list(chunks.keys()):
                            bt.logging.debug(
                                f"Adding chunk {i} to chunks, size: {sys.getsizeof(response.data)}"
                            )
                            chunks[i] = base64.b64decode(response.data)
                            bt.logging.debug(f"chunk {i} | {chunks[i][:100]}")
                    else:
                        bt.logging.error(
                            f"Failed to verify store commitment from UID: {uid}"
                        )

        bt.logging.trace(f"chunks after: {[chunk[:100] for chunk in chunks.values()]}")
        bt.logging.trace(
            f"len(chunks) after: {[len(chunk) for chunk in chunks.values()]}"
        )
        # Reconstruct the data
        data = b"".join(chunks.values())
        bt.logging.trace(f"retrieved data: {data[:100]}")
        validator_encryption_payload = await retrieve_encryption_payload(
            "validator:" + full_hash, self.database
        )
        bt.logging.debug(
            f"validator_encryption_payload: {validator_encryption_payload}"
        )
        decrypted_data = decrypt_data_with_private_key(
            data,
            bytes(json.dumps(validator_encryption_payload), "utf-8"),
            bytes(self.wallet.coldkey.private_key.hex(), "utf-8"),
        )
        bt.logging.debug(f"decrypted_data: {decrypted_data[:100]}")
        encryption_payload = await retrieve_encryption_payload(full_hash, self.database)
        bt.logging.debug(f"retrieved encryption_payload: {encryption_payload}")
        return decrypted_data, encryption_payload

    def run(self):
        bt.logging.info("run()")
        if not self.wallet.hotkey.ss58_address in self.metagraph.hotkeys:
            raise Exception(
                f"API is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
            )
        try:
            while not self.should_exit:
                start_epoch = time.time()

                # --- Wait until next epoch.
                current_block = self.subtensor.get_current_block()
                while (
                    current_block - self.prev_step_block
                    < self.config.neuron.blocks_per_step
                ):
                    # --- Wait for next bloc.
                    time.sleep(1)
                    current_block = self.subtensor.get_current_block()

                    # --- Check if we should exit.
                    if self.should_exit:
                        break

                # --- Update the metagraph with the latest network state.
                self.prev_step_block = self.subtensor.get_current_block()

                self.metagraph = self.subtensor.metagraph(
                    netuid=self.config.netuid,
                    lite=True,
                    block=self.prev_step_block,
                )

        # If someone intentionally stops the miner, it'll safely terminate operations.
        except KeyboardInterrupt:
            self.axon.stop()
            bt.logging.success("Miner killed by keyboard interrupt.")
            exit()

        # In case of unforeseen errors, the miner will log the error and continue operations.
        except Exception as e:
            bt.logging.error(traceback.format_exc())

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
    neuron().run()


if __name__ == "__main__":
    main()
