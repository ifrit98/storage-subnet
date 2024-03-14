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
import copy
import time
import torch
import base64
import typing
import asyncio
import websocket
import bittensor as bt

from pprint import pformat
from pyinstrument import Profiler
from Crypto.Random import get_random_bytes

from storage.validator.event import EventSchema
from storage import protocol
from storage.shared.ecc import (
    hash_data,
    setup_CRS,
    ecc_point_to_hex,
)
from storage.validator.utils import (
    make_random_file,
    compute_chunk_distribution_mut_exclusive_numpy_reuse_uids,
)
from storage.validator.encryption import encrypt_data
from storage.validator.verify import verify_store_with_seed
from storage.validator.reward import apply_reward_scores
from storage.validator.database import (
    add_metadata_to_hotkey,
    store_chunk_metadata,
    store_file_chunk_mapping_ordered,
    get_ordered_metadata,
    hotkey_at_capacity,
)
from storage.validator.cid import generate_cid_string
from storage.validator.bonding import update_statistics

from .reward import create_reward_vector
from .network import ping_and_retry_uids, compute_and_ping_chunks, reroll_distribution


async def store_encrypted_data(
    self,
    encrypted_data: typing.Union[bytes, str],
    encryption_payload: dict,
    exclude_uids: typing.List[str] = [],
    ttl: int = None,
    k: int = None,
    max_retries: int = 3,
) -> bool:
    event = EventSchema(
        task_name="Store",
        successful=[],
        completion_times=[],
        task_status_messages=[],
        task_status_codes=[],
        block=self.subtensor.get_current_block(),
        uids=[],
        step_length=0.0,
        best_uid="",
        best_hotkey="",
        rewards=[],
        moving_averaged_scores=[],
    )

    start_time = time.time()

    encrypted_data = (
        encrypted_data.encode("utf-8")
        if isinstance(encrypted_data, str)
        else encrypted_data
    )

    # Setup CRS for this round of validation
    g, h = setup_CRS(curve=self.config.neuron.curve)

    # Hash the data
    data_hash = hash_data(encrypted_data)

    # Convert to base64 for compactness
    # TODO: Don't do this if it's already b64 encoded. (Check first)
    b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

    if self.config.neuron.verbose:
        bt.logging.debug(f"storing user data: {encrypted_data[:12]}...")
        bt.logging.debug(f"storing user hash: {data_hash}")
        bt.logging.debug(f"b64 encrypted data: {b64_encrypted_data[:12]}...")

    synapse = protocol.Store(
        encrypted_data=b64_encrypted_data,
        curve=self.config.neuron.curve,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        seed=get_random_bytes(32).hex(),  # 256-bit seed
        ttl=ttl or self.config.neuron.data_ttl,
    )

    # Select subset of miners to query (e.g. redunancy factor of N)
    uids, _ = await ping_and_retry_uids(
        self,
        k=k or 4,
        max_retries=max_retries,
        exclude_uids=exclude_uids,
    )
    bt.logging.debug(f"store_encrypted_data() uids: {uids}")

    axons = [self.metagraph.axons[uid] for uid in uids]
    failed_uids = [None]

    retries = 0
    while len(failed_uids) and retries < max_retries:
        if failed_uids == [None]:
            # initial loop
            failed_uids = []

        # Broadcast the query to selected miners on the network.
        responses = await self.dendrite(
            axons,
            synapse,
            deserialize=False,
            timeout=60,
        )

        # Compute the rewards for the responses given proc time.
        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        async def success(hotkey, idx, uid, response):
            # Prepare storage for the data for particular miner
            response_storage = {
                "prev_seed": synapse.seed,
                "size": sys.getsizeof(encrypted_data),  # in bytes, not len(data)
                "encryption_payload": encryption_payload,
            }
            bt.logging.trace(f"Storing UID {uid} data {pformat(response_storage)}")

            # Store in the database according to the data hash and the miner hotkey
            await add_metadata_to_hotkey(
                hotkey,
                data_hash,
                response_storage,
                self.database,
                ttl=ttl or self.config.neuron.data_ttl,
            )
            bt.logging.debug(
                f"Stored data in database with hotkey: {hotkey} | uid {uid} | {data_hash}"
            )

        def failure(uid):
            failed_uids.append(uid)

        await create_reward_vector(
            self, synapse, rewards, uids, responses, event, success, failure
        )
        event.rewards.extend(rewards.tolist())

        if self.config.neuron.verbose and self.config.neuron.log_responses:
            bt.logging.debug(f"Store responses round: {retries}")
            [
                bt.logging.debug(f"Store response: {response.axon.dict()}")
                for response in responses
            ]

        bt.logging.trace(f"Applying store rewards for retry: {retries}")
        data_size = sys.getsizeof(b64_encrypted_data)
        apply_reward_scores(
            self,
            uids=uids,
            responses=responses,
            rewards=rewards,
            data_sizes=[data_size] * len(responses),
        )

        # Get a new set of UIDs to query for those left behind
        if failed_uids != []:
            bt.logging.trace(f"Failed to store on uids: {failed_uids}")
            uids, _ = await ping_and_retry_uids(
                self, k=len(failed_uids), exclude_uids=exclude_uids
            )
            bt.logging.trace(f"Retrying with new uids: {uids}")
            axons = [self.metagraph.axons[uid] for uid in uids]
            failed_uids = []  # reset failed uids for next round
            retries += 1

    # Calculate step length
    end_time = time.time()
    event.step_length = end_time - start_time

    # Determine the best UID based on rewards
    if event.rewards:
        best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
        event.best_uid = event.uids[best_index]
        event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

    # Update event log with moving averaged scores
    event.moving_averaged_scores = self.moving_averaged_scores.tolist()

    return event


async def store_random_data(self):
    """
    Stores data on the network and ensures it is correctly committed by the miners.

    Parameters:
    - data (bytes, optional): The data to be stored.
    - wallet (bt.wallet, optional): The wallet to be used for encrypting the data.

    Returns:
    - The status of the data storage operation.
    """

    # Setup CRS for this round of validation
    g, h = setup_CRS(curve=self.config.neuron.curve)

    # Make a random bytes file to test the miner if none provided
    data = make_random_file(maxsize=self.config.neuron.maxsize)
    bt.logging.debug(f"Random store data size: {sys.getsizeof(data)}")

    # Encrypt the data
    # TODO: create and use a throwaway wallet (never decrypable)
    encrypted_data, encryption_payload = encrypt_data(data, self.encryption_wallet)

    return await store_encrypted_data(
        self,
        encrypted_data,
        encryption_payload,
        k=15,
        ttl=self.config.neuron.data_ttl,
    )


async def store_broadband(
    self,
    encrypted_data,
    encryption_payload,
    R=3,
    k=10,
    data_hash=None,
    exclude_uids=None,
    ttl=None,
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
        exclude_uids: (list of int, optional): A list of UIDs to exclude from the storage process. Default is None.

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
        event = EventSchema(
            task_name="Store",
            successful=[],
            completion_times=[],
            task_status_messages=[],
            task_status_codes=[],
            block=self.subtensor.get_current_block(),
            uids=[],
            step_length=0.0,
            best_uid="",
            best_hotkey="",
            rewards=[],
            moving_averaged_scores=[],
        )

        g, h = setup_CRS(curve=self.config.neuron.curve)

        bt.logging.debug(f"type(chunk): {type(chunk)}")
        bt.logging.debug(f"chunk: {chunk[:100]}")
        chunk = chunk.encode("utf-8") if isinstance(chunk, str) else chunk
        b64_encoded_chunk = await asyncio.to_thread(base64.b64encode, chunk)
        b64_encoded_chunk = b64_encoded_chunk.decode("utf-8")
        bt.logging.debug(f"b64_encoded_chunk: {b64_encoded_chunk[:100]}")
        random_seed = get_random_bytes(32).hex()

        synapse = protocol.Store(
            encrypted_data=b64_encoded_chunk,
            curve=self.config.neuron.curve,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            seed=random_seed,
            ttl=ttl or self.config.neuron.data_ttl,
        )

        uids = [
            uid
            for uid in uids
            if not await hotkey_at_capacity(self.metagraph.hotkeys[uid], self.database)
        ]

        axons = [self.metagraph.axons[uid] for uid in uids]
        responses = await self.dendrite(
            axons,
            synapse,
            deserialize=False,
            timeout=60,
        )

        # Compute the rewards for the responses given proc time.
        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        async def success(hotkey, idx, uid, response):
            bt.logging.debug(f"Stored data in database with key: {hotkey}")

        failed_uids = []

        def failure(uid):
            failed_uids.append(uid)

        await create_reward_vector(
            self, synapse, rewards, uids, responses, event, success, failure
        )
        event.rewards.extend(rewards.tolist())

        data_size = sys.getsizeof(b64_encoded_chunk)
        apply_reward_scores(
            self,
            uids=uids,
            responses=responses,
            rewards=rewards,
            data_sizes=[data_size] * len(responses),
        )

        bt.logging.debug(f"Updated reward scores: {rewards.tolist()}")

        # Determine the best UID based on rewards
        if event.rewards:
            best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
            event.best_uid = event.uids[best_index]
            event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

        chunk_size = sys.getsizeof(chunk)  # chunk size in bytes
        bt.logging.debug(f"chunk size: {chunk_size}")

        await store_chunk_metadata(
            full_hash,
            chunk_hash,
            [self.metagraph.hotkeys[uid] for uid in uids],
            chunk_size,  # this should be len(chunk) but we need to fix the chunking
            self.database,
        )

        return responses, b64_encoded_chunk, random_seed

    async def handle_uid_operations(
        uid, response, b64_encoded_chunk, random_seed, chunk_hash, chunk_size
    ):
        ss = time.time()
        start = time.time()

        # Offload the CPU-intensive verification to a separate thread
        verified = await asyncio.to_thread(
            verify_store_with_seed, response, b64_encoded_chunk, random_seed
        )

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
                ttl=ttl or self.config.neuron.data_ttl,
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
        bt.logging.debug(f"handle_uid_operations time for uid {uid} : {time.time()-ss}")

        return {"chunk_hash": chunk_hash, "uid": uid, "verified": verified}

    async def semaphore_query_miners(distributions):
        tasks = []
        async with semaphore:
            for i, dist in enumerate(distributions):
                bt.logging.trace(
                    f"Start index: {dist['start_idx']}, End index: {dist['end_idx']}"
                )
                chunk = encrypted_data[dist["start_idx"] : dist["end_idx"]]
                bt.logging.trace(f"chunk: {chunk[:12]}")
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
        results = await asyncio.gather(*tasks)
        # Grab the responses and relevant data necessary for verify from the results
        for i, result_group in enumerate(results):
            responses, b64_encoded_chunk, random_seed = result_group
            bt.logging.debug(f"-- responses_nested: {pformat(responses)}")
            bt.logging.debug(f"-- b64_encoded_chunk: {b64_encoded_chunk[:100]}")
            bt.logging.debug(f"-- random_seed: {random_seed}")

            # Update the distributions with responses
            distributions[i]["responses"] = responses
            distributions[i]["b64_encoded_chunk"] = b64_encoded_chunk
            distributions[i]["random_seed"] = random_seed

        return distributions

    async def semaphore_query_uid_operations(distributions):
        tasks = []
        for dist in distributions:
            chunk_hash = dist["chunk_hash"]
            chunk_size = dist["chunk_size"]
            random_seed = dist["random_seed"]
            b64_encoded_chunk = dist["b64_encoded_chunk"]
            for uid, response in zip(dist["uids"], dist["responses"]):
                task = asyncio.create_task(
                    handle_uid_operations(
                        uid,
                        response,
                        b64_encoded_chunk,
                        random_seed,
                        chunk_hash,
                        chunk_size,
                    )
                )
                tasks.append(task)
        uid_verified_dict_list = await asyncio.gather(*tasks)
        return uid_verified_dict_list

    async def create_initial_distributions(encrypted_data, R, k):
        dist_gen = compute_chunk_distribution_mut_exclusive_numpy_reuse_uids(
            self,
            data_size=sys.getsizeof(encrypted_data),
            R=R,
            k=k,
            exclude=exclude_uids,
        )
        # Ping first to see if we need to reroll instead of waiting for the timeout
        distributions = [dist async for dist in dist_gen]
        distributions = await compute_and_ping_chunks(self, distributions)
        return distributions

    bt.logging.debug(f"store_broadband() {encrypted_data[:100]}")

    full_hash = data_hash or generate_cid_string(encrypted_data)
    bt.logging.debug(f"full hash: {full_hash}")

    # Check and see if hash already exists, reject if so.
    if await get_ordered_metadata(full_hash, self.database):
        bt.logging.warning(f"Hash {full_hash} already exists on the network.")
        return full_hash

    exclude_uids = copy.deepcopy(exclude_uids)
    bt.logging.debug(f"Original exclude_uids: {exclude_uids}")

    # Remove failed UIDs from consideration in chunk distributions
    uids, failed_uids = await ping_and_retry_uids(
        self,
        k=50,
        max_retries=1,
        exclude_uids=exclude_uids,
    )
    bt.logging.debug(f"ping_and_retry_uids() failed uids: {failed_uids}")
    if exclude_uids is None:
        exclude_uids = []
    exclude_uids = exclude_uids + list(failed_uids)
    bt.logging.debug(f"Updated exclude_uids: {exclude_uids}")

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
            bt.logging.warning("Failed to create initial distributions, retrying...")
            retries += 1
        except Exception as e:
            bt.logging.warning(
                f"Failed to create initial distributions: {e}, retrying..."
            )
            retries += 1

    bt.logging.trace(f"computed distributions: {pformat(distributions)}")

    chunk_hashes = []
    # TODO: review is variable is needed
    retry_dists = [None]  # sentinel for first iteration
    retries = 0
    while len(distributions) > 0 and retries < 3:
        async with semaphore:
            # Store on the network: query miners for each chunk
            # Updated distributions now contain responses from the network
            updated_distributions = await semaphore_query_miners(distributions)
            # Verify the responses and store the metadata for each verified response
            verifications = await semaphore_query_uid_operations(updated_distributions)
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
                    failed_uids = [v["uid"] for v in verifications if not v["verified"]]
                    bt.logging.trace(f"failed uids: {pformat(failed_uids)}")
                    # Reroll distribution with failed UIDs
                    rerolled_dist = await reroll_distribution(self, dist, failed_uids)
                    bt.logging.trace(f"rerolled uids: {pformat(rerolled_dist['uids'])}")
                    # Replace the original distribution with the rerolled one
                    distributions.append(rerolled_dist)

        retries += 1

    # Update the chunk hash mapping for this entire file
    # TODO: change this to store_file_chunk_mapping_ordered
    # to append rather than overwrite
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
