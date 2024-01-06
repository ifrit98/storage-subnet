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
import time
import torch
import base64
import typing
import asyncio
import bittensor as bt

from pprint import pformat
from Crypto.Random import get_random_bytes, random

from storage import protocol
from storage.validator.event import EventSchema
from storage.shared.ecc import hash_data
from storage.shared.utils import (
    b64_encode,
    b64_decode,
    chunk_data,
    safe_key_search,
)
from storage.validator.verify import verify_retrieve_with_seed
from storage.validator.reward import apply_reward_scores
from storage.validator.database import (
    get_metadata_for_hotkey,
    get_metadata_for_hotkey_and_hash,
    update_metadata_for_data_hash,
    get_ordered_metadata,
    retrieve_encryption_payload,
)
from storage.validator.encryption import decrypt_data_with_private_key
from storage.validator.bonding import update_statistics, get_tier_factor

from .network import ping_and_retry_uids
from .reward import create_reward_vector


async def handle_retrieve(self, uid):
    bt.logging.trace(f"handle_retrieve uid: {uid}")
    hotkey = self.metagraph.hotkeys[uid]
    keys = await self.database.hkeys(f"hotkey:{hotkey}")

    if keys == []:
        bt.logging.warning(
            f"handle_retrieve() No data found for uid: {uid} | hotkey: {hotkey}"
        )
        # Create a dummy response to send back
        return None, ""

    data_hash = random.choice(keys).decode("utf-8")
    bt.logging.trace(f"handle_retrieve() data_hash: {data_hash}")

    data = await get_metadata_for_hotkey_and_hash(
        hotkey, data_hash, self.database, self.config.neuron.verbose
    )
    axon = self.metagraph.axons[uid]

    synapse = protocol.Retrieve(
        data_hash=data_hash,
        seed=get_random_bytes(32).hex(),
    )
    response = await self.dendrite(
        [axon],
        synapse,
        deserialize=False,
        timeout=self.config.neuron.retrieve_timeout,
    )

    try:
        bt.logging.trace(f"Fetching AES payload from UID: {uid}")

        # Load the data for this miner from validator storage
        data = await get_metadata_for_hotkey_and_hash(
            hotkey, data_hash, self.database, self.config.neuron.verbose
        )

        # If we reach here, this miner has passed verification. Update the validator storage.
        data["prev_seed"] = synapse.seed
        await update_metadata_for_data_hash(hotkey, data_hash, data, self.database)
        bt.logging.trace(f"Updated metadata for UID: {uid} with data: {pformat(data)}")
        # TODO: get a temp link from the server to send back to the client instead

    except Exception as e:
        bt.logging.error(
            f"Failed to retrieve data from UID {uid} | hotkey {hotkey} with error: {e}"
        )

    return response[0], data_hash, synapse.seed


async def retrieve_data(
    self, data_hash: str = None
) -> typing.Tuple[bytes, typing.Callable]:
    """
    Retrieves and verifies data from the network, ensuring integrity and correctness of the data associated with the given hash.

    Parameters:
        data_hash (str): The hash of the data to be retrieved.

    Returns:
        The retrieved data if the verification is successful.
    """

    # Initialize event schema
    event = EventSchema(
        task_name="Retrieve",
        successful=[],
        completion_times=[],
        task_status_messages=[],
        task_status_codes=[],
        block=self.subtensor.get_current_block(),
        uids=[],
        step_length=0.0,
        best_uid=-1,
        best_hotkey="",
        rewards=[],
        set_weights=[],
    )

    start_time = time.time()

    uids, _ = await ping_and_retry_uids(
        self, k=self.config.neuron.challenge_sample_size
    )

    # Ensure that each UID has data to retreive. If not, skip it.
    uids = [
        uid
        for uid in uids
        if await get_metadata_for_hotkey(self.metagraph.hotkeys[uid], self.database)
        != {}
    ]
    bt.logging.debug(f"retrieve() UIDs to query   : {uids}")
    bt.logging.debug(
        f"retrieve() Hotkeys to query: {[self.metagraph.hotkeys[uid] for uid in uids]}"
    )

    tasks = []
    for uid in uids:
        tasks.append(asyncio.create_task(handle_retrieve(self, uid)))
    response_tuples = await asyncio.gather(*tasks)

    if self.config.neuron.verbose and self.config.neuron.log_responses:
        [
            bt.logging.trace(
                f"Retrieve response: {uid} | {pformat(response.dendrite.dict())}"
            )
            for uid, (response, _, _) in zip(uids, response_tuples)
        ]
    rewards: torch.FloatTensor = torch.zeros(
        len(response_tuples), dtype=torch.float32
    ).to(self.device)

    decoded_data = b""
    for idx, (uid, (response, data_hash, seed)) in enumerate(
        zip(uids, response_tuples)
    ):
        hotkey = self.metagraph.hotkeys[uid]

        if response == None:
            bt.logging.debug(f"No response: skipping retrieve for uid {uid}")
            continue  # We don't have any data for this hotkey, skip it.

        try:
            decoded_data = base64.b64decode(response.data)
        except Exception as e:
            bt.logging.error(
                f"Failed to decode data from UID: {uids[idx]} with error {e}"
            )
            rewards[idx] = 0.0

            # Update the retrieve statistics
            await update_statistics(
                ss58_address=hotkey,
                success=False,
                task_type="retrieve",
                database=self.database,
            )
            continue

        if str(hash_data(decoded_data)) != data_hash:
            bt.logging.error(
                f"Hash of received data does not match expected hash! {str(hash_data(decoded_data))} != {data_hash}"
            )
            rewards[idx] = 0.0

            # Update the retrieve statistics
            await update_statistics(
                ss58_address=hotkey,
                success=False,
                task_type="retrieve",
                database=self.database,
            )
            continue

        success = verify_retrieve_with_seed(response, seed)
        if not success:
            bt.logging.error(
                f"data verification failed! {pformat(response.axon.dict())}"
            )
            rewards[idx] = 0.0  # Losing use data is unacceptable, harsh punishment

            # Update the retrieve statistics
            await update_statistics(
                ss58_address=hotkey,
                success=False,
                task_type="retrieve",
                database=self.database,
            )
            continue  # skip trying to decode the data
        else:
            # Success. Reward based on miner tier
            bt.logging.trace("Getting tier factor for hotkey {}".format(hotkey))
            tier_factor = await get_tier_factor(hotkey, self.database)
            rewards[idx] = 1.0 * tier_factor

            bt.logging.trace("Updating success retreival for hotkey {}".format(hotkey))
            await update_statistics(
                ss58_address=hotkey,
                success=True,
                task_type="retrieve",
                database=self.database,
            )

        event.uids.append(uid)
        event.successful.append(success)
        event.completion_times.append(time.time() - start_time)
        event.task_status_messages.append(response.dendrite.status_message)
        event.task_status_codes.append(response.dendrite.status_code)
        event.rewards.append(rewards[idx].item())

    bt.logging.trace("Applying retrieve rewards")
    bt.logging.debug(f"retrieve() rewards: {rewards}")
    apply_reward_scores(
        self,
        uids,
        [response_tuple[0] for response_tuple in response_tuples],
        rewards,
        timeout=self.config.neuron.retrieve_timeout,
        mode="minmax",
    )

    # Determine the best UID based on rewards
    if event.rewards:
        best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
        event.best_uid = event.uids[best_index]
        event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

    return decoded_data, event


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
        bt.logging.debug(f"Updated reward scores: {rewards.tolist()}")

        apply_reward_scores(
            self,
            uids,
            responses,
            rewards,
            timeout=self.config.neuron.retrieve_timeout,
            mode="minmax",
        )

        # Determine the best UID based on rewards
        if event.rewards:
            best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
            event.best_uid = event.uids[best_index]
            event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

        return responses, synapse.seed

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
                if hotkey
                in self.metagraph.hotkeys  # TODO: more efficient check for this
            ]
            total_size += chunk_metadata["size"]
            tasks.append(
                asyncio.create_task(
                    retrieve_chunk_group(chunk_metadata["chunk_hash"], uids)
                )
            )
        responses = await asyncio.gather(*tasks)

        chunks = {}
        # TODO: make these asyncio tasks and use .to_thread() to avoid blocking
        for i, (response_group, seed) in enumerate(responses):
            for response in response_group:
                if response.dendrite.status_code != 200:
                    bt.logging.debug(f"failed response: {response.dendrite.dict()}")
                    continue
                verified = verify_retrieve_with_seed(response, seed)
                if verified:
                    # Add to final chunks dict
                    if i not in list(chunks.keys()):
                        bt.logging.debug(
                            f"Adding chunk {i} to chunks, size: {sys.getsizeof(response.data)}"
                        )
                        chunks[i] = base64.b64decode(response.data)
                        bt.logging.debug(f"chunk {i} | {chunks[i][:10]}")
                else:
                    uid = self.metagraph.hotkeys.index(response.axon.hotkey)
                    bt.logging.error(
                        f"Failed to verify store commitment from UID: {uid}"
                    )

    bt.logging.trace(f"chunks after: {[chunk[:12] for chunk in chunks.values()]}")
    bt.logging.trace(f"len(chunks) after: {[len(chunk) for chunk in chunks.values()]}")

    # Reconstruct the data
    encrypted_data = b"".join(chunks.values())
    bt.logging.trace(f"retrieved data: {encrypted_data[:12]}")

    # Retrieve user encryption payload (if exists)
    encryption_payload = await retrieve_encryption_payload(full_hash, self.database)
    bt.logging.debug(f"retrieved encryption_payload: {encryption_payload}")

    return encrypted_data, encryption_payload
