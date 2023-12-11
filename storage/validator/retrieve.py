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
import bittensor as bt

from loguru import logger
from pprint import pformat
from functools import partial
from pyinstrument import Profiler
from traceback import print_exception
from random import choice as random_choice
from Crypto.Random import get_random_bytes, random

from dataclasses import asdict
from storage.validator.event import EventSchema

from storage import protocol

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
    safe_key_search,
)

from storage.validator.utils import (
    make_random_file,
    get_random_chunksize,
    check_uid_availability,
    get_random_uids,
    get_query_miners,
    get_query_validators,
    get_available_query_miners,
    get_current_validtor_uid_round_robin,
)

from storage.validator.encryption import (
    decrypt_data,
    encrypt_data,
)

from storage.validator.verify import (
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)

from storage.validator.config import config, check_config, add_args

from storage.validator.state import (
    should_checkpoint,
    checkpoint,
    should_reinit_wandb,
    reinit_wandb,
    load_state,
    save_state,
    init_wandb,
    ttl_get_block,
    log_event,
)

from storage.validator.reward import apply_reward_scores

from storage.validator.weights import (
    should_set_weights,
    set_weights,
)

from storage.validator.database import (
    add_metadata_to_hotkey,
    get_miner_statistics,
    get_metadata_for_hotkey,
    total_network_storage,
    store_chunk_metadata,
    store_file_chunk_mapping_ordered,
    get_metadata_for_hotkey_and_hash,
    update_metadata_for_data_hash,
    get_all_chunk_hashes,
    get_ordered_metadata,
    hotkey_at_capacity,
    get_miner_statistics,
)

from storage.validator.bonding import (
    miner_is_registered,
    update_statistics,
    get_tier_factor,
    compute_all_tiers,
)


async def handle_retrieve(self, uid):
    bt.logging.debug(f"handle_retrieve uid: {uid}")
    hotkey = self.metagraph.hotkeys[uid]
    keys = await self.database.hkeys(f"hotkey:{hotkey}")

    if keys == []:
        bt.logging.warning(f"No data found for uid: {uid} | hotkey: {hotkey}")
        # Create a dummy response to send back
        return None, ""

    data_hash = random.choice(keys).decode("utf-8")
    bt.logging.debug(f"handle_retrieve data_hash: {data_hash}")

    data = await get_metadata_for_hotkey_and_hash(hotkey, data_hash, self.database)
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
        data = await get_metadata_for_hotkey_and_hash(hotkey, data_hash, self.database)

        # If we reach here, this miner has passed verification. Update the validator storage.
        data["prev_seed"] = synapse.seed
        await update_metadata_for_data_hash(hotkey, data_hash, data, self.database)
        bt.logging.trace(f"Updated metadata for UID: {uid} with data: {pformat(data)}")
        # TODO: get a temp link from the server to send back to the client instead

    except Exception as e:
        bt.logging.error(f"Failed to retrieve data from UID: {uid} with error: {e}")

    return response[0], data_hash


async def retrieve_data(
    self, data_hash: str = None, yield_event: bool = True
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

    uids = await get_available_query_miners(
        self, k=self.config.neuron.challenge_sample_size
    )

    # Ensure that each UID has data to retreive. If not, skip it.
    uids = [
        uid
        for uid in uids
        if await get_metadata_for_hotkey(self.metagraph.hotkeys[uid], self.database)
        != {}
    ]
    bt.logging.debug(f"UIDs to query   : {uids}")
    bt.logging.debug(
        f"Hotkeys to query: {[self.metagraph.hotkeys[uid][:5] for uid in uids]}"
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
            for uid, (response, _) in zip(uids, response_tuples)
        ]
    rewards: torch.FloatTensor = torch.zeros(
        len(response_tuples), dtype=torch.float32
    ).to(self.device)

    for idx, (uid, (response, data_hash)) in enumerate(zip(uids, response_tuples)):
        hotkey = self.metagraph.hotkeys[uid]

        if response == None:
            continue  # We don't have any data for this hotkey, skip it.

        try:
            decoded_data = base64.b64decode(response.data)
        except Exception as e:
            bt.logging.error(
                f"Failed to decode data from UID: {uids[idx]} with error {e}"
            )
            rewards[idx] = -0.1

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
                f"Hash of recieved data does not match expected hash! {str(hash_data(decoded_data))} != {data_hash}"
            )
            rewards[idx] = -0.1

            # Update the retrieve statistics
            await update_statistics(
                ss58_address=hotkey,
                success=False,
                task_type="retrieve",
                database=self.database,
            )
            continue

        success = verify_retrieve_with_seed(response)
        if not success:
            bt.logging.error(
                f"data verification failed! {pformat(response.axon.dict())}"
            )
            rewards[idx] = -0.1  # Losing use data is unacceptable, harsh punishment

            # Update the retrieve statistics
            bt.logging.trace(f"Updating retrieve statistics for {hotkey}")
            await update_statistics(
                ss58_address=hotkey,
                success=False,
                task_type="retrieve",
                database=self.database,
            )
            continue  # skip trying to decode the data
        else:
            # Success. Reward based on miner tier
            tier_factor = await get_tier_factor(hotkey, self.database)
            rewards[idx] = 1.0 * tier_factor

        event.uids.append(uid)
        event.successful.append(success)
        event.completion_times.append(time.time() - start_time)
        event.task_status_messages.append(response.dendrite.status_message)
        event.task_status_codes.append(response.dendrite.status_code)
        event.rewards.append(rewards[idx].item())

    bt.logging.trace("Applying retrieve rewards")
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

    return event
