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


async def handle_challenge(self, uid: int) -> typing.Tuple[bool, protocol.Challenge]:
    """
    Handles a challenge sent to a miner and verifies the response.

    Parameters:
    - uid (int): The UID of the miner being challenged.

    Returns:
    - Tuple[bool, protocol.Challenge]: A tuple containing the verification result and the challenge.
    """
    hotkey = self.metagraph.hotkeys[uid]
    keys = await self.database.hkeys(f"hotkey:{hotkey}")
    bt.logging.trace(f"{len(keys)} hashes pulled for hotkey {hotkey}")
    if keys == []:
        # Create a dummy response to send back
        dummy_response = protocol.Challenge(
            challenge_hash="",
            chunk_size=0,
            g="",
            h="",
            curve="",
            challenge_index=0,
            seed="",
        )
        return None, [dummy_response]  # no data found associated with this miner hotkey

    data_hash = random.choice(keys).decode("utf-8")
    data = await get_metadata_for_hotkey_and_hash(hotkey, data_hash, self.database)

    if self.config.neuron.verbose:
        bt.logging.trace(f"Challenge lookup key: {data_hash}")
        bt.logging.trace(f"Challenge data: {data}")

    try:
        chunk_size = (
            self.config.neuron.override_chunk_size
            if self.config.neuron.override_chunk_size > 0
            else get_random_chunksize(
                minsize=self.config.neuron.min_chunk_size,
                maxsize=max(
                    self.config.neuron.min_chunk_size,
                    data["size"] // self.config.neuron.chunk_factor,
                ),
            )
        )
    except:
        bt.logging.error(
            f"Failed to get chunk size {self.config.neuron.min_chunk_size} | {self.config.neuron.chunk_factor} | {data['size'] // self.config.neuron.chunk_factor}"
        )
        chunk_size = 0

    num_chunks = (
        data["size"] // chunk_size if data["size"] > chunk_size else data["size"]
    )
    if self.config.neuron.verbose:
        bt.logging.trace(f"challenge data size : {data['size']}")
        bt.logging.trace(f"challenge chunk size: {chunk_size}")
        bt.logging.trace(f"challenge num chunks: {num_chunks}")

    # Setup new Common-Reference-String for this challenge
    g, h = setup_CRS()

    synapse = protocol.Challenge(
        challenge_hash=data_hash,
        chunk_size=chunk_size,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        curve="P-256",
        challenge_index=random.choice(range(num_chunks)),
        seed=get_random_bytes(32).hex(),
    )

    axon = self.metagraph.axons[uid]

    response = await self.dendrite(
        [axon],
        synapse,
        deserialize=True,
        timeout=self.config.neuron.challenge_timeout,
    )
    verified = verify_challenge_with_seed(response[0])

    if verified:
        data["prev_seed"] = synapse.seed
        await update_metadata_for_data_hash(hotkey, data_hash, data, self.database)

    # Record the time taken for the challenge
    return verified, response


async def challenge_data(self):
    """
    Initiates a series of challenges to miners, verifying their data storage through the network's consensus mechanism.

    Asynchronously challenge and see who returns the data fastest (passes verification), and rank them highest
    """

    event = EventSchema(
        task_name="Challenge",
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
    )

    start_time = time.time()
    tasks = []
    uids = await get_available_query_miners(
        self, k=self.config.neuron.challenge_sample_size
    )
    bt.logging.debug(f"challenge uids {uids}")
    responses = []
    for uid in uids:
        tasks.append(asyncio.create_task(handle_challenge(self, uid)))
    responses = await asyncio.gather(*tasks)

    if self.config.neuron.verbose and self.config.neuron.log_responses:
        [
            bt.logging.trace(
                f"Challenge response {uid} | {pformat(response[0].axon.dict())}"
            )
            for uid, response in zip(uids, responses)
        ]

    # Compute the rewards for the responses given the prompt.
    rewards: torch.FloatTensor = torch.zeros(len(responses), dtype=torch.float32).to(
        self.device
    )

    for idx, (uid, (verified, response)) in enumerate(zip(uids, responses)):
        if self.config.neuron.verbose:
            bt.logging.trace(
                f"Challenge idx {idx} uid {uid} verified {verified} response {pformat(response[0].axon.dict())}"
            )

        hotkey = self.metagraph.hotkeys[uid]

        if verified == None:
            continue  # We don't have any data for this hotkey, skip it.

        # Update the challenge statistics
        await update_statistics(
            ss58_address=hotkey,
            success=verified,
            task_type="challenge",
            database=self.database,
        )

        # Apply reward for this challenge
        tier_factor = await get_tier_factor(hotkey, self.database)
        rewards[idx] = 1.0 * tier_factor if verified else -0.1 * tier_factor

        # Log the event data for this specific challenge
        event.uids.append(uid)
        event.successful.append(verified)
        event.completion_times.append(response[0].dendrite.process_time)
        event.task_status_messages.append(response[0].dendrite.status_message)
        event.task_status_codes.append(response[0].dendrite.status_code)
        event.rewards.append(rewards[idx].item())

    # Calculate the total step length for all challenges
    event.step_length = time.time() - start_time

    responses = [response[0] for (verified, response) in responses]
    bt.logging.trace("Applying challenge rewards")
    apply_reward_scores(
        self,
        uids,
        responses,
        rewards,
        timeout=self.config.neuron.challenge_timeout,
        mode="minmax",
    )

    # Determine the best UID based on rewards
    if event.rewards:
        best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
        event.best_uid = event.uids[best_index]
        event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

    return event
