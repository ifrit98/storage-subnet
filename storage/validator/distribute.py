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


async def distribute_store(
    self,
    encrypted_data: bytes,
    uid: str,
):
    """
    Store encrypted data on a specific miner identified by hotkey.

    Parameters:
    - encrypted_data (bytes): The encrypted data to store.
    - uid (str): The uid of the miner where the data is to be stored.
    """
    # Prepare the synapse protocol for storing data

    g, h = setup_CRS()

    synapse = protocol.Store(
        encrypted_data=encrypted_data,
        curve=self.config.neuron.curve,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        seed=get_random_bytes(32).hex(),  # 256-bit seed
    )

    # Retrieve the axon for the specified miner
    axon = self.metagraph.axons[uid]

    # Send the store request to the miner
    response = await self.dendrite(
        [axon],
        synapse,
        deserialize=False,
        timeout=self.config.neuron.store_timeout,
    )

    # TODO: check if successful and error handle


async def distribute_retrieve(self, hotkey, data_hash, metadata):
    bt.logging.debug(f"distribute_retrieve data_hash: {data_hash[:10]} | {hotkey[:10]}")
    uid = self.metagraph.hotkeys.index(hotkey)
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

    verified = False
    try:
        verified = verify_retrieve_with_seed(response[0])
        if verified:
            metadata["prev_seed"] = synapse.seed
            await update_metadata_for_data_hash(
                hotkey, data_hash, metadata, self.database
            )

            bt.logging.trace(
                f"Updated metadata for UID: {uid} with data: {pformat(metadata)}"
            )

        else:
            bt.logging.error(f"Failed to verify distribute retrieve from UID: {uid}")

    except:
        bt.logging.error(f"Failed to verify distribute retrieve from UID: {uid}")

    return response, verified


async def distribute_data(self, k: int, dropped_hotkeys=[]):
    """
    Distribute data storage among miners by migrating data from a set of miners to others.

    Parameters:
    - k (int): The number of miners to query and distribute data from.
    - dropped_hotkeys (list of str): A list of hotkeys to re-add to the rebalancing process.

    Returns:
    - A report of the rebalancing process.
    """

    full_hashes = [key async for key in self.database.scan_iter("file:*")]
    full_hash = random.choice(full_hashes).decode("utf-8").split(":")[1]
    encryption_payload = await database.get(f"payload:{full_hash}")
    ordered_metadata = await get_ordered_metadata(full_hash, self.database)
    bt.logging.debug(f"distribute ordered metadata: {ordered_metadata}")

    # Get the hotkeys/uids to query
    tasks = []
    total_size = 0
    bt.logging.debug(f"ordered metadata: {pformat(ordered_metadata)}")
    # TODO: change this to use retrieve_mutually_exclusive_hotkeys_full_hash
    # to avoid possibly double querying miners for greater retrieval efficiency

    semaphore = asyncio.Semaphore(self.config.neuron.semaphore_size)

    async with semaphore:
        exclude_uids = set()
        for chunk_metadata in ordered_metadata:
            bt.logging.debug(f"chunk metadata: {chunk_metadata}")
            uids = [
                self.metagraph.hotkeys.index(hotkey)
                for hotkey in chunk_metadata["hotkeys"]
                if hotkey not in dropped_hotkeys  # ensure we use new miners
            ]
            # Collect all uids for later exclusion
            exclude_uids.update(uids)

            total_size += chunk_metadata["size"]
            tasks.append(
                asyncio.create_task(
                    retrieve_chunk_group(chunk_metadata["chunk_hash"], uids)
                )
            )
        responses = await asyncio.gather(*tasks)

        # Get the chunks from the responses
        chunks = {}
        for i, response_group in enumerate(responses):
            for response in response_group:
                if response.dendrite.status_code != 200:
                    bt.logging.debug(f"failed response: {response.dendrite.dict()}")
                    continue  # TODO: punish miners for failed responses
                if i not in list(chunks.keys()):
                    verified = verify_retrieve_with_seed(response)
                    if verified:
                        # Add to final chunks dict
                        bt.logging.debug(
                            f"Adding chunk {i} to chunks, size: {sys.getsizeof(response.data)}"
                        )
                        chunks[i] = base64.b64decode(response.data)
                        bt.logging.debug(f"chunk {i} | {chunks[i][:100]}")
                    else:
                        bt.logging.warning(
                            f"Failed to verify store commitment from UID: {uid}"
                        )
                        # TODO: punish failed verification

    bt.logging.trace(f"chunks after: {[chunk[:100] for chunk in chunks.values()]}")
    bt.logging.trace(f"len(chunks) after: {[len(chunk) for chunk in chunks.values()]}")

    # Pick random new UIDs
    self.store_broadband(
        b"".join(chunks.values()),
        encryption_payload=encryption_payload,
        exclude_uids=exclude_uids,
    )
