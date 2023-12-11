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
        timeout=self.config.neuron.ping_timeout,
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

        while len(successful_uids) < target_number_of_uids and retries < max_retries:
            # Ping all UIDs
            current_successful_uids, _ = await self.ping_uids(dist["uids"])
            successful_uids.update(current_successful_uids)

            # If enough UIDs are successful, select the first k items
            if len(successful_uids) >= target_number_of_uids:
                dist["uids"] = tuple(sorted(successful_uids)[:target_number_of_uids])
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
            bt.logging.warning(f"Insufficient successful UIDs for distribution: {dist}")

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
