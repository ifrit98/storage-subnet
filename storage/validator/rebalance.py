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
    is_file_chunk,
)

from storage.validator.bonding import (
    miner_is_registered,
    update_statistics,
    get_tier_factor,
    compute_all_tiers,
)


from .retrieve import retrieve_data
from .store import store_encrypted_data


async def rebalance_data_for_hotkey(self, k: int, source_hotkey: str):
    """
    TODO: This might take a while, would be better to run in a separate process/thread
    rather than block other validator duties?

    Get all data from a given miner/hotkey and rebalance it to other miners.

    (1) Get all data from a given miner/hotkey.
    (2) Find out which chunks belong to full files, ignore the rest (challenges)
    (3) Distribute the data that belongs to full files to other miners.

    """

    source_uid = self.metagraph.uids.index(source_hotkey)

    metadata = await get_metadata_for_hotkey(source_hotkey, self.database)

    miner_hashes = list(metadata)
    bt.logging.debug(f"miner hashes {miner_hashes[:5]}")

    rebalance_hashes = []
    for _hash in miner_hashes:
        if await is_file_chunk(_hash, self.database):
            rebalance_hashes.append(_hash)

    bt.logging.debug(f"rebalance hashes: {rebalance_hashes[:5]}")

    for _hash in rebalance_hashes:
        await rebalance_data_for_hash(
            self, data_hash=_hash, dropped_uid=source_uid, k=k
        )


async def rebalance_data_for_hash(self, data_hash: str, dropped_uid: int, k: int):
    data, _ = await retrieve_data(self, data_hash)
    await store_encrypted_data(self, data, k=k, exclude_uids=[dropped_uid])


async def rebalance_data(self, k: int = 2, dropped_hotkeys: typing.List[str] = []):
    if isinstance(dropped_hotkeys, str):
        dropped_hotkeys = [dropped_hotkeys]

    for hotkey in dropped_hotkeys:
        await rebalance_data_for_hotkey(self, k, hotkey)
