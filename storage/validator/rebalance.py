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

import typing
import bittensor as bt

from pprint import pformat
from storage.validator.database import is_file_chunk, get_metadata_for_hotkey
from storage.validator.database import retrieve_encryption_payload

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
    try:
        source_uid = self.metagraph.hotkeys.index(source_hotkey)
    except Exception as e:
        bt.logging.warning(
            f"Distribute source hotkey {source_hotkey} already replaced in metagraph."
        )

    metadata = await get_metadata_for_hotkey(source_hotkey, self.database)

    miner_hashes = list(metadata)
    bt.logging.trace(f"miner hashes {miner_hashes[:5]}")

    rebalance_hashes = []
    for _hash in miner_hashes:
        if await is_file_chunk(_hash, self.database):
            rebalance_hashes.append(_hash)

    bt.logging.debug(f"rebalance hashes: {rebalance_hashes[:5]}")

    for _hash in rebalance_hashes:
        await rebalance_data_for_hash(self, data_hash=_hash, k=k)


async def rebalance_data_for_hash(self, data_hash: str, k: int):
    data, event = await retrieve_data(self, data_hash)

    payload = await retrieve_encryption_payload(data_hash, self.database)

    await store_encrypted_data(self, data, payload, k=k)


async def rebalance_data(self, k: int = 2, dropped_hotkeys: typing.List[str] = []):
    if isinstance(dropped_hotkeys, str):
        dropped_hotkeys = [dropped_hotkeys]

    for hotkey in dropped_hotkeys:
        await rebalance_data_for_hotkey(self, k, hotkey)
