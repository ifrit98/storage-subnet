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
import base64
import typing
import asyncio
import bittensor as bt

from pprint import pformat
from Crypto.Random import get_random_bytes, random

from storage import protocol
from storage.validator.verify import (
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)
from storage.validator.database import (
    update_metadata_for_data_hash,
    get_ordered_metadata,
)

from .store import store_broadband
from .retrieve import retrieve_broadband


async def distribute_data(self, k: int):
    """
    Distribute data storage among miners by migrating data from a set of miners to others.

    Parameters:
    - k (int): The number of miners to query and distribute data from.

    Returns:
    - A report of the rebalancing process.
    """

    full_hashes = [key async for key in self.database.scan_iter("file:*")]
    if full_hashes == []:
        bt.logging.warning("No full hashes found, skipping distribute step.")
        return

    full_hash = random.choice(full_hashes).decode("utf-8").split(":")[1]
    encryption_payload = await self.database.get(f"payload:{full_hash}")
    ordered_metadata = await get_ordered_metadata(full_hash, self.database)

    # Get the hotkeys/uids to query
    bt.logging.debug(f"ordered metadata: {pformat(ordered_metadata)}")

    # TODO: Add proper error handling, try/excepts here
    # This is to get the hotkeys that already contain chunks for file
    # Such that we can exclude them from the subsequent call to store_broadband
    exclude_uids = set()
    for chunk_metadata in ordered_metadata:
        bt.logging.debug(f"chunk metadata: {chunk_metadata}")
        uids = [
            self.metagraph.hotkeys.index(hotkey)
            for hotkey in chunk_metadata["hotkeys"]
            if hotkey
            in self.metagraph.hotkeys  # TODO: make a more efficient check for this
        ]
        # Collect all uids for later exclusion
        exclude_uids.update(uids)

    # Use primitives to retrieve and store all the chunks:
    retrieved_data, retrieved_payload = await retrieve_broadband(self, full_hash)

    # Pick random new UIDs
    await store_broadband(
        self,
        retrieved_data,
        encryption_payload=retrieved_payload,
        exclude_uids=list(exclude_uids),
    )
