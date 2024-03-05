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
import csv
import json
import time
import bittensor as bt

from pprint import pformat
from storage.validator.state import log_event
from storage.validator.bonding import compute_all_tiers
from storage.validator.database import (
    total_validator_storage,
    get_all_chunk_hashes,
    get_miner_statistics,
    purge_expired_ttl_keys,
    purge_challenges_for_all_hotkeys,
)
from storage.validator.state import save_state
from storage.validator.utils import get_current_epoch

from .challenge import challenge_data
from .retrieve import retrieve_data
from .rebalance import rebalance_data
from .store import store_random_data
from .distribute import distribute_data
from .network import monitor


async def forward(self):
    bt.logging.info(f"forward step: {self.step}")

    # Record forward time
    start = time.time()

    # Store some random data
    bt.logging.info("initiating store random")
    event = await store_random_data(self)

    # Log store event
    log_event(self, event)

    # Challenge every opportunity (e.g. every 2.5 blocks with 30 sec timeout)
    bt.logging.info("initiating challenge")
    event = await challenge_data(self)

    # Log event
    log_event(self, event)

    if self.step % 5 == 0:
        # Retrieve some data
        bt.logging.info("initiating retrieve")
        _, event = await retrieve_data(self)

        # Log event
        log_event(self, event)

    if self.step % 10 == 0:
        # Distribute data
        bt.logging.info("initiating distribute")
        await distribute_data(self, 4)

    # Monitor every step
    down_uids = await monitor(self)
    if len(down_uids) > 0:
        bt.logging.info(f"Downed uids marked for rebalance: {down_uids}")
        await rebalance_data(
            self,
            k=2,  # increase redundancy
            dropped_hotkeys=[self.metagraph.hotkeys[uid] for uid in down_uids],
            hotkey_replaced=False,  # Don't delete challenge data (only in subscription handler)
        )

    # Purge all challenge data to start fresh and avoid requerying hotkeys with stale challenge data
    current_epoch = get_current_epoch(self.subtensor)
    bt.logging.info(
        f"Current epoch: {current_epoch} | Last purged epoch: {self.last_purged_epoch}"
    )
    if current_epoch % 10 == 0:
        if self.last_purged_epoch < current_epoch:
            bt.logging.info("initiating challenges purge")
            await purge_challenges_for_all_hotkeys(self.database)
            self.last_purged_epoch = current_epoch
            save_state(self)

    # Purge expired TTL keys
    if self.step % 60 == 0:
        bt.logging.info("initiating TTL purge for expired keys")
        await purge_expired_ttl_keys(self.database)

    if self.subtensor.get_current_block() % 1080 == 0 and self.step > 0:
        bt.logging.info("initiating compute stats")
        await compute_all_tiers(self.database)

        # Update miner statistics and usage data.
        stats = await get_miner_statistics(self.database)
        bt.logging.debug(f"miner stats: {pformat(stats)}")

        # Log all chunk hash <> hotkey pairs
        chunk_hash_map = await get_all_chunk_hashes(self.database)

        # Log the statistics, storage, and hashmap to wandb.
        if not self.config.wandb.off and self.wandb is not None:
            with open(self.config.neuron.miner_stats_path, "w") as file:
                json.dump(stats, file)

            self.wandb.save(self.config.neuron.miner_stats_path)

            with open(self.config.neuron.hash_map_path, "w") as file:
                json.dump(chunk_hash_map, file)

            self.wandb.save(self.config.neuron.hash_map_path)

            # Also upload the total network storage periodically
            self.wandb.save(self.config.neuron.total_storage_path)

    # Update the total network storage
    total_storage = await total_validator_storage(self.database)
    bt.logging.info(f"Total validator storage (GB): {int(total_storage) // (1024**3)}")

    # Get the current local time
    current_time = time.localtime()

    # Format the time in a readable format, for example: "Year-Month-Day Hour:Minute:Second"
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", current_time)

    total_storage_time = {
        "total_storage": total_storage,
        "timestamp": formatted_time,
    }

    # Check if the CSV already exists
    file_exists = os.path.isfile(self.config.neuron.total_storage_path)

    # Open the CSV file in append mode
    with open(self.config.neuron.total_storage_path, "a", newline="") as csvfile:
        # Define the field names
        fieldnames = ["total_storage", "timestamp"]

        # Create a writer object specifying the field names
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write the header only if the file is being created
        if not file_exists:
            writer.writeheader()

        # Write the data row
        writer.writerow(total_storage_time)

    forward_time = time.time() - start
    bt.logging.info(f"forward step time: {forward_time:.2f}s")
