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

import bittensor as bt

from storage.validator.config import config, check_config, add_args
from storage.validator.state import log_event
from storage.validator.bonding import compute_all_tiers
from storage.validator.reward import apply_reward_scores
from storage.validator.database import (
    total_network_storage,
    get_all_chunk_hashes,
    get_miner_statistics,
)

from .challenge import challenge_data
from .retrieve import retrieve_data
from .store import store_random_data
from .distribute import distribute_data
from .network import monitor


async def forward(self):
    bt.logging.info(f"forward step: {self.step}")

    try:
        # Store some random data
        bt.logging.info("initiating store random")
        event = await store_random_data(self)

        if self.config.neuron.verbose:
            bt.logging.debug(f"STORE EVENT LOG: {event}")

        # Log event
        log_event(self, event)

    except Exception as e:
        bt.logging.error(f"Failed to store random data: {e}")

    # Challenge every opportunity (e.g. every 2.5 blocks with 30 sec timeout)
    try:
        # Challenge some data
        bt.logging.info("initiating challenge")
        event = await challenge_data(self)

        if self.config.neuron.verbose:
            bt.logging.debug(f"CHALLENGE EVENT LOG: {event}")

        # Log event
        log_event(self, event)

    except Exception as e:
        bt.logging.error(f"Failed to challenge data: {e}")

    try:
        # Retrieve some data
        bt.logging.info("initiating retrieve")
        _, event = await retrieve_data(self)

        if self.config.neuron.verbose:
            bt.logging.debug(f"RETRIEVE EVENT LOG: {event}")

        # Log event
        log_event(self, event)

    except Exception as e:
        bt.logging.error(f"Failed to retrieve data: {e}")

    if self.step % self.config.neuron.distribute_step_length == 0:
        bt.logging.info("initiating distribute")
        try:
            await distribute_data(self, self.config.neuron.store_redundancy)

        except Exception as e:
            bt.logging.error(f"Failed to distribute data {e}")

    if self.step % self.config.neuron.monitor_step_length == 0:
        # Monitor all miner UIDs to see if they are still online.
        # After n failed pings consecutively, we rebalance the data.
        down_uids = await monitor(self)
        if len(down_uids) > 0:
            await rebalance_data(
                self,
                k=2,  # increase redundancy
                dropped_hotkeys=[self.metagraph.hotkeys[uid] for uid in down_uids],
            )

    try:
        # Update miner tiers
        bt.logging.info("Computing tiers")
        await compute_all_tiers(self.database)

        # Fetch miner statistics and usage data.
        stats = await get_miner_statistics(self.database)

        # Log all chunk hash <> hotkey pairs
        chunk_hash_map = await get_all_chunk_hashes(self.database)

        # Log the statistics and hashmap to wandb.
        if not self.config.wandb.off:
            self.wandb.log(stats)
            self.wandb.log(chunk_hash_map)

    except Exception as e:
        bt.logging.error(f"Failed to compute tiers: {e}")

    try:
        # Update the total network storage
        total_storage = await total_network_storage(self.database)
        bt.logging.info(f"Total network storage: {total_storage}")

        # Log the total storage to wandb.
        if not self.config.wandb.off:
            self.wandb.log({"total_storage": total_storage})

    except Exception as e:
        bt.logging.error(f"Failed to calculate total network storage: {e}")
