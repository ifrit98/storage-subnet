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

import torch
import typing
import bittensor as bt

from storage.validator.utils import get_available_query_miners
from storage.validator.bonding import update_statistics


async def ping_uids(self, uids):
    """
    Ping a list of UIDs to check their availability.
    Returns a tuple with a list of successful UIDs and a list of failed UIDs.
    """
    axons = [self.metagraph.axons[uid] for uid in uids]
    try:
        responses = await self.dendrite(
            axons,
            bt.Synapse(),
            deserialize=False,
            timeout=self.config.api.ping_timeout,
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
    except Exception as e:
        bt.logging.error(f"Dendrite ping failed: {e}")
        successful_uids = []
        failed_uids = uids
    bt.logging.debug("ping() successful uids:", successful_uids)
    bt.logging.debug("ping() failed uids    :", failed_uids)
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
            current_successful_uids, _ = await ping_uids(self, dist["uids"])
            successful_uids.update(current_successful_uids)

            # If enough UIDs are successful, select the first k items
            if len(successful_uids) >= target_number_of_uids:
                dist["uids"] = tuple(sorted(successful_uids)[:target_number_of_uids])
                break

            # Reroll for k UIDs excluding the successful ones
            new_uids = await get_available_query_miners(
                self, k=target_number_of_uids, exclude=successful_uids
            )
            bt.logging.trace("compute_and_ping_chunks() new uids:", new_uids)

            # Update the distribution with new UIDs
            dist["uids"] = tuple(new_uids)
            retries += 1

        # Log if the maximum retries are reached without enough successful UIDs
        if len(successful_uids) < target_number_of_uids:
            bt.logging.warning(
                f"compute_and_ping_chunks(): Insufficient successful UIDs for distribution: {dist}"
            )

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


async def ping_and_retry_uids(
    self, k: int = None, max_retries: int = 3, exclude_uids: typing.List[int] = []
):
    """
    Fetch available uids to minimize waiting for timeouts if they're going to fail anyways...
    """
    # Select initial subset of miners to query
    uids = await get_available_query_miners(
        self, k=k or self.config.neuron.store_redundancy, exclude=exclude_uids
    )
    bt.logging.debug("initial ping_and_retry() uids:", uids)

    retries = 0
    successful_uids = set()
    failed_uids = set()
    while len(successful_uids) < k and retries < max_retries:
        # Ping all UIDs
        current_successful_uids, current_failed_uids = await ping_uids(self, uids)
        successful_uids.update(current_successful_uids)
        failed_uids.update(current_failed_uids)

        # If enough UIDs are successful, select the first k items
        if len(successful_uids) >= k:
            uids = list(successful_uids)[:k]
            break

        # Reroll for k UIDs excluding the successful ones
        new_uids = await get_available_query_miners(
            self, k=k, exclude=list(successful_uids.union(failed_uids))
        )
        bt.logging.debug(f"ping_and_retry() new uids: {new_uids}")
        retries += 1

    # Log if the maximum retries are reached without enough successful UIDs
    if len(successful_uids) < k:
        bt.logging.warning(
            f"Insufficient successful UIDs for k: {k} Success UIDs {successful_uids} Failed UIDs: {failed_uids}"
        )

    return list(successful_uids)[:k], failed_uids


# Monitor all UIDs by ping and keep track of how many failures
async def monitor(self):
    """
    Monitor all UIDs by ping and keep track of how many failures
    occur. If a UID fails too many times, remove it from the
    list of UIDs to ping.
    """
    # Ping current subset of UIDs
    query_uids = await get_available_query_miners(
        self, k=self.config.neuron.monitor_sample_size
    )
    bt.logging.debug(f"monitor() uids: {query_uids}")
    _, failed_uids = await ping_uids(self, query_uids)

    down_uids = []
    for uid in failed_uids:
        self.monitor_lookup[uid] += 1
        if self.monitor_lookup[uid] > self.config.neuron.max_failed_pings:
            self.monitor_lookup[uid] = 0
            down_uids.append(uid)
    bt.logging.debug(f"monitor() down uids: {down_uids}")

    if down_uids:
        # Negatively reward
        rewards = torch.zeros(len(down_uids), dtype=torch.float32).to(self.device)

        for i, uid in enumerate(down_uids):
            await update_statistics(
                ss58_address=self.metagraph.hotkeys[uid],
                success=False,
                task_type="monitor",
                database=self.database,
            )
            rewards[i] = 0.0

        bt.logging.debug(f"monitor() rewards: {rewards}")
        scattered_rewards: torch.FloatTensor = self.moving_averaged_scores.scatter(
            0, torch.tensor(down_uids).to(self.device), rewards
        ).to(self.device)

        alpha: float = self.config.neuron.moving_average_alpha
        self.moving_averaged_scores: torch.FloatTensor = alpha * scattered_rewards + (
            1 - alpha
        ) * self.moving_averaged_scores.to(self.device)

    return down_uids
