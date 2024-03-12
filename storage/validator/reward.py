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
import numpy as np
import bittensor as bt
from bittensor import Synapse
from typing import Union, List
from functools import partial
from pprint import pformat

from storage.validator.verify import (
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)
from storage.validator.bonding import update_statistics, get_tier_factor
from storage.validator.event import EventSchema

from storage.constants import (
    STORE_FAILURE_REWARD,
    RETRIEVAL_FAILURE_REWARD,
    CHALLENGE_FAILURE_REWARD,
)
from storage.protocol import Store, Retrieve, Challenge


def adjusted_sigmoid(x, steepness=1, shift=0):
    """
    Adjusted sigmoid function.

    This function is a modified version of the sigmoid function that is shifted
    to the right by a certain amount.
    """
    return 1 / (1 + np.exp(-steepness * (x - shift)))


def adjusted_sigmoid_inverse(x, steepness=1, shift=0):
    """
    Inverse of the adjusted sigmoid function.

    This function is a modified version of the sigmoid function that is shifted to
    the right by a certain amount but inverted such that low completion times are
    rewarded and high completions dimes are punished.
    """
    return 1 / (1 + np.exp(steepness * (x - shift)))


def calculate_sigmoid_params(timeout):
    """
    Calculate sigmoid parameters based on the timeout value.

    Args:
    - timeout (float): The current timeout value.

    Returns:
    - tuple: A tuple containing the 'steepness' and 'shift' values for the current timeout.
    """
    base_timeout = 1
    base_steepness = 7
    base_shift = 0.3

    # Calculate the ratio of the current timeout to the base timeout
    ratio = timeout / base_timeout

    # Calculate steepness and shift based on the pattern
    steepness = base_steepness / ratio
    shift = base_shift * ratio

    return steepness, shift


def get_sorted_response_times(uids, responses, max_time: float):
    """
    Sorts a list of axons based on their response times.

    This function pairs each uid with its corresponding axon's response time,
    and then sorts this list in ascending order. Lower response times are considered better.

    Args:
        uids (List[int]): List of unique identifiers for each axon.
        responses (List[Response]): List of Response objects corresponding to each axon.
        max_time (float): The maximum response time for the current batch of axons.

    Returns:
        List[Tuple[int, float]]: A sorted list of tuples, where each tuple contains an axon's uid and its response time.

    Example:
        >>> get_sorted_response_times([1, 2, 3], [response1, response2, response3])
        [(2, 0.1), (1, 0.2), (3, 0.3)]
    """
    axon_times = [
        (
            uids[idx],
            response.dendrite.process_time
            if response.dendrite.process_time is not None
            else max_time,
        )
        for idx, response in enumerate(responses)
    ]
    # Sorting in ascending order since lower process time is better
    sorted_axon_times = sorted(axon_times, key=lambda x: x[1])
    bt.logging.debug(f"sorted_axon_times: {sorted_axon_times}")
    return sorted_axon_times


def sigmoid_normalize(process_times, max_time):
    # Center the completion times around 0 for effective sigmoid scaling
    centered_times = process_times - np.mean(process_times)

    # Calculate steepness and shift based on maximum time in the batch
    steepness, shift = calculate_sigmoid_params(max_time)

    # Apply adjusted sigmoid function to scale the times
    return adjusted_sigmoid_inverse(centered_times, steepness, shift)


def scale_rewards(
    uids, responses, rewards, data_sizes: List[float], device
):
    """
    Scales the rewards for each axon based on their response times using sigmoid normalization.
    Args:
        uids (List[int]): A list of unique identifiers for each axon.
        responses (List[Response]): A list of Response objects corresponding to each axon.
        rewards (List[float]): A list of initial reward values for each axon.
        data_sizes (List[int]): A list of data sizes corresponding to each axon.

    Returns:
        List[float]: A list of scaled rewards for each axon.
    """
    max_time = max(
        [
            response.dendrite.process_time for response in responses
            if response.dendrite.process_time is not None
        ] or [1] # nobody responded successfully
    )

    sorted_axon_times = get_sorted_response_times(uids, responses, max_time=max_time)

    # Extract only the process times
    process_times = [proc_time for _, proc_time in sorted_axon_times]

    # Apply logarithmic scaling to data sizes
    bt.logging.trace(f"Unnormalized data sizes: {data_sizes}")
    log_data_sizes_np = np.log1p(data_sizes)
    bt.logging.trace(f"Logarithmically scaled data sizes: {log_data_sizes_np}")

    # Normalize the response times by data size (unit time)
    data_normalized_process_times = np.asarray(np.array(process_times) / log_data_sizes_np)

    # Normalize the response times
    normalized_times = sigmoid_normalize(data_normalized_process_times, max(data_normalized_process_times))

    # Create a dictionary mapping UIDs to normalized times
    uid_to_normalized_time = {
        uid: normalized_time
        for (uid, _), normalized_time in zip(sorted_axon_times, normalized_times)
    }

    # Scale the data size-scaled rewards with normalized times
    time_scaled_rewards = torch.tensor(
        [   # tier reward * latency based normalized reward
            rewards[i] * uid_to_normalized_time[uid]
            for i, uid in enumerate(uids)
        ]
    )

    # Final normalization if needed
    rescale_factor = torch.sum(rewards) / torch.sum(time_scaled_rewards)
    bt.logging.trace(f"Rescale factor: {rescale_factor}")
    scaled_rewards = [reward * rescale_factor for reward in time_scaled_rewards]

    return scaled_rewards


def apply_reward_scores(
    self,
    uids,
    responses,
    rewards,
    data_sizes: List[float],
):
    """
    Adjusts the moving average scores for a set of UIDs based on their response times and reward values.

    This should reflect the distribution of axon response times

    Parameters:
        uids (List[int]): A list of UIDs for which rewards are being applied.
        responses (List[Response]): A list of response objects received from the nodes.
        rewards (torch.FloatTensor): A tensor containing the computed reward values.
        data_sizes (List[float]): The size of each data piece used for the forward pass.
    """
    if self.config.neuron.verbose:
        bt.logging.debug(f"Applying rewards: {rewards}")
        bt.logging.debug(f"Reward shape: {rewards.shape}")
        bt.logging.debug(f"UIDs: {uids}")

    # Scale rewards based on response times
    scaled_rewards = scale_rewards(
        uids,
        responses,
        rewards,
        data_sizes=data_sizes,
        device=self.device,
    )
    scaled_rewards = torch.tensor(scaled_rewards).type(
        torch.FloatTensor
    )  # Ensure same type as rewards
    bt.logging.debug(f"Normalized rewards: {scaled_rewards}")

    # Compute forward pass rewards
    # shape: [ metagraph.n ]
    scattered_rewards: torch.FloatTensor = (
        self.moving_averaged_scores.to(self.device)
        .scatter(
            0,
            torch.tensor(uids).to(self.device),
            scaled_rewards.to(self.device),
        )
        .to(self.device)
    )
    bt.logging.trace(f"Scattered rewards: {scattered_rewards}")

    # Update moving_averaged_scores with rewards produced by this step.
    # shape: [ metagraph.n ]
    alpha: float = 0.05
    self.moving_averaged_scores: torch.FloatTensor = alpha * scattered_rewards + (
        1 - alpha
    ) * self.moving_averaged_scores.to(self.device)
    bt.logging.trace(f"Updated moving avg scores: {self.moving_averaged_scores}")


async def create_reward_vector(
    self,
    synapse: Union[Store, Retrieve, Challenge],
    rewards: torch.FloatTensor,
    uids: List[int],
    responses: List[Synapse],
    event: EventSchema,
    callback: callable,
    fail_callback: callable,
):
    # Determine if the commitment is valid
    success = False
    if isinstance(synapse, Store):
        verify_fn = partial(
            verify_store_with_seed,
            b64_encrypted_data=synapse.encrypted_data,
            seed=synapse.seed,
        )
        task_type = "store"
        failure_reward = STORE_FAILURE_REWARD
    elif isinstance(synapse, Retrieve):
        verify_fn = partial(verify_retrieve_with_seed, seed=synapse.seed)
        task_type = "retrieve"
        failure_reward = RETRIEVAL_FAILURE_REWARD
    elif isinstance(synapse, Challenge):
        verify_fn = partial(verify_challenge_with_seed, seed=synapse.seed)
        task_type = "challenge"
        failure_reward = CHALLENGE_FAILURE_REWARD
    else:
        raise ValueError(f"Invalid synapse type: {type(synapse)}")

    times = [
        response.dendrite.process_time or synapse.timeout
        for response in responses
    ]
    bt.logging.debug(f"Dendrite Times: {times}")
    sorted_times = sorted(list(zip(uids, times)), key=lambda x: x[1])

    bt.logging.debug(f"Sorted Times: {sorted_times}")
    in_top_2_dict = {
        uid: True if time < synapse.timeout else False
        for (uid, time) in sorted_times[:2]
    }
    bt.logging.debug(f"Is Top 2 Dict: {pformat(in_top_2_dict)}")

    for idx, (uid, response) in enumerate(zip(uids, responses)):
        # Verify the commitment
        hotkey = self.metagraph.hotkeys[uid]

        # Determine if the commitment is valid
        success = verify_fn(synapse=response)
        if success:
            bt.logging.debug(
                f"Successfully verified {synapse.__class__} commitment from UID: {uid} | hotkey: {hotkey}"
            )
            await callback(hotkey, idx, uid, response)
        else:
            bt.logging.error(
                f"Failed to verify {synapse.__class__} commitment from UID: {uid} | hotkey: {hotkey}"
            )
            fail_callback(uid)

        # Update the storage statistics
        await update_statistics(
            ss58_address=hotkey,
            success=success,
            task_type=task_type,
            database=self.database,
        )

        # Apply reward for this task
        tier_factor = await get_tier_factor(
            hotkey, self.database, in_top_2=in_top_2_dict.get(uid, False)
        )
        rewards[idx] = 1.0 * tier_factor if success else failure_reward * tier_factor

        event.successful.append(success)
        event.uids.append(uid)
        event.completion_times.append(response.dendrite.process_time)
        event.task_status_messages.append(response.dendrite.status_message)
        event.task_status_codes.append(response.dendrite.status_code)
