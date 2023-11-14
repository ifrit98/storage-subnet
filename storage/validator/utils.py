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
import math
import numpy as np
from typing import Dict, List, Any, Union, Optional, Tuple

from Crypto.Random import random

from ..shared.ecc import hex_to_ecc_point, ecc_point_to_hex, hash_data, ECCommitment
from ..shared.merkle import MerkleTree

import bittensor as bt


def generate_file_size_with_lognormal(
    mu: float = np.log(10 * 1024**2), sigma: float = 1.5
) -> float:
    """
    Generate a single file size using a lognormal distribution.
    Default parameters are set to model a typical file size distribution,
    but can be overridden for custom distributions.

    :param mu: Mean of the log values, default is set based on medium file size (10 MB).
    :param sigma: Standard deviation of the log values, default is set to 1.5.
    :return: File size in bytes.
    """

    # Generate a file size using the lognormal distribution
    file_size = np.random.lognormal(mean=mu, sigma=sigma)

    # Scale the file size to a realistic range (e.g., bytes)
    scaled_file_size = int(file_size)

    return scaled_file_size


def make_random_file(name: str = None, maxsize: int = None) -> Union[bytes, str]:
    """
    Creates a file with random binary data or returns a bytes object with random data if no name is provided.

    Args:
        name (str, optional): The name of the file to create. If None, the function returns the random data instead.
        maxsize (int): The maximum size of the file or bytes object to be created, in bytes. Defaults to 1024.

    Returns:
        bytes: If 'name' is not provided, returns a bytes object containing random data.
        None: If 'name' is provided, a file is created and returns the filepath stored.

    Raises:
        OSError: If the function encounters an error while writing to the file.
    """
    size = (
        random.randint(random.randint(24, 128), maxsize)
        if maxsize != None
        else generate_file_size_with_lognormal()
    )
    data = os.urandom(size)
    if isinstance(name, str):
        with open(name, "wb") as fout:
            fout.write(data)
        return name  # Return filepath of saved data
    else:
        return data  # Return the data itself


# Determine a random chunksize between 24kb-512kb (random sample from this range) store as chunksize_E
def get_random_chunksize(minsize: int = 24, maxsize: int = 512) -> int:
    """
    Determines a random chunk size within a specified range for data chunking.

    Args:
        maxsize (int): The maximum size limit for the random chunk size. Defaults to 128.

    Returns:
        int: A random chunk size between 2kb and 'maxsize' kilobytes.

    Raises:
        ValueError: If maxsize is set to a value less than 2.
    """
    return random.randint(minsize, maxsize)


def get_sorted_response_times(uids, responses):
    """
    Sorts a list of axons based on their response times.

    This function pairs each uid with its corresponding axon's response time,
    and then sorts this list in ascending order. Lower response times are considered better.

    Args:
        uids (List[int]): List of unique identifiers for each axon.
        responses (List[Response]): List of Response objects corresponding to each axon.

    Returns:
        List[Tuple[int, float]]: A sorted list of tuples, where each tuple contains an axon's uid and its response time.

    Example:
        >>> get_sorted_response_times([1, 2, 3], [response1, response2, response3])
        [(2, 0.1), (1, 0.2), (3, 0.3)]
    """
    axon_times = [
        (
            uids[idx],
            response.axon.process_time if response.axon.process_time != None else 100,
        )
        for idx, response in enumerate(responses)
    ]
    # Sorting in ascending order since lower process time is better
    bt.logging.debug(f"axon_times: {axon_times}")
    sorted_axon_times = sorted(axon_times, key=lambda x: x[1])
    bt.logging.debug(f"sorted_axon_times: {sorted_axon_times}")
    return sorted_axon_times


def scale_rewards_by_response_time(uids, responses, rewards):
    sorted_axon_times = get_sorted_response_times(uids, responses)

    # Extract only the process times
    process_times = [proc_time for _, proc_time in sorted_axon_times]

    # Find min and max values for normalization, avoid division by zero
    min_time = min(process_times)
    max_time = max(process_times) if max(process_times) > min_time else min_time + 1

    # Normalize these times to a scale of 0 to 1 (inverted)
    normalized_scores = [
        (max_time - proc_time) / (max_time - min_time) for proc_time in process_times
    ]

    # Create a mapping from uid to its normalized score
    uid_to_normalized_score = {
        uid: normalized_score
        for (uid, _), normalized_score in zip(sorted_axon_times, normalized_scores)
    }

    # Scale the rewards by these normalized scores
    for i, uid in enumerate(uids):
        rewards[i] += rewards[i] * uid_to_normalized_score.get(uid, 0)

    return rewards


def check_uid_availability(
    metagraph: "bt.metagraph.Metagraph", uid: int, vpermit_tao_limit: int
) -> bool:
    """Check if uid is available. The UID should be available if it is serving and has less than vpermit_tao_limit stake
    Args:
        metagraph (:obj: bt.metagraph.Metagraph): Metagraph object
        uid (int): uid to be checked
        vpermit_tao_limit (int): Validator permit tao limit
    Returns:
        bool: True if uid is available, False otherwise
    """
    # Filter non serving axons.
    if not metagraph.axons[uid].is_serving:
        return False
    # Filter validator permit > 1024 stake.
    if metagraph.validator_permit[uid]:
        if metagraph.S[uid] > vpermit_tao_limit:
            return False
    # Available otherwise.
    return True


def select_subset_uids(uids: List[int], N: int):
    """Selects a random subset of uids from a list of uids.
    Args:
        uids (List[int]): List of uids to select from.
        N (int): Number of uids to select.
    Returns:
        List[int]: List of selected uids.
    """
    # If N is greater than the number of uids, return all uids.
    if N >= len(uids):
        return uids
    # Otherwise, randomly select N uids from the list.
    else:
        return random.sample(uids, N)
