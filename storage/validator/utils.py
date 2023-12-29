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
import time
import torch
import functools
import numpy as np
import multiprocessing
import random as pyrandom

from math import comb
from Crypto.Random import random
from itertools import combinations, cycle
from typing import Dict, List, Any, Union, Optional, Tuple

from ..shared.ecc import hex_to_ecc_point, ecc_point_to_hex, hash_data, ECCommitment
from ..shared.merkle import MerkleTree
from ..validator.database import hotkey_at_capacity

import bittensor as bt


MIN_CHUNK_SIZE = 64 * 1024 * 1024  # 128 MB
MAX_CHUNK_SIZE = 512 * 1024 * 1024  # 512 MB


def chunk_data_generator(data, chunk_size):
    """
    Generator that yields chunks of data.

    Args:
        data (bytes): The data to be chunked.
        chunk_size (int): The size of each chunk in bytes.

    Yields:
        bytes: The next chunk of data.
    """
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


def generate_file_size_with_lognormal(
    mu: float = np.log(5 * 1024**2), sigma: float = 1.5
) -> float:
    """
    Generate a single file size using a lognormal distribution.
    Default parameters are set to model a typical file size distribution,
    but can be overridden for custom distributions.

    :param mu: Mean of the log values, default is set based on medium file size (20 MB).
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


# Determine a random chunksize between 512kb (random sample from this range) store as chunksize_E
def get_random_chunksize(minsize: int = 128, maxsize: int = 1024) -> int:
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


def ttl_cache(maxsize=128, ttl=10):
    """A simple TTL cache decorator for functions with a single argument."""

    def wrapper_cache(func):
        cache = functools.lru_cache(maxsize=maxsize)(func)
        last_time = time.time()

        @functools.wraps(func)
        def wrapped_func(*args, **kwargs):
            nonlocal last_time
            current_time = time.time()
            if current_time - last_time > ttl:
                cache.cache_clear()
                last_time = current_time
            return cache(*args, **kwargs)

        return wrapped_func

    return wrapper_cache


def current_block_hash(self):
    """
    Get the current block hash with caching.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the current block hash.

    Returns:
        str: The current block hash.
    """
    return self.subtensor.get_block_hash(self.subtensor.get_current_block())


def get_block_seed(self):
    """
    Get the block seed for the current block.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the block seed.

    Returns:
        int: The block seed.
    """
    block_hash = current_block_hash(self)
    bt.logging.trace(f"block hash in get_block_seed: {block_hash}")
    return int(block_hash, 16)


def get_pseudorandom_uids(self, uids, k):
    """
    Get a list of pseudorandom uids from the given list of uids.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the block_seed.
        uids (list): The list of uids to generate pseudorandom uids from.

    Returns:
        list: A list of pseudorandom uids.
    """
    block_seed = get_block_seed(self)
    pyrandom.seed(block_seed)

    # Ensure k is not larger than the number of uids
    k = min(k, len(uids))
    bt.logging.trace(f"uids: {uids} k: {k}")

    return pyrandom.sample(uids, k=k)


def get_available_uids(self, exclude: list = None):
    """Returns all available uids from the metagraph.

    Returns:
        uids (torch.LongTensor): All available uids.
    """
    avail_uids = []

    for uid in range(self.metagraph.n.item()):
        uid_is_available = check_uid_availability(
            self.metagraph, uid, self.config.neuron.vpermit_tao_limit
        )

        if uid_is_available and (exclude is None or uid not in exclude):
            avail_uids.append(uid)

    return avail_uids


# TODO: update this to use the block hash seed paradigm so that we don't get uids that are unavailable
def get_random_uids(
    self, k: int, exclude: List[int] = None, seed: int = None
) -> torch.LongTensor:
    """Returns k available random uids from the metagraph.
    Args:
        k (int): Number of uids to return.
        exclude (List[int]): List of uids to exclude from the random sampling.
    Returns:
        uids (torch.LongTensor): Randomly sampled available uids.
    Notes:
        If `k` is larger than the number of available `uids`, set `k` to the number of available `uids`.
    """
    candidate_uids = []
    avail_uids = []

    for uid in range(self.metagraph.n.item()):
        uid_is_available = check_uid_availability(
            self.metagraph, uid, self.config.neuron.vpermit_tao_limit
        )
        uid_is_not_excluded = exclude is None or uid not in exclude

        if uid_is_available and uid_is_not_excluded:
            candidate_uids.append(uid)
        elif uid_is_available:
            avail_uids.append(uid)

    # If not enough candidate_uids, supplement from avail_uids, ensuring they're not in exclude list
    if len(candidate_uids) < k:
        additional_uids_needed = k - len(candidate_uids)
        filtered_avail_uids = [uid for uid in avail_uids if uid not in exclude]
        additional_uids = random.sample(
            filtered_avail_uids, min(additional_uids_needed, len(filtered_avail_uids))
        )
        candidate_uids.extend(additional_uids)

    # Safeguard against trying to sample more than what is available
    num_to_sample = min(k, len(candidate_uids))
    if seed:  # use block hash seed if provided
        random.seed(seed)
    uids = random.sample(candidate_uids, num_to_sample)
    bt.logging.debug(f"returning available uids: {uids}")
    return uids


def get_all_validators(self, return_hotkeys=False):
    """
    Retrieve all validator UIDs from the metagraph. Optionally, return their hotkeys instead.

    Args:
        return_hotkeys (bool): If True, returns the hotkeys of the validators; otherwise, returns the UIDs.

    Returns:
        list: A list of validator UIDs or hotkeys, depending on the value of return_hotkeys.
    """
    # Determine validator axons to query from metagraph
    vpermits = self.metagraph.validator_permit
    vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
    vpermit_uids = torch.where(vpermits)[0]
    query_idxs = torch.where(
        self.metagraph.S[vpermit_uids] > self.config.neuron.vpermit_tao_limit
    )[0]
    query_uids = vpermit_uids[query_idxs].tolist()

    return (
        [self.metagraph.hotkeys[uid] for uid in query_uids]
        if return_hotkeys
        else query_uids
    )


def get_all_miners(self):
    """
    Retrieve all miner UIDs from the metagraph, excluding those that are validators.

    Returns:
        list: A list of UIDs of miners.
    """
    # Determine miner axons to query from metagraph
    vuids = get_all_validators(self)
    return [uid for uid in self.metagraph.uids.tolist() if uid not in vuids]


def get_query_miners(self, k=20, exlucde=None):
    """
    Obtain a list of miner UIDs selected pseudorandomly based on the current block hash.

    Args:
        k (int): The number of miner UIDs to retrieve.

    Returns:
        list: A list of pseudorandomly selected miner UIDs.
    """
    # Determine miner axons to query from metagraph with pseudorandom block_hash seed
    muids = get_all_miners(self)
    if exlucde is not None:
        muids = [muid for muid in muids if muid not in exlucde]
    return get_pseudorandom_uids(self, muids, k=k)


def get_query_validators(self, k=3):
    """
    Obtain a list of available validator UIDs selected pseudorandomly based on the current block hash.

    Args:
        k (int): The number of available miner UIDs to retreive.

    Returns:
        list: A list of pseudorandomly selected available validator UIDs
    """
    vuids = get_all_validators(self)
    return get_pseudorandom_uids(self, uids=vuids, k=k)


async def get_available_query_miners(self, k, exclude=None):
    """
    Obtain a list of available miner UIDs selected pseudorandomly based on the current block hash.

    Args:
        k (int): The number of available miner UIDs to retrieve.

    Returns:
        list: A list of pseudorandomly selected available miner UIDs.
    """
    # Determine miner axons to query from metagraph with pseudorandom block_hash seed
    muids = get_available_uids(self, exclude=exclude)
    muids_nonfull = [
        uid
        for uid in muids
        if not await hotkey_at_capacity(self.metagraph.hotkeys[uid], self.database)
    ]
    return get_pseudorandom_uids(self, muids, k=k)


def get_current_validator_uid_pseudorandom(self):
    """
    Retrieve a single validator UID selected pseudorandomly based on the current block hash.

    Returns:
        int: A pseudorandomly selected validator UID.
    """
    block_seed = get_block_seed(self)
    pyrandom.seed(block_seed)
    vuids = get_query_validators(self)
    return pyrandom.choice(vuids)


def get_current_validtor_uid_round_robin(self):
    """
    Retrieve a validator UID using a round-robin selection based on the current block and epoch length.

    Returns:
        int: The UID of the validator selected via round-robin.
    """
    vuids = get_all_validators(self)
    vidx = self.subtensor.get_current_block() // 100 % len(vuids)
    return vuids[vidx]


def generate_efficient_combinations(available_uids, R):
    """
    Generates all possible combinations of UIDs for a given redundancy factor.

    Args:
        available_uids (list): A list of UIDs that are available for storing data.
        R (int): The redundancy factor specifying the number of UIDs to be used for each chunk of data.

    Returns:
        list: A list of tuples, where each tuple contains a combination of UIDs.

    Raises:
        ValueError: If the redundancy factor is greater than the number of available UIDs.
    """

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    # Generate all combinations of available UIDs for the redundancy factor
    uid_combinations = list(combinations(available_uids, R))

    return uid_combinations


def assign_combinations_to_hashes_by_block_hash(self, hashes, combinations):
    """
    Assigns combinations of UIDs to each data chunk hash based on a pseudorandom seed derived from the blockchain's current block hash.

    Args:
        subtensor: The subtensor instance used to obtain the current block hash for pseudorandom seed generation.
        hashes (list): A list of hashes, where each hash represents a unique data chunk.
        combinations (list): A list of UID combinations, where each combination is a tuple of UIDs.

    Returns:
        dict: A dictionary mapping each chunk hash to a pseudorandomly selected combination of UIDs.

    Raises:
        ValueError: If there are not enough unique UID combinations for the number of data chunk hashes.
    """

    if len(hashes) > len(combinations):
        raise ValueError(
            "Not enough unique UID combinations for the given redundancy factor and number of hashes."
        )
    block_seed = get_block_seed(self)
    pyrandom.seed(block_seed)

    # Shuffle once and then iterate in order for assignment
    pyrandom.shuffle(combinations)
    return {hash_val: combinations[i] for i, hash_val in enumerate(hashes)}


def assign_combinations_to_hashes(hashes, combinations):
    """
    Assigns combinations of UIDs to each data chunk hash in a pseudorandom manner.

    Args:
        hashes (list): A list of hashes, where each hash represents a unique data chunk.
        combinations (list): A list of UID combinations, where each combination is a tuple of UIDs.

    Returns:
        dict: A dictionary mapping each chunk hash to a pseudorandomly selected combination of UIDs.

    Raises:
        ValueError: If there are not enough unique UID combinations for the number of data chunk hashes.
    """

    if len(hashes) > len(combinations):
        raise ValueError(
            "Not enough unique UID combinations for the given redundancy factor and number of hashes."
        )

    # Shuffle once and then iterate in order for assignment
    pyrandom.shuffle(combinations)
    return {hash_val: combinations[i] for i, hash_val in enumerate(hashes)}


def optimal_chunk_size(
    data_size,
    num_available_uids,
    R,
    min_chunk_size=MIN_CHUNK_SIZE,
    max_chunk_size=MAX_CHUNK_SIZE,
):
    """
    Determines the optimal chunk size for data distribution, taking into account the total data size,
    the number of available UIDs, and the desired redundancy factor. The function aims to balance
    the chunk size between specified minimum and maximum limits, considering the efficient utilization
    of UIDs and the number of chunks that can be created.

    Args:
        data_size (int): The total size of the data to be distributed, in bytes.
        num_available_uids (int): The number of available UIDs that can be assigned to data chunks.
        R (int): The redundancy factor, defining how many UIDs each data chunk should be associated with.
        min_chunk_size (int, optional): The minimum permissible size for each data chunk, in bytes.
                                        Defaults to a predefined MIN_CHUNK_SIZE.
        max_chunk_size (int, optional): The maximum permissible size for each data chunk, in bytes.
                                        Defaults to a predefined MAX_CHUNK_SIZE.

    Returns:
        int: The calculated optimal size for each data chunk, in bytes. The chunk size is optimized to
             ensure efficient distribution across the available UIDs while respecting the minimum
             and maximum chunk size constraints.

    Note:
        The optimal chunk size is crucial for balancing data distribution and storage efficiency in
        distributed systems or parallel processing scenarios. This function ensures that each chunk
        is large enough to be meaningful yet small enough to allow for diverse distribution across
        different UIDs, adhering to the specified redundancy factor.
    """
    # Estimate the number of chunks based on redundancy and available UIDs
    # Ensuring that we do not exceed the number of available UIDs
    max_chunks = num_available_uids // R

    # Calculate the ideal chunk size based on the estimated number of chunks
    if max_chunks > 0:
        ideal_chunk_size = data_size / max_chunks
    else:
        ideal_chunk_size = max_chunk_size

    # Ensure the chunk size is within the specified bounds
    chunk_size = max(min_chunk_size, min(ideal_chunk_size, max_chunk_size))

    # Return data size if smaller than chunk size
    if chunk_size > data_size:
        return data_size

    return int(chunk_size)


def compute_chunk_distribution(
    self, data, R, k, min_chunk_size=MIN_CHUNK_SIZE, max_chunk_size=MAX_CHUNK_SIZE
):
    """
    Computes the distribution of data chunks to UIDs for data distribution.

    Args:
        subtensor: The subtensor instance used to obtain the current block hash for pseudorandom seed generation.
        data (bytes): The data to be distributed.
        R (int): The redundancy factor for each data chunk.
        k (int): The number of UIDs to be used for each data chunk.
        min_chunk_size (int): The minimum size for each data chunk, in bytes.
        max_chunk_size (int): The maximum size for each data chunk, in bytes.

    Returns:
        dict: A dictionary mapping each chunk hash to a pseudorandomly selected combination of UIDs.
    """
    available_uids = get_random_uids(self, k=k)

    data_size = len(data)
    chunk_size = optimal_chunk_size(
        data_size, len(available_uids), R, min_chunk_size, max_chunk_size
    )

    # Ensure chunk size is not larger than data size
    if chunk_size > data_size:
        chunk_size = data_size
    uid_combinations = generate_efficient_combinations(available_uids, R)

    # Create a generator for chunking the data
    data_chunks = chunk_data_generator(data, chunk_size)

    # Use multiprocessing to process chunks in parallel
    block_seed = get_block_seed(self)

    # Pre-shuffle the UID combinations
    pyrandom.seed(block_seed)
    pyrandom.shuffle(uid_combinations)

    # Process each chunk and yield it's distribution of UIDs
    for i, chunk in enumerate(data_chunks):
        yield {hash_data(chunk): {"chunk": chunk, "uids": uid_combinations[i]}}


def partition_uids(available_uids, R):
    """
    Partitions the available UIDs into non-overlapping groups of size R.

    Args:
        available_uids (list): List of available UIDs.
        R (int): Size of each group (redundancy factor).

    Returns:
        list of tuples: A list where each tuple contains a unique group of UIDs.
    """
    return [tuple(available_uids[i : i + R]) for i in range(0, len(available_uids), R)]


def adjust_uids_to_multiple(available_uids, R):
    """
    Adjusts the list of available UIDs to ensure its length is a multiple of R.

    Args:
        available_uids (list): The original list of available UIDs.
        R (int): The redundancy factor.

    Returns:
        list: A modified list of UIDs with a length that is a multiple of R.
    """
    # Calculate the maximum number of complete groups of R that can be formed
    max_complete_groups = len(available_uids) // R

    # Adjust the list length to be a multiple of R
    adjusted_length = max_complete_groups * R
    return available_uids[:adjusted_length]


async def compute_chunk_distribution_mut_exclusive_numpy_reuse_uids_yield(
    self, data, R, k
):
    """
    Asynchronously computes and yields chunk distributions for given data, considering the redundancy
    factor and the number of query miners. This function splits the data into chunks, assigns a group
    of miners to each chunk, and handles redundancy by reusing UIDs when necessary.

    Parameters:
        data (bytes): The data to be distributed in chunks across the network.
        R (int): Redundancy factor indicating the number of times each chunk should be replicated.
        k (int): The number of unique identifiers (UIDs) or miners to be involved in the distribution.

    Yields:
        dict: A dictionary for each chunk containing its hash, the chunk data itself, and the UIDs of
              the miners assigned to it.

    Raises:
        ValueError: If the redundancy factor R is greater than the number of available UIDs.

    Note:
        - This function is essential for distributed storage systems where data needs to be stored
          redundantly across multiple nodes.
        - It ensures that each data chunk is stored by R different miners for redundancy.
        - The distribution of chunks takes into account the availability of miners and may reuse UIDs
          to meet the required redundancy factor.
        - The yielded chunks can be used to parallelize storage operations across the network.
    """
    available_uids = await get_available_query_miners(self, k=k)
    data_size = len(data)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)
    available_uids = adjust_uids_to_multiple(available_uids, R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    # Create initial UID groups
    initial_uid_groups = partition_uids(available_uids, R)
    uid_groups = list(initial_uid_groups)

    # If more groups are needed, start reusing UIDs
    total_chunks_needed = data_size // chunk_size
    while len(uid_groups) < total_chunks_needed:
        for group in cycle(initial_uid_groups):
            if len(uid_groups) >= total_chunks_needed:
                break
            uid_groups.append(group)

    data_chunks = chunk_data_generator(data, chunk_size)
    for chunk, uid_group in zip(data_chunks, uid_groups):
        chunk_hash = hash_data(chunk)
        yield {"chunk_hash": chunk_hash, "chunk": chunk, "uids": uid_group.tolist()}


def calculate_chunk_indices(data_size, chunk_size):
    """
    Calculate the start and end indices for each chunk.

    :param data_size: The total size of the data to be chunked.
    :param chunk_size: The chunk size.
    :return: A list of tuples, each tuple containing the start and end index of a chunk.
    """
    indices = []
    num_chunks = math.ceil(data_size / chunk_size)

    for i in range(num_chunks):
        start_idx = i * chunk_size
        end_idx = min(start_idx + chunk_size, data_size)
        indices.append((start_idx, end_idx))

        # Adjust the end index for the last chunk if necessary
        if i == num_chunks - 1 and end_idx < data_size:
            indices[-1] = (start_idx, data_size)

    return indices


def calculate_chunk_indices_from_num_chunks(data_size, num_chunks):
    """
    Calculate the start and end indices for each chunk.

    :param data_size: The total size of the data to be chunked.
    :param num_chunks: The desired number of chunks.
    :return: A list of tuples, each tuple containing the start and end index of a chunk.
    """
    chunk_size = max(1, data_size // num_chunks)  # Determine the size of each chunk
    indices = []

    for i in range(num_chunks):
        start_idx = i * chunk_size
        end_idx = min(start_idx + chunk_size, data_size)
        indices.append((start_idx, end_idx))

        # Adjust the end index for the last chunk if necessary
        if i == num_chunks - 1 and end_idx < data_size:
            indices[-1] = (start_idx, data_size)

    return indices


async def compute_chunk_distribution_mut_exclusive_numpy_reuse_uids(
    self, data_size, R, k, chunk_size=None, exclude=None
):
    """
    Asynchronously computes a distribution of data chunks across a set of unique identifiers (UIDs),
    taking into account redundancy and chunk size optimization. This function is useful for distributing
    data across a network of nodes or miners in a way that ensures redundancy and optimal utilization.

    Parameters:
        self: Reference to the class instance from which this method is called.
        data_size (int): The total size of the data to be distributed, in bytes.
        R (int): Redundancy factor, denoting the number of times each chunk should be replicated.
        k (int): The number of unique identifiers (UIDs) to be involved in the distribution.
        chunk_size (int, optional): The size of each data chunk. If not provided, an optimal chunk size
                                    is calculated based on the data size and the number of UIDs.

    Yields:
        dict: A dictionary representing a chunk's metadata, including its size, start index, end index,
              the UIDs assigned to it, and its index in the chunk sequence.

    Raises:
        ValueError: If the redundancy factor R is greater than the number of available UIDs.

    Note:
        - This function is designed to be used in distributed storage or processing systems where
          data needs to be split and stored across multiple nodes with redundancy.
        - It evenly divides the data into chunks and assigns UIDs to each chunk while ensuring that
          the redundancy requirements are met.
    """

    available_uids = await get_available_query_miners(self, k=k, exclude=exclude)
    chunk_size = chunk_size or optimal_chunk_size(data_size, len(available_uids), R)
    available_uids = adjust_uids_to_multiple(available_uids, R)
    chunk_indices = calculate_chunk_indices(data_size, chunk_size)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    # Create initial UID groups
    initial_uid_groups = partition_uids(available_uids, R)
    uid_groups = list(initial_uid_groups)

    # If more groups are needed, start reusing UIDs
    total_chunks_needed = data_size // chunk_size
    while len(uid_groups) < total_chunks_needed:
        for group in cycle(initial_uid_groups):
            if len(uid_groups) >= total_chunks_needed:
                break
            uid_groups.append(group)

    for i, ((start, end), uid_group) in enumerate(zip(chunk_indices, uid_groups)):
        yield {
            "chunk_size": chunk_size,
            "start_idx": start,
            "end_idx": end,
            "uids": uid_group,
            "chunk_index": i,
        }
