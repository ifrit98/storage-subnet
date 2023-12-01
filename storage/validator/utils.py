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
import torch
import numpy as np
import multiprocessing
from math import comb
from itertools import combinations, cycle
from typing import Dict, List, Any, Union, Optional, Tuple

from Crypto.Random import random
import random as pyrandom

from ..shared.ecc import hex_to_ecc_point, ecc_point_to_hex, hash_data, ECCommitment
from ..shared.merkle import MerkleTree

import bittensor as bt


MIN_CHUNK_SIZE = 32 * 1024 * 1024  # 32 MB
MAX_CHUNK_SIZE = 256 * 1024 * 1024  # 256 MB


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
    mu: float = np.log(1 * 1024**2), sigma: float = 1.5
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


def current_block_hash(subtensor):
    """
    Get the current block hash.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the current block hash.

    Returns:
        str: The current block hash.
    """
    return subtensor.get_block_hash(subtensor.get_current_block())


def get_block_seed(subtensor):
    """
    Get the block seed for the current block.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the block seed.

    Returns:
        int: The block seed.
    """
    return int(current_block_hash(subtensor), 16)


def get_pseudorandom_uids(subtensor, uids, k=3):
    """
    Get a list of pseudorandom uids from the given list of uids.

    Args:
        subtensor (bittensor.subtensor.Subtensor): The subtensor instance to use for getting the block_seed.
        uids (list): The list of uids to generate pseudorandom uids from.

    Returns:
        list: A list of pseudorandom uids.
    """
    block_seed = get_block_seed(subtensor)
    pyrandom.seed(block_seed)

    # Ensure k is not larger than the number of uids
    k = min(k, len(uids))

    return pyrandom.sample(uids, k=k)


def get_avaialble_uids(self):
    """Returns all available uids from the metagraph.

    Returns:
        uids (torch.LongTensor): All available uids.
    """
    avail_uids = []

    for uid in range(self.metagraph.n.item()):
        uid_is_available = check_uid_availability(
            self.metagraph, uid, self.config.neuron.vpermit_tao_limit
        )

        if uid_is_available:
            avail_uids.append(uid)

    return avail_uids


def get_random_uids_OG(
    self, k: int, exclude: List[int] = [8, 9, 10, 11, 12, 13]
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

        if uid_is_available:
            avail_uids.append(uid)
            if uid_is_not_excluded:
                candidate_uids.append(uid)

    # Check if candidate_uids contain enough for querying, if not grab all avaliable uids
    available_uids = candidate_uids
    if len(candidate_uids) < k:
        available_uids += random.sample(
            [uid for uid in avail_uids if uid not in candidate_uids],
            k - len(candidate_uids),
        )
    uids = torch.tensor(random.sample(available_uids, k))
    bt.logging.debug(f"returning available uids: {uids}")
    return uids.tolist()


def get_random_uids(
    self, k: int, exclude: List[int] = [8, 9, 10, 11, 12, 13]
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
    uids = torch.tensor(random.sample(candidate_uids, num_to_sample))
    bt.logging.debug(f"returning available uids: {uids}")
    return uids.tolist()


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
    query_uids = vpermit_uids[query_idxs]

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
    return [uid.item() for uid in self.metagraph.uids if uid not in vuids]


def get_query_miners(self, k=3):
    """
    Obtain a list of miner UIDs selected pseudorandomly based on the current block hash.

    Args:
        k (int): The number of miner UIDs to retrieve.

    Returns:
        list: A list of pseudorandomly selected miner UIDs.
    """
    # Determine miner axons to query from metagraph with pseudorandom block_hash seed
    muids = get_all_miners(self)
    return get_pseudorandom_uids(self.subtensor, muids, k=k)


def get_available_query_miners(self, k=3):
    """
    Obtain a list of available miner UIDs selected pseudorandomly based on the current block hash.

    Args:
        k (int): The number of available miner UIDs to retrieve.

    Returns:
        list: A list of pseudorandomly selected available miner UIDs.
    """
    # Determine miner axons to query from metagraph with pseudorandom block_hash seed
    muids = get_avaialble_uids(self)
    return get_pseudorandom_uids(self.subtensor, muids, k=k)


def get_current_validator_uid_pseudorandom(self):
    """
    Retrieve a single validator UID selected pseudorandomly based on the current block hash.

    Returns:
        int: A pseudorandomly selected validator UID.
    """
    block_seed = get_block_seed(self.subtensor)
    pyrandom.seed(block_seed)
    vuids = get_query_validators(self)
    return pyrandom.choice(vuids).item()


def get_current_validtor_uid_round_robin(self, epoch_length=760):
    """
    Retrieve a validator UID using a round-robin selection based on the current block and a specified epoch length.

    Args:
        epoch_length (int): The length of an epoch, used to determine the validator index in a round-robin manner.

    Returns:
        int: The UID of the validator selected via round-robin.
    """
    vuids = get_all_validators(self)
    vidx = self.subtensor.get_current_block() // epoch_length % len(vuids)
    return vuids[vidx].item()


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


def assign_combinations_to_hashes_by_block_hash(subtensor, hashes, combinations):
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
    block_seed = get_block_seed(subtensor)
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

    return int(chunk_size)


def optimal_chunk_size2(data_size, num_available_uids, R):
    """
    Calculates an optimal chunk size for data distribution based on the total data size,
    the number of available UIDs, and the desired redundancy factor. This version of the
    function aims to balance the number of data chunks against the total number of
    unique combinations of UIDs that can be formed.

    Args:
        data_size (int): The total size of the data to be distributed, in bytes.
        num_available_uids (int): The total number of unique UIDs available for distribution.
        R (int): The desired redundancy factor, indicating how many UIDs are assigned to each chunk.

    Returns:
        int: The calculated optimal size for each data chunk, in bytes. If the calculated
             number of chunks is zero (indicating a very small data size), the function returns
             the entire data size.

    Note:
        This function is designed to ensure a balanced distribution of data across the available UIDs,
        considering the total number of possible unique combinations that can be formed with the UIDs.
    """
    total_combinations = comb(num_available_uids, R)
    max_chunks = min(data_size // MIN_CHUNK_SIZE, total_combinations)

    if max_chunks == 0:
        return data_size  # Return the entire data size if it's too small

    return data_size // max_chunks


def optimal_chunk_size3(
    data_size, num_available_uids, R, max_chunk_size=MAX_CHUNK_SIZE
):
    """
    Calculates an optimal chunk size for data distribution, aiming to maximize the chunk size
    while respecting a maximum limit. This function considers the total data size, the number of
    available UIDs, and the desired redundancy factor. The goal is to use the available UIDs
    efficiently by forming the maximum number of unique UID groups.

    Args:
        data_size (int): The total size of the data to be distributed, in bytes.
        num_available_uids (int): The total number of unique UIDs available for distribution.
        R (int): The desired redundancy factor, indicating how many UIDs are assigned to each chunk.
        max_chunk_size (int, optional): The maximum allowed size for each data chunk, in bytes.

    Returns:
        int: The calculated optimal size for each data chunk, in bytes. The chunk size is
             constrained by the maximum chunk size and is calculated to efficiently use
             the available UIDs for the specified redundancy factor.

    Note:
        This function is particularly useful for scenarios where the data size is large, and
        the goal is to maximize the utilization of each data chunk while ensuring each UID
        set is used efficiently and not more frequently than necessary.
    """
    # Calculate the maximum number of unique UID groups
    num_uid_groups = num_available_uids // R

    # Estimate the ideal chunk size based on the data size and the number of UID groups
    ideal_chunk_size = data_size / num_uid_groups

    # Ensure the chunk size is within the maximum limit
    chunk_size = min(ideal_chunk_size, max_chunk_size)

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
    block_seed = get_block_seed(self.subtensor)

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


def compute_chunk_distribution_mut_exclusive(self, data, R, k):
    """
    Computes and yields the distribution of data chunks across unique sets of UIDs, ensuring mutual exclusivity of UIDs across all chunks.

    Args:
        data (bytes): The data to be distributed across the network.
        R (int): The redundancy factor, indicating the number of unique UIDs per chunk.
        k (int): The total number of UIDs available for distribution.

    Yields:
        dict: A dictionary mapping each chunk's hash to its data and an assigned unique set of UIDs.

    Raises:
        ValueError: If the redundancy factor R is greater than the number of available UIDs, or if the available UIDs are not a multiple of R.
    """
    available_uids = get_random_uids(self, k=k)

    data_size = len(data)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)

    available_uids = adjust_uids_to_multiple(available_uids, R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    # Partition UIDs into exclusive groups
    uid_groups = partition_uids(available_uids, R)

    data_chunks = chunk_data_generator(data, chunk_size)

    for chunk, uid_group in zip(data_chunks, uid_groups):
        chunk_hash = hash_data(chunk)
        yield {chunk_hash: {"chunk": chunk, "uids": uid_group}}


def compute_chunk_distribution_mut_exclusive_numpy(self, data, R, k):
    """
    Similar to compute_chunk_distribution_mut_exclusive, but utilizes NumPy arrays for potentially more efficient handling of large lists of UIDs.

    Args:
        data (bytes): The data to be distributed across the network.
        R (int): The redundancy factor, indicating the number of unique UIDs per chunk.
        k (int): The total number of UIDs available for distribution.

    Yields:
        dict: A dictionary mapping each chunk's hash to its data and an assigned unique set of UIDs.

    Raises:
        ValueError: If the redundancy factor R is greater than the number of available UIDs, or if the available UIDs are not a multiple of R.
    """
    available_uids = get_random_uids(self, k=k)

    data_size = len(data)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)

    available_uids = adjust_uids_to_multiple(available_uids, R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    # Partition UIDs into exclusive groups
    uid_groups = partition_uids(available_uids, R)

    # Convert uid_groups to a more efficient numpy array if beneficial
    uid_groups = np.array(uid_groups)

    data_chunks = chunk_data_generator(data, chunk_size)

    for chunk, uid_group in zip(data_chunks, uid_groups):
        chunk_hash = hash_data(chunk)
        yield {"chunk_hash": chunk_hash, "chunk": chunk, "uids": uid_group.tolist()}


def compute_chunk_distribution_mut_exclusive_numpy_reuse_uids(self, data, R, k):
    available_uids = get_random_uids(self, k=k)
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

    # Convert uid_groups to a numpy array
    uid_groups = np.array(uid_groups)

    data_chunks = chunk_data_generator(data, chunk_size)
    for chunk, uid_group in zip(data_chunks, uid_groups):
        chunk_hash = hash_data(chunk)
        yield {"chunk_hash": chunk_hash, "chunk": chunk, "uids": uid_group.tolist()}


def compute_chunk_distribution_mut_exclusive_numpy_reuse_uids2(self, data_size, R, k):
    available_uids = get_random_uids(self, k=k)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)
    available_uids = adjust_uids_to_multiple(available_uids, R)
    chunk_sizes = [chunk_size] * (data_size - 1) + [data_size % chunk_size]

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
    for i, (chunk_size, uid_group) in enumerate(zip(chunk_sizes, uid_groups)):
        yield {
            "chunk_size": chunk_size,
            "start_idx": i * chunk_size,
            "end_idx": (i + 1) * chunk_size,
            "uids": uid_group,
        }


def compute_chunk_distribution_mut_exclusive_file(self, file_path, R, k):
    """
    Computes and yields the distribution of data chunks to UIDs directly from a file,
    ensuring mutually exclusive UID sets for each chunk.

    Args:
        file_path (str): The path to the file from which data chunks are to be read.
        R (int): The redundancy factor, defining the number of UIDs assigned to each chunk.
        k (int): The number of unique UIDs available for assignment.

    Yields:
        dict: A dictionary for each chunk with its hash, the chunk data, and the associated UIDs.

    Raises:
        ValueError: If the redundancy factor exceeds the number of available UIDs or if the
                    number of available UIDs is not a multiple of the redundancy factor.
    """
    available_uids = get_query_miners(self, k=k)

    # Getting the size of the file
    data_size = os.path.getsize(file_path)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)

    available_uids = adjust_uids_to_multiple(available_uids, R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    uid_groups = partition_uids(available_uids, R)

    # Read and process chunks from the file
    with open(file_path, "rb") as file:
        for uid_group in uid_groups:
            chunk = file.read(chunk_size)
            if not chunk:
                break  # End of file
            chunk_hash = hash_data(chunk)
            yield {chunk_hash: {"chunk": chunk, "uids": uid_group}}


def pre_process_chunk_distribution_file(self, file_path, R, k):
    """
    Pre-processes and returns metadata for each chunk of a file, including file path,
    start position, chunk size, and associated UIDs. This allows for efficient,
    on-demand loading of data chunks.

    Args:
        file_path (str): The path to the file to be processed.
        R (int): The redundancy factor, defining the number of UIDs assigned to each chunk.
        k (int): The number of unique UIDs available for assignment.

    Returns:
        list: A list of dictionaries, each containing metadata for a chunk of the file.
              Each dictionary includes the file path, start position, chunk size, and UIDs.

    Raises:
        ValueError: If the redundancy factor exceeds the number of available UIDs or if the
                    number of available UIDs is not a multiple of the redundancy factor.
    """
    available_uids = get_query_miners(self, k=k)

    data_size = os.path.getsize(file_path)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)

    available_uids = adjust_uids_to_multiple(available_uids, R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )

    uid_groups = partition_uids(available_uids, R)
    chunk_meta_data = []

    # Calculate the number of chunks and their metadata
    num_chunks = data_size // chunk_size + (1 if data_size % chunk_size != 0 else 0)
    for i in range(num_chunks):
        start_pos = i * chunk_size
        chunk_meta_data.append(
            {
                "start_pos": start_pos,
                "chunk_size": chunk_size,
                "uids": uid_groups[i % len(uid_groups)],
            }
        )

    return chunk_meta_data


def yield_chunk_distribution_file(self, file_path, R, k):
    """
    Yields metadata and UIDs for each chunk of a file, enabling efficient, on-demand data processing.
    This function calculates the distribution of data chunks across a set of UIDs, ensuring mutually exclusive UID sets
    for each chunk based on the file's size.

    Args:
        file_path (str): The path to the file from which data chunks will be processed.
        R (int): The redundancy factor, defining the number of UIDs to be associated with each data chunk.
        k (int): The total number of UIDs available for distribution across the chunks.

    Yields:
        tuple: A tuple for each chunk, containing a list of UIDs for the chunk and a dictionary
               with the chunk's metadata (file path, start position, and chunk size).

    Raises:
        ValueError: If the redundancy factor R is greater than the number of available UIDs or
                    if the available UIDs are not a multiple of R, ensuring exclusive distribution.

    Note:
        This function is designed for efficient handling of large files, as it computes and yields
        the chunk distribution without loading the entire file into memory. It is particularly useful
        for scenarios where data needs to be processed in segments and associated with unique sets
        of UIDs for tasks like distributed storage or parallel processing.
    """
    available_uids = get_query_miners(self, k=k)

    data_size = os.path.getsize(file_path)
    chunk_size = optimal_chunk_size(data_size, len(available_uids), R)

    if R > len(available_uids):
        raise ValueError(
            "Redundancy factor cannot be greater than the number of available UIDs."
        )
    if len(available_uids) % R != 0:
        raise ValueError(
            "Number of available UIDs must be a multiple of the redundancy factor R."
        )

    uid_groups = partition_uids(available_uids, R)

    # Calculate the number of chunks and their metadata
    num_chunks = data_size // chunk_size + (1 if data_size % chunk_size != 0 else 0)
    for i in range(num_chunks):
        start_pos = i * chunk_size
        chunk_meta = {
            "file_path": file_path,
            "start_pos": start_pos,
            "chunk_size": chunk_size,
        }
        yield uid_groups[i % len(uid_groups)], load_chunk(chunk_meta)


def load_chunk(chunk_meta):
    """
    Loads a specific data chunk from a file based on provided metadata.

    Args:
        chunk_meta (dict): A dictionary containing metadata for the chunk,
                           including the file path, start position, and chunk size.

    Returns:
        dict: A dictionary containing the loaded chunk data and its associated UIDs.
    """
    with open(chunk_meta["file_path"], "rb") as file:
        file.seek(chunk_meta["start_pos"])
        chunk_data = file.read(chunk_meta["chunk_size"])
        return {"chunk_data": chunk_data, "uids": chunk_meta["uids"]}
