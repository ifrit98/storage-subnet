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
from itertools import combinations, cycle
from typing import Dict, List, Any, Union, Optional, Tuple

from Crypto.Random import random
import random as pyrandom

from ..shared.ecc import hex_to_ecc_point, ecc_point_to_hex, hash_data, ECCommitment
from ..shared.merkle import MerkleTree

import bittensor as bt


MIN_CHUNK_SIZE = 32 * 1024 * 1024  # 32 MB
MAX_CHUNK_SIZE = 256 * 1024 * 1024  # 256 MB


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


def get_random_uids(self, k: int, exclude: List[int] = None) -> torch.LongTensor:
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
    return [uid.item() for uid in metagraph.uids if uid not in vuids]


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
    Calculates the optimal chunk size for data distribution based on the total data size, available UIDs, and redundancy factor.

    Args:
        data_size (int): The total size of the data to be distributed, in bytes.
        min_chunk_size (int): The minimum size for each data chunk, in bytes.
        max_chunk_size (int): The maximum size for each data chunk, in bytes.
        num_available_uids (int): The number of available UIDs for data storage.
        R (int): The redundancy factor for each data chunk.

    Returns:
        int: The optimal size for each data chunk, in bytes.
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


def compute_chunk_distribution(
    subtensor, data, R, k, min_chunk_size=MIN_CHUNK_SIZE, max_chunk_size=MAX_CHUNK_SIZE
):
    """
    Distributes data across the network by dividing it into chunks, hashing each chunk, and assigning UID combinations to each chunk for storage.
    Additionally, returns a comprehensive mapping of each data chunk, its hash, and the assigned UIDs.

    Args:
        data (bytes): The data to be distributed across the network.
        R (int): The redundancy factor for each data chunk.
        k (int): The number of UIDs to consider for combinations.
        min_chunk_size (int, optional): The minimum size for each data chunk. Defaults to MIN_CHUNK_SIZE.
        max_chunk_size (int, optional): The maximum size for each data chunk. Defaults to MAX_CHUNK_SIZE.

    Returns:
        dict: A comprehensive mapping of each data chunk's hash to its data and assigned combination of UIDs for storage.
    """

    # Step 1: Get all available UIDs
    available_uids = [
        "uid" + str(i) for i in range(k)
    ]  # get_available_query_miners(self, k)

    # Step 2: Select optimal chunk size
    data_size = len(data)
    chunk_size = optimal_chunk_size(
        data_size, len(available_uids), min_chunk_size, max_chunk_size, R
    )

    # Step 3: Chunk the data
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    # Step 4: Hash each chunk
    chunk_hashes = [hash_data(chunk) for chunk in chunks]

    # Step 5: Generate efficient combinations
    uid_combinations = generate_efficient_combinations(available_uids, R)

    # Step 6: Assign combinations to each chunk hash
    chunk_distribution = assign_combinations_to_hashes_by_block_hash(
        subtensor, chunk_hashes, uid_combinations
    )

    # Create a comprehensive mapping of chunk data, hash, and UID distribution
    comprehensive_distribution = {
        hash_val: {
            "chunk_data": chunks[i],
            "uid_combination": chunk_distribution[hash_val],
        }
        for i, hash_val in enumerate(chunk_hashes)
    }

    return comprehensive_distribution
