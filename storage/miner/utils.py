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
import json
import time
import shutil
import storage
import wandb
import copy
import asyncio
import multiprocessing
import bittensor as bt
from collections import deque

from ..shared.ecc import (
    ecc_point_to_hex,
    hash_data,
)
from ..shared.merkle import (
    MerkleTree,
)


def commit_data_with_seed(committer, data_chunks, n_chunks, seed):
    """
    Commits chunks of data with a seed using a Merkle tree structure to create a proof of
    integrity for each chunk. This function is used in environments where the integrity
    and order of data need to be verifiable.

    Parameters:
    - committer: The committing object, which should have a commit method.
    - data_chunks (list): A list of data chunks to be committed.
    - n_chunks (int): The number of chunks expected to be committed.
    - seed: A seed value that is combined with data chunks before commitment.

    Returns:
    - randomness (list): A list of randomness values associated with each data chunk's commitment.
    - chunks (list): The list of original data chunks that were committed.
    - points (list): A list of commitment points in hex format.
    - merkle_tree (MerkleTree): A Merkle tree constructed from the commitment points.

    This function handles the conversion of commitment points to hex format and adds them to the
    Merkle tree. The completed tree represents the combined commitments.
    """
    merkle_tree = MerkleTree()

    # Commit each chunk of data
    randomness, chunks, points = [None] * n_chunks, [None] * n_chunks, [None] * n_chunks
    for index, chunk in enumerate(data_chunks):
        c, m_val, r = committer.commit(chunk + str(seed).encode())
        c_hex = ecc_point_to_hex(c)
        randomness[index] = r
        chunks[index] = chunk
        points[index] = c_hex
        merkle_tree.add_leaf(c_hex)

    # Create the tree from the leaves
    merkle_tree.make_tree()
    return randomness, chunks, points, merkle_tree


def save_data_to_filesystem(data, directory, hotkey, filename):
    """
    Saves data to the filesystem at the specified directory and filename. If the directory does
    not exist, it is created.

    Parameters:
    - data: The data to be saved.
    - directory (str): The directory path where the data should be saved.
    - hotkey (str): The hotkey associated with the data.
    - filename (str): The name of the file to save the data in.

    Returns:
    - file_path (str): The full path to the saved file.

    This function is useful for persisting data to the disk.
    """
    # Ensure the directory exists
    directory = os.path.join(os.path.expanduser(directory), hotkey)
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, filename)
    with open(file_path, "wb") as file:
        file.write(data)
    return file_path


def load_from_filesystem(filepath):
    """
    Loads data from a file in the filesystem.

    Parameters:
    - filepath (str): The path to the file from which data is to be loaded.

    Returns:
    - data: The data read from the file.

    This function is a straightforward utility for reading binary data from a file.
    """
    with open(os.path.expanduser(filepath), "rb") as file:
        data = file.read()
    return data


def compute_subsequent_commitment(data, previous_seed, new_seed, verbose=False):
    """
    Computes a new commitment based on provided data and a change from an old seed to a new seed.
    This function is typically used in cryptographic operations to update commitments without
    altering the underlying data.

    Parameters:
    - data: The original data for which the commitment is being updated.
    - previous_seed: The seed used in the previous commitment.
    - new_seed: The seed to be used for the new commitment.
    - verbose (bool): If True, additional debug information will be printed. Defaults to False.

    Returns:
    - A tuple containing the new commitment and the proof of the old commitment.

    If verbose is set to True, debug information about the types and contents of the parameters
    will be printed to aid in debugging.
    """
    if verbose:
        bt.logging.debug("IN COMPUTE SUBESEQUENT COMMITMENT")
        bt.logging.debug("type of data     :", type(data))
        bt.logging.debug("type of prev_seed:", type(previous_seed))
        bt.logging.debug("type of new_seed :", type(new_seed))
    proof = hash_data(data + previous_seed)
    return hash_data(str(proof).encode("utf-8") + new_seed), proof


def init_wandb(self, reinit=False):
    """Starts a new wandb run."""
    tags = [
        self.wallet.hotkey.ss58_address,
        storage.__version__,
        str(storage.__spec_version__),
        f"netuid_{self.metagraph.netuid}",
    ]

    if self.config.mock:
        tags.append("mock")

    wandb_config = {
        key: copy.deepcopy(self.config.get(key, None))
        for key in ("neuron", "reward", "netuid", "wandb")
    }

    if wandb_config["neuron"] is not None:
        wandb_config["neuron"].pop("full_path", None)

    self.wandb = wandb.init(
        anonymous="allow",
        reinit=reinit,
        project=self.config.wandb.project_name,
        entity=self.config.wandb.entity,
        config=wandb_config,
        mode="offline" if self.config.wandb.offline else "online",
        dir=self.config.neuron.full_path
        if self.config.neuron is not None
        else "wandb_logs",
        tags=tags,
        notes=self.config.wandb.notes,
    )
    bt.logging.success(
        prefix="Started a new wandb run",
        sufix=f"<blue> {self.wandb.name} </blue>",
    )


def get_disk_space_stats(path):
    """
    Retrieves the disk space statistics for the drive containing the specified path.

    This function provides the total, used, and free disk space of the drive on which the specified path resides.
    It's useful for understanding the storage capacity and usage of the system where the miner is running.

    Args:
        path (str): A file path on the drive whose disk space statistics are to be fetched. Typically, you can
                    provide the root path ('/') to get the stats for the primary drive.

    Returns:
        dict: A dictionary containing the 'total_gb', 'used_gb', and 'free_gb', representing the total, used,
              and free space on the disk in gigabytes (GB), respectively.

    Usage:
        disk_stats = get_disk_space_stats('/')
    """
    path = os.path.expanduser(path)
    total, used, free = shutil.disk_usage(path)
    return {
        "total_bytes": total,
        "used_bytes": used,
        "free_bytes": free,
    }


def get_free_disk_space(path="."):
    """
    Retrieves the free disk space for the drive containing the specified path.

    This function provides the free disk space of the drive on which the specified path resides.
    It's useful for understanding the storage capacity and usage of the system where the miner is running.

    Args:
        path (str): A file path on the drive whose free disk space is to be fetched. Typically, you can
                    provide the root path ('/') to get the stats for the primary drive.

    Returns:
        int: The free space on the disk in bytes (B).

    Usage:
        free_disk_space_gb = get_free_disk_space('/')
    """
    stats = get_disk_space_stats(path)
    free = stats.get("free_bytes", 0)
    return free


def get_directory_size(path):
    """
    Calculates the total size of files in a specified directory.

    This function traverses the directory at the given path, including all subdirectories, and sums up the size
    of each file to calculate the total directory size.

    Args:
        path (str): The file path of the directory whose size is to be calculated.

    Returns:
        int: The total size of the directory in bytes (B).

    Usage:
        directory_size_gb = get_directory_size('/path/to/directory')
    """
    total_size = 0
    path = os.path.expanduser(path)
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
    return total_size


def update_storage_stats(self):
    """
    Updates the miner's storage statistics.

    This function updates the miner's storage statistics, including the free disk space, current storage usage,
    and percent disk usage. It's useful for understanding the storage capacity and usage of the system where
    the miner is running.
    """

    self.free_memory = get_free_disk_space(self.config.database.directory)
    bt.logging.info(f"Free memory: {self.free_memory} bytes")
    self.current_storage_usage = get_directory_size(self.config.database.directory)
    bt.logging.info(f"Miner storage usage: {self.current_storage_usage} bytes")
    self.percent_disk_usage = self.current_storage_usage / (self.free_memory + self.current_storage_usage)
    bt.logging.info(f"Miner % disk usage : {100 * self.percent_disk_usage:.3f}%")


def load_request_log(request_log_path: str) -> dict:
    """
    Loads the request logger from disk if it exists.

    Args:
        log_path (str): The path to the directory containing the request log.

    Returns:
        Dict: The request log data, if it exists, or an empty dictionary.

    This method loads the request log from disk if it exists. If not, it returns an empty dictionary.
    """
    if os.path.exists(request_log_path):
        try:
            with open(request_log_path, "r") as f:
                request_log = json.load(f)
        except Exception as e:
            bt.logging.error(f"Error loading request log: {e}. Resetting.")
            request_log = {}
    else:
        request_log = {}
    return request_log


def log_request(synapse: "bt.Synapse", request_log: dict):
    """
    Log the request and store the timestamp of each request.

    Args:
        synapse (bt.Synapse): The synapse object with the request details.
        request_log (dict): The dictionary to log request timestamps.

    The function logs the time of each request in the request log and the request type.
    """
    current_time = time.time()
    caller = synapse.dendrite.hotkey
    if caller not in request_log:
        request_log[caller] = []

    request_log[caller].append((synapse.name, current_time))
    return request_log


class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()

    def is_allowed(self, caller):
        current_time = time.time()
        while (
            self.requests
            and current_time - self.requests[0]["timestamp"] > self.time_window
        ):
            self.requests.popleft()

        if len(self.requests) < self.max_requests:
            self.requests.append({"caller": caller, "timestamp": current_time})
            return True
        else:
            return False


def get_purge_ttl_script_path(current_dir):
    """
    Constructs and returns the path to the 'rebalance_deregistration.sh' script within a project directory.

    This function takes the root path of a project and appends the relative path to the 'rebalance_deregistration.sh' script.
    It assumes that the script is located within the 'scripts' subdirectory of the given project root.

    Parameters:
    project_root (str): The root path of the project directory.

    Returns:
    str: The full path to the 'rebalance_deregistration.sh' script.
    """
    project_root = os.path.join(current_dir, "..")
    project_root = os.path.normpath(project_root)
    script_path = os.path.join(project_root, "scripts", "run_ttl_purge.sh")
    return script_path


def run_async_in_sync_context(
    coroutine_function: callable,
    loop: asyncio.unix_events._UnixSelectorEventLoop = None,
    ttl: int = 100,
    *args,
):
    """
    Runs an asynchronous coroutine in a synchronous context using a separate process.

    This function is useful for running asynchronous coroutines in a synchronous context, such as in a synchronous
    function or method. It creates a separate process to run the asynchronous coroutine and waits for it to complete
    before returning control to the caller.

    Parameters:
    - coroutine_function (callable): The asynchronous coroutine function to be run.
    - loop (asyncio.unix_events._UnixSelectorEventLoop): The event loop to be used for running the coroutine.
    - ttl (int): The time-to-live (TTL) for the process. If the process does not complete within this time, it will be terminated.
    - *args: The arguments to be passed to the coroutine function.

    Usage:
    ```python
    async def async_function():
        await asyncio.sleep(1)
        print("Async function completed")

    def sync_function():
        run_async_in_sync_context(async_function)
        print("Sync function completed")
    ```
    """
    if loop is None:
        loop = asyncio.get_event_loop()

    def sync_wrapper(self):
        async def run_async_coro():
            await asyncio.gather(coroutine_function(*args))
        loop.run_until_complete(run_async_coro())

    process = multiprocessing.Process(target=sync_wrapper, args=args)
    process.start()
    process.join(timeout=ttl)
