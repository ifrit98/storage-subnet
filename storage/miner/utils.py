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
import storage
import wandb
import copy
import bittensor as bt

from ..shared.ecc import (
    ecc_point_to_hex,
    hex_to_ecc_point,
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


def save_data_to_filesystem(data, directory, filename):
    """
    Saves data to the filesystem at the specified directory and filename. If the directory does
    not exist, it is created.

    Parameters:
    - data: The data to be saved.
    - directory (str): The directory path where the data should be saved.
    - filename (str): The name of the file to save the data in.

    Returns:
    - file_path (str): The full path to the saved file.

    This function is useful for persisting data to the disk.
    """
    # Ensure the directory exists
    directory = os.path.expanduser(directory)
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
