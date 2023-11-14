import os
import json
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
    # Ensure the directory exists
    directory = os.path.expanduser(directory)
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, filename)
    with open(file_path, "wb") as file:
        file.write(data)
    return file_path


def load_from_filesystem(filepath):
    with open(os.path.expanduser(filepath), "rb") as file:
        data = file.read()
    return data


def compute_subsequent_commitment(data, previous_seed, new_seed, verbose=False):
    """Compute a subsequent commitment based on the original data, previous seed, and new seed."""
    if verbose:
        bt.logging.debug("IN COMPUTE SUBESEQUENT COMMITMENT")
        bt.logging.debug("type of data     :", type(data))
        bt.logging.debug("type of prev_seed:", type(previous_seed))
        bt.logging.debug("type of new_seed :", type(new_seed))
    proof = hash_data(data + previous_seed)
    return hash_data(str(proof).encode("utf-8") + new_seed), proof
