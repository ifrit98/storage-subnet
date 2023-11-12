import os
import json
import bittensor as bt

from ..utils import (
    safe_key_search,
    ecc_point_to_hex,
    hex_to_ecc_point,
    MerkleTree,
    MerkleTreeException,
    hash_data,
)


def commit_data_with_seed(committer, data_chunks, n_chunks, seed):
    merkle_tree = MerkleTree()

    # Commit each chunk of data
    randomness, chunks, points = [None] * n_chunks, [None] * n_chunks, [None] * n_chunks
    bt.logging.debug("n_chunks:", n_chunks)
    for index, chunk in enumerate(data_chunks):
        bt.logging.debug("index:", index)
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


def total_storage(database):
    # Fetch all keys from Redis
    all_keys = safe_key_search(database, "*")

    # Filter out keys that contain a period (temporary, remove later)
    filtered_keys = [key for key in all_keys if b"." not in key]
    bt.logging.debug("filtered_keys:", filtered_keys)

    # Get the size of each data object and sum them up
    total_size = sum(
        [
            json.loads(database.get(key).decode("utf-8")).get("size", 0)
            for key in filtered_keys
        ]
    )
    return total_size


def compute_subsequent_commitment(data, previous_seed, new_seed, verbose=False):
    """Compute a subsequent commitment based on the original data, previous seed, and new seed."""
    if verbose:
        print("IN COMPUTE SUBESEQUENT COMMITMENT")
        print("type of data     :", type(data))
        print("type of prev_seed:", type(previous_seed))
        print("type of new_seed :", type(new_seed))
    proof = hash_data(data + previous_seed)
    return hash_data(str(proof).encode("utf-8") + new_seed), proof
