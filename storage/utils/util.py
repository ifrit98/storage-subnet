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
import base64
import hashlib
import binascii
from collections import defaultdict
from typing import Dict, List, Any

import Crypto
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .ecc import hex_to_ecc_point, ecc_point_to_hex, hash_data, ECCommitment
from .merkle import MerkleTree


def make_random_file(name=None, maxsize=1024):
    """
    Creates a file with random binary data or returns a bytes object with random data if no name is provided.

    Args:
        name (str, optional): The name of the file to create. If None, the function returns the random data instead.
        maxsize (int): The maximum size of the file or bytes object to be created, in bytes. Defaults to 1024.

    Returns:
        bytes: If 'name' is not provided, returns a bytes object containing random data.
        None: If 'name' is provided, a file is created and nothing is returned.

    Raises:
        OSError: If the function encounters an error while writing to the file.
    """
    size = random.randint(128, maxsize)
    data = os.urandom(size)
    if isinstance(name, str):
        with open(name, "wb") as fout:
            fout.write(data)
    else:
        return data


# Determine a random chunksize between 2kb-128kb (random sample from this range) store as chunksize_E
def get_random_chunksize(maxsize=128):
    """
    Determines a random chunk size within a specified range for data chunking.

    Args:
        maxsize (int): The maximum size limit for the random chunk size. Defaults to 128.

    Returns:
        int: A random chunk size between 2kb and 'maxsize' kilobytes.

    Raises:
        ValueError: If maxsize is set to a value less than 2.
    """
    return random.randint(2, maxsize)


def chunk_data(data, chunksize: int):
    """
    Generator function that chunks the given data into pieces of a specified size.

    Args:
        data (bytes): The binary data to be chunked.
        chunksize (int): The size of each chunk in bytes.

    Yields:
        bytes: A chunk of the data with the size equal to 'chunksize' or the remaining size of data.

    Raises:
        ValueError: If 'chunksize' is less than or equal to 0.
    """
    for i in range(0, len(data), chunksize):
        yield data[i : i + chunksize]


def is_hex_str(s):
    """
    Check if the input string is a valid hexadecimal string.

    :param s: The string to check
    :return: True if s is a valid hexadecimal string, False otherwise
    """
    # A valid hex string must have an even number of characters
    if len(s) % 2 != 0:
        return False

    # Check if each character is a valid hex character
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def encrypt_data(filename, key):
    """
    Encrypt the data in the given filename using AES-GCM.

    Parameters:
    - filename: str or bytes. If str, it's considered as a file name. If bytes, as the data itself.
    - key: bytes. 16-byte (128-bit), 24-byte (192-bit), or 32-byte (256-bit) secret key.

    Returns:
    - cipher_text: bytes. The encrypted data.
    - nonce: bytes. The nonce used for the GCM mode.
    - tag: bytes. The tag for authentication.
    """

    # If filename is a string, treat it as a file name and read the data
    if isinstance(filename, str):
        with open(filename, "rb") as file:
            data = file.read()
    else:
        data = filename

    # Initialize AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM)

    # Encrypt the data
    cipher_text, tag = cipher.encrypt_and_digest(data)

    return cipher_text, cipher.nonce, tag


def decrypt_aes_gcm(cipher_text, key, nonce, tag):
    """
    Decrypt the data using AES-GCM.

    Parameters:
    - cipher_text: bytes. The encrypted data.
    - key: bytes. The secret key used for decryption.
    - nonce: bytes. The nonce used in the GCM mode for encryption.
    - tag: bytes. The tag for authentication.

    Returns:
    - data: bytes. The decrypted data.
    """

    # Initialize AES-GCM cipher with the given key and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Decrypt the data and verify the tag
    try:
        data = cipher.decrypt_and_verify(cipher_text, tag)
    except ValueError:
        # This is raised if the tag does not match
        raise ValueError("Incorrect decryption key or corrupted data.")

    return data


def decode_storage(encoded_storage):
    """
    Decodes a base64-encoded string that represents storage data. This storage data is expected
    to contain 'commitments' and 'params', where 'commitments' will be further decoded using
    a separate function, and 'params' are base64-decoded and then JSON-decoded.

    Args:
        encoded_storage (str): A base64-encoded string representing storage data.

    Returns:
        dict: A dictionary with the decoded storage data, including 'commitments' and 'params'.

    Raises:
        ValueError: If encoded_storage is not a valid base64-encoded string or the JSON decoding fails.
    """
    decoded_storage = base64.b64decode(encoded_storage).decode("utf-8")
    dict_storage = json.loads(decoded_storage)
    dict_storage["commitments"] = decode_commitments(dict_storage["commitments"])
    dict_storage["params"] = json.loads(
        base64.b64decode(dict_storage["params"]).decode("utf-8")
    )
    return dict_storage


def b64_encode(data):
    """
    Encodes the given data into a base64 string. If the data is a list or dictionary of bytes, it converts
    the bytes into hexadecimal strings before encoding.

    Args:
        data (list or dict): The data to be base64 encoded. Can be a list of bytes or a dictionary with bytes values.

    Returns:
        str: The base64 encoded string of the input data.

    Raises:
        TypeError: If the input is not a list, dict, or bytes.
    """
    if isinstance(data, bytes):
        data = data.hex()
    if isinstance(data, list) and isinstance(data[0], bytes):
        data = [d.hex() for d in data]
    if isinstance(data, dict) and isinstance(data[list(data.keys())[0]], bytes):
        data = {k: v.hex() for k, v in data.items()}
    return base64.b64encode(json.dumps(data).encode()).decode("utf-8")


def b64_decode(data, decode_hex=False, encrypted=False):
    """
    Decodes a base64 string into a list or dictionary. If decode_hex is True, it converts any hexadecimal strings
    within the data back into bytes.

    Args:
        data (bytes or str): The base64 encoded data to be decoded.
        decode_hex (bool): A flag to indicate whether to decode hex strings into bytes. Defaults to False.

    Returns:
        list or dict: The decoded data. Returns a list if the original encoded data was a list, and a dict if it was a dict.

    Raises:
        ValueError: If the input is not properly base64 encoded or if hex decoding fails.
    """
    data = data.decode("utf-8") if isinstance(data, bytes) else data
    decoded_data = json.loads(
        base64.b64decode(data) if encrypted else base64.b64decode(data).decode("utf-8")
    )
    if decode_hex:
        try:
            decoded_data = (
                [bytes.fromhex(d) for d in decoded_data]
                if isinstance(decoded_data, list)
                else {k: bytes.fromhex(v) for k, v in decoded_data.items()}
            )
        except:
            pass
    return decoded_data


def xor_data_and_seed(data, seed):
    """XOR the data and the seed, extending the seed if necessary."""
    seed = (seed * (len(data) // len(seed))) + seed[: len(data) % len(seed)]
    return bytes(a ^ b for a, b in zip(data, seed))


def validate_merkle_proof(proof, target_hash, merkle_root):
    """
    Validates a Merkle proof by computing the hash path from the target hash to the expected Merkle root.

    Args:
        proof (list of dicts): The Merkle proof, each entry containing a 'left' or 'right' sibling hash.
        target_hash (str): The hex string of the hash of the target data.
        merkle_root (str): The hex string of the expected Merkle root.

    Returns:
        bool: True if the proof is valid and the computed hash path matches the Merkle root, False otherwise.

    Raises:
        ValueError: If proof elements do not contain a 'left' or 'right' key.
    """
    merkle_root = bytearray.fromhex(merkle_root)
    target_hash = bytearray.fromhex(target_hash)
    if len(proof) == 0:
        return target_hash == merkle_root
    else:
        proof_hash = target_hash
        for p in proof:
            try:
                # the sibling is a left node
                sibling = bytearray.fromhex(p["left"])
                proof_hash = hashlib.sha3_256(sibling + proof_hash).digest()
            except:
                # the sibling is a right node
                sibling = bytearray.fromhex(p["right"])
                proof_hash = hashlib.sha3_256(proof_hash + sibling).digest()
        return proof_hash == merkle_root


def verify_chained_commitment(proof, seed, commitment, verbose=False):
    """Verify a commitment using the proof, seed, and commitment."""
    expected_commitment = str(hash_data(proof.encode() + seed.encode()))
    if verbose:
        print(
            "types: ",
            "proof",
            type(proof),
            "seed",
            type(seed),
            "commitment",
            type(commitment),
        )
        print("recieved proof     : ", proof)
        print("recieved seed      : ", seed)
        print("recieved commitment: ", commitment)
        print("excpected commitment:", expected_commitment)
        print("type expected commit:", type(expected_commitment))
    return expected_commitment == commitment


def verify_challenge_with_seed(synapse, verbose=False):
    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        print(f"Initial commitment hash does not match expected result.")
        return False

    # TODO: Add checks and defensive programming here to handle all types
    # (bytes, str, hex, ecc point, etc)
    committer = ECCommitment(
        hex_to_ecc_point(synapse.g, synapse.curve),
        hex_to_ecc_point(synapse.h, synapse.curve),
    )
    commitment = hex_to_ecc_point(synapse.commitment, synapse.curve)

    if not committer.open(
        commitment,
        hash_data(base64.b64decode(synapse.data_chunk) + str(synapse.seed).encode()),
        synapse.randomness,
    ):
        print(f"Opening commitment failed")
        return False

    if not validate_merkle_proof(
        b64_decode(synapse.merkle_proof),
        ecc_point_to_hex(commitment),
        synapse.merkle_root,
    ):
        print(f"Merkle proof validation failed")
        return False

    return True


def verify_store_with_seed(synapse):
    # TODO: Add checks and defensive programming here to handle all types
    # (bytes, str, hex, ecc point, etc)
    decoded_data = base64.b64decode(synapse.encrypted_data)
    seed_value = str(synapse.seed).encode()
    reconstructed_hash = hash_data(decoded_data + seed_value)

    # TODO: make these types the same:
    # e.g. send synapse.commitment_hash as an int for consistency
    if synapse.commitment_hash != str(reconstructed_hash):
        print(f"Initial commitment hash does not match hash(data + seed)")
        return False

    committer = ECCommitment(
        hex_to_ecc_point(synapse.g, synapse.curve),
        hex_to_ecc_point(synapse.h, synapse.curve),
    )
    commitment = hex_to_ecc_point(synapse.commitment, synapse.curve)

    if not committer.open(
        commitment,
        hash_data(decoded_data + str(synapse.seed).encode()),
        synapse.randomness,
    ):
        print(f"Opening commitment failed")
        return False

    return True


def verify_retrieve_with_seed(synapse, verbose=False):
    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        print(f"Initial commitment hash does not match expected result.")
        return False

    return True
