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

import base64
from pprint import pformat

from ..shared.ecc import (
    hash_data,
    hex_to_ecc_point,
    ecc_point_to_hex,
    ECCommitment,
)
from ..shared.merkle import (
    validate_merkle_proof,
)

from ..shared.utils import (
    b64_decode,
)

import bittensor as bt


def verify_chained_commitment(proof, seed, commitment, verbose=True):
    """
    Verifies the accuracy of a chained commitment using the provided proof, seed, and commitment.
    The function hashes the concatenation of the proof and seed and compares this result with the provided commitment
    to determine if the commitment is valid.
    Args:
        proof (str): The proof string involved in the commitment.
        seed (str): The seed string used in generating the commitment.
        commitment (str): The expected commitment hash to validate against.
        verbose (bool, optional): Enables verbose logging for debugging. Defaults to True.
    Returns:
        bool: True if the commitment is verified successfully, False otherwise.
    """
    expected_commitment = str(hash_data(proof.encode() + seed.encode()))
    if verbose:
        bt.logging.debug(
            "types: ",
            "proof",
            type(proof),
            "seed",
            type(seed),
            "commitment",
            type(commitment),
        )
        bt.logging.debug("recieved proof     : ", proof)
        bt.logging.debug("recieved seed      : ", seed)
        bt.logging.debug("recieved commitment: ", commitment)
        bt.logging.debug("excpected commitment:", expected_commitment)
        bt.logging.debug("type expected commit:", type(expected_commitment))
    return expected_commitment == commitment


def verify_challenge_with_seed(synapse, verbose=False):
    """
    Verifies a challenge in a decentralized network using a seed and the details contained in a synapse.
    The function validates the initial commitment hash against the expected result, checks the integrity of the commitment,
    and verifies the merkle proof.
    Args:
        synapse (Synapse): The synapse object containing challenge details.
        verbose (bool, optional): Enables verbose logging for debugging. Defaults to False.
    Returns:
        bool: True if the challenge is verified successfully, False otherwise.
    """
    if synapse.commitment_hash == None or synapse.commitment_proof == None:
        bt.logging.error(
            f"Missing commitment hash or proof for synapse: {pformat(synapse.dendrite.dict())}."
        )
        return False

    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        bt.logging.error(f"Initial commitment hash does not match expected result.")
        bt.logging.error(f"synapse {pformat(synapse.dendrite.dict())}")
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
        if verbose:
            bt.logging.error(f"Opening commitment failed!")
            bt.logging.error(f"commitment: {synapse.commitment}")
            bt.logging.error(f"seed      : {synapse.seed}")
            bt.logging.error(f"synapse   : {pformat(synapse.dendrite.dict())}")
        return False

    if not validate_merkle_proof(
        b64_decode(synapse.merkle_proof),
        ecc_point_to_hex(commitment),
        synapse.merkle_root,
    ):
        if verbose:
            bt.logging.error(f"Merkle proof validation failed!")
            bt.logging.error(f"commitment  : {synapse.commitment}")
            bt.logging.error(f"merkle root : {merkle_root}")
            bt.logging.error(f"merkle proof: {pformat(merkle_proof)}")
            bt.logging.error(f"synapse     : {pformat(synapse.dendrite.dict())}")
        return False

    return True


def verify_store_with_seed(synapse, verbose=False):
    """
    Verifies the storing process in a decentralized network using the provided synapse and seed.
    This function decodes the data, reconstructs the hash using the seed, and verifies it against the commitment hash.
    It also opens the commitment to validate the process.
    Args:
        synapse (Synapse): The synapse object containing store process details.
        verbose (bool, optional): Enables verbose logging for debugging. Defaults to False.
    Returns:
        bool: True if the storing process is verified successfully, False otherwise.
    """
    # TODO: Add checks and defensive programming here to handle all types
    # (bytes, str, hex, ecc point, etc)
    try:
        decoded_data = base64.b64decode(synapse.encrypted_data)
    except Exception as e:
        bt.logging.error(f"Could not decode data with error: {e}")
        return False

    seed_value = str(synapse.seed).encode()
    reconstructed_hash = hash_data(decoded_data + seed_value)

    # e.g. send synapse.commitment_hash as an int for consistency
    if synapse.commitment_hash != str(reconstructed_hash):
        if verbose:
            bt.logging.error(f"Initial commitment hash != hash(data + seed)")
            bt.logging.error(f"commitment hash   : {commitment_hash}")
            bt.logging.error(f"reconstructed hash: {reconstructed_hash}")
            bt.logging.error(f"synapse           : {synapse.dendrite.dict()}")
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
        bt.logging.error(f"Opening commitment failed")
        bt.logging.error(f"synapse: {synapse.dendrite.dict()}")
        return False

    return True


def verify_retrieve_with_seed(synapse, verbose=False):
    """
    Verifies the retrieval process in a decentralized network using the provided synapse and seed.
    The function validates the initial commitment hash against the expected result using the provided seed and commitment proof.
    Args:
        synapse (Synapse): The synapse object containing retrieval process details.
        verbose (bool, optional): Enables verbose logging for debugging. Defaults to False.
    Returns:
        bool: True if the retrieval process is verified successfully, False otherwise.
    """
    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        bt.logging.error(f"Initial commitment hash does not match expected result.")
        if verboses:
            bt.logging.error(f"synapse {synapse.dendrite.dict()}")
            bt.logging.error(f"commitment_proof: {synapse.commitment_proof}")
            bt.logging.error(f"seed            : {synapse.seed}")
            bt.logging.error(f"commitment_hash : {synapse.commitment_hash}")
        return False

    return True
