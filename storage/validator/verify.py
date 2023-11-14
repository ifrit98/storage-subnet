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
    """Verify a commitment using the proof, seed, and commitment."""
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
    if synapse.commitment_hash == None or synapse.commitment_proof == None:
        bt.logging.error(
            f"Missing commitment hash or proof for synapse: {synapse.axon.dict()}."
        )
        return False

    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        bt.logging.error(f"Initial commitment hash does not match expected result.")
        bt.logging.error(f"synapse {synapse}")
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
        bt.logging.error(f"Opening commitment failed")
        bt.logging.error(f"synapse {synapse}")
        return False

    if not validate_merkle_proof(
        b64_decode(synapse.merkle_proof),
        ecc_point_to_hex(commitment),
        synapse.merkle_root,
    ):
        bt.logging.error(f"Merkle proof validation failed")
        bt.logging.error(f"synapse {synapse}")
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
        bt.logging.error(f"Initial commitment hash does not match hash(data + seed)")
        bt.logging.error(f"synapse: {synapse}")
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
        bt.logging.error(f"synapse: {synapse}")
        return False

    return True


def verify_retrieve_with_seed(synapse, verbose=False):
    if not verify_chained_commitment(
        synapse.commitment_proof, synapse.seed, synapse.commitment_hash, verbose=verbose
    ):
        bt.logging.error(f"Initial commitment hash does not match expected result.")
        return False

    return True
