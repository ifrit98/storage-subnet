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

import Crypto
import typing
import bittensor as bt

from Crypto.PublicKey import ECC


# Basically setup for a given piece of data
class Store(bt.Synapse):
    # TODO: write deserialize

    # Data to store
    encrypted_data: str  # base64 encoded string of encrypted data (bytes)

    # Setup parameters
    curve: str  # e.g. P-256
    g: str  # base point   (hex string representation)
    h: str  # random point (hex string representation)

    seed: typing.Union[
        str, int, bytes
    ]  # random seed (bytes stored as hex) for the commitment

    # Return signature of received data
    randomness: typing.Optional[int] = None
    commitment: typing.Optional[str] = None
    signature: typing.Optional[bytes] = None
    commitment_hash: typing.Optional[str] = None  # includes seed


class Challenge(bt.Synapse):
    # TODO: write deserialize

    # Query parameters
    challenge_hash: str  # hash of the data to challenge
    challenge_index: int  # block indices to challenge
    chunk_size: int  # bytes (e.g. 1024) for how big the chunks should be

    # Setup parameters
    g: str  # base point   (hex string representation)
    h: str  # random point (hex string representation)
    curve: str
    seed: typing.Union[str, int]  # random seed for the commitment

    # Returns
    # - commitment hash (hex string) hash( hash( data + prev_seed ) + seed )
    # - commitment (point represented as hex string)
    # - data chunk (base64 encoded string of bytes)
    # - random value (int)
    # - merkle proof (List[Dict[<left|right>, hex strings])
    # - merkle root (hex string)
    commitment_hash: typing.Optional[str] = None
    commitment_proof: typing.Optional[str] = None
    commitment: typing.Optional[str] = None
    data_chunk: typing.Optional[bytes] = None
    randomness: typing.Optional[int] = None
    merkle_proof: typing.Optional[
        typing.Union[typing.List[typing.Dict[str, str]], str]
    ] = None
    merkle_root: typing.Optional[str] = None


class Retrieve(bt.Synapse):
    # Where to find the data
    data_hash: str
    seed: str

    # Fetched data and proof
    data: typing.Optional[str] = None
    commitment_hash: typing.Optional[str] = None
    commitment_proof: typing.Optional[str] = None
