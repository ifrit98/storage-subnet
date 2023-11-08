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
import storage

from .ecc import setup_CRS, ecc_point_to_hex
from .util import encrypt_data, make_random_file, hash_data, get_random_bytes


def GetSynapse(curve, maxsize, key=None):
    # Setup CRS for this round of validation
    g, h = setup_CRS(curve=curve)

    # Make a random bytes file to test the miner
    random_data = b"this is a random bytestring, long enough to be chunked into segments and reconstructed at the end"
    # random_data = make_random_file(maxsize=maxsize)

    # Random encryption key for now (never will decrypt)
    key = key or get_random_bytes(32)  # 256-bit key

    # Encrypt the data
    encrypted_data, nonce, tag = encrypt_data(
        random_data,
        key,  # TODO: Use validator key as the encryption key?
    )

    # Convert to base64 for compactness
    b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

    # Hash the encrypted datad
    data_hash = hash_data(encrypted_data)

    syn = synapse = storage.protocol.Store(
        data_hash=data_hash,
        encrypted_data=b64_encrypted_data,
        curve=curve,
        g=ecc_point_to_hex(g),
        h=ecc_point_to_hex(h),
        seed=get_random_bytes(32).hex(),
    )
    return synapse, (key, nonce, tag)
