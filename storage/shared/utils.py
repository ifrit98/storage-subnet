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

import json
import torch
import base64
import random
from typing import List, Union


def safe_key_search(database, pattern):
    """
    Safely search for keys in the database that doesn't block.
    `scan_iter` uses cursor under the hood.
    """
    return [key for key in database.scan_iter(pattern)]


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
    if isinstance(data, list) and len(data) and isinstance(data[0], bytes):
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


def xor_data(x: bytes, y: bytes):
    """XOR the x (data) and the y (seed), extending y (seed) if necessary for symmetry."""
    y = (y * (len(x) // len(y))) + y[: len(x) % len(y)]
    return bytes(a ^ b for a, b in zip(x, y))


def chunk_data(data: bytes, chunksize: int) -> List[bytes]:
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


def is_hex_str(s: str) -> bool:
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
