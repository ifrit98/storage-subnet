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

import binascii
import hashlib
from Crypto.Random import random
from Crypto.PublicKey import ECC


def xor_bytes(a, b):
    """
    XOR two byte-like objects together.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def hash_data(data):
    """
    Compute a SHA3-256 hash of the input data and return its integer representation.

    The function handles both byte-like and non-byte-like inputs by converting non-byte inputs to
    strings and then encoding to bytes before hashing.

    Parameters:
    - data (bytes | bytearray | object): Data to be hashed.

    Returns:
    - int: Integer representation of the SHA3-256 hash of the input data.

    Raises:
    - TypeError: If the hashing operation encounters an incompatible data type.
    """
    if not isinstance(data, (bytes, bytearray)):
        data_str = str(data)
        data = data_str.encode()
    h = hashlib.sha3_256(data).hexdigest()
    return int(h, 16)


def setup_CRS(curve="P-256"):
    """
    Generate a pair of random points to serve as a Common Reference String (CRS) for elliptic curve operations.

    The CRS is essential for various cryptographic protocols that rely on a shared reference
    between parties, typically for the purpose of ensuring consistent cryptographic operations.

    Parameters:
    - curve (str, optional): Name of the elliptic curve to use; defaults to "P-256".

    Returns:
    - tuple(ECC.EccPoint, ECC.EccPoint): A 2-tuple of ECC.EccPoint instances representing the base points (g, h).

    Raises:
    - ValueError: If the specified elliptic curve name is not recognized.
    """
    curve_obj = ECC.generate(curve=curve)
    g = curve_obj.pointQ  # Base point
    h = ECC.generate(curve=curve).pointQ  # Another random point
    return g, h


def ecc_point_to_hex(point):
    """
    Convert an elliptic curve point to a hexadecimal string.

    This encoding is typically used for compact representation or for preparing the data
    to be transmitted over protocols that may not support binary data.

    Parameters:
    - point (ECC.EccPoint): An ECC point to convert.

    Returns:
    - str: Hexadecimal string representing the elliptic curve point.

    Raises:
    - AttributeError: If the input is not a valid ECC point with accessible x and y coordinates.
    """
    point_str = "{},{}".format(point.x, point.y)
    return binascii.hexlify(point_str.encode()).decode()


def hex_to_ecc_point(hex_str, curve):
    """
    Convert a hexadecimal string back into an elliptic curve point.

    This function is typically used to deserialize an ECC point that has been transmitted or stored as a hex string.

    Parameters:
    - hex_str (str): The hex string representing an elliptic curve point.
    - curve (str): The name of the elliptic curve the point belongs to.

    Returns:
    - ECC.EccPoint: The elliptic curve point represented by the hex string.

    Raises:
    - ValueError: If the hex string is not properly formatted or does not represent a valid point on the specified curve.
    """
    point_str = binascii.unhexlify(hex_str).decode()
    x, y = map(int, point_str.split(","))
    return ECC.EccPoint(x, y, curve=curve)


class ECCommitment:
    """
    Elliptic Curve based commitment scheme allowing one to commit to a chosen value while keeping it hidden to others.

    Attributes:
        g (ECC.EccPoint): The base point of the elliptic curve used as part of the commitment.
        h (ECC.EccPoint): Another random point on the elliptic curve used as part of the commitment.

    Methods:
        commit(m): Accepts a message, hashes it, and produces a commitment to the hashed message.
        open(c, m_val, r): Accepts a commitment, a hashed message, and a random value to verify the commitment.

    The `commit` method will print the commitment process, and the `open` method will print the verification process.
    """

    def __init__(self, g, h):
        self.g = g  # Base point of the curve
        self.h = h  # Another random point on the curve

    def commit(self, m):  # AKA Seal.
        """
        Create a cryptographic commitment to a message.

        The message is hashed, and the hash is used along with a random number to form the commitment
        using the public parameters g and h. The commitment can be verified with the `open` method.

        Parameters:
        - m (bytes | bytearray | object): The message to commit to.

        Returns:
        - tuple: A 3-tuple (commitment, hashed message value, random number used in the commitment).

        Side Effects:
        - This method will print the commitment details to the console.

        Raises:
        - Exception: If the commitment calculation fails.
        """
        m_val = hash_data(m)  # Compute hash of the data
        r = random.randint(1, 2**256)
        c1 = self.g.__mul__(m_val)
        c2 = self.h.__mul__(r)
        c = c1.__add__(c2)
        print(
            f"Committing: Data = {m}\nHashed Value = {m_val}\nRandom Value = {r}\nComputed Commitment = {c}\n"
        )
        return c, m_val, r

    def open(self, c, m_val, r):
        """
        Verify a commitment using the original message hash and randomness.

        This method recomputes the commitment using the public parameters and compares it with
        the provided commitment to check its validity.

        Parameters:
        - c (ECC.EccPoint): The commitment point to verify.
        - m_val (int): The integer value of the hashed message used in the commitment.
        - r (int): The random number used in the commitment.

        Returns:
        - bool: True if the verification succeeds (commitment is valid), False otherwise.

        Side Effects:
        - This method will print the verification details to the console.

        Raises:
        - Exception: If the verification calculation fails.
        """
        c1 = self.g.__mul__(m_val)
        c2 = self.h.__mul__(r)
        computed_c = c1.__add__(c2)
        print(
            f"\nOpening: Hashed Value = {m_val}\nRandom Value = {r}\nRecomputed Commitment = {computed_c}\nOriginal Commitment = {c}"
        )
        return computed_c == c
