import base58
import typing
import hashlib
import multibase
import multihash
import multicodec

from ipfs_cid import cid_sha256_hash as compute_cidv1
from morphys import ensure_bytes, ensure_unicode


def generate_multihash(data):
    """
    Generates a multihash for the given data using the specified hash function.

    :param data: Data to hash. Can be a string or bytes.
    :return: A multihash-encoded hash of the data.
    """
    data_bytes = ensure_bytes(data)

    hash_bytes = hashlib.sha256(data_bytes).digest()

    encoded_multihash = multihash.encode(hash_bytes, "sha2-256")

    return encoded_multihash


class BaseCID(object):
    __hash__ = object.__hash__

    def __init__(self, version, codec, multihash):
        """
        Creates a new CID object. This class should not be used directly, use :py:class:`cid.cid.CIDv0` or
        :py:class:`cid.cid.CIDv1` instead.


        :param str codec: codec to be used for encoding the hash
        :param str multihash: the multihash
        """

        if version not in (1,):
            raise ValueError(
                "version should be 1, {} was provided".format(version)
            )
        if not multicodec.is_codec(codec):
            raise ValueError("invalid codec {} provided, please check".format(codec))
        if not (isinstance(multihash, str) or isinstance(multihash, bytes)):
            raise ValueError(
                "invalid type for multihash provided, should be str or bytes"
            )

        self._version = version
        self._codec = codec
        self._multihash = ensure_bytes(multihash)

    @property
    def version(self):
        """CID version"""
        return self._version

    @property
    def codec(self):
        """CID codec"""
        return self._codec

    @property
    def multihash(self):
        """CID multihash"""
        return self._multihash

    @property
    def buffer(self):
        raise NotImplementedError

    def encode(self, *args, **kwargs):
        raise NotImplementedError

    def __repr__(self):
        def truncate(s, length):
            return s[:length] + b".." if len(s) > length else s

        truncate_length = 20
        return (
            "{class_}(version={version}, codec={codec}, multihash={multihash})".format(
                class_=self.__class__.__name__,
                version=self._version,
                codec=self._codec,
                multihash=truncate(self._multihash, truncate_length),
            )
        )

    def __str__(self):
        return ensure_unicode(self.encode())

    def __eq__(self, other):
        return (
            (self.version == other.version)
            and (self.codec == other.codec)
            and (self.multihash == other.multihash)
        )


class CIDv1(BaseCID):
    """CID version 1 object"""

    def __init__(self, codec, multihash):
        super(CIDv1, self).__init__(1, codec, multihash)

    @property
    def buffer(self) -> bytes:
        """
        The raw representation of the CID

        :return: raw representation of the CID
        :rtype: bytes
        """
        return b"".join(
            [bytes([self.version]), multicodec.add_prefix(self.codec, self.multihash)]
        )

    def encode(self, encoding="base58btc") -> bytes:
        """
        Encoded version of the raw representation

        :param str encoding: the encoding to use to encode the raw representation, should be supported by
            ``py-multibase``
        :return: encoded raw representation with the given encoding
        :rtype: bytes
        """
        return multibase.encode(encoding, self.buffer)


def make_cid(data: typing.Union[str, bytes]) -> "CIDv1":
    """
    Creates a CIDv1 object from raw data using the specified codec.

    :param raw_data: The raw data to create a CID for.
    :return: A CID object.
    """
    raw_data = ensure_bytes(data)

    cid = compute_cidv1(raw_data)
    return CIDv1("sha2-256", cid)


def decode_cid(cid_input) -> bytes:
    """
    Decodes a CID string or object into a multihash.

    :param cid_input: A CID string or object.
    :return: A multihash.
    """
    if isinstance(cid_input, BaseCID):
        cid_input = cid_input.multihash

    if isinstance(cid_input, bytes):
        if cid_input.startswith(b"Qm"):
            decoded_multihash = multihash.decode(base58.b58decode(cid_input))
            return decoded_multihash.digest

        elif cid_input.startswith(b"b"):
            cid_bytes = multibase.decode(ensure_bytes(cid_input))
            i = 1
            while i < len(cid_bytes) and (cid_bytes[i] & 0x80) != 0:
                i += 1
            multihash_bytes = cid_bytes[i + 1 :]
            decoded_multihash = multihash.decode(multihash_bytes)
            return decoded_multihash.digest

    elif isinstance(cid_input, str):
        if cid_input.startswith("Qm"):  # CIDv0
            decoded_multihash = multihash.decode(base58.b58decode(cid_input))
            return decoded_multihash.digest

        elif cid_input.startswith("b"):  # CIDv1
            cid_bytes = multibase.decode(ensure_bytes(cid_input))
            i = 1
            while i < len(cid_bytes) and (cid_bytes[i] & 0x80) != 0:
                i += 1
            multihash_bytes = cid_bytes[i + 1 :]
            decoded_multihash = multihash.decode(multihash_bytes)
            return decoded_multihash.digest

    else:
        raise ValueError("Invalid CID input type. Must be a CID object or a string.")


def generate_cid_string(data: typing.Union[str, bytes]) -> str:
    """
    Generates a CID string for the given data using the specified CID version.

    :param data: Data to hash. Can be a string or bytes.
    :param version: CID version to use. Must be 0 or 1.
    :return: A CID string.
    """
    data_bytes = ensure_bytes(data)

    return compute_cidv1(data_bytes)
