import base58
import hashlib
import multibase
import multihash
import multicodec
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


        :param int version: CID version (0 or 1)
        :param str codec: codec to be used for encoding the hash
        :param str multihash: the multihash
        """

        if version not in (0, 1):
            raise ValueError(
                "version should be 0 or 1, {} was provided".format(version)
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
    def buffer(self):
        """
        The raw representation of the CID

        :return: raw representation of the CID
        :rtype: bytes
        """
        return b"".join(
            [bytes([self.version]), multicodec.add_prefix(self.codec, self.multihash)]
        )

    def encode(self, encoding="base58btc"):
        """
        Encoded version of the raw representation

        :param str encoding: the encoding to use to encode the raw representation, should be supported by
            ``py-multibase``
        :return: encoded raw representation with the given encoding
        :rtype: bytes
        """
        return multibase.encode(encoding, self.buffer)


def make_cid(raw_data, codec_name="sha2-256"):
    """
    Creates a CIDv1 object from raw data using the specified codec.

    :param raw_data: The raw data to create a CID for.
    :param codec_name: The name of the codec to use.
    :return: A CIDv1 object.
    """
    _multihash = generate_multihash(raw_data)

    if not multicodec.is_codec(codec_name):
        raise ValueError("Invalid codec")

    return CIDv1(codec_name, _multihash)


def decode_cid(cid_input):
    """
    Decodes a CID to extract the original hash of the data.

    :param cid_input: The CID object or its string representation.
    :return: The original hash of the data.
    """
    if isinstance(cid_input, str):
        cid_bytes = multibase.decode(ensure_bytes(cid_input))
    elif isinstance(cid_input, BaseCID):
        cid_bytes = cid_input.buffer
    else:
        raise ValueError("Invalid CID input type. Must be a CID object or a string.")

    # Extract the multihash part directly from the CID bytes.
    # Assuming that the first byte is the version (1 byte) and the next bytes are the codec.
    # The rest is the multihash.
    if cid_bytes[0] == 1:  # CIDv1
        # Find the end of the codec varint
        i = 1
        while i < len(cid_bytes) and (cid_bytes[i] & 0x80) != 0:
            i += 1
        multihash_bytes = cid_bytes[i + 1 :]
    elif cid_bytes[0] == 0:  # CIDv0 (just a multihash)
        multihash_bytes = cid_bytes[1:]
    else:
        raise ValueError("Unknown CID version")

    decoded_multihash = multihash.decode(multihash_bytes)
    return decoded_multihash.digest
