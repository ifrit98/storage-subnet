import unittest
import hashlib
import requests

from ipfs_cid import cid_sha256_hash as compute_cidv1  # pip install ipfs-cid
from ipfs_cid_v0 import compute_cid as compute_cidv0  # pip install ipdfs-cid-v0
from ipfs_cid_v0 import compute_hash, compute_hash_hex
from storage.validator.cid import make_cid, decode_cid


def fetch_ipfs_content(cid):
    gateway_url = f"https://ipfs.io/ipfs/{cid}"
    response = requests.get(gateway_url)
    if response.status_code == 200:
        return response.content
    else:
        raise Exception(
            f"Failed to retrieve content. Status code: {response.status_code}"
        )


class TestIPFSCID(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.AARDVARK_CIDv0 = "QmcRD4wkPPi6dig81r5sLj9Zm1gDCL4zgpEj9CfuRrGbzF"
        cls.aardvark = fetch_ipfs_content(cls.AARDVARK_CIDv0)

    def test_cidv0(self):
        aardvark_cidv0 = compute_cidv0(self.aardvark)
        self.assertEqual(aardvark_cidv0, self.AARDVARK_CIDv0)

    def test_cidv1(self):
        aardvark_cidv1 = compute_cidv1(self.aardvark)
        expected_hash = hashlib.sha256(self.aardvark).digest()
        self.assertEqual(decode_cid(aardvark_cidv1), expected_hash)

    def test_make_cid_v0(self):
        cid0 = make_cid(self.aardvark, version=0)
        self.assertEqual(cid0.multihash.decode(), self.AARDVARK_CIDv0)

    def test_compute_hash(self):
        expected_hash = compute_hash(self.aardvark)[2:]
        self.assertEqual(decode_cid(self.AARDVARK_CIDv0), expected_hash)

    def test_make_cid_v1(self):
        data = b"Hello World!"
        cid1 = make_cid(data, version=1)
        expected_hash = hashlib.sha256(data).digest()
        self.assertEqual(decode_cid(cid1), expected_hash)

    def test_decode_cid_v0(self):
        data = b"Hello World!"
        cid0 = make_cid(data, version=0)
        dcid0 = decode_cid(cid0)
        self.assertEqual(dcid0, compute_hash(data)[2:])

    def test_consistent_v0_hashing(self):
        data = b"Hello World!"
        expected_v0_hash = compute_hash(data)[2:]
        cid0_1 = make_cid(data, version=0)
        self.assertEqual(decode_cid(cid0_1), expected_v0_hash)
        cid0_2 = make_cid(data, version=0)
        self.assertEqual(decode_cid(cid0_2), expected_v0_hash)
        cid0_3 = make_cid(data, version=0)
        self.assertEqual(decode_cid(cid0_3), expected_v0_hash)
        cid0_4 = make_cid(data, version=0)
        self.assertEqual(decode_cid(cid0_4), expected_v0_hash)

    def test_consistent_v1_hashing(self):
        data = b"Hello World!"
        expected_v1_hash = hashlib.sha256(data).digest()
        cid1_1 = make_cid(data, version=1)
        self.assertEqual(decode_cid(cid1_1), expected_v1_hash)
        cid1_2 = make_cid(data, version=1)
        self.assertEqual(decode_cid(cid1_2), expected_v1_hash)
        cid1_3 = make_cid(data, version=1)
        self.assertEqual(decode_cid(cid1_3), expected_v1_hash)
        cid1_4 = make_cid(data, version=1)


if __name__ == "__main__":
    unittest.main()
