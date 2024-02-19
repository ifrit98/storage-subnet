import unittest
import hashlib
import requests

from ipfs_cid import cid_sha256_hash as compute_cidv1  # pip install ipfs-cid
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

    def test_cidv1(self):
        aardvark_cidv1 = compute_cidv1(self.aardvark)
        expected_hash = hashlib.sha256(self.aardvark).digest()
        self.assertEqual(decode_cid(aardvark_cidv1), expected_hash)

    def test_make_cid_v1(self):
        data = b"Hello World!"
        cid1 = make_cid(data)
        expected_hash = hashlib.sha256(data).digest()
        self.assertEqual(decode_cid(cid1), expected_hash)

    def test_consistent_v1_hashing(self):
        data = b"Hello World!"
        expected_v1_hash = hashlib.sha256(data).digest()
        cid1_1 = make_cid(data)
        self.assertEqual(decode_cid(cid1_1), expected_v1_hash)
        cid1_2 = make_cid(data)
        self.assertEqual(decode_cid(cid1_2), expected_v1_hash)
        cid1_3 = make_cid(data)
        self.assertEqual(decode_cid(cid1_3), expected_v1_hash)
        cid1_4 = make_cid(data)


if __name__ == "__main__":
    unittest.main()
