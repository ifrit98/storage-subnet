import unittest
import hashlib

from storage.validator.cid import make_cid, decode_cid


class TestCIDFunctions(unittest.TestCase):
    def test_cid(self):
        raw_data = "abcdef"
        cid = make_cid(raw_data)
        decoded_hash = decode_cid(cid)
        self.assertEqual(decoded_hash, hashlib.sha256(raw_data.encode()).digest())

        cid_str = str(cid)
        decoded_hash_str = decode_cid(cid_str)
        self.assertEqual(decoded_hash_str, hashlib.sha256(raw_data.encode()).digest())

    def test_cid_with_different_inputs(self):
        test_data = [
            "",  # Empty string
            "Hello World",  # Simple string
            "😊🌍🚀",  # Unicode string
            "a" * 1000,  # Long string
        ]

        for data in test_data:
            cid = make_cid(data)
            decoded_hash = decode_cid(cid)
            self.assertEqual(
                decoded_hash,
                hashlib.sha256(data.encode()).digest(),
                f"Test failed for data: {data}",
            )


if __name__ == "__main__":
    unittest.main()
