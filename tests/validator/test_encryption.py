from unittest import TestCase

from storage.validator.encryption import (
    encrypt_data,
    encrypt_data_with_wallet,
    decrypt_data_with_wallet,
)

from bittensor import wallet as bt_wallet
from nacl import pwhash, secret

import os
import sys


TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir))

NACL_SALT = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1"


class TestStoreCommand(TestCase):
    def test_encrypt_data_with_wallet(self):
        raw_data = "this is so secret, you cannot believe"
        raw_data = bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data
        kdf = pwhash.argon2i.kdf

        key = kdf(
            secret.SecretBox.KEY_SIZE,
            b"whatever",
            NACL_SALT,
            opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
            memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
        )
        # Encrypt the data
        box_1 = secret.SecretBox(key)

        encrypted_1_1 = box_1.encrypt(raw_data)
        decrypted_1_1 = box_1.decrypt(encrypted_1_1)
        self.assertEquals(raw_data, decrypted_1_1)

        """
        #
        # This should be the final test that ensures the code used is OK
        # Generate random data and encrypt/decrypt
        # 
        random_data = os.urandom(256)

        # Generate a new wallet if none exists
        wallet = bt_wallet()
        raw_data = bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data

        encrypted_data = encrypt_data_with_wallet(raw_data, wallet)
        decrypted_data = decrypt_data_with_wallet(raw_data, wallet)

        self.assertEquals(raw_data, decrypted_data)
        """
