from unittest import TestCase

from storage.validator.encryption import encrypt_data, encrypt_data_with_wallet

from bittensor import wallet as bt_wallet
from nacl import pwhash, secret

import os
import sys


TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir))

NACL_SALT = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1"


class TestStoreCommand(TestCase):

    def test_encrypt_data_with_wallet(self):
        
        raw_data = 'this is so secret, you cannot believe'
        raw_data = bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data
        kdf = pwhash.argon2i.kdf

        key = kdf(
            secret.SecretBox.KEY_SIZE,
            b'whatever',
            NACL_SALT,
            opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
            memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
        )

        # Encrypt the data
        box_1 = secret.SecretBox(key)
        box_2 = secret.SecretBox(key)
        #self.assertEquals(box_1, box_2) # this is FALSE, commented to trigger next asserts
        # 2 boxes with same key are different

        encrypted_1_1 = box_1.encrypt(raw_data)
        encrypted_1_2 = box_1.encrypt(raw_data)
        # same box encrypting same data produces different outputs
    
        self.assertEquals(encrypted_1_1, encrypted_1_2)

        '''
        #
        # This should be the final test that ensures the code used is OK
        # I'm just leaving the code above to expose the internals that are producing diferents hashes for the same content in diff executions
        #
        # commented bcz is not needed, above code is enough
        filepath = f'{PROJECT_DIR}/cli/test-data/random-text.txt'

        with open(filepath, "rb") as f:
            raw_data = f.read()

        wallet = bt_wallet(
            name='test_subnet_21', hotkey='default'
        )
        raw_data = bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data

        encrypted_data_1 = encrypt_data_with_wallet(raw_data, wallet)
        encrypted_data_2 = encrypt_data_with_wallet(raw_data, wallet)

        self.assertEquals(encrypted_data_1, encrypted_data_2)
        '''