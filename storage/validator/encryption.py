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

import os
import json
import typing

import bittensor as bt
from Crypto.Cipher import AES
from nacl import pwhash, secret
from nacl.encoding import HexEncoder
from nacl.utils import EncryptedMessage

NACL_SALT = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1"


def encrypt_aes(filename: typing.Union[bytes, str], key: bytes) -> bytes:
    """
    Encrypt the data in the given filename using AES-GCM.

    Parameters:
    - filename: str or bytes. If str, it's considered as a file name. If bytes, as the data itself.
    - key: bytes. 16-byte (128-bit), 24-byte (192-bit), or 32-byte (256-bit) secret key.

    Returns:
    - cipher_text: bytes. The encrypted data.
    - nonce: bytes. The nonce used for the GCM mode.
    - tag: bytes. The tag for authentication.
    """

    # If filename is a string, treat it as a file name and read the data
    if isinstance(filename, str):
        with open(filename, "rb") as file:
            data = file.read()
    else:
        data = filename

    # Initialize AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM)

    # Encrypt the data
    cipher_text, tag = cipher.encrypt_and_digest(data)

    return cipher_text, cipher.nonce, tag


def decrypt_aes(cipher_text: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt the data using AES-GCM.

    Parameters:
    - cipher_text: bytes. The encrypted data.
    - key: bytes. The secret key used for decryption.
    - nonce: bytes. The nonce used in the GCM mode for encryption.
    - tag: bytes. The tag for authentication.

    Returns:
    - data: bytes. The decrypted data.
    """

    # Initialize AES-GCM cipher with the given key and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Decrypt the data and verify the tag
    try:
        data = cipher.decrypt_and_verify(cipher_text, tag)
    except ValueError:
        # This is raised if the tag does not match
        raise ValueError("Incorrect decryption key or corrupted data.")

    return data


def encrypt_data_with_wallet(data: bytes, wallet) -> bytes:
    """
    Encrypts the given data using a symmetric key derived from the wallet's coldkey public key.

    Args:
        data (bytes): Data to be encrypted.
        wallet (bt.wallet): Bittensor wallet object containing the coldkey.

    Returns:
        bytes: Encrypted data.

    This function generates a symmetric key using the public key of the wallet's coldkey.
    The generated key is used to encrypt the data using the NaCl secret box (XSalsa20-Poly1305).
    The function is intended for encrypting arbitrary data securely using wallet-based keys.
    """
    # Derive symmetric key from wallet's coldkey
    password = wallet.coldkey.private_key.hex()
    password_bytes = bytes(password, "utf-8")
    kdf = pwhash.argon2i.kdf
    key = kdf(
        secret.SecretBox.KEY_SIZE,
        password_bytes,
        NACL_SALT,
        opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
        memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
    )

    # Encrypt the data
    box = secret.SecretBox(key)
    encrypted = box.encrypt(data)
    return encrypted


def decrypt_data_with_coldkey_private_key(
    encrypted_data: bytes, private_key: typing.Union[str, bytes]
) -> bytes:
    """
    Decrypts the given encrypted data using a symmetric key derived from the wallet's coldkey public key.

    Args:
        encrypted_data (bytes): Data to be decrypted.
        private_key (bytes): The bittensor wallet private key (password) to decrypt the AES payload.

    Returns:
        bytes: Decrypted data.

    Similar to the encryption function, this function derives a symmetric key from the wallet's coldkey public key.
    It then uses this key to decrypt the given encrypted data. The function is primarily used for decrypting data
    that was previously encrypted by the `encrypt_data_with_wallet` function.
    """
    password_bytes = (
        bytes(private_key, "utf-8") if isinstance(private_key, str) else private_key
    )

    kdf = pwhash.argon2i.kdf
    key = kdf(
        secret.SecretBox.KEY_SIZE,
        password_bytes,
        NACL_SALT,
        opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
        memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
    )

    box = secret.SecretBox(key)
    decrypted = box.decrypt(encrypted_data)
    return decrypted


def decrypt_data_with_wallet(encrypted_data: bytes, wallet) -> bytes:
    """
    Decrypts the given encrypted data using a symmetric key derived from the wallet's coldkey public key.

    Args:
        encrypted_data (bytes): Data to be decrypted.
        wallet (bt.wallet): Bittensor wallet object containing the coldkey.

    Returns:
        bytes: Decrypted data.

    Similar to the encryption function, this function derives a symmetric key from the wallet's coldkey public key.
    It then uses this key to decrypt the given encrypted data. The function is primarily used for decrypting data
    that was previously encrypted by the `encrypt_data_with_wallet` function.
    """
    # Derive symmetric key from wallet's coldkey
    password = wallet.coldkey.private_key.hex()
    password_bytes = bytes(password, "utf-8")
    kdf = pwhash.argon2i.kdf
    key = kdf(
        secret.SecretBox.KEY_SIZE,
        password_bytes,
        NACL_SALT,
        opslimit=pwhash.argon2i.OPSLIMIT_SENSITIVE,
        memlimit=pwhash.argon2i.MEMLIMIT_SENSITIVE,
    )

    # Decrypt the data
    box = secret.SecretBox(key)
    decrypted = box.decrypt(encrypted_data)
    return decrypted


def encrypt_data_with_aes_and_serialize(
    data: bytes, wallet: bt.wallet
) -> typing.Tuple[bytes, bytes]:
    """
    Decrypts the given encrypted data using a symmetric key derived from the wallet's coldkey public key.

    Args:
        encrypted_data (bytes): Data to be decrypted.
        wallet (bt.wallet): Bittensor wallet object containing the coldkey.

    Returns:
        bytes: Decrypted data.

    Similar to the encryption function, this function derives a symmetric key from the wallet's coldkey public key.
    It then uses this key to decrypt the given encrypted data. The function is primarily used for decrypting data
    that was previously encrypted by the `encrypt_data_with_wallet` function.
    """
    # Generate a random AES key
    aes_key = os.urandom(32)  # AES key for 256-bit encryption

    # Create AES cipher
    cipher = AES.new(aes_key, AES.MODE_GCM)
    nonce = cipher.nonce

    # Encrypt the data
    encrypted_data, tag = cipher.encrypt_and_digest(data)

    # Serialize AES key, nonce, and tag
    aes_info = {
        "aes_key": aes_key.hex(),  # Convert bytes to hex string for serialization
        "nonce": nonce.hex(),
        "tag": tag.hex(),
    }
    aes_info_str = json.dumps(aes_info)

    encrypted_msg: EncryptedMessage = encrypt_data_with_wallet(
        aes_info_str.encode(), wallet
    )  # Encrypt the serialized JSON string

    return encrypted_data, serialize_nacl_encrypted_message(encrypted_msg)


encrypt_data = encrypt_data_with_aes_and_serialize


def decrypt_data_and_deserialize(
    encrypted_data: bytes, encryption_payload: bytes, wallet: bt.wallet
) -> bytes:
    """
    Decrypts and deserializes the encrypted payload to extract the AES key, nonce, and tag, which are then used to
    decrypt the given encrypted data.

    Args:
        encrypted_data (bytes): AES encrypted data.
        encryption_payload (bytes): Encrypted payload containing the AES key, nonce, and tag.
        wallet (bt.wallet): Bittensor wallet object containing the coldkey.

    Returns:
        bytes: Decrypted data.

    This function reverses the process performed by `encrypt_data_with_aes_and_serialize`.
    It first decrypts the payload to extract the AES key, nonce, and tag, and then uses them to decrypt the data.
    """

    # Deserialize the encrypted payload to get the AES key, nonce, and tag in nacl.utils.EncryptedMessage format
    encrypted_msg: EncryptedMessage = deserialize_nacl_encrypted_message(
        encryption_payload
    )

    # Decrypt the payload to get the JSON string
    decrypted_aes_info_str = decrypt_data_with_wallet(encrypted_msg, wallet)

    # Deserialize JSON string to get AES key, nonce, and tag
    aes_info = json.loads(decrypted_aes_info_str)
    aes_key = bytes.fromhex(aes_info["aes_key"])
    nonce = bytes.fromhex(aes_info["nonce"])
    tag = bytes.fromhex(aes_info["tag"])

    # Decrypt data
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    return decrypted_data


def decrypt_data_and_deserialize_with_coldkey_private_key(
    encrypted_data: bytes,
    encryption_payload: bytes,
    private_key: typing.Union[str, bytes],
) -> bytes:
    """
    Decrypts and deserializes the encrypted payload to extract the AES key, nonce, and tag, which are then used to
    decrypt the given encrypted data.

    Args:
        encrypted_data (bytes): AES encrypted data.
        encryption_payload (bytes): Encrypted payload containing the AES key, nonce, and tag.
        private_key (bytes): The bittensor wallet private key (password) to decrypt the AES payload.

    Returns:
        bytes: Decrypted data.

    This function reverses the process performed by `encrypt_data_with_aes_and_serialize`.
    It first decrypts the payload to extract the AES key, nonce, and tag, and then uses them to decrypt the data.
    """

    # Deserialize the encrypted payload to get the AES key, nonce, and tag in nacl.utils.EncryptedMessage format
    encrypted_msg: EncryptedMessage = deserialize_nacl_encrypted_message(
        encryption_payload
    )

    # Decrypt the payload to get the JSON string
    decrypted_aes_info_str = decrypt_data_with_coldkey_private_key(
        encrypted_msg, private_key
    )

    # Deserialize JSON string to get AES key, nonce, and tag
    aes_info = json.loads(decrypted_aes_info_str)
    aes_key = bytes.fromhex(aes_info["aes_key"])
    nonce = bytes.fromhex(aes_info["nonce"])
    tag = bytes.fromhex(aes_info["tag"])

    # Decrypt data
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    return decrypted_data


decrypt_data = decrypt_data_and_deserialize
decrypt_data_with_private_key = decrypt_data_and_deserialize_with_coldkey_private_key


def serialize_nacl_encrypted_message(encrypted_message: EncryptedMessage) -> str:
    """
    Serializes an EncryptedMessage object to a JSON string.

    Args:
        encrypted_message (EncryptedMessage): The EncryptedMessage object to serialize.

    Returns:
        str: A JSON string representing the serialized object.

    This function takes an EncryptedMessage object, extracts its nonce and ciphertext,
    and encodes them into a hex format. It then constructs a dictionary with these
    values and serializes the dictionary into a JSON string.
    """
    data = {
        "nonce": HexEncoder.encode(encrypted_message.nonce).decode("utf-8"),
        "ciphertext": HexEncoder.encode(encrypted_message.ciphertext).decode("utf-8"),
    }
    return json.dumps(data)


def deserialize_nacl_encrypted_message(serialized_data: str) -> EncryptedMessage:
    """
    Deserializes a JSON string back into an EncryptedMessage object.

    Args:
        serialized_data (str): The JSON string to deserialize.

    Returns:
        EncryptedMessage: The reconstructed EncryptedMessage object.

    This function takes a JSON string representing a serialized EncryptedMessage object,
    decodes it into a dictionary, and extracts the nonce and ciphertext. It then
    reconstructs the EncryptedMessage object using the original nonce and ciphertext.
    """
    data = json.loads(serialized_data)
    nonce = HexEncoder.decode(data["nonce"].encode("utf-8"))
    ciphertext = HexEncoder.decode(data["ciphertext"].encode("utf-8"))
    combined = nonce + ciphertext
    return EncryptedMessage._from_parts(nonce, ciphertext, combined)


def setup_encryption_wallet(
    wallet_name="encryption",
    wallet_hotkey="encryption",
    password="dummy_password",
    n_words=12,
    use_encryption=False,
    overwrite=False,
):
    """
    Sets up a Bittensor wallet with coldkey and coldkeypub using a generated mnemonic.

    Args:
        wallet_name (str): Name of the wallet. Default is 'encryption_coldkey'.
        wallet_hotkey (str): Name of the hotkey. Default is 'encryption_hotkey'.
        n_words (int): Number of words for the mnemonic. Default is 12.
        password (str): Password used for encryption. Default is 'your_password'.
        use_encryption (bool): Flag to determine if encryption should be used. Default is True.
        overwrite (bool): Flag to determine if existing keys should be overwritten. Default is False.

    Returns:
        bt.wallet: A Bittensor wallet object with coldkey and coldkeypub set.
    """

    # Init wallet
    w = bt.wallet(wallet_name, wallet_hotkey)

    # Check if wallet exists on device
    if w.coldkey_file.exists_on_device() or w.coldkeypub_file.exists_on_device():
        bt.logging.info(f"Wallet {w} already exists on device. Not overwriting wallet.")
        return w

    # Generate mnemonic and create keypair
    mnemonic = bt.Keypair.generate_mnemonic(n_words)
    keypair = bt.Keypair.create_from_mnemonic(mnemonic)

    # Set coldkeypub
    w._coldkeypub = bt.Keypair(ss58_address=keypair.ss58_address)
    w.coldkeypub_file.set_keypair(
        w._coldkeypub, encrypt=use_encryption, overwrite=overwrite, password=password
    )

    # Set coldkey
    w._coldkey = keypair
    w.coldkey_file.set_keypair(
        w._coldkey, encrypt=use_encryption, overwrite=overwrite, password=password
    )

    # Write cold keyfile data to file with specified password
    keyfile = w.coldkey_file
    keyfile.make_dirs()
    keyfile_data = bt.serialized_keypair_to_keyfile_data(keypair)
    if use_encryption:
        keyfile_data = bt.encrypt_keyfile_data(keyfile_data, password)
    keyfile._write_keyfile_data_to_file(keyfile_data, overwrite=True)

    # Setup hotkey (dummy, but necessary)
    mnemonic = bt.Keypair.generate_mnemonic(n_words)
    keypair = bt.Keypair.create_from_mnemonic(mnemonic)
    w.set_hotkey(keypair, encrypt=False, overwrite=True)

    return w
