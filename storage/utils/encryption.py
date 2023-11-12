import os
import json
import time
import typing

import bittensor as bt
from Crypto.Cipher import AES
from nacl import pwhash, secret

NACL_SALT = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1"


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
    password = wallet.coldkey.public_key.hex()
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
    password = wallet.coldkey.public_key.hex()
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

    return encrypted_data, encrypt_data_with_wallet(
        aes_info_str.encode(), wallet
    )  # Encrypt the serialized JSON string


def decrypt_data_and_deserialize(
    encrypted_data: bytes, encrypted_payload: bytes, wallet: bt.wallet
) -> bytes:
    """
    Decrypts and deserializes the encrypted payload to extract the AES key, nonce, and tag, which are then used to
    decrypt the given encrypted data.

    Args:
        encrypted_data (bytes): AES encrypted data.
        encrypted_payload (bytes): Encrypted payload containing the AES key, nonce, and tag.
        wallet (bt.wallet): Bittensor wallet object containing the coldkey.

    Returns:
        bytes: Decrypted data.

    This function reverses the process performed by `encrypt_data_with_aes_and_serialize`.
    It first decrypts the payload to extract the AES key, nonce, and tag, and then uses them to decrypt the data.
    """
    # Decrypt the payload to get the JSON string
    decrypted_aes_info_str = decrypt_data_with_wallet(encrypted_payload, wallet)

    # Deserialize JSON string to get AES key, nonce, and tag
    aes_info = json.loads(decrypted_aes_info_str)
    aes_key = bytes.fromhex(aes_info["aes_key"])
    nonce = bytes.fromhex(aes_info["nonce"])
    tag = bytes.fromhex(aes_info["tag"])

    # Decrypt data
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)

    return decrypted_data


def test_encrypt_decrypt_small_data():
    """
    A test function to demonstrate the encryption and decryption of a small string using the wallet-based encryption scheme.

    This function is intended for testing and demonstration purposes. It shows how to encrypt and decrypt a small string
    of data using the `encrypt_data_with_wallet` and `decrypt_data_with_wallet` functions.
    """

    data_to_encrypt = b"Your small string here"

    # Encrypt
    encrypted_data = encrypt_data(data_to_encrypt, bt.wallet())

    # Decrypt
    decrypted_data = decrypt_data(encrypted_data, bt.wallet())

    print("Original:", data_to_encrypt)
    print("Encrypted:", encrypted_data)
    print("Decrypted:", decrypted_data)


def test_encrypt_decrypt_large_data():
    """
    A test function to demonstrate the encryption and decryption of a large amount of data using AES and wallet-based encryption.

    This function is intended for testing and demonstration purposes. It shows how to encrypt and decrypt large data
    using the `encrypt_data_with_aes_and_serialize` and `decrypt_data_and_deserialize` functions.
    """

    # Encrypting large data
    data_to_encrypt = b"Large amount of data here..."
    encrypted_data, encrypted_payload = encrypt_data_with_aes_and_serialize(
        data_to_encrypt, bt.wallet()
    )

    # Decrypting data
    decrypted_data = decrypt_data_and_deserialize(
        encrypted_data, encrypted_payload, bt.wallet()
    )

    print("Original Data:", data_to_encrypt)
    print("Decrypted Data:", decrypted_data)


# Timing function for large data encryption and decryption
def time_encrypt_decrypt_large_data(exp=9):
    """
    Measures and prints the time taken to encrypt and decrypt a large amount of data.

    Args:
        exp (int, optional): Exponent to determine the size of the data. Defaults to 9 (1GB).

    This function is used for performance testing. It generates a large amount of random data,
    encrypts it using `encrypt_data_with_aes_and_serialize`, and then decrypts it using
    `decrypt_data_and_deserialize`. The time taken for each operation is printed out.
    """

    wallet = bt.wallet()
    wallet.coldkey  # unlock wallet before timing

    # Generate large data for test
    data_to_encrypt = os.urandom(10**exp)  # 10**9 => 1000MB of random data

    # Start timing encryption
    start_time = time.time()
    encrypted_data, encrypted_payload = encrypt_data_with_aes_and_serialize(
        data_to_encrypt, wallet
    )
    encryption_time = time.time() - start_time

    # Start timing decryption
    start_time = time.time()
    decrypted_data = decrypt_data_and_deserialize(
        encrypted_data, encrypted_payload, wallet
    )
    decryption_time = time.time() - start_time

    # Output timings
    print(f"Encryption Time: {encryption_time} seconds")
    print(f"Decryption Time: {decryption_time} seconds")

    # Optional: Verify if the decrypted data matches the original
    assert (
        decrypted_data == data_to_encrypt
    ), "Decrypted data does not match the original"
