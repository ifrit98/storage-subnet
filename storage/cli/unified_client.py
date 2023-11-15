import json
import torch
import base64
import argparse

import storage
from storage.validator.encryption import encrypt_data
from storage.validator.encryption import decrypt_data_with_private_key

import bittensor as bt


def add_args(parser):
    parser.add_argument(
        "--mode",
        type=str,
        default=None,
        choices=["store", "retrieve"],
        help="Operation mode: 'store' or 'retrieve'.",
    )
    parser.add_argument(
        "--netuid", type=str, default=22, help="Network unique identifier."
    )
    parser.add_argument("--data_hash", type=str, help="Hash of the data to query.")
    parser.add_argument("--network", type=str, help="Network to connect to.")
    parser.add_argument("--wallet.name", type=str, help="Wallet coldkey name.")
    parser.add_argument("--wallet.hotkey", type=str, help="Hotkey name to use.")
    parser.add_argument(
        "--stake_limit", type=float, default=1000, help="Stake limit to query."
    )
    parser.add_argument(
        "--filepath", type=str, help="Filepath for storing or retrieving data."
    )


def get_config():
    parser = argparse.ArgumentParser()
    add_args(parser)
    return bt.config(parser)


class StorageClient:
    def __init__(self, config=None):
        self.config = config or get_config()
        self.sub = bt.subtensor(network=config.network)
        self.mg = self.sub.metagraph(config.netuid)
        self.wallet = bt.wallet(config=config)
        self.dendrite = bt.dendrite(wallet=self.wallet)

        # unlock wallet
        self.wallet.hotkey
        self.wallet.coldkey

    def determine_axons_to_query(self):
        # Determine axons to query from metagraph
        vpermits = self.mg.validator_permit
        vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
        vpermit_uids = torch.where(vpermits)[0]

        query_uids = torch.where(self.mg.S[vpermit_uids] > self.config.stake_limit)[0]
        axons = [self.mg.axons[uid] for uid in query_uids]
        print(axons)
        return axons

    def store_data(self):
        with open(self.config.filepath, "rb") as f:
            raw_data = f.read()

        encrypted_data, encryption_payload = encrypt_data(
            bytes(raw_data, "utf-8"),
            self.wallet,
        )
        synapse = storage.protocol.StoreUser(
            encrypted_data=base64.b64encode(encrypted_data),
            encryption_payload=encryption_payload,
        )
        print(synapse)

        axons = self.determine_axons_to_query()

        # Query axons
        responses = self.dendrite.query(axons, synapse, deserialize=False)
        print(responses)

        for response in responses:
            if response.dendrite.status_code != 200:
                continue

            # Decrypt the response
            data_hash = response.data_hash
            print("Data hash: {}".format(data_hash))
            break

        # Save hash mapping after successful storage
        data_hash = "some_generated_hash"  # Replace with actual hash generation logic
        save_hash_mapping(self.config.filepath, data_hash)
        print(f"Stored {self.config.filepath} with hash: {data_hash}")

    def retrieve_data(self):
        synapse = storage.protocol.RetrieveUser(data_hash=self.config.data_hash)
        print(synapse)

        axons = self.determine_axons_to_query()

        # Query axons
        responses = self.dendrite.query(axons, synapse, deserialize=False)
        print(responses)

        for response in responses:
            if response.dendrite.status_code != 200:
                continue

            # Decrypt the response
            encrypted_data = base64.b64decode(response.encrypted_data)
            decrypted_data = decrypt_data_with_private_key(
                encrypted_data,
                response.encryption_payload,
                bytes(self.wallet.coldkey.private_key.hex(), "utf-8"),
            )
            print(decrypted_data)

        # Save the data
        with open(config.filepath, "wb") as f:
            f.write(decrypted_data)

        print("Saved data to: {}".format(config.filepath))


def main():
    # Initialize the client
    config = get_config()
    print(config)

    client = StorageClient(config)

    if config.mode == "store":
        client.store_data()

    if config.mode == "retrieve":
        client.retrieve_data()


if __name__ == "__main__":
    main()
