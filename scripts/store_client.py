import torch
import base64
import argparse

import storage
from storage.validator.encryption import encrypt_data

import bittensor as bt


def add_args(parser):
    parser.add_argument(
        "--filepath",
        type=str,
        required=True,
        help="Path of the data to store on the network.",
    )
    parser.add_argument(
        "--netuid", type=str, default=22, help="Network unique identifier."
    )
    parser.add_argument(
        "--network", type=str, default="test", help="Network to connect to."
    )
    parser.add_argument(
        "--wallet.name", type=str, default="default", help="Wallet coldkey name."
    )
    parser.add_argument(
        "--wallet.hotkey", type=str, default="default", help="Hotkey name to use."
    )


def get_config():
    parser = argparse.ArgumentParser()
    add_args(parser)
    return bt.config(parser)


def main():
    # Initialize the client
    config = get_config()
    print(config)

    wallet = bt.wallet(config=config)
    print(wallet)

    dendrite = bt.dendrite(wallet=wallet)
    print(dendrite)

    with open(config.filepath, "rb") as f:
        raw_data = f.read()

    encrypted_data, encryption_payload = encrypt_data(
        bytes(raw_data, "utf-8"),
        wallet,
    )
    synapse = storage.protocol.StoreUser(
        encrypted_data=base64.b64encode(encrypted_data),
        encryption_payload=encryption_payload,
    )
    print(synapse)

    sub = bt.subtensor(network=config.network)
    print(sub)

    mg = sub.metagraph(config.netuid)
    print(mg)

    # Determine axons to query from metagraph
    vpermits = mg.validator_permit
    vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
    vpermit_uids = torch.where(vpermits)[0]

    query_uids = torch.where(mg.S[vpermit_uids] > config.stake_limit)[0]
    axons = [mg.axons[uid] for uid in query_uids]
    print(axons)

    # Query axons
    responses = dendrite.query(axons, synapse, deserialize=False)
    print(responses)

    for response in responses:
        if response.dendrite.status_code != 200:
            continue

        # Decrypt the response
        data_hash = response.data_hash
        print("Data hash: {}".format(data_hash))
        break

    print("Stored data from: {}".format(config.filepath))


if __name__ == "__main__":
    import sys

    print(sys.argv)
    main()
