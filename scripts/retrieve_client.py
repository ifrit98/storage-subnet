import torch
import base64
import argparse

import storage
from storage.validator.encryption import decrypt_data_with_private_key

import bittensor as bt


def add_args(parser):
    parser.add_argument(
        "--netuid", type=str, default=22, help="Network unique identifier."
    )
    parser.add_argument(
        "--data_hash",
        type=str,
        default="53511951809382199553183129787036271877629422226473062616888327316540937412815",
        help="Hash of the data to query.",
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
    parser.add_argument(
        "--stake_limit", type=float, default=1000, help="Stake limit to query."
    )
    parser.add_argument(
        "--filepath", type=str, default="./test.txt", help="Filepath to save data."
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

    synapse = storage.protocol.RetrieveUser(data_hash=config.data_hash)
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
        encrypted_data = base64.b64decode(response.encrypted_data)
        decrypted_data = decrypt_data_with_private_key(
            encrypted_data,
            response.encryption_payload,
            bytes(wallet.coldkey.private_key.hex(), "utf-8"),
        )
        print(decrypted_data)

    # Save the data
    with open(config.filepath, "wb") as f:
        f.write(decrypted_data)

    print("Saved data to: {}".format(config.filepath))


if __name__ == "__main__":
    main()
