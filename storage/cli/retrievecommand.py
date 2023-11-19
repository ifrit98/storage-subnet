import os
import sys
import json
import torch
import base64
import argparse

import storage
from storage.validator.encryption import decrypt_data_with_private_key

import bittensor

from rich import print
from rich.console import Console
from rich.tree import Tree
from typing import List, Optional
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt
from tqdm import tqdm

from .default_values import defaults


# Create a console instance for CLI display.
console = bittensor.__console__


def get_coldkey_wallets_for_path(path: str) -> List["bittensor.wallet"]:
    try:
        wallet_names = next(os.walk(os.path.expanduser(path)))[1]
        return [bittensor.wallet(path=path, name=name) for name in wallet_names]
    except StopIteration:
        # No wallet files found.
        wallets = []
    return wallets


def get_hash_mapping(hash_file, filename):
    try:
        with open(os.path.expanduser(hash_file), "r") as file:
            hashes = json.load(file)
            return hashes.get(filename)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


class RetrieveData:
    """
    Executes the 'get' command to retrieve data from the Bittensor network using a specific data hash.
    This command is crucial for users who wish to access data stored on the network using its unique identifier.

    Usage:
    The command fetches the data associated with the provided hash by querying validator axons with sufficient stake.
    The retrieved data is decrypted using the wallet's private key and stored at a specified location.

    The command caters to users who need to access specific data from the network, ensuring a secure and efficient retrieval process.

    Optional arguments:
    - --data_hash (str): The unique hash of the data to be retrieved.
    - --hash_basepath (str): The base path where hash files are stored. Defaults to '~/.bittensor/hashes'.
    - --stake_limit (float): The stake limit for excluding validator axons from the query.
    - --storage_basepath (str): The path to store the retrieved data. Defaults to '~/.bittensor/storage'.

    The resulting output includes:
    - Success or failure message regarding data retrieval.
    - Location where the retrieved data is saved (if successful).

    Example usage:
    >>> stcli retrieve get --data_hash "123abc"

    Note:
    This command is essential for individuals and applications that require access to specific data from the Bittensor network.
    It emphasizes security through encryption and selective querying of validator axons.
    """

    @staticmethod
    def run(cli):
        r"""Retrieve data from the Bittensor network for the given data_hash."""

        wallet = bittensor.wallet(
            name=cli.config.wallet.name, hotkey=cli.config.wallet.hotkey
        )
        bittensor.logging.debug("wallet:", wallet)

        cli.config.storage_basepath = os.path.expanduser(cli.config.storage_basepath)

        if not os.path.exists(cli.config.storage_basepath):
            bittensor.logging.info(
                "generating filepath: {}".format(cli.config.storage_basepath)
            )
            os.makedirs(cli.config.storage_basepath)
        outpath = os.path.expanduser(cli.config.storage_basepath)
        outpath = os.path.join(outpath, cli.config.data_hash)
        bittensor.logging.debug("outpath:", outpath)

        dendrite = bittensor.dendrite(wallet=wallet)
        bittensor.logging.debug("dendrite:", dendrite)

        synapse = storage.protocol.RetrieveUser(data_hash=cli.config.data_hash)
        bittensor.logging.debug("synapse:", synapse)

        sub = bittensor.subtensor(network=cli.config.subtensor.network)
        bittensor.logging.debug("subtensor:", sub)

        mg = sub.metagraph(cli.config.netuid)
        bittensor.logging.debug("metagraph:", mg)

        # Determine axons to query from metagraph
        vpermits = mg.validator_permit
        vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
        vpermit_uids = torch.where(vpermits)[0]

        query_uids = torch.where(mg.S[vpermit_uids] > cli.config.stake_limit)[0]
        axons = [mg.axons[uid] for uid in query_uids]
        bittensor.logging.debug("query axons:", axons)

        # Query axons
        responses = dendrite.query(axons, synapse, deserialize=False)
        bittensor.logging.debug("axon responses:", responses)

        success = False
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
            bittensor.logging.debug(decrypted_data)
            success = True

        if success:
            # Save the data
            with open(outpath, "wb") as f:
                f.write(decrypted_data)

            bittensor.logging.info("Saved retrieved data to: {}".format(outpath))
        else:
            bittensor.logging.error("Failed to retrieve data.")

    @staticmethod
    def check_config(config: "bittensor.config"):
        if not config.is_set("subtensor.network") and not config.no_prompt:
            network = Prompt.ask(
                "Enter subtensor network",
                default=defaults.subtensor.network,
                choices=["finney", "test"],
            )
            config.subtensor.network = str(network)

        if not config.is_set("netuid") and not config.no_prompt:
            netuid = Prompt.ask(
                "Enter netuid",
                default=defaults.netuid
                if config.subtensor.network == "finney"
                else "22",
            )
            config.netuid = str(netuid)

        if not config.is_set("wallet.name") and not config.no_prompt:
            wallet_name = Prompt.ask("Enter wallet name", default=defaults.wallet.name)
            config.wallet.name = str(wallet_name)

        if not config.is_set("wallet.hotkey") and not config.no_prompt:
            wallet_hotkey = Prompt.ask(
                "Enter wallet hotkey", default=defaults.wallet.hotkey
            )
            config.wallet.hotkey = str(wallet_hotkey)

        if not config.is_set("storage_basepath") and not config.no_prompt:
            config.storage_basepath = Prompt.ask(
                "Enter path to store retrieved data",
                default=defaults.storage_basepath,
            )

        if not config.is_set("data_hash") and not config.no_prompt:
            config.data_hash = Prompt.ask("Enter hash of data to retrieve")

    @staticmethod
    def add_args(parser: argparse.ArgumentParser):
        retrieve_parser = parser.add_parser(
            "get", help="""Retrieve data from the Bittensor network."""
        )
        retrieve_parser.add_argument(
            "--data_hash",
            type=str,
            help="Data hash to retrieve in the Bittensor network.",
        )
        retrieve_parser.add_argument(
            "--hash_basepath",
            type=str,
            default=defaults.hash_basepath,
            help="Path to store hashes",
        )
        retrieve_parser.add_argument(
            "--stake_limit",
            type=float,
            default=1000,
            help="Stake limit to exclude validator axons to query.",
        )
        retrieve_parser.add_argument(
            "--storage_basepath",
            type=str,
            default=defaults.storage_basepath,
            help="Path to store retrieved data.",
        )
        retrieve_parser.add_argument(
            "--netuid",
            type=str,
            default=defaults.netuid,
            help="Network identifier for the Bittensor network.",
        )

        bittensor.wallet.add_args(retrieve_parser)
        bittensor.subtensor.add_args(retrieve_parser)
        bittensor.logging.add_args(retrieve_parser)
