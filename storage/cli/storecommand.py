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
import sys
import json
import torch
import base64
import argparse

import storage
from storage.validator.encryption import encrypt_data
from storage.shared.ecc import hash_data

import bittensor

from rich import print
from rich.console import Console
from rich.tree import Tree
from typing import List, Optional
from rich.align import Align
from rich.table import Table
from rich.prompt import Prompt
from tqdm import tqdm
from storage.validator.utils import get_all_validators

bittensor.trace()

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


def save_hash_mapping(hash_file, filename, data_hash):
    base_dir = os.path.basename(hash_file)
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    try:
        with open(hash_file, "r") as file:
            hashes = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        hashes = {}

    hashes[filename] = data_hash

    with open(hash_file, "w") as file:
        json.dump(hashes, file)


def list_all_hashes(hash_file):
    try:
        with open(hash_file, "r") as file:
            hashes = json.load(file)
            return hashes
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


class StoreData:
    """
    Executes the 'put' command to store data from the local disk on the Bittensor network.
    This command is essential for users who wish to upload and store data securely on the network.

    Usage:
    The command encrypts and sends the data located at the specified file path to the network.
    The data is encrypted using the wallet's private key, ensuring secure storage.
    After successful storage, a unique hash corresponding to the data is generated and saved,
    allowing for easy retrieval of the data in the future.

    This command is particularly useful for users looking to leverage the decentralized nature of the
    Bittensor network for secure data storage.

    Optional arguments:
    - --filepath (str): The path to the data file to be stored on the network.
    - --hash_basepath (str): The base path where hash files are stored. Defaults to '~/.bittensor/hashes'.
    - --stake_limit (float): The stake limit for excluding validator axons from the query.

    The resulting output includes:
    - Success or failure message regarding data storage.
    - The unique data hash generated upon successful storage.

    Example usage:
    >>> ftcli store put --filepath "/path/to/data.txt"

    Note:
    This command is vital for users who need to store data on the Bittensor network securely.
    It provides a streamlined process for encrypting and uploading data, with an emphasis on security and data integrity.
    """

    @staticmethod
    def run(cli):
        r"""Store data from local disk on the Bittensor network."""

        wallet = bittensor.wallet(
            name=cli.config.wallet.name, hotkey=cli.config.wallet.hotkey
        )
        bittensor.logging.debug("wallet:", wallet)

        # Unlock the wallet
        if not cli.config.noencrypt:
            wallet.hotkey
            wallet.coldkey

        cli.config.filepath = os.path.expanduser(cli.config.filepath)
        if not os.path.exists(cli.config.filepath):
            bittensor.logging.error(
                "File does not exist: {}".format(cli.config.filepath)
            )
            return

        with open(cli.config.filepath, "rb") as f:
            raw_data = f.read()

        if not cli.config.noencrypt:
            encrypted_data, encryption_payload = encrypt_data(
                bytes(raw_data, "utf-8") if isinstance(raw_data, str) else raw_data,
                wallet,
            )
        else:
            encrypted_data = raw_data
            encryption_payload = "{}"
        encoded_data = base64.b64encode(encrypted_data)
        bittensor.logging.trace(f"CLI encrypted_data : {encrypted_data[:100]}")
        bittensor.logging.trace(f"CLI encryption_pay : {encryption_payload}")
        bittensor.logging.trace(f"CLI B64ENCODED DATA: {encoded_data[:100]}")
        synapse = storage.protocol.StoreUser(
            encrypted_data=encoded_data,
            encryption_payload=encryption_payload,
        )
        bittensor.logging.debug(f"sending synapse: {synapse.dendrite.dict()}")

        hash_basepath = os.path.expanduser(cli.config.hash_basepath)
        hash_filepath = os.path.join(hash_basepath, wallet.name + ".json")
        bittensor.logging.debug("store hashes path:", hash_filepath)

        dendrite = bittensor.dendrite(wallet=wallet)
        bittensor.logging.debug("dendrite:", dendrite)

        sub = bittensor.subtensor(network=cli.config.subtensor.network)
        bittensor.logging.debug("subtensor:", sub)

        mg = sub.metagraph(cli.config.netuid)
        bittensor.logging.debug("metagraph:", mg)

        self = argparse.Namespace()
        self.config = cli.config
        self.metagraph = mg

        # Determine axons to query from metagraph
        query_uids = get_all_validators(self)
        bittensor.logging.debug("query uids:", query_uids)
        axons = [mg.axons[uid] for uid in query_uids]
        bittensor.logging.debug("query axons:", axons)

        with bittensor.__console__.status(":satellite: Storing data..."):
            # Query axons
            responses = dendrite.query(axons, synapse, timeout=270, deserialize=False)
            bittensor.logging.debug(
                "axon responses:", [resp.dendrite.dict() for resp in responses]
            )

            success = False
            failure_modes = {"code": [], "message": []}
            for response in responses:
                if response.dendrite.status_code != 200:
                    failure_modes["code"].append(response.dendrite.status_code)
                    failure_modes["message"].append(response.dendrite.status_message)
                    continue

                data_hash = (
                    response.data_hash.decode("utf-8")
                    if isinstance(response.data_hash, bytes)
                    else response.data_hash
                )
                bittensor.logging.debug("received data hash: {}".format(data_hash))
                success = True
                break

        if success:
            # Save hash mapping after successful storage
            filename = os.path.basename(cli.config.filepath)
            save_hash_mapping(hash_filepath, filename=filename, data_hash=data_hash)
            bittensor.logging.info(
                f"Stored {filename} on the Bittensor network with hash {data_hash}"
            )
        else:
            bittensor.logging.error(f"Failed to store data at {cli.config.filepath}.")
            bittensor.logging.error(
                f"Response failure codes & messages {failure_modes}"
            )

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

        if not config.is_set("filepath") and not config.no_prompt:
            config.filepath = Prompt.ask(
                "Enter path to data you with to store on the Bittensor network",
            )

    @staticmethod
    def add_args(parser: argparse.ArgumentParser):
        store_parser = parser.add_parser(
            "put", help="""Store data on the Bittensor network."""
        )
        store_parser.add_argument(
            "--hash_basepath",
            type=str,
            default=defaults.hash_basepath,
            help="Path to store hashes",
        )
        store_parser.add_argument(
            "--stake_limit",
            type=float,
            default=500,
            help="Stake limit to exclude validator axons to query.",
        )
        store_parser.add_argument(
            "--filepath",
            type=str,
            help="Path to data to store on the Bittensor network.",
        )
        store_parser.add_argument(
            "--netuid",
            type=str,
            default=defaults.netuid,
            help="Network identifier for the Bittensor network.",
        )
        store_parser.add_argument(
            "--neuron.vpermit_tao_limit",
            type=int,
            default=500,
            help="Tao limit for the validator permit.",
        )
        store_parser.add_argument(
            "--noencrypt",
            action="store_true",
            help="Do not encrypt the data before storing it on the Bittensor network.",
        )

        bittensor.wallet.add_args(store_parser)
        bittensor.subtensor.add_args(store_parser)
        bittensor.logging.add_args(store_parser)
