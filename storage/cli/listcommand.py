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
import argparse
import storage
import bittensor
from rich import print
from rich.console import Console
from rich.tree import Tree
from typing import List, Optional
from rich.align import Align
from rich.table import Table
from tqdm import tqdm

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


def save_hash_mapping(hash_file, filename, data_hash):
    try:
        with open(os.path.expanduser(hash_file), "r") as file:
            hashes = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        hashes = {}

    hashes[filename] = data_hash

    with open(os.path.expanduser(hash_file), "w") as file:
        json.dump(hashes, file)


def get_hash_mapping(hash_file, filename):
    try:
        with open(os.path.expanduser(hash_file), "r") as file:
            hashes = json.load(file)
            return hashes.get(filename)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def list_all_hashes(hash_file):
    try:
        with open(os.path.expanduser(hash_file), "r") as file:
            hashes = json.load(file)
            return hashes
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def display_hashes_in_table(wallet_name, hashes_dict):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Filename", style="dim", width=30)
    table.add_column("Data Hash", width=120)

    for filename, data_hash in hashes_dict.items():
        table.add_row(filename, data_hash)

    console = Console()
    console.print(f"Hashes for Wallet: {wallet_name}", style="bold green")
    console.print(table)


def create_unified_table(data):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Wallet Name", style="dim", width=20)
    table.add_column("Filename", width=30)
    table.add_column("Data Hash", width=200)

    for wallet_name, hashes in data.items():
        for filename, data_hash in hashes.items():
            table.add_row(wallet_name, filename, data_hash)

    console = Console()
    console.print(table)


class ListLocalHashes:
    """
    Executes the 'list' command to display a table of hashes associated with data stored in the Bittensor network.
    This command is used to list and manage hashes that correspond to data available for retrieval from the network.

    Usage:
    The command iterates through all wallets within the specified wallet path and aggregates hashes from each wallet's designated hash file.
    It then displays these hashes in a unified table format, listing the wallet name, filename, and the corresponding data hash.

    The command is particularly useful for users who store and manage data on the Bittensor network, as it provides an organized view
    of all available data hashes across different wallets.

    Optional arguments:
    - --hash_basepath (str): The base path where hash files are stored. Defaults to '~/.bittensor/hashes'.

    The resulting table includes:
    - Wallet Name: The name of the wallet associated with the data.
    - Filename: The name of the file for which the hash is stored.
    - Data Hash: The hash corresponding to the stored data.

    Example usage:
    >>> stcli retrieve list --hash_basepath ~/.bittensor/hashes

    Note:
    This command is an essential tool for users who interact with data on the Bittensor network,
    allowing them to track and access data hashes conveniently. It helps in maintaining an organized record
    of data hashes for various applications and wallets.
    """

    @staticmethod
    def run(cli):
        r"""Lists hashes available to fetch data from the Bittensor network."""

        try:
            wallets = next(os.walk(os.path.expanduser(cli.config.wallet.path)))[1]
        except StopIteration:
            # No wallet files found.
            wallets = []

        if not os.path.exists(os.path.expanduser(cli.config.hash_basepath)):
            bittensor.logging.warning(
                "Hashes directory does not exist, creating it now"
            )
            os.makedirs(os.path.expanduser(cli.config.hash_basepath))

        cold_wallets = get_coldkey_wallets_for_path(cli.config.wallet.path)
        unified_data = {}
        for cold_wallet in tqdm(cold_wallets, desc="Pulling hashes"):
            if (
                cold_wallet.coldkeypub_file.exists_on_device()
                and not cold_wallet.coldkeypub_file.is_encrypted()
            ):
                hash_file = (
                    os.path.join(cli.config.hash_basepath, cold_wallet.name) + ".json"
                )
                hashes_dict = list_all_hashes(hash_file)
                unified_data[cold_wallet.name] = hashes_dict

        # Display the unified table
        create_unified_table(unified_data)

    @staticmethod
    def check_config(config: "bittensor.config"):
        pass

    @staticmethod
    def add_args(parser: argparse.ArgumentParser):
        list_parser = parser.add_parser("list", help="""List wallets""")
        list_parser.add_argument(
            "--hash_basepath",
            type=str,
            default="~/.bittensor/hashes",
            help="Path to store hashes",
        )
        bittensor.wallet.add_args(list_parser)
        bittensor.subtensor.add_args(list_parser)
