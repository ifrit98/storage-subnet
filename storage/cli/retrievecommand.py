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
import torch
import base64
import argparse

import storage
from storage.validator.encryption import decrypt_data_with_private_key
from storage.api.retrieve_api import retrieve

import bittensor

from typing import List
from rich.prompt import Prompt

from .default_values import defaults


# Create a console instance for CLI display.
console = bittensor.__console__


def list_all_hashes(hash_file):
    try:
        with open(os.path.expanduser(hash_file), "r") as file:
            hashes = json.load(file)
            return hashes
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


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
    >>> ftcli retrieve get --data_hash "123abc"

    Note:
    This command is essential for individuals and applications that require access to specific data from the Bittensor network.
    It emphasizes security through encryption and selective querying of validator axons.
    """

    @staticmethod
    async def run(cli):
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
        base_outpath = os.path.expanduser(cli.config.storage_basepath)
        outpath = os.path.join(base_outpath, cli.config.cid)
        try:
            if (
                wallet.coldkeypub_file.exists_on_device()
                and not wallet.coldkeypub_file.is_encrypted()
            ):
                hash_file = (
                    os.path.join(cli.config.hash_basepath, wallet.name) + ".json"
                )
                hashes_dict = list_all_hashes(hash_file)
                bittensor.logging.debug(f"hashes dict: {hashes_dict}")
                reverse_hashes_dict = {v: k for k, v in hashes_dict.items() if "hotkeys" not in k}
                if cli.config.cid in reverse_hashes_dict:
                    filename = reverse_hashes_dict[cli.config.cid]
                    outpath = os.path.join(base_outpath, filename)
                    bittensor.logging.debug(f"set filename: {filename}")
                    hotkeys = hashes_dict[filename + "_hotkeys"]

        except Exception as e:
            bittensor.logging.warning(
                "Failed to lookup filename for CID: {} ".format(e),
                "Reverting to hash value as filename {outpath}",
            )

        # TODO: Pull hotkeys from the cache for the given cid.

        try:
            sub = bittensor.subtensor(network=cli.config.subtensor.network)
            bittensor.logging.debug("subtensor:", sub)
            await RetrieveData._run(cli, sub, outpath, wallet, hotkeys)
        finally:
            if "sub" in locals():
                sub.close()
                bittensor.logging.debug("closing subtensor connection")

    @staticmethod
    async def _run(cli, sub: "bittensor.subtensor", outpath: str, wallet: "bittensor.wallet", hotkeys: List[str] = None):
        r"""Retrieve data from the Bittensor network for the given data_hash."""

        success = False
        with bittensor.__console__.status(":satellite: Retreiving data..."):

            data = await retrieve(
                cli.config.cid,
                wallet,
                sub,
                netuid=cli.config.netuid,
                hotkeys=hotkeys,
            )

            success = True

        if success:
            # Save the data
            with open(outpath, "wb") as f:
                f.write(data)

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

        if not config.is_set("cid") and not config.no_prompt:
            config.cid = Prompt.ask("Enter CID of data to retrieve")

    @staticmethod
    def add_args(parser: argparse.ArgumentParser):
        retrieve_parser = parser.add_parser(
            "get", help="""Retrieve data from the Bittensor network."""
        )
        retrieve_parser.add_argument(
            "--cid",
            type=str,
            help="Data content id to retrieve from= the Bittensor network.",
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
