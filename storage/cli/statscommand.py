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

import argparse
from redis import asyncio as aioredis
import asyncio
import bittensor as bt
from rich.table import Table
from rich.console import Console
from storage.validator.database import get_miner_statistics, total_hotkey_storage


async def show_all_miner_statistics(r: aioredis.Redis):
    data = await get_miner_statistics(r)

    console = Console()

    # Create a table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Hotkey", style="dim")
    table.add_column("Total Successes")
    table.add_column("Store A/S")
    table.add_column("Challenge A/S")
    table.add_column("Retrieve A/S")
    table.add_column("Store Rate")
    table.add_column("Challenge Rate")
    table.add_column("Retrieve Rate")
    table.add_column("Tier")
    table.add_column("Current Storage / Limit (GB)")

    for hotkey, stats in data.items():
        # Compute the success rate for each task type
        challenge_success_rate = (
            int(stats["challenge_successes"]) / int(stats["challenge_attempts"])
            if int(stats["challenge_attempts"]) > 0
            else 0
        )
        retrieval_success_rate = (
            int(stats["retrieve_successes"]) / int(stats["retrieve_attempts"])
            if int(stats["retrieve_attempts"]) > 0
            else 0
        )
        store_success_rate = (
            int(stats["store_successes"]) / int(stats["store_attempts"])
            if int(stats["store_attempts"]) > 0
            else 0
        )

        # Add rows to the table
        table.add_row(
            hotkey,
            stats["total_successes"],
            stats["store_attempts"] + " / " + stats["store_successes"],
            stats["challenge_successes"] + " / " + stats["challenge_attempts"],
            stats["retrieve_successes"] + " / " + stats["retrieve_attempts"],
            str(store_success_rate * 100),
            str(challenge_success_rate * 100),
            str(retrieval_success_rate * 100),
            stats["tier"],
            str(await total_hotkey_storage(hotkey, r) // (1024**3))
            + " / "
            + str(int(stats["storage_limit"]) // (1024**3)),
        )

    # Print the table to the console
    console.print(table)


class ListMinerStats:
    """
    Show the miner stats for a given hotkey.

    Optional arguments:
    - --wallet.name The name of the wallet associated with the data.
    - --wallet.hotkey The hotkey name associated with the wallet.
    - --index The index of the redis database running on the miner.

    Example usage:
    >>> ftcli miner stats --index 0

    Note:
    This command is an essential tool for users who interact with data on the Bittensor network,
    allowing them to track and access data hashes conveniently. It helps in maintaining an organized record
    of data hashes for various applications and wallets.
    """

    @staticmethod
    def run(cli):
        r"""Lists hashes available to fetch data from the Bittensor network."""

        # Get stats from redis
        r = aioredis.StrictRedis(db=cli.config.index)
        coro = show_all_miner_statistics(r)
        asyncio.run(coro)

    @staticmethod
    def check_config(config: "bt.config"):
        pass

    @staticmethod
    def add_args(parser: argparse.ArgumentParser):
        stats_parser = parser.add_parser("stats", help="""Show stats for hotkey.""")
        stats_parser.add_argument(
            "--index",
            type=int,
            default=0,
            help="Path to store hashes",
        )
        bt.wallet.add_args(stats_parser)
