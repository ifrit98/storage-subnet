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
import torch
import argparse
import bittensor as bt
from loguru import logger


def check_config(cls, config: "bt.Config"):
    r"""Checks/validates the config namespace object."""
    bt.logging.check_config(config)

    if config.mock:
        config.wallet._mock = True

    full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            config.miner.name,
        )
    )
    config.miner.full_path = os.path.expanduser(full_path)
    if not os.path.exists(config.miner.full_path):
        os.makedirs(config.miner.full_path, exist_ok=True)

    if not config.miner.dont_save_events:
        # Add custom event logger for the events.
        logger.level("EVENTS", no=38, icon="📝")
        logger.add(
            config.miner.full_path + "/" + "completions.log",
            rotation=config.miner.events_retention_size,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            level="EVENTS",
            format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
        )


def add_args(cls, parser):
    parser.add_argument("--netuid", type=int, default=21, help="The chain subnet uid.")
    parser.add_argument("--test", default=False, action="store_true")
    parser.add_argument(
        "--miner.name",
        type=str,
        help="Trials for this miner go in miner.root / (wallet_cold - wallet_hot) / miner.name. ",
        default="core_storage_miner",
    )
    parser.add_argument(
        "--miner.device",
        type=str,
        help="Device to run the validator on.",
        default="cuda" if torch.cuda.is_available() else "cpu",
    )
    parser.add_argument("--miner.verbose", default=False, action="store_true")

    parser.add_argument(
        "--database.host", default="localhost", help="The host of the redis database."
    )
    parser.add_argument(
        "--database.port",
        type=int,
        default=6379,
        help="The port of the redis database.",
    )
    parser.add_argument(
        "--database.index",
        type=int,
        default=10,
        help="The index of the redis database.",
    )
    parser.add_argument(
        "--database.directory",
        default="~/.data",
        help="The directory to store data in.",
    )

    # Run config.
    parser.add_argument(
        "--miner.blocks_per_epoch",
        type=str,
        help="Blocks until the miner sets weights on chain",
        default=100,
    )

    # Blacklist.
    parser.add_argument(
        "--miner.blacklist.blacklist",
        type=str,
        required=False,
        nargs="*",
        help="Blacklist certain hotkeys",
        default=[],
    )
    parser.add_argument(
        "--miner.blacklist.whitelist",
        type=str,
        required=False,
        nargs="*",
        help="Whitelist certain hotkeys",
        default=[],
    )
    parser.add_argument(
        "--miner.blacklist.force_validator_permit",
        action="store_true",
        help="Only allow requests from validators",
        default=False,
    )
    parser.add_argument(
        "--miner.blacklist.allow_non_registered",
        action="store_true",
        help="If True, the miner will allow non-registered hotkeys to mine.",
        default=False,
    )
    parser.add_argument(
        "--miner.blacklist.minimum_stake_requirement",
        type=float,
        help="Minimum stake requirement",
        default=0.0,
    )
    parser.add_argument(
        "--miner.blacklist.min_request_period",
        type=int,
        help="Time period (in minute) to serve a maximum of 50 requests for each hotkey",
        default=5,
    )

    # Priority.
    parser.add_argument(
        "--miner.priority.default",
        type=float,
        help="Default priority of non-registered requests",
        default=0.0,
    )
    parser.add_argument(
        "--miner.priority.time_stake_multiplicate",
        type=int,
        help="Time (in minute) it takes to make the stake twice more important in the priority queue",
        default=10,
    )
    parser.add_argument(
        "--miner.priority.len_request_timestamps",
        type=int,
        help="Number of historic request timestamps to record",
        default=50,
    )
    # Switches.
    parser.add_argument(
        "--miner.no_set_weights",
        action="store_true",
        help="If True, the miner does not set weights.",
        default=False,
    )
    parser.add_argument(
        "--miner.no_serve",
        action="store_true",
        help="If True, the miner doesnt serve the axon.",
        default=False,
    )
    parser.add_argument(
        "--miner.no_start_axon",
        action="store_true",
        help="If True, the miner doesnt start the axon.",
        default=False,
    )

    # Mocks.
    parser.add_argument(
        "--miner.mock_subtensor",
        action="store_true",
        help="If True, the miner will allow non-registered hotkeys to mine.",
        default=False,
    )

    # Wandb args
    parser.add_argument(
        "--wandb.off", action="store_true", help="Turn off wandb.", default=False
    )
    parser.add_argument(
        "--wandb.project_name",
        type=str,
        help="The name of the project where you are sending the new run.",
        default="philanthropic-thunder",
    )
    parser.add_argument(
        "--wandb.entity",
        type=str,
        help="An entity is a username or team name where youre sending runs.",
        default="philanthrope",
    )
    parser.add_argument(
        "--wandb.offline",
        action="store_true",
        help="Runs wandb in offline mode.",
        default=False,
    )
    parser.add_argument(
        "--wandb.weights_step_length",
        type=int,
        help="How many steps before we log the weights.",
        default=10,
    )
    parser.add_argument(
        "--wandb.run_step_length",
        type=int,
        help="How many steps before we rollover to a new run.",
        default=1500,
    )
    parser.add_argument(
        "--wandb.notes",
        type=str,
        help="Notes to add to the wandb run.",
        default="",
    )


def config(cls):
    parser = argparse.ArgumentParser()
    bt.subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.wallet.add_args(parser)
    bt.axon.add_args(parser)
    cls.add_args(parser)
    return bt.config(parser)
