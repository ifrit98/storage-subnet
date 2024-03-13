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
import time
import torch
import argparse
import datetime
import bittensor as bt
from loguru import logger


def check_config(cls, config: "bt.Config"):
    r"""Checks/validates the config namespace object."""
    bt.logging.check_config(config)

    if config.mock:
        config.wallet._mock = True

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            config.neuron.name,
        )
    )
    log_path = os.path.join(full_path, "logs", timestamp)

    config.neuron.full_path = os.path.expanduser(full_path)
    config.neuron.log_path = log_path

    if not os.path.exists(config.neuron.full_path):
        os.makedirs(config.neuron.full_path, exist_ok=True)
    if not os.path.exists(config.neuron.log_path):
        os.makedirs(config.neuron.log_path, exist_ok=True)

    if not config.neuron.dont_save_events:
        # Add custom event logger for the events.
        logger.level("EVENTS", no=38, icon="📝")
        logger.add(
            config.neuron.log_path + "/" + "EVENTS.log",
            rotation=config.neuron.events_retention_size,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            level="EVENTS",
            format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
        )

        logger.add(
            config.neuron.log_path + "/" + "INFO.log",
            rotation=config.neuron.events_retention_size,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            level="INFO",
            format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
        )

        logger.add(
            config.neuron.log_path + "/" + "DEBUG.log",
            rotation=config.neuron.events_retention_size,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            level="DEBUG",
            format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
        )

        logger.add(
            config.neuron.log_path + "/" + "TRACE.log",
            rotation=config.neuron.events_retention_size,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
            level="TRACE",
            format="{time:YYYY-MM-DD at HH:mm:ss} | {level} | {message}",
        )

        # Set miner stats and total storage save path
        config.neuron.miner_stats_path = os.path.expanduser(
            os.path.join(config.neuron.full_path + "/" + "miner_stats.json")
        )
        config.neuron.hash_map_path = os.path.expanduser(
            os.path.join(config.neuron.full_path + "/" + "hash_map.json")
        )
        config.neuron.total_storage_path = os.path.expanduser(
            os.path.join(config.neuron.full_path + "/" + "total_storage.csv")
        )
        config.neuron.events_json_log_path = os.path.expanduser(
            os.path.join(config.neuron.full_path + "/" + "events.json")
        )

    bt.logging.info(f"Loaded config in fullpath: {config.neuron.full_path}")


def add_args(cls, parser):
    # Netuid Arg
    parser.add_argument("--netuid", type=int, help="Storage network netuid", default=21)

    parser.add_argument(
        "--neuron.name",
        type=str,
        help="Trials for this miner go in miner.root / (wallet_cold - wallet_hot) / miner.name. ",
        default="core_storage_validator",
    )
    parser.add_argument(
        "--neuron.device",
        type=str,
        help="Device to run the validator on.",
        default="cuda" if torch.cuda.is_available() else "cpu",
    )
    parser.add_argument(
        "--neuron.curve",
        default="P-256",
        help="Curve for elliptic curve cryptography.",
        choices=["P-256"],  # TODO: expand this list
    )
    parser.add_argument(
        "--neuron.maxsize",
        default=None,  # Use lognormal random gaussian if None (2**16, # 64KB)
        type=int,
        help="Maximum size of random data to store.",
    )
    parser.add_argument(
        "--neuron.min_chunk_size",
        default=256,
        type=int,
        help="Minimum chunk size of random data to challenge (bytes).",
    )
    parser.add_argument(
        "--neuron.disable_log_rewards",
        action="store_true",
        help="Disable all reward logging, suppresses reward functions and their values from being logged to wandb.",
        default=False,
    )
    parser.add_argument(
        "--neuron.subscription_logging_path",
        type=str,
        help="The path to save subscription logs.",
        default="subscription_logs.txt",
    )
    parser.add_argument(
        "--neuron.chunk_factor",
        type=int,
        help="The chunk factor to divide data.",
        default=4,
    )
    parser.add_argument(
        "--neuron.num_concurrent_forwards",
        type=int,
        help="The number of concurrent forwards running at any time.",
        default=1,
    )
    parser.add_argument(
        "--neuron.disable_set_weights",
        action="store_true",
        help="Disables setting weights.",
        default=False,
    )
    parser.add_argument(
        "--neuron.semaphore_size",
        type=int,
        help="How many async calls to limit concurrently.",
        default=256,
    )
    parser.add_argument(
        "--neuron.checkpoint_block_length",
        type=int,
        help="Blocks before a checkpoint is saved.",
        default=100,
    )
    parser.add_argument(
        "--neuron.events_retention_size",
        type=str,
        help="Events retention size.",
        default="2 GB",
    )
    parser.add_argument(
        "--neuron.dont_save_events",
        action="store_true",
        help="If set, we dont save events to a log file.",
        default=False,
    )
    parser.add_argument(
        "--neuron.vpermit_tao_limit",
        type=int,
        help="The maximum number of TAO allowed to query a validator with a vpermit.",
        default=500,
    )
    parser.add_argument(
        "--neuron.verbose",
        action="store_true",
        help="If set, we will print verbose detailed logs.",
        default=False,
    )
    parser.add_argument(
        "--neuron.log_responses",
        action="store_true",
        help="If set, we will log responses. These can be LONG.",
        default=False,
    )
    parser.add_argument(
        "--neuron.data_ttl",
        type=int,
        help="The number of blocks before data expires (seconds).",
        default=60 * 60 * 24 * 30,  # 30 days
    )
    parser.add_argument(
        "--neuron.profile",
        action="store_true",
        help="If set, we will profile the neuron network and I/O actions.",
        default=False,
    )
    parser.add_argument(
        "--neuron.debug_logging_path",
        type=str,
        help="The path to save debug logs.",
        default="debug_logs.txt",
    )

    # Redis arguments
    parser.add_argument(
        "--database.host", default="localhost", help="The host of the redis database."
    )
    parser.add_argument(
        "--database.port", default=6379, help="The port of the redis database."
    )
    parser.add_argument(
        "--database.index",
        default=1,
        help="The database number of the redis database.",
    )
    parser.add_argument(
        "--database.redis_password",
        type=str,
        default=None,
        help="The redis password.",
    )
    parser.add_argument(
        "--database.redis_conf_path",
        type=str,
        help="Redis configuration path.",
        default="/etc/redis/redis.conf",
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

    # Mocks
    parser.add_argument(
        "--mock", action="store_true", help="Mock all items.", default=False
    )

    # API specific
    parser.add_argument(
        "--api.store_timeout",
        type=int,
        help="Store data query timeout.",
        default=60,
    )
    parser.add_argument(
        "--api.retrieve_timeout",
        type=int,
        help="Retrieve data query timeout.",
        default=60,
    )
    parser.add_argument(
        "--api.ping_timeout",
        type=int,
        help="Ping data query timeout.",
        default=5,
    )
    parser.add_argument(
        "--api.blacklisted_hotkeys",
        nargs="+",
        type=list,
        help="List of blacklisted hotkeys.",
        default=[],
    )
    parser.add_argument(
        "--api.whitelisted_hotkeys",
        nargs="+",
        type=list,
        help="List of whitelisted hotkeys.",
        default=[],
    )
    parser.add_argument(
        "--api.open_access",
        action="store_true",
        help="If set, we whitelist all hotkeys by default to test easily. (NOT RECOMMENDED FOR PRODUCTION)",
    )

    # Encryption wallet
    parser.add_argument(
        "--encryption.wallet_name",
        type=str,
        help="The name of the wallet to use for encryption.",
        default="core_storage_coldkey",
    )
    parser.add_argument(
        "--encryption.wallet_hotkey",
        type=str,
        help="The hotkey name of the wallet to use for encryption.",
        default="core_storage_hotkey",
    )
    parser.add_argument(
        "--encryption.password",
        type=str,
        help="The password of the wallet to use for encryption.",
        default="dummy_password",
    )


def config(cls):
    parser = argparse.ArgumentParser()
    bt.wallet.add_args(parser)
    bt.subtensor.add_args(parser)
    bt.logging.add_args(parser)
    bt.axon.add_args(parser)
    cls.add_args(parser)
    return bt.config(parser)
