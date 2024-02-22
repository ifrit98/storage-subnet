#!/usr/bin/env python

import asyncio
from redis import asyncio as aioredis
import argparse
import bittensor as bt

from storage.shared.utils import get_redis_password
from storage.shared.checks import check_environment
from storage.validator.rebalance import rebalance_data


async def main(args):

    redis_password = get_redis_password(args.redis_password)
    try:
        asyncio.run(check_environment(
            args.redis_conf_path,
            args.database_host,
            args.database_port,
            redis_password
        ))
    except AssertionError as e:
        bt.logging.warning(
            f"Something is missing in your environment: {e}. Please check your configuration, use the README for help, and try again."
        )
        exit(1)

    try:
        bt.logging.info(
            f"Loading subtensor and metagraph on {args.network} | netuid {args.netuid}"
        )
        subtensor = bt.subtensor(network=args.network)
        metagraph = bt.metagraph(netuid=args.netuid, network=args.network)
        metagraph.sync(subtensor=subtensor)

        bt.logging.info(
            f"Loading database from {args.database_host}:{args.database_port}"
        )
        database = aioredis.StrictRedis(
            host=args.database_host,
            port=args.database_port,
            db=args.database_index,
            password=redis_password,
        )

        hotkeys = args.hotkeys.split(",")
        bt.logging.info(
            f"Deregistered hotkeys {hotkeys} will be rebalanced in the index."
        )

        self = argparse.Namespace()
        self.metagraph = metagraph
        self.database = database

        await rebalance_data(self, k=2, dropped_hotkeys=hotkeys, hotkey_replaced=True)

    finally:
        if "subtensor" in locals():
            subtensor.close()
            bt.logging.debug("closing subtensor connection")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--hotkeys",
            type=str,
            required=True,
            help="comma separated list of hotkeys to deregister",
        )
        parser.add_argument("--network", type=str, default="local")
        parser.add_argument("--netuid", type=int, default=21)
        parser.add_argument("--database_index", type=int, default=1)
        parser.add_argument("--database_host", type=str, default="localhost")
        parser.add_argument("--database_port", type=int, default=6379)
        parser.add_argument(
            "--redis_password",
            type=str,
            default=None,
            help="password for the redis database",
        )
        parser.add_argument(
            "--redis_conf_path",
            type=str,
            default="/etc/redis/redis.conf",
            help="path to the redis configuration file",
        )
        args = parser.parse_args()

        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
    except ValueError as e:
        print(f"ValueError: {e}")
