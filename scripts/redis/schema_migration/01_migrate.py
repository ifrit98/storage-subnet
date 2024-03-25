#!/usr/bin/env python

import asyncio
import argparse
import bittensor as bt
from redis import asyncio as aioredis

from storage.shared.utils import get_redis_password
from storage.shared.checks import check_environment
from storage.miner.database import convert_all_to_hotkey_format


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

    try:
        bt.logging.info(f"Loading database from {args.database_host}:{args.database_port}")
        database = aioredis.StrictRedis(
            host=args.database_host,
            port=args.database_port,
            db=args.database_index,
            password=redis_password,
        )
        bt.logging.info("Converting to new schema...")
        await convert_all_to_hotkey_format(database)
        bt.logging.info("Conversion to new schema complete.")

    except Exception as e:
        bt.logging.error(f"Error converting to new schema: {e}")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
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
        parser.add_argument("--database_host", type=str, default="localhost")
        parser.add_argument("--database_port", type=int, default=6379)
        parser.add_argument("--database_index", type=int, default=0)
        args = parser.parse_args()

        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
    except ValueError as e:
        print(f"ValueError: {e}")
