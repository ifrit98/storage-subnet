import os
import asyncio
from redis import asyncio as aioredis
import argparse
import bittensor as bt
from storage.shared.utils import get_redis_password
from storage.shared.checks import check_environment
from storage.miner.database import migrate_data_directory


async def main(args):
    new_directory = os.path.expanduser(args.new_data_directory)
    bt.logging.info(f"Attempting miner data migration to {new_directory}")
    if not os.path.exists(new_directory):
        os.makedirs(new_directory, exist_ok=True)

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

    bt.logging.info(
        f"Loading database from {args.database_host}:{args.database_port}"
    )
    database = aioredis.StrictRedis(
        host=args.database_host,
        port=args.database_port,
        db=args.database_index,
        password=redis_password,
    )
    failed_uids = await migrate_data_directory(database, new_directory, return_failures=True)

    if failed_uids is not None:
        bt.logging.error(
            f"Failed to migrate {len(failed_uids)} filepaths to the new directory: {new_directory}."
        )
    else:
        bt.logging.success("All data was migrated to the new directory.")


if __name__ == "__main__":
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
    parser.add_argument("--new_data_directory", type=str, required=True)
    args = parser.parse_args()

    asyncio.run(main(args))
