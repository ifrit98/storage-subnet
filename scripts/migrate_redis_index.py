import os
import asyncio
import aioredis
import argparse
import bittensor as bt
from storage.miner.database import migrate_data_directory


async def main(args):
    new_directory = os.path.expanduser(args.new_data_directory)
    bt.logging.info(f"Attempting miner data migration to {new_directory}")
    if not os.path.exists(new_directory):
        os.makedirs(new_directory, exist_ok=True)

    bt.logging.info(f"Connecting to Redis at db={args.database_index}...")
    r = aioredis.StrictRedis(db=args.database_index)
    failed_uids = await migrate_data_directory(r, new_directory)

    if failed_uids != None:
        bt.logging.warn(
            f"Failed to migrate {len(failed_uids)} filepaths for the following chunks: {failed_uids}"
        )
        bt.logging.warn(
            "Thus not all data was migrated, and index remains unchanged for these filepaths."
        )
        bt.logging.warn(
            "Please ensure the data exists at the new directory and try again."
        )
    else:
        bt.logging.success("All data was migrated to the new directory.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database_index", type=int, default=0)
    parser.add_argument("--new_data_directory", type=str, required=True)
    args = parser.parse_args()

    asyncio.run(main(args))
