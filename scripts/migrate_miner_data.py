import aioredis
import argparse
from storage.miner.database import migrate_data_directory


def main(args):
    r = aioredis.StrictRedis(db=args.database_index)
    failed_uids = await migrate_data_directory(r, args.new_data_directory)
    if any(failed_uids):
        print(f"Failed to migrate filepaths for the following chunks: {failed_uids}")
        print(
            "Thus not all data was migrated, and index remains unchanged for these filepaths."
        )
        print("Please ensure the data exists at the new directory and try again.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database_index", type=int, default=0)
    parser.add_argument("--new_data_directory", type=str, required=True)
    args = parser.parse_args()

    main(args)
