#!/bin/bash
# Usage: ./migrate_database_directory.sh <old_path> <new_path>

# Check if two arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <old_path> <new_path> <database_index>"
    exit 1
fi

OLD_PATH=$1
NEW_PATH=$2
DB_INDEX=$3

# Use rsync to synchronize contents of OLD_PATH to NEW_PATH
echo Migrating database from "$OLD_PATH" to "$NEW_PATH"...
rsync -a "${OLD_PATH}/" "${NEW_PATH}" && \
    python scripts/migrate_redis_index.py --database_index "$DB_INDEX" --new_data_directory "$NEW_PATH"
