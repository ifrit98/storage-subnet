#!/bin/bash

# Usage: ./start_subtensor.sh <path_to_subtensor_directory>
# Example: ./start_subtensor.sh ~/subtensor

# Check if the path to the subtensor directory is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path_to_subtensor_directory>"
    exit 1
fi

SUBTENSOR_DIR=$1

# Change to the subtensor directory
cd "$SUBTENSOR_DIR" || exit

# Check if the binary exists in the expected location
if [ ! -f "./target/release/node-subtensor" ]; then
    echo "Subtensor binary not found. Please build it before running this script."
    exit 1
fi

# Start the subtensor node using pm2
pm2 start ./target/release/node-subtensor \
    --name subtensor -- \
    --base-path /tmp/blockchain \
    --chain ./raw_spec.json \
    --rpc-external --rpc-cors all \
    --ws-external --no-mdns \
    --ws-max-connections 10000 --in-peers 500 --out-peers 500 \
    --bootnodes /dns/bootnode.finney.opentensor.ai/tcp/30333/ws/p2p/12D3KooWRwbMb85RWnT8DSXSYMWQtuDwh4LJzndoRrTDotTR5gDC \
    --sync warp

echo "Subtensor node started."
