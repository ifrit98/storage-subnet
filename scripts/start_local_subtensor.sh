#!/bin/bash

# Run this command from inside the subtensor repository (subtensor/)
# If your subtensor repo is in a different location, change the path below
# e.g. cd ~/subtensor (if in your $HOME directory)

# Run this command only after building local subtensor binary
pm2 start ./target/release/node-subtensor \
    --name subtensor -- \
    --base-path /tmp/blockchain \
    --chain ./raw_spec.json \
    --rpc-external --rpc-cors all \
    --ws-external --no-mdns \
    --ws-max-connections 10000 --in-peers 500 --out-peers 500 \
    --bootnodes /dns/bootnode.finney.opentensor.ai/tcp/30333/ws/p2p/12D3KooWRwbMb85RWnT8DSXSYMWQtuDwh4LJzndoRrTDotTR5gDC \
    --sync warp
