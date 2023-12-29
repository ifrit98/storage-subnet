#!/bin/bash

WALLET_NAME=$1
WALLET_HOTKEY=$2
SUBTENSOR_NETWORK=$3

python ./scripts/send_extrinsic.py --wallet $WALLET_NAME --hotkey $WALLET_HOTKEY -network $SUBTENSOR_NETWORK