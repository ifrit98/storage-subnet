#!/usr/bin/env python

import os
import asyncio
import argparse
import bittensor as bt

from storage.miner.set_weights import set_weights


async def main(args):
    subtensor = bt.subtensor(network=args.network)
    wallet = bt.wallet(name=args.wallet, hotkey=args.hotkey)
    metagraph = bt.metagraph(
        netuid=args.netuid, network=args.network, sync=False
    )
    metagraph.sync(subtensor=subtensor)
    my_subnet_uid = metagraph.hotkeys.index(
        wallet.hotkey.ss58_address
    )

    last_updated = metagraph.last_update[my_subnet_uid].item()
    current_block = subtensor.get_current_block()

    if current_block - last_updated > 180:
        weights_were_set = set_weights(
            subtensor=subtensor,
            netuid=args.netuid,
            uid=my_subnet_uid,
            wallet=wallet,
            wandb_on=False,
            wait_for_inclusion=False,
            wait_for_finalization=True,
        )
        bt.logging.info(f'Were weights set? {weights_were_set}')
    else:
        bt.logging.info(f'Not setting weights because we did it {current_block - last_updated} blocks ago. Last updated: {last_updated}, Current Block: {current_block}')
    

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("--wallet", type=str, default='default')
        parser.add_argument("--hotkey", type=str, default='default')
        parser.add_argument("--network", type=str, default='local')
        parser.add_argument("--netuid", type=int, default=21)
        args = parser.parse_args()

        asyncio.run(main(args))
    except KeyboardInterrupt:
        print('KeyboardInterrupt')
    except ValueError as e:
        print(f'ValueError: {e}')
