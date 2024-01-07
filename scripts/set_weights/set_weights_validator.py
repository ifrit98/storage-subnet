import os
import time
import torch
import bittensor as bt
from storage import __spec_version__ as spec_version

bt.trace()


def check_last_update(uid, metagraph=None, subtensor=None, netuid=21):
    if not subtensor:
        subtensor = bt.subtensor("subtensor.sybil.com:9944")
    if not metagraph:
        metagraph = subtensor.metagraph(netuid)
    else:
        metagraph.sync()
    return subtensor.get_current_block() - metagraph.last_update[uid]


def load_state(path, metagraph):
    r"""Load hotkeys and moving average scores from filesystem."""
    bt.logging.info("load_state()")
    try:
        state_dict = torch.load(f"{path}/model.torch")
        neuron_weights = torch.tensor(state_dict["neuron_weights"])
        # Check to ensure that the size of the neruon weights matches the metagraph size.
        if neuron_weights.shape != (metagraph.n,):
            bt.logging.warning(
                f"Neuron weights shape {neuron_weights.shape} does not match metagraph n {metagraph.n}"
                "Populating new moving_averaged_scores IDs with zeros"
            )
            moving_averaged_scores[: len(neuron_weights)]
        # Check for nans in saved state dict
        elif not torch.isnan(neuron_weights).any():
            moving_averaged_scores = neuron_weights.to("cpu")
        bt.logging.success(
            prefix="Reloaded model",
            sufix=f"<blue>{path}/model.torch</blue>",
        )
    except Exception as e:
        bt.logging.warning(f"Failed to load model with error: {e}")

    return moving_averaged_scores


def set_weights(moving_averaged_scores, wallet, metagraph, subtensor, netuid):
    # Calculate the average reward for each uid across non-zero values.
    # Replace any NaN values with 0.
    raw_weights = torch.nn.functional.normalize(moving_averaged_scores, p=1, dim=0)

    bt.logging.debug("raw_weights", raw_weights)
    bt.logging.debug("raw_weight_uids", metagraph.uids.to("cpu"))
    # Process the raw weights to final_weights via subtensor limitations.
    (
        processed_weight_uids,
        processed_weights,
    ) = bt.utils.weight_utils.process_weights_for_netuid(
        uids=metagraph.uids.to("cpu"),
        weights=raw_weights.to("cpu"),
        netuid=netuid,
        subtensor=subtensor,
        metagraph=metagraph,
    )
    bt.logging.debug("processed_weights", processed_weights)
    bt.logging.debug("processed_weight_uids", processed_weight_uids)

    # Convert to uint16 weights and uids.
    uint_uids, uint_weights = bt.utils.weight_utils.convert_weights_and_uids_for_emit(
        uids=processed_weight_uids, weights=processed_weights
    )
    bt.logging.debug("uint_weights", uint_weights)
    bt.logging.debug("uint_uids", uint_uids)

    # Set the weights on chain via our subtensor connection.
    result = subtensor.set_weights(
        wallet=wallet,
        netuid=netuid,
        uids=uint_uids,
        weights=uint_weights,
        wait_for_finalization=False,
        wait_for_inclusion=False,
        version_key=spec_version,
    )
    if result is True:
        bt.logging.info("set_weights on chain successfully!")
    else:
        bt.logging.error("set_weights failed")


def main(args):
    wallet = bt.wallet(name=args.wallet, hotkey=args.hotkey)
    bt.logging.info("wallet", wallet)

    try:
        uid = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
    except Exception as e:
        bt.logging.error(
            f"Failed to get uid with error: {e}.\nPerhaps you areot registerd on chain?"
        )
        exit()

    excepted = False
    while True:
        subtensor = bt.subtensor(network="local")
        bt.logging.info("subtensor", subtensor)
        metagraph = subtensor.metagraph(args.netuid, lite=True)
        bt.logging.info("metagraph", metagraph)

        bt.logging.info("Checking if should set weights")
        if check_last_update(metagraph, subtensor) > args.update_interval:
            bt.logging.info("Loading state...")
            try:
                moving_averaged_scores = load_state(args.path)
            except Exception as e:
                excepted = True
                bt.logging.error(
                    f"load_state failed with error: {e}. Please check your path: {args.path}"
                )
                exit()
            bt.logging.info(f"moving_averaged_scores: {moving_averaged_scores}")

            bt.logging.info("Setting weights...")
            try:
                set_weights(
                    moving_averaged_scores,
                    wallet,
                    metagraph,
                    subtensor,
                    netuid=args.netuid,
                )
                excepted = False
            except Exception as e:
                excepted = True
                bt.logging.error(f"set_weights failed with error: {e}")
                bt.logging.info("Sleeping for 3 minutes and trying again...")
                time.sleep(180)  # try again in 3 minutes

        if not excepted:
            bt.logging.info(
                f"Sleeping for {(args.update_interval * 12) / 60} minutes..."
            )
            time.sleep((args.update_interval + 1) * 12)


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        # This is where the neuron info is stored to set the weights with.
        # Typically: "~/.bittensor/miners/{WALLET}/{HOTKEY}/netuid{NETUID}/core_storage_validator"
        parser.add_argument(
            "--state_path",
            type=str,
            required=True,
            help="Path to the state dict to load",
        )
        parser.add_argument(
            "--wallet", type=str, default="default", help="Wallet name to use"
        )
        parser.add_argument(
            "--hotkey", type=str, default="default", help="Hotkey name to use"
        )
        parser.add_argument(
            "--network", type=str, default="local", help="Network to use"
        )
        parser.add_argument(
            "--netuid", type=int, default=21, help="Subnet netuid to use"
        )
        parser.add_argument(
            "--update_interval",
            type=int,
            default=200,
            help="How often to set weights in blocks",
        )
        args = parser.parse_args()

        main(args)
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
    except ValueError as e:
        print(f"ValueError: {e}")
