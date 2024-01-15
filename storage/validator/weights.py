# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 philanthrope

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# Utils for weights setting on chain.

import wandb
import torch
import bittensor as bt

from storage import __spec_version__ as spec_version
from storage.shared.subtensor import get_current_block
from storage.shared.weights import set_weights


def set_weights_for_validator(
    subtensor: "bt.subtensor",
    wallet: "bt.wallet",
    netuid: int,
    metagraph: "bt.metagraph",
    moving_averaged_scores: "torch.Tensor",
    wandb_on: bool = False,
    wait_for_inclusion: bool = False,
    wait_for_finalization: bool = False,
):
    """
    Sets miners' weights on the Bittensor network.

    This function assigns a weight of 1 to the current miner (identified by its UID) and
    a weight of 0 to all other peers in the network. The weights determine the trust level
    the miner assigns to other nodes on the network.

    Args:
        subtensor (bt.subtensor): The Bittensor object managing the blockchain connection.
        wallet (bt.wallet): The miner's wallet holding cryptographic information.
        netuid (int): The unique identifier for the chain subnet.
        uids (torch.Tensor): miners UIDs on the network.
        metagraph (bt.metagraph): Bittensor metagraph.
        moving_averaged_scores (torch.Tensor): .
        wandb_on (bool, optional): Flag to determine if logging to Weights & Biases is enabled. Defaults to False.
        tempo (int): Tempo for 'netuid' subnet.
        wait_for_inclusion (bool, optional): Wether to wait for the extrinsic to enter a block
        wait_for_finalization (bool, optional): Wether to wait for the extrinsic to be finalized on the chain

    Returns:
        success (bool):
            flag is true if extrinsic was finalized or uncluded in the block.
            If we did not wait for finalization / inclusion, the response is true.

    Raises:
        Exception: If there's an error while setting weights, the exception is logged for diagnosis.
    """
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
    success = set_weights(
        subtensor=subtensor,
        wallet=wallet,
        netuid=netuid,
        uids=uint_uids,
        weights=uint_weights,
        wandb_on=wandb_on,
        version_key=spec_version,
        wait_for_finalization=False,
        wait_for_inclusion=False,
    )

    if success is True:
        bt.logging.info("set_weights on chain successfully!")
    else:
        bt.logging.error("set_weights failed")
