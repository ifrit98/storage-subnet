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

import torch

from storage.shared.weights import set_weights


def set_weights_for_miner(
    subtensor: "bt.subtensor",
    netuid: int,
    uid: int,
    wallet: "bt.wallet",
    metagraph: "bt.metagraph",
    wandb_on: bool = False,
    tempo: int = 360,
    wait_for_inclusion: bool = False,
    wait_for_finalization: bool = False,
) -> bool:
    """
    Sets the miner's weights on the Bittensor network.

    This function assigns a weight of 1 to the current miner (identified by its UID) and
    a weight of 0 to all other peers in the network. The weights determine the trust level
    the miner assigns to other nodes on the network.

    The function performs the following steps:
    1. Queries the Bittensor network for the total number of peers.
    2. Sets a weight vector with a value of 1 for the current miner and 0 for all other peers.
    3. Updates these weights on the Bittensor network using the `set_weights` method of the subtensor.
    4. Optionally logs the weight-setting operation to Weights & Biases (wandb) for monitoring.

    Args:
        subtensor (bt.subtensor): The Bittensor object managing the blockchain connection.
        netuid (int): The unique identifier for the chain subnet.
        uid (int): The unique identifier for the miner on the network.
        wallet (bt.wallet): The miner's wallet holding cryptographic information.
        metagraph (bt.metagraph): Bittensor metagraph
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
    # --- query the chain for the most current number of peers on the network
    chain_weights = torch.zeros(subtensor.subnetwork_n(netuid=netuid))
    chain_weights[uid] = 1
    uids = torch.arange(0, len(chain_weights))
    version_key = 1

    # --- Set weights.
    return set_weights(
        subtensor=subtensor,
        wallet=wallet,
        netuid=netuid,
        uids=uids,
        weights=chain_weights,
        metagraph=metagraph,
        wandb_on=wandb_on,
        tempo=tempo,
        wait_for_inclusion=wait_for_inclusion,
        wait_for_finalization=wait_for_finalization,
        version_key=version_key,
    )
