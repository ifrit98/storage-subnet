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
from storage.validator.state import ttl_get_block
from storage import __spec_version__ as spec_version


def should_set_weights(self) -> bool:
    # Check if enough epoch blocks have elapsed since the last epoch.
    if self.config.neuron.disable_set_weights:
        return False
    return (
        ttl_get_block(self) % self.config.neuron.set_weights_epoch_length
        < self.prev_step_block % self.config.neuron.set_weights_epoch_length
    )


def set_weights(self):
    # Calculate the average reward for each uid across non-zero values.
    # Replace any NaN values with 0.
    raw_weights = torch.nn.functional.normalize(self.moving_averaged_scores, p=1, dim=0)

    bt.logging.debug("raw_weights", raw_weights)
    bt.logging.debug("raw_weight_uids", self.metagraph.uids.to("cpu"))
    # Process the raw weights to final_weights via subtensor limitations.
    (
        processed_weight_uids,
        processed_weights,
    ) = bt.utils.weight_utils.process_weights_for_netuid(
        uids=self.metagraph.uids.to("cpu"),
        weights=raw_weights.to("cpu"),
        netuid=self.config.netuid,
        subtensor=self.subtensor,
        metagraph=self.metagraph,
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
    result = self.subtensor.set_weights(
        wallet=self.wallet,
        netuid=self.config.netuid,
        uids=uint_uids,
        weights=uint_weights,
        wait_for_finalization=False,
        wait_for_inclusion=True,
        version_key=spec_version,
    )
    if result is True:
        bt.logging.info("set_weights on chain successfully!")
    else:
        bt.logging.error("set_weights failed")
