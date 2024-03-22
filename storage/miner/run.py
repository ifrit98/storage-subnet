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

import bittensor as bt
from substrateinterface import SubstrateInterface
from storage.shared.checks import check_registration
from .utils import update_storage_stats


def run(self):
    """
    Initiates and manages the main loop for the miner on the Bittensor network.

    This function performs the following primary tasks:
    1. Check for registration on the Bittensor network.
    2. Attaches the miner's forward, blacklist, and priority functions to its axon.
    3. Starts the miner's axon, making it active on the network.
    4. Regularly updates the metagraph with the latest network state.
    5. Optionally sets weights on the network, defining how much trust to assign to other nodes.
    6. Handles graceful shutdown on keyboard interrupts and logs unforeseen errors.

    The miner continues its operations until `should_exit` is set to True or an external interruption occurs.
    During each epoch of its operation, the miner waits for new blocks on the Bittensor network, updates its
    knowledge of the network (metagraph), and sets its weights. This process ensures the miner remains active
    and up-to-date with the network's latest state.

    Note:
        - The function leverages the global configurations set during the initialization of the miner.
        - The miner's axon serves as its interface to the Bittensor network, handling incoming and outgoing requests.

    Raises:
        KeyboardInterrupt: If the miner is stopped by a manual interruption.
        Exception: For unforeseen errors during the miner's operation, which are logged for diagnosis.
    """
    block_handler_substrate = SubstrateInterface(
        ss58_format=bt.__ss58_format__,
        use_remote_preset=True,
        url=self.subtensor.chain_endpoint,
        type_registry=bt.__type_registry__,
    )

    netuid = self.config.netuid

    # --- Check for registration.
    check_registration(self.subtensor, self.wallet, netuid)

    tempo = block_handler_substrate.query(
        module="SubtensorModule", storage_function="Tempo", params=[netuid]
    ).value

    def handler(obj, update_nr, subscription_id):
        current_block = obj["header"]["number"]
        bt.logging.debug(f"New block #{current_block}")

        # --- Check for registration every 100 blocks (20 minutes).
        if current_block % 100 == 0:
            check_registration(self.subtensor, self.wallet, netuid)

        bt.logging.debug(
            f"Blocks since epoch: {(current_block + netuid + 1) % (tempo + 1)}"
        )

        new_epoch = ((current_block + netuid + 1) % (tempo + 1) == 0)
        if new_epoch:

            # --- Update the miner storage information periodically.
            update_storage_stats(self)
            bt.logging.debug("Storage statistics updated...")

        if self.should_exit:
            return True

    block_handler_substrate.subscribe_block_headers(handler)
