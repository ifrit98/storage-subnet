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
import time
import wandb
import bittensor as bt
import traceback
from .set_weights import set_weights


def should_wait_until_next_epoch(current_block, last_epoch_block, epoch_lenght):
    diff_blocks = current_block - last_epoch_block
    return diff_blocks < epoch_lenght


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
    # --- Check for registration.
    if not self.subtensor.is_hotkey_registered(
        netuid=self.config.netuid,
        hotkey_ss58=self.wallet.hotkey.ss58_address,
    ):
        bt.logging.error(
            f"Wallet: {self.wallet} is not registered on netuid {self.config.netuid}"
            f"Please register the hotkey using `btcli subnets register` before trying again"
        )
        exit()

    # --- Run until should_exit = True.
    if self.config.miner.set_weights_at_start:
        self.last_epoch_block = -1
    else:
        self.last_epoch_block = self.subtensor.get_current_block()

    bt.logging.info(f"Miner starting at block: {self.last_epoch_block}")

    # This loop maintains the miner's operations until intentionally stopped.
    bt.logging.info(f"Starting main loop")
    step = 0
    wait_factor_next_set_weights = 0
    try:
        while not self.should_exit:
            start_epoch = time.time()

            # --- Wait until next epoch.
            self.current_block = self.subtensor.get_current_block()

            # --- To control messages without changing time.sleep within the while-loop
            # we can increase/decrease 'seconds_waiting_in_loop' without problems
            # with 'seconds_to_wait_to_log_presence_message' we control the logging factor in the wait
            seconds_waiting_in_loop = 1
            seconds_to_wait_to_log_presence_message = 2
            presence_message_seconds_count = 0
            while should_wait_until_next_epoch(
                self.current_block,
                self.last_epoch_block, 
                self.config.miner.set_weights_epoch_length
            ):
                # --- Wait for next bloc.
                time.sleep(seconds_waiting_in_loop)
                presence_message_seconds_count += seconds_waiting_in_loop

                if presence_message_seconds_count % seconds_to_wait_to_log_presence_message == 0:
                    self.current_block = self.subtensor.get_current_block()

                bt.logging.info(f"Miner running at block {self.current_block}...")

                # --- Check if we should exit.
                if self.should_exit:
                    break

            presence_message_seconds_count = 0

            # --- Set weights.
            weights_were_set = False
            if not self.config.miner.no_set_weights:
                bt.logging.info(f"Setting weights on chain.")
                # if both 'wait_for_*' args are False, weights_were_set = True
                # even if they are not set yet or the extrinsic has failed
                weights_were_set = set_weights(
                    self.subtensor,
                    self.config.netuid,
                    self.my_subnet_uid,
                    self.wallet,
                    self.config.wandb.on,
                    wait_for_inclusion=self.config.miner.set_weights_wait_for_inclusion,
                    wait_for_finalization=self.config.miner.set_weights_wait_for_finalization,
                )
            step += 1

            # --- Update the metagraph with the latest network state.
            if weights_were_set:
                current_block = self.subtensor.get_current_block()
                self.last_epoch_block = current_block
                self.current_block = current_block

                self.metagraph = self.subtensor.metagraph(
                    netuid=self.config.netuid,
                    lite=True,
                    block=self.last_epoch_block,
                )
                log = (
                    f"Step:{step} | "
                    f"Block:{self.metagraph.block.item()} | "
                    f"Stake:{self.metagraph.S[self.my_subnet_uid]} | "
                    f"Rank:{self.metagraph.R[self.my_subnet_uid]} | "
                    f"Trust:{self.metagraph.T[self.my_subnet_uid]} | "
                    f"Consensus:{self.metagraph.C[self.my_subnet_uid] } | "
                    f"Incentive:{self.metagraph.I[self.my_subnet_uid]} | "
                    f"Emission:{self.metagraph.E[self.my_subnet_uid]}"
                )
                bt.logging.info(log)
                if self.config.wandb.on:
                    wandb.log(log)

                wait_factor_next_set_weights = 0
            else:
                self.current_block = self.subtensor.get_current_block()
                num_blocks_to_wait = 3
                bt.logging.info(f"Weights were not set. Waiting {num_blocks_to_wait} blocks to set weights again.")
                time.sleep(num_blocks_to_wait*12) # It takes 12 secs to generate a block

    # If someone intentionally stops the miner, it'll safely terminate operations.
    except KeyboardInterrupt:
        self.axon.stop()
        bt.logging.success("Miner killed by keyboard interrupt.")
        exit()

    # In case of unforeseen errors, the miner will log the error and continue operations.
    except Exception as e:
        bt.logging.error(traceback.format_exc())
