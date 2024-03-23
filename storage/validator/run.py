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

from storage.validator.state import (
    checkpoint,
    load_state,
    init_wandb,
    should_checkpoint,
    reinit_wandb,
)
from storage.validator.weights import (
    set_weights_for_validator,
)
from storage.shared.subtensor import get_current_block


def run(self):
    """
    Initiates and manages the main loop for the validator on the Bittensor network.

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

    Raises:
        KeyboardInterrupt: If the validator is stopped by a manual interruption.
        Exception: For unforeseen errors during the validator's operation, which are logged for diagnosis.
    """
    bt.logging.info("run()")

    load_state(self)
    checkpoint(self)

    bt.logging.info("starting subscription handler")
    self.run_subscription_thread()

    try:
        while 1:
            start_epoch = time.time()

            self.metagraph.sync(subtensor=self.subtensor)
            prev_set_weights_block = self.metagraph.last_update[
                self.my_subnet_uid
            ].item()

            # --- Wait until next step epoch.
            current_block = self.subtensor.get_current_block()
            while current_block - self.prev_step_block < 3:
                # --- Wait for next block.
                time.sleep(1)
                current_block = self.subtensor.get_current_block()

            time.sleep(5)
            if self.wallet.hotkey.ss58_address not in self.metagraph.hotkeys:
                raise Exception(
                    f"Validator is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
                )

            bt.logging.info(
                f"step({self.step}) block({get_current_block(self.subtensor)})"
            )

            # Run multiple forwards.
            async def run_forward():
                coroutines = [
                    forward(self)
                    for _ in range(self.config.neuron.num_concurrent_forwards)
                ]
                await asyncio.gather(*coroutines)

            self.loop.run_until_complete(run_forward())

            # Init wandb.
            if not self.config.wandb.off and self.wandb is not None:
                bt.logging.debug("loading wandb")
                init_wandb(self)

            # Resync the network state
            bt.logging.info("Checking if should checkpoint")
            current_block = get_current_block(self.subtensor)
            should_checkpoint_validator = should_checkpoint(
                current_block,
                self.prev_step_block,
                self.config.neuron.checkpoint_block_length,
            )
            bt.logging.debug(
                f"should_checkpoint() params: (current block) {current_block} (prev block) {self.prev_step_block} (checkpoint_block_length) {self.config.neuron.checkpoint_block_length}"
            )
            bt.logging.debug(f"should checkpoint ? {should_checkpoint_validator}")
            if should_checkpoint_validator:
                bt.logging.info("Checkpointing...")
                checkpoint(self)

            # Set the weights on chain.
            bt.logging.info("Checking if should set weights")
            validator_should_set_weights = should_set_weights(
                get_current_block(self.subtensor),
                prev_set_weights_block,
                360,  # tempo
                self.config.neuron.disable_set_weights,
            )
            bt.logging.debug(
                f"Should validator check weights? -> {validator_should_set_weights}"
            )
            if validator_should_set_weights:
                bt.logging.debug(f"Setting weights {self.moving_averaged_scores}")
                event = set_weights_for_validator(
                    subtensor=self.subtensor,
                    wallet=self.wallet,
                    metagraph=self.metagraph,
                    netuid=self.config.netuid,
                    moving_averaged_scores=self.moving_averaged_scores,
                    wandb_on=self.config.wandb.on,
                )
                prev_set_weights_block = get_current_block(self.subtensor)
                save_state(self)

                if event is not None:
                    log_event(self, event)

            # Rollover wandb to a new run.
            if should_reinit_wandb(self):
                bt.logging.info("Reinitializing wandb")
                reinit_wandb(self)

            self.prev_step_block = get_current_block(self.subtensor)
            if self.config.neuron.verbose:
                bt.logging.debug(f"block at end of step: {self.prev_step_block}")
                bt.logging.debug(f"Step took {time.time() - start_epoch} seconds")
            self.step += 1

    except Exception as err:
        bt.logging.error("Error in training loop", str(err))
        bt.logging.debug(print_exception(type(err), err, err.__traceback__))

    except KeyboardInterrupt:
        if not self.config.wandb.off:
            bt.logging.info(
                "KeyboardInterrupt caught, gracefully closing the wandb run..."
            )
            if self.wandb is not None:
                self.wandb.finish()

    # After all we have to ensure subtensor connection is closed properly
    finally:
        if hasattr(self, "subtensor"):
            bt.logging.debug("Closing subtensor connection")
            self.subtensor.close()
            self.stop_subscription_thread()