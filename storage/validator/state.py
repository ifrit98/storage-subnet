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

# Utils for checkpointing and saving the model.
import torch
import wandb
import copy
import time
import math
import hashlib as rpccheckhealth

from math import floor
from loguru import logger
from dataclasses import asdict
from typing import Callable, Any
from functools import lru_cache, update_wrapper

import storage
import storage.validator as validator
from storage.validator.event import EventSchema

import bittensor as bt


# LRU Cache with TTL
def ttl_cache(maxsize: int = 128, typed: bool = False, ttl: int = -1):
    if ttl <= 0:
        ttl = 65536
    hash_gen = _ttl_hash_gen(ttl)

    def wrapper(func: Callable) -> Callable:
        @lru_cache(maxsize, typed)
        def ttl_func(ttl_hash, *args, **kwargs):
            return func(*args, **kwargs)

        def wrapped(*args, **kwargs) -> Any:
            th = next(hash_gen)
            return ttl_func(th, *args, **kwargs)

        return update_wrapper(wrapped, func)

    return wrapper


def _ttl_hash_gen(seconds: int):
    start_time = time.time()
    while True:
        yield floor((time.time() - start_time) / seconds)


# 12 seconds updating block.
@ttl_cache(maxsize=1, ttl=12)
def ttl_get_block(self) -> int:
    return self.subtensor.get_current_block()


def should_reinit_wandb(self):
    # Check if wandb run needs to be rolled over.
    return (
        not self.config.wandb.off
        and self.step
        and self.step % self.config.wandb.run_step_length == 0
    )


def init_wandb(self, reinit=False):
    """Starts a new wandb run."""
    tags = [
        self.wallet.hotkey.ss58_address,
        storage.__version__,
        str(storage.__spec_version__),
        f"netuid_{self.metagraph.netuid}",
    ]

    if self.config.mock:
        tags.append("mock")
    if self.config.neuron.disable_set_weights:
        tags.append("disable_set_weights")
    if self.config.neuron.disable_log_rewards:
        tags.append("disable_log_rewards")

    wandb_config = {
        key: copy.deepcopy(self.config.get(key, None))
        for key in ("neuron", "reward", "netuid", "wandb")
    }
    wandb_config["neuron"].pop("full_path", None)

    self.wandb = wandb.init(
        anonymous="allow",
        reinit=reinit,
        project=self.config.wandb.project_name,
        entity=self.config.wandb.entity,
        config=wandb_config,
        mode="offline" if self.config.wandb.offline else "online",
        dir=self.config.neuron.full_path,
        tags=tags,
        notes=self.config.wandb.notes,
    )
    bt.logging.success(
        prefix="Started a new wandb run",
        sufix=f"<blue> {self.wandb.name} </blue>",
    )


def reinit_wandb(self):
    """Reinitializes wandb, rolling over the run."""
    self.wandb.finish()
    init_wandb(self, reinit=True)


def should_checkpoint(self):
    # Check if enough epoch blocks have elapsed since the last checkpoint.
    a = ttl_get_block(self) % self.config.neuron.checkpoint_block_length
    b = self.prev_step_block % self.config.neuron.checkpoint_block_length
    bt.logging.debug(
        f"should_checkpoint() calculation:\nblock % checkpoint_block_length: {ttl_get_block(self)} % {self.config.neuron.checkpoint_block_length}\n"
        f"prev_step_block % checkpoint_block_length: {self.prev_step_block} % {self.config.neuron.checkpoint_block_length}\n"
        f"{a} < {b}: {a < b}"
    )
    return a < b


def checkpoint(self):
    """Checkpoints the training process."""
    bt.logging.info("checkpoint()")
    resync_metagraph(self)
    save_state(self)


def resync_metagraph(self: "validator.neuron.neuron"):
    """Resyncs the metagraph and updates the hotkeys and moving averages based on the new metagraph."""
    bt.logging.info("resync_metagraph()")

    # Copies state of metagraph before syncing.
    previous_metagraph = copy.deepcopy(self.metagraph)

    # Sync the metagraph.
    self.metagraph.sync(subtensor=self.subtensor)

    # Check if the metagraph axon info has changed.
    metagraph_axon_info_updated = previous_metagraph.axons != self.metagraph.axons
    bt.logging.debug(f"metagraph_axon_info_updated: {metagraph_axon_info_updated}")

    if metagraph_axon_info_updated:
        bt.logging.info(
            "resync_metagraph() Metagraph updated, re-syncing moving averages"
        )

        # Zero out all hotkeys that have been replaced.
        for uid, hotkey in enumerate(previous_metagraph.hotkeys):
            if hotkey != self.metagraph.hotkeys[uid]:
                bt.logging.debug(
                    f"resync_metagraph() old hotkey {hotkey} | uid {uid} has been replaced by {self.metagraph.hotkeys[uid]}"
                )
                self.moving_averaged_scores[uid] = 0  # hotkey has been replaced

        # Check to see if the metagraph has changed size.
        # If so, we need to add new hotkeys and moving averages.
        if len(self.moving_averaged_scores) < len(self.metagraph.hotkeys):
            bt.logging.info(
                f"resync_metagraph() Metagraph has grown, adding new hotkeys and moving averages"
            )
            # Update the size of the moving average scores.
            new_moving_average = torch.zeros((self.metagraph.n)).to(self.device)
            min_len = min(len(self.metagraph.hotkeys), len(self.moving_averaged_scores))
            new_moving_average[:min_len] = self.moving_averaged_scores[:min_len]
            self.moving_averaged_scores = new_moving_average


def save_state(self):
    r"""Save hotkeys, neuron model and moving average scores to filesystem."""
    bt.logging.info("save_state()")
    try:
        neuron_state_dict = {
            "neuron_weights": self.moving_averaged_scores.to("cpu").tolist(),
        }
        torch.save(neuron_state_dict, f"{self.config.neuron.full_path}/model.torch")
        bt.logging.success(
            prefix="Saved model",
            sufix=f"<blue>{ self.config.neuron.full_path }/model.torch</blue>",
        )
    except Exception as e:
        bt.logging.warning(f"Failed to save model with error: {e}")

    # empty cache
    torch.cuda.empty_cache()


def load_state(self):
    r"""Load hotkeys and moving average scores from filesystem."""
    bt.logging.info("load_state()")
    try:
        state_dict = torch.load(f"{self.config.neuron.full_path}/model.torch")
        neuron_weights = torch.tensor(state_dict["neuron_weights"])
        # Check to ensure that the size of the neruon weights matches the metagraph size.
        if neuron_weights.shape != (self.metagraph.n,):
            bt.logging.warning(
                f"Neuron weights shape {neuron_weights.shape} does not match metagraph n {self.metagraph.n}"
                "Populating new moving_averaged_scores IDs with zeros"
            )
            self.moving_averaged_scores[: len(neuron_weights)] = neuron_weights.to(
                self.device
            )
        # Check for nans in saved state dict
        elif not torch.isnan(neuron_weights).any():
            self.moving_averaged_scores = neuron_weights.to(self.device)
        bt.logging.success(
            prefix="Reloaded model",
            sufix=f"<blue>{ self.config.neuron.full_path }/model.torch</blue>",
        )
    except Exception as e:
        bt.logging.warning(f"Failed to load model with error: {e}")


def log_event(self, event):
    # Log event
    if not self.config.neuron.dont_save_events:
        logger.log("EVENTS", "events", **event.__dict__)

    # Log the event to wandb
    if not self.config.wandb.off:
        wandb_event = EventSchema.from_dict(event.__dict__)
        self.wandb.log(asdict(wandb_event))
