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

import os
import sys
import copy
import json
import time
import torch
import base64
import typing
import asyncio
import aioredis
import traceback
import websocket
import bittensor as bt
import threading

from storage import protocol
from storage.shared.ecc import hash_data
from storage.shared.subtensor import get_current_block
from storage.validator.config import config, check_config, add_args
from storage.validator.state import should_checkpoint
from storage.validator.encryption import encrypt_data

from storage.validator.store import store_broadband
from storage.validator.retrieve import retrieve_broadband
from storage.validator.network import (
    reroll_distribution,
    compute_and_ping_chunks,
    ping_uids,
)

from storage.validator.database import retrieve_encryption_payload

from storage.validator.encryption import decrypt_data_with_private_key


def MockDendrite():
    pass


class neuron:
    """
    API node for storage network

    Attributes:
        subtensor (bt.subtensor): The interface to the Bittensor network's blockchain.
        wallet (bt.wallet): Cryptographic wallet containing keys for transactions and encryption.
        metagraph (bt.metagraph): Graph structure storing the state of the network.
        database (redis.StrictRedis): Database instance for storing metadata and proofs.
    """

    @classmethod
    def check_config(cls, config: "bt.Config"):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return config(cls)

    subtensor: "bt.subtensor"
    wallet: "bt.wallet"
    metagraph: "bt.metagraph"

    def __init__(self):
        self.config = neuron.config()
        self.check_config(self.config)
        bt.logging(config=self.config, logging_dir=self.config.neuron.full_path)
        print(self.config)
        bt.logging.info("neuron.__init__()")

        # Init device.
        bt.logging.debug("loading device")
        self.device = torch.device(self.config.neuron.device)
        bt.logging.debug(str(self.device))

        # Init subtensor
        bt.logging.debug("loading subtensor")
        self.subtensor = (
            bt.MockSubtensor()
            if self.config.neuron.mock_subtensor
            else bt.subtensor(config=self.config)
        )
        bt.logging.debug(str(self.subtensor))

        # Init validator wallet.
        bt.logging.debug("loading wallet")
        self.wallet = bt.wallet(config=self.config)
        self.wallet.create_if_non_existent()

        if not self.config.wallet._mock:
            if not self.subtensor.is_hotkey_registered_on_subnet(
                hotkey_ss58=self.wallet.hotkey.ss58_address, netuid=self.config.netuid
            ):
                raise Exception(
                    f"Wallet not currently registered on netuid {self.config.netuid}, please first register wallet before running"
                )

        bt.logging.debug(f"wallet: {str(self.wallet)}")

        # Setup dummy wallet for encryption purposes. No password needed.
        self.encryption_wallet = bt.wallet(
            name=self.config.neuron.encryption_wallet_name,
            hotkey=self.config.neuron.encryption_hotkey,
        )
        self.encryption_wallet.create_if_non_existent(coldkey_use_password=False)
        self.encryption_wallet.coldkey  # Unlock the coldkey.

        # Init metagraph.
        bt.logging.debug("loading metagraph")
        self.metagraph = bt.metagraph(
            netuid=self.config.netuid, network=self.subtensor.network, sync=False
        )  # Make sure not to sync without passing subtensor
        self.metagraph.sync(subtensor=self.subtensor)  # Sync metagraph with subtensor.
        bt.logging.debug(str(self.metagraph))

        # Setup database
        self.database = aioredis.StrictRedis(
            host=self.config.database.host,
            port=self.config.database.port,
            db=self.config.database.index,
        )
        self.db_semaphore = asyncio.Semaphore()

        # Init Weights.
        bt.logging.debug("loading moving_averaged_scores")
        self.moving_averaged_scores = torch.zeros((self.metagraph.n)).to(self.device)
        bt.logging.debug(str(self.moving_averaged_scores))

        self.my_subnet_uid = self.metagraph.hotkeys.index(
            self.wallet.hotkey.ss58_address
        )
        bt.logging.info(f"Running validator on uid: {self.my_subnet_uid}")

        bt.logging.debug("serving ip to chain...")
        try:
            self.axon = bt.axon(wallet=self.wallet, config=self.config)

            self.axon.attach(
                forward_fn=self.store_user_data,
                blacklist_fn=self.store_blacklist,
                priority_fn=self.store_priority,
            ).attach(
                forward_fn=self.retrieve_user_data,
                blacklist_fn=self.retrieve_blacklist,
                priority_fn=self.retrieve_priority,
            )

            try:
                self.subtensor.serve_axon(
                    netuid=self.config.netuid,
                    axon=self.axon,
                )
                self.axon.start()

            except Exception as e:
                bt.logging.error(f"Failed to serve Axon: {e}")
                pass

        except Exception as e:
            bt.logging.error(f"Failed to create Axon initialize: {e}")
            pass

        # Dendrite pool for querying the network.
        bt.logging.debug("loading dendrite_pool")
        if self.config.neuron.mock:
            self.dendrite = MockDendrite()  # TODO: fix this import error
        else:
            self.dendrite = bt.dendrite(wallet=self.wallet)
        bt.logging.debug(str(self.dendrite))

        # Init the event loop.
        self.loop = asyncio.get_event_loop()

        if self.config.neuron.challenge_sample_size == 0:
            self.config.neuron.challenge_sample_size = self.metagraph.n

        self.prev_step_block = get_current_block(self.subtensor)

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()
        self.request_timestamps: typing.Dict = {}

        self.step = 0

        self._top_n_validators = None
        self.get_top_n_validators()

    def get_top_n_validators(self):
        """
        Retrieves a list of the top N validators based on the stake value from the metagraph.
        This list represents the top 10% of validators by stake.

        Returns:
            list: A list of UIDs (unique identifiers) for the top N validators.

        Note:
            - The method filters out the UID of the current instance (self) if it is in the top N list.
            - This function is typically used to identify validators with the highest stake in the network,
            which can be crucial for decision-making processes in a distributed system.
        """
        top_uids = torch.where(
            self.metagraph.S > torch.quantile(self.metagraph.S, 1 - 0.1)
        )[0].tolist()
        if self.my_subnet_uid in top_uids:
            top_uids.remove(self.my_subnet_uid)
        return top_uids

    @property
    def top_n_validators(self):
        """
        A property that provides access to the top N validators' UIDs. It calculates the top N validators
        if they have not been computed yet or if a checkpoint condition is met (indicated by the
        'should_checkpoint' function).

        Returns:
            list: A list of UIDs for the top N validators.

        Note:
            - This property employs lazy loading and caching to efficiently manage the retrieval of top N validators.
            - The cache is updated based on specific conditions, such as crossing a checkpoint in the network.
        """
        if self._top_n_validators == None or should_checkpoint(
            get_current_block(self.subtensor),
            self.prev_step_block,
            self.config.neuron.checkpoint_block_length,
        ):
            self._top_n_validators = self.get_top_n_validators()
        return self._top_n_validators

    async def store_user_data(self, synapse: protocol.StoreUser) -> protocol.StoreUser:
        """
        Asynchronously handles the storage of user data by processing a store user request. It stores the
        encrypted user data on the network and updates the request with the resulting data hash.

        Parameters:
            synapse (protocol.StoreUser): An instance of the StoreUser protocol class containing information
                                        about the data to be stored.

        Returns:
            protocol.StoreUser: The updated instance of the StoreUser protocol class with the data hash
                                of the stored data.

        Note:
            - This method is part of a larger protocol for storing data in a distributed network.
            - It relies on the 'store_broadband' method for actual storage and hash generation.
            - The method logs detailed information about the storage process for monitoring and debugging.
        """
        bt.logging.debug(f"store_user_data() {synapse.dendrite.dict()}")

        decoded_data = base64.b64decode(synapse.encrypted_data)
        decoded_data = (
            decoded_data.encode("utf-8")
            if isinstance(decoded_data, str)
            else decoded_data
        )
        validator_encrypted_data, validator_encryption_payload = encrypt_data(
            decoded_data, self.encryption_wallet
        )

        # Hash the original data to avoid data confusion
        data_hash = hash_data(decoded_data)

        if isinstance(validator_encryption_payload, dict):
            validator_encryption_payload = json.dumps(validator_encryption_payload)

        await self.database.set(
            f"payload:validator:{data_hash}", validator_encryption_payload
        )

        _ = await store_broadband(
            self,
            encrypted_data=validator_encrypted_data,
            encryption_payload=synapse.encryption_payload,
            data_hash=data_hash,
        )
        synapse.data_hash = data_hash
        return synapse

    async def store_blacklist(
        self, synapse: protocol.StoreUser
    ) -> typing.Tuple[bool, str]:
        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."

        # If a validator with top n% stake, allow.
        if synapse.dendrite.hotkey in self.top_n_validators:
            return False, f"Hotkey {synapse.dendrite.hotkey} in top n% stake."

        # If debug mode, whitelist everything (NOT RECOMMENDED)
        if self.config.api.debug:
            return False, "Debug all whitelisted"

        # Otherwise, reject.
        return (
            True,
            f"Hotkey {synapse.dendrite.hotkey} not whitelisted or in top n% stake.",
        )

    async def store_priority(self, synapse: protocol.StoreUser) -> float:
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", priority
        )
        return priority

    async def retrieve_user_data(
        self, synapse: protocol.RetrieveUser
    ) -> protocol.RetrieveUser:
        """
        Asynchronously handles the retrieval of user data from the network based on a given hash.
        It retrieves and verifies the data, then updates the synapse object with the retrieved data.

        Parameters:
            synapse (protocol.RetrieveUser): An instance of the RetrieveUser protocol class containing
                                            the hash of the data to be retrieved.

        Returns:
            protocol.RetrieveUser: The updated instance of the RetrieveUser protocol class with the
                                retrieved encrypted data and encryption payload.

        Note:
            - The function is part of a larger protocol for data retrieval in a distributed network.
            - It utilizes the 'retrieve_broadband' method to perform the actual data retrieval and
            verification based on the provided data hash.
            - The method logs the retrieval process and the resulting data for monitoring and debugging.
        """
        validator_encrypted_data, user_encryption_payload = await retrieve_broadband(
            self, synapse.data_hash
        )

        validator_encryption_payload = await retrieve_encryption_payload(
            "validator:" + synapse.data_hash, self.database
        )

        bt.logging.debug(
            f"validator_encryption_payload: {validator_encryption_payload}"
        )
        decrypted_data = decrypt_data_with_private_key(
            validator_encrypted_data,
            bytes(json.dumps(validator_encryption_payload), "utf-8"),
            bytes(self.encryption_wallet.coldkey.private_key.hex(), "utf-8"),
        )
        bt.logging.debug(f"decrypted_data: {decrypted_data[:100]}")

        bt.logging.debug(f"returning user data: {decrypted_data[:100]}")
        bt.logging.debug(f"returning user payload: {user_encryption_payload}")
        synapse.encrypted_data = base64.b64encode(user_encryption_payload)
        synapse.encryption_payload = (
            json.dumps(user_encryption_payload)
            if isinstance(user_encryption_payload, dict)
            else user_encryption_payload
        )
        return synapse

    async def retrieve_blacklist(
        self, synapse: protocol.RetrieveUser
    ) -> typing.Tuple[bool, str]:
        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."

        # If a validator with top n% stake, allow.
        if synapse.dendrite.hotkey in self.top_n_validators:
            return False, f"Hotkey {synapse.dendrite.hotkey} in top n% stake."

        # If debug mode, whitelist everything (NOT RECOMMENDED)
        if self.config.api.debug:
            return False, "Debug all whitelisted."

        # Otherwise, reject.
        return (
            True,
            f"Hotkey {synapse.dendrite.hotkey} not whitelisted or in top n% stake.",
        )

    async def retrieve_priority(self, synapse: protocol.RetrieveUser) -> float:
        caller_uid = self.metagraph.hotkeys.index(
            synapse.dendrite.hotkey
        )  # Get the caller index.
        priority = float(
            self.metagraph.S[caller_uid]
        )  # Return the stake as the priority.
        bt.logging.trace(
            f"Prioritizing {synapse.dendrite.hotkey} with value: ", priority
        )
        return priority

    def run(self):
        bt.logging.info("run()")
        if not self.wallet.hotkey.ss58_address in self.metagraph.hotkeys:
            raise Exception(
                f"API is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
            )
        try:
            while not self.should_exit:
                start_epoch = time.time()

                # --- Wait until next epoch.
                current_block = self.subtensor.get_current_block()
                while (
                    current_block - self.prev_step_block
                    < self.config.neuron.blocks_per_step
                ):
                    # --- Wait for next bloc.
                    time.sleep(1)
                    current_block = self.subtensor.get_current_block()

                    # --- Check if we should exit.
                    if self.should_exit:
                        break

                # --- Update the metagraph with the latest network state.
                self.prev_step_block = self.subtensor.get_current_block()

                self.metagraph = self.subtensor.metagraph(
                    netuid=self.config.netuid,
                    lite=True,
                    block=self.prev_step_block,
                )

        # If someone intentionally stops the API, it'll safely terminate operations.
        except KeyboardInterrupt:
            self.axon.stop()
            bt.logging.success("API killed by keyboard interrupt.")
            exit()

        # In case of unforeseen errors, the API will log the error and continue operations.
        except Exception as e:
            bt.logging.error(traceback.format_exc())

        # After all we have to ensure subtensor connection is closed properly
        finally:
            if hasattr(self, "subtensor"):
                bittensor.logging.debug("Closing subtensor connection")
                self.subtensor.close()

    def run_in_background_thread(self):
        """
        Starts the miner's operations in a separate background thread.
        This is useful for non-blocking operations.
        """
        if not self.is_running:
            bt.logging.debug("Starting miner in background thread.")
            self.should_exit = False
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()
            self.is_running = True
            bt.logging.debug("Started")

    def stop_run_thread(self):
        """
        Stops the miner's operations that are running in the background thread.
        """
        if self.is_running:
            bt.logging.debug("Stopping miner in background thread.")
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            bt.logging.debug("Stopped")

    def __enter__(self):
        """
        Starts the miner's operations in a background thread upon entering the context.
        This method facilitates the use of the miner in a 'with' statement.
        """
        self.run_in_background_thread()

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Stops the miner's background operations upon exiting the context.
        This method facilitates the use of the miner in a 'with' statement.

        Args:
            exc_type: The type of the exception that caused the context to be exited.
                      None if the context was exited without an exception.
            exc_value: The instance of the exception that caused the context to be exited.
                       None if the context was exited without an exception.
            traceback: A traceback object encoding the stack trace.
                       None if the context was exited without an exception.
        """
        self.stop_run_thread()


def main():
    neuron().run()


if __name__ == "__main__":
    main()
