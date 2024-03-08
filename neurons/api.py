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

import json
import time
import torch
import base64
import typing
import asyncio
from redis import asyncio as aioredis
import traceback
import bittensor as bt
import threading

from storage import protocol
from storage.shared.ecc import hash_data
from storage.shared.checks import check_environment, check_registration
from storage.shared.utils import get_redis_password
from storage.shared.subtensor import get_current_block
from storage.validator.config import config, check_config, add_args
from storage.validator.state import should_checkpoint
from storage.validator.encryption import encrypt_data, setup_encryption_wallet
from storage.validator.store import store_broadband
from storage.validator.retrieve import retrieve_broadband
from storage.validator.database import retrieve_encryption_payload, get_ordered_metadata
from storage.validator.cid import generate_cid_string
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

        try:
            asyncio.run(check_environment(self.config.database.redis_conf_path))
        except AssertionError as e:
            bt.logging.warning(
                f"Something is missing in your environment: {e}. Please check your configuration, use the README for help, and try again."
            )

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
            check_registration(self.subtensor, self.wallet, self.config.netuid)

        bt.logging.debug(f"wallet: {str(self.wallet)}")

        # Setup dummy wallet for encryption purposes. No password needed.
        self.encryption_wallet = setup_encryption_wallet(
            wallet_name=self.config.encryption.wallet_name,
            wallet_hotkey=self.config.encryption.hotkey,
            password=self.config.encryption.password,
        )
        self.encryption_wallet.coldkey  # Unlock the coldkey.
        bt.logging.info(f"loading encryption wallet {self.encryption_wallet}")

        # Init metagraph.
        bt.logging.debug("loading metagraph")
        self.metagraph = bt.metagraph(
            netuid=self.config.netuid, network=self.subtensor.network, sync=False
        )  # Make sure not to sync without passing subtensor
        self.metagraph.sync(subtensor=self.subtensor)  # Sync metagraph with subtensor.
        bt.logging.debug(str(self.metagraph))

        # Setup database
        bt.logging.info("loading database")
        redis_password = get_redis_password(self.config.database.redis_password)
        self.database = aioredis.StrictRedis(
            host=self.config.database.host,
            port=self.config.database.port,
            db=self.config.database.index,
            socket_keepalive=True,
            socket_connect_timeout=300,
            password=redis_password,
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

        self.prev_step_block = get_current_block(self.subtensor)

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()
        self.request_timestamps: typing.Dict = {}

        self.step = 0

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
        bt.logging.debug(f"store_user_data() {synapse.axon.dict()}")

        decoded_data = base64.b64decode(synapse.encrypted_data)
        decoded_data = (
            decoded_data.encode("utf-8")
            if isinstance(decoded_data, str)
            else decoded_data
        )

        # Hash the original data to avoid data confusion
        content_id = generate_cid_string(decoded_data)

        # Check and see if hash already exists, reject if so.
        if await get_ordered_metadata(content_id, self.database):
            bt.logging.warning(f"Hash {content_id} already exists on the network.")
            synapse.data_hash = content_id
            return synapse

        validator_encrypted_data, validator_encryption_payload = encrypt_data(
            decoded_data, self.encryption_wallet
        )

        if isinstance(validator_encryption_payload, dict):
            validator_encryption_payload = json.dumps(validator_encryption_payload)

        await self.database.set(
            f"payload:validator:{content_id}", validator_encryption_payload
        )

        _ = await store_broadband(
            self,
            encrypted_data=validator_encrypted_data,
            encryption_payload=synapse.encryption_payload,
            data_hash=content_id,
        )
        synapse.data_hash = content_id
        return synapse

    async def store_blacklist(
        self, synapse: protocol.StoreUser
    ) -> typing.Tuple[bool, str]:
        # If debug mode, whitelist everything (NOT RECOMMENDED)

        if self.config.api.open_access:
            return False, "Open access: WARNING all whitelisted"

        if synapse.dendrite.hotkey in self.config.api.blacklisted_hotkeys:
            return True, f"Hotkey {synapse.dendrite.hotkey} blacklisted."

        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."

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
        synapse.encrypted_data = base64.b64encode(decrypted_data)
        synapse.encryption_payload = (
            json.dumps(user_encryption_payload)
            if isinstance(user_encryption_payload, dict)
            else user_encryption_payload
        )
        return synapse

    async def retrieve_blacklist(
        self, synapse: protocol.RetrieveUser
    ) -> typing.Tuple[bool, str]:
        # If debug mode, whitelist everything (NOT RECOMMENDED)
        if self.config.api.open_access:
            return False, "Open access: WARNING all whitelisted"

        # If explicitly whitelisted hotkey, allow.
        if synapse.dendrite.hotkey in self.config.api.whitelisted_hotkeys:
            return False, f"Hotkey {synapse.dendrite.hotkey} whitelisted."

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
        if self.wallet.hotkey.ss58_address not in self.metagraph.hotkeys:
            raise Exception(
                f"API is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
            )
        try:
            while not self.should_exit:
                # --- Wait until next epoch.
                current_block = self.subtensor.get_current_block()
                while current_block - self.prev_step_block < 3:
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
        except Exception:
            bt.logging.error(traceback.format_exc())

        # After all we have to ensure subtensor connection is closed properly
        finally:
            if hasattr(self, "subtensor"):
                bt.logging.debug("Closing subtensor connection")
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


def run_api():
    neuron().run()


if __name__ == "__main__":
    run_api()
