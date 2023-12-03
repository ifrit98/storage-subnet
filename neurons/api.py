import os
import sys
import copy
import json
import time
import redis
import torch
import base64
import typing
import asyncio
import argparse
import traceback
import bittensor as bt

from loguru import logger
from pprint import pformat
from functools import partial
from traceback import print_exception
from random import choice as random_choice
from Crypto.Random import get_random_bytes, random

from dataclasses import asdict
from storage.validator.event import EventSchema

from storage import protocol

from storage.shared.ecc import (
    hash_data,
    setup_CRS,
    ECCommitment,
    ecc_point_to_hex,
    hex_to_ecc_point,
)

from storage.shared.merkle import (
    MerkleTree,
)

from storage.shared.utils import (
    b64_encode,
    b64_decode,
    chunk_data,
    safe_key_search,
)

from storage.validator.utils import (
    make_random_file,
    get_random_chunksize,
    check_uid_availability,
    get_random_uids,
    get_query_miners,
    get_query_validators,
    get_available_query_miners,
    get_current_validtor_uid_round_robin,
    compute_chunk_distribution_mut_exclusive_numpy_reuse_uids,
)

from storage.validator.encryption import (
    decrypt_data,
    encrypt_data,
)

from storage.validator.verify import (
    verify_store_with_seed,
    verify_challenge_with_seed,
    verify_retrieve_with_seed,
)

from storage.validator.config import config, check_config, add_args

from storage.validator.state import (
    should_checkpoint,
    checkpoint,
    should_reinit_wandb,
    reinit_wandb,
    load_state,
    save_state,
    init_wandb,
    ttl_get_block,
    log_event,
)

from storage.validator.reward import apply_reward_scores

from storage.validator.weights import (
    should_set_weights,
    set_weights,
)

from storage.validator.database import (
    add_metadata_to_hotkey,
    get_miner_statistics,
    get_metadata_for_hotkey,
    total_network_storage,
    store_chunk_metadata,
    store_file_chunk_mapping_ordered,
    get_metadata_for_hotkey_and_hash,
    update_metadata_for_data_hash,
    get_all_chunk_hashes,
    get_ordered_metadata,
    hotkey_at_capacity,
    get_miner_statistics,
)

from storage.validator.bonding import (
    miner_is_registered,
    update_statistics,
    get_tier_factor,
    compute_all_tiers,
)


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

        # Init wallet.
        bt.logging.debug("loading wallet")
        self.wallet = bt.wallet(config=self.config)
        self.wallet.coldkey  # Unlock for testing
        self.wallet.create_if_non_existent()
        if not self.config.wallet._mock:
            if not self.subtensor.is_hotkey_registered_on_subnet(
                hotkey_ss58=self.wallet.hotkey.ss58_address, netuid=self.config.netuid
            ):
                raise Exception(
                    f"Wallet not currently registered on netuid {self.config.netuid}, please first register wallet before running"
                )

        bt.logging.debug(f"wallet: {str(self.wallet)}")

        # Init metagraph.
        bt.logging.debug("loading metagraph")
        self.metagraph = bt.metagraph(
            netuid=self.config.netuid, network=self.subtensor.network, sync=False
        )  # Make sure not to sync without passing subtensor
        self.metagraph.sync(subtensor=self.subtensor)  # Sync metagraph with subtensor.
        self.hotkeys = copy.deepcopy(self.metagraph.hotkeys)
        bt.logging.debug(str(self.metagraph))

        # Setup database
        self.database = redis.StrictRedis(
            host=self.config.database.host,
            port=self.config.database.port,
            db=6,  # self.config.database.index,
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

        # Init wandb.
        if not self.config.wandb.off:
            bt.logging.debug("loading wandb")
            init_wandb(self)

        if self.config.neuron.epoch_length_override:
            self.config.neuron.epoch_length = self.config.neuron.epoch_length_override
        else:
            self.config.neuron.epoch_length = 100
        bt.logging.debug(f"Set epoch_length {self.config.neuron.epoch_length}")

        if self.config.neuron.challenge_sample_size == 0:
            self.config.neuron.challenge_sample_size = self.metagraph.n

        self.prev_step_block = ttl_get_block(self)
        self.step = 0

    # TODO: Develop the agreement gossip protocol across validators to accept storage requests
    # and accept retrieve requests given agreement of top n % stake
    async def agreement_protocol(self):
        raise NotImplementedError

    async def store_user_data(self, synapse: protocol.StoreUser) -> protocol.StoreUser:
        await self.store_broadband(synapse.encrypted_data)

    async def store_blacklist(self, synapse: protocol.StoreUser) -> Tuple[bool, str]:
        return False, "NotImplemented. Whitelisting all.."

    async def store_priority(self, synapse: protocl.StoreUser) -> float:
        return 0.0

    async def retrieve_user_data(
        self, synapse: protocol.RetrieveUser
    ) -> protocol.RetrieveUser:
        data = await self.retrieve_broadband(synapse.data_hash)
        synapse.encrypted_data = data
        return synapse
        # TODO: determine at what level we will use encryption
        # Will we decrypt here or just pass encrypted data + payload back to user for them to decrypt?
        # Are we going to use bittensor wallet encryptin for everything? E.g. create user accounts WITH
        # bittensor wallets, even if they're not on the blockchain or have TAO. Just to keep the scheme
        # consistent and easy to develop with. (no other encryption schemes except to login to frontend)

    async def retrieve_blacklist(
        self, synapse: protocol.RetrieveUser
    ) -> Tuple[bool, str]:
        return False, "NotImplemented. Whitelisting all.."

    async def retrieve_priority(self, synapse: protocl.RetrieveUser) -> float:
        return 0.0

    async def store_broadband(self, data, R=3, k=10):
        """
        Stores data on the network and ensures it is correctly committed by the miners.

        Uses a semaphore to restrict the number of concurrent requests to the network.

        Stores chunks in groups of R, and queries k miners for each chunk.

        Basic algorthim:
            - Split data into chunks
            - Compute chunk distribution
            - For each chunk:
                - Select R miners to store the chunk
            - Verify the response from each miner
            - Store the data for each verified response

        Parameters:
            data: bytes
                The data to be stored.
            R: int
                The redundancy factor for the data storage.
            k: int
                The target number of miners to query for each chunk.
        """
        semaphore = asyncio.Semaphore(self.config.neuron.semaphore_size)

        # TODO: add a retry mechanism like with store_encrypted_data
        # TODO: how will you handle encryption here? (if at all)
        async def store_chunk_group(chunk_hash, chunk, uids):
            g, h = setup_CRS(curve=self.config.neuron.curve)

            b64_encoded_chunk = base64.b64encode(chunk).decode("utf-8")

            synapse = protocol.Store(
                encrypted_data=b64_encoded_chunk,
                curve=self.config.neuron.curve,
                g=ecc_point_to_hex(g),
                h=ecc_point_to_hex(h),
                seed=get_random_bytes(32).hex(),
            )

            # TODO: do this more elegantly, possibly reroll with fresh miner
            # uids to get back to redundancy factor R before querying
            uids = [
                uid
                for uid in uids
                if not hotkey_at_capacity(self.hotkeys[uid], self.database)
            ]

            axons = [self.metagraph.axons[uid] for uid in uids]
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
                timeout=60,
            )

            return responses

        tasks = []
        chunks = []
        chunk_hashes = []
        uids_nested = []
        full_hash = hash_data(data)
        full_size = sys.getsizeof(data)
        async with semaphore:
            for i, dist in enumerate(
                compute_chunk_distribution_mut_exclusive_numpy_reuse_uids(
                    self, data, R, k
                )
            ):
                bt.logging.debug(f"Chunk {i} | uid distribution: {dist['uids']}")
                chunks.append(dist["chunk"])
                uids_nested.append(dist["uids"])
                chunk_hashes.append(dist["chunk_hash"])
                tasks.append(
                    asyncio.create_task(
                        store_chunk_group(
                            dist["chunk_hash"], dist["chunk"], dist["uids"]
                        )
                    )
                )
            responses_nested = await asyncio.gather(*tasks)

        for i, (uids, responses, chunk, chunk_hash) in enumerate(
            zip(uids_nested, responses_nested, chunks, chunk_hashes)
        ):
            chunk_size = sys.getsizeof(chunk)

            store_chunk_metadata(
                full_hash,
                chunk_hash,
                [self.hotkeys[uid] for uid in uids],
                chunk_size,
                self.database,
            )

            for uid, response in zip(uids, responses):
                verified = verify_store_with_seed(response)
                if verified:
                    # Prepare storage for the data for particular miner
                    response_storage = {
                        "prev_seed": response.seed,
                        "size": chunk_size,
                    }
                    # Store in the database according to the data hash and the miner hotkey
                    add_metadata_to_hotkey(
                        self.hotkeys[uid],
                        chunk_hash,
                        response_storage,  # seed + size
                        self.database,
                    )
                    bt.logging.debug(
                        f"Stored data in database for uid: {uid} | {str(chunk_hash)}"
                    )
                else:
                    bt.logging.error(
                        f"Failed to verify store commitment from UID: {uid}"
                    )

                # Update the storage statistics
                update_statistics(
                    ss58_address=self.hotkeys[uid],
                    success=verified,
                    task_type="store",
                    database=self.database,
                )

        # Update the chunk hash mapping for this entire file
        store_file_chunk_mapping_ordered(
            full_hash=full_hash,
            chunk_hashes=chunk_hashes,
            chunk_indices=list(range(len(chunks))),
            database=self.database,
        )

    async def retrieve_broadband(self, full_hash: str):
        """
        Retrieves and verifies data from the network, ensuring integrity and correctness of the data associated with the given hash.

        Parameters:
            data_hash (str): The hash of the data to be retrieved.

        Returns:
            The retrieved data if the verification is successful.
        """
        semaphore = asyncio.Semaphore(self.config.neuron.semaphore_size)

        async def retrieve_chunk_group(chunk_hash, uids):
            synapse = protocol.Retrieve(
                data_hash=chunk_hash,
                seed=get_random_bytes(32).hex(),
            )

            axons = [self.metagraph.axons[uid] for uid in uids]
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
                timeout=60,
            )

            return responses

        # Get the chunks you need to reconstruct IN order
        ordered_metadata = get_ordered_metadata(full_hash, self.database)
        if ordered_metadata == []:
            bt.logging.error(f"No metadata found for full hash: {full_hash}")
            return None

        # Get the hotkeys/uids to query
        tasks = []
        total_size = 0
        bt.logging.debug(f"ordered metadata: {ordered_metadata}")
        # TODO: change this to use retrieve_mutually_exclusive_hotkeys_full_hash
        # to avoid possibly double querying miners for greater retrieval efficiency
        for chunk_metadata in ordered_metadata:
            uids = [self.hotkeys.index(hotkey) for hotkey in chunk_metadata["hotkeys"]]
            total_size += chunk_metadata["size"]
            tasks.append(
                asyncio.create_task(
                    retrieve_chunk_group(chunk_metadata["chunk_hash"], uids)
                )
            )
        responses = await asyncio.gather(*tasks)

        chunks = {}
        for i, response_group in enumerate(responses):
            for response in response_group:
                verified = verify_retrieve_with_seed(response)
                if verified:
                    # Add to final chunks dict
                    if i not in list(chunks.keys()):
                        chunks[i] = base64.b64decode(response.data)
                else:
                    bt.logging.error(
                        f"Failed to verify store commitment from UID: {uid}"
                    )

        # Reconstruct the data
        data = b"".join(chunks.values())

        if total_size != sys.getsizeof(data):
            bt.logging.warning(
                f"Data reconstruction has different size than metadata: {total_size} != {sys.getsizeof(data)}"
            )

        return data

    def run(self):
        bt.logging.info("run()")
        load_state(self)
        checkpoint(self)
        try:
            while True:
                start_epoch = time.time()

                # --- Wait until next step epoch.
                current_block = self.subtensor.get_current_block()
                while (
                    current_block - self.prev_step_block
                    < self.config.neuron.blocks_per_step
                ):
                    # --- Wait for next block.
                    time.sleep(1)
                    current_block = self.subtensor.get_current_block()

                if not self.wallet.hotkey.ss58_address in self.metagraph.hotkeys:
                    raise Exception(
                        f"API is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
                    )

                bt.logging.info(f"step({self.step}) block({ttl_get_block( self )})")

                # Rollover wandb to a new run.
                if should_reinit_wandb(self):
                    bt.logging.info(f"Reinitializing wandb")
                    reinit_wandb(self)

                self.prev_step_block = ttl_get_block(self)
                if self.config.neuron.verbose:
                    bt.logging.debug(f"block at end of step: {self.prev_step_block}")
                    bt.logging.debug(f"Step took {time.time() - start_epoch} seconds")
                self.step += 1

        except Exception as err:
            bt.logging.error("Error in training loop", str(err))
            bt.logging.debug(print_exception(type(err), err, err.__traceback__))


def main():
    neuron().run()


if __name__ == "__main__":
    main()
