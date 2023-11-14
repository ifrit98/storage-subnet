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

from functools import partial
from traceback import print_exception
from random import choice as random_choice
from Crypto.Random import get_random_bytes, random

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
    select_subset_uids,
    scale_rewards_by_response_time,
    check_uid_availability,
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
)

from storage.validator.weights import (
    should_set_weights,
    set_weights,
)

from storage.validator.database import (
    add_metadata_to_hotkey,
    get_metadata_from_hash,
    get_all_data_for_hotkey,
    get_all_data_hashes,
    get_all_hotkeys_for_data_hash,
    update_metadata_for_data_hash,
)


class neuron:
    """
    A Neuron instance represents a node in the Bittensor network that performs validation tasks.
    It manages the data validation cycle, including storing, challenging, and retrieving data,
    while also participating in the network consensus.

    Attributes:
        subtensor (bt.subtensor): The interface to the Bittensor network's blockchain.
        wallet (bt.wallet): Cryptographic wallet containing keys for transactions and encryption.
        metagraph (bt.metagraph): Graph structure storing the state of the network.
        database (redis.StrictRedis): Database instance for storing metadata and proofs.
        moving_averaged_scores (torch.Tensor): Tensor tracking performance scores of other nodes.
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
        bt.logging.debug("loading", "device")
        self.device = torch.device(self.config.neuron.device)
        bt.logging.debug(str(self.device))

        # Init subtensor
        bt.logging.debug("loading", "subtensor")
        self.subtensor = bt.subtensor(config=self.config)
        bt.logging.debug(str(self.subtensor))

        # Init wallet.
        bt.logging.debug("loading", "wallet")
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
        bt.logging.debug("loading", "metagraph")
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
            db=self.config.database.index,
        )

        # Init Weights.
        bt.logging.debug("loading", "moving_averaged_scores")
        self.moving_averaged_scores = torch.zeros((self.metagraph.n)).to(self.device)
        bt.logging.debug(str(self.moving_averaged_scores))

        bt.logging.debug("serving ip to chain...")
        try:
            self.axon = bt.axon(wallet=self.wallet, config=self.config)

            self.axon.attach(
                forward_fn=self.update_index,
            )

            try:
                self.subtensor.serve_axon(
                    netuid=self.config.netuid,
                    axon=self.axon,
                )
            except Exception as e:
                bt.logging.error(f"Failed to serve Axon with exception: {e}")
                pass

        except Exception as e:
            bt.logging.error(f"Failed to create Axon initialize with exception: {e}")
            pass

        # Dendrite pool for querying the network.
        bt.logging.debug("loading", "dendrite_pool")
        if self.config.neuron.mock_dendrite_pool:
            self.dendrite = MockDendrite()
        else:
            self.dendrite = bt.dendrite(wallet=self.wallet)
        bt.logging.debug(str(self.dendrite))

        # Init the event loop.
        self.loop = asyncio.get_event_loop()

        # Init wandb.
        if not self.config.wandb.off:
            bt.logging.debug("loading", "wandb")
            init_wandb(self)

        if self.config.neuron.epoch_length_override:
            self.config.neuron.epoch_length = self.config.neuron.epoch_length_override
        else:
            self.config.neuron.epoch_length = 100
        bt.logging.debug(f"Set epoch_length {self.config.neuron.epoch_length}")

        self.prev_step_block = ttl_get_block(self)
        self.step = 0

    def get_random_uids(
        self, k: int, exclude: typing.List[int] = None
    ) -> torch.LongTensor:
        """Returns k available random uids from the metagraph.
        Args:
            k (int): Number of uids to return.
            exclude (List[int]): List of uids to exclude from the random sampling.
        Returns:
            uids (torch.LongTensor): Randomly sampled available uids.
        Notes:
            If `k` is larger than the number of available `uids`, set `k` to the number of available `uids`.
        """
        candidate_uids = []
        avail_uids = []

        for uid in range(self.metagraph.n.item()):
            uid_is_available = check_uid_availability(
                self.metagraph, uid, self.config.neuron.vpermit_tao_limit
            )
            uid_is_not_excluded = exclude is None or uid not in exclude

            if uid_is_available:
                avail_uids.append(uid)
                if uid_is_not_excluded:
                    candidate_uids.append(uid)

        # Check if candidate_uids contain enough for querying, if not grab all avaliable uids
        available_uids = candidate_uids
        if len(candidate_uids) < k:
            available_uids += random.sample(
                [uid for uid in avail_uids if uid not in candidate_uids],
                k - len(candidate_uids),
            )
        uids = torch.tensor(random.sample(available_uids, k))
        return uids

    def apply_reward_scores(self, uids, responses, rewards):
        """
        Adjusts the moving average scores for a set of UIDs based on their response times and reward values.

        This should reflect the distribution of axon response times (minmax norm)

        Parameters:
            uids (List[int]): A list of UIDs for which rewards are being applied.
            responses (List[Response]): A list of response objects received from the nodes.
            rewards (torch.FloatTensor): A tensor containing the computed reward values.
        """

        bt.logging.debug(f"Applying rewards: {rewards}")
        bt.logging.debug(f"Reward shape: {rewards.shape}")
        bt.logging.debug(f"UIDs: {uids}")
        scaled_rewards = scale_rewards_by_response_time(uids, responses, rewards)
        bt.logging.debug(f"Scaled rewards: {scaled_rewards}")

        # Compute forward pass rewards, assumes followup_uids and answer_uids are mutually exclusive.
        # shape: [ metagraph.n ]
        scattered_rewards: torch.FloatTensor = self.moving_averaged_scores.scatter(
            0, torch.tensor(uids).to(self.device), scaled_rewards
        ).to(self.device)
        bt.logging.debug(f"Scattered rewards: {scattered_rewards}")

        # Update moving_averaged_scores with rewards produced by this step.
        # shape: [ metagraph.n ]
        alpha: float = self.config.neuron.moving_average_alpha
        self.moving_averaged_scores: torch.FloatTensor = alpha * scattered_rewards + (
            1 - alpha
        ) * self.moving_averaged_scores.to(self.device)
        bt.logging.debug(f"Updated moving avg scores: {self.moving_averaged_scores}")

    def update_index(self, synapse: protocol.Update):
        """
        Updates the validator's index with new data received from a synapse.

        Parameters:
        - synapse (protocol.Update): The synapse object containing the update information.
        """
        data = self.get_metadata_from_hash(synapse.data_hash, synapse.hotkey)
        entry = {
            k: v
            for k, v in synapse.dict()
            if k
            in [
                "prev_seed",
                "size",
                "counter",
                "encryption_payload",
            ]
        }
        if not data:
            # Add it to the index directly
            add_metadata_to_hotkey(
                synapse.axon.hotkey, synapse.data_hash, entry, self.database
            )
        else:
            # Check for conflicts
            local_entry = json.loads(database.get(synapse.key))
            if local_entry["counter"] > synapse.counter:
                # Do nothing, we have a newer or current version
                return
            else:
                # Update the index to the latest data
                update_metadata_for_data_hash(
                    synapse.axon.hotkey, synapse.data_hash, entry, self.database
                )

    async def broadcast(self, hotkey, data_hash, data):
        """
        Broadcasts updates to all validators on the network for creating or updating an index value.

        Parameters:
        - lookup_key: The key associated with the data to broadcast.
        - data: The data to be broadcast to other validators.
        """
        # Determine axons to query from metagraph
        vpermits = self.metagraph.validator_permit
        vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
        vpermit_uids = torch.where(vpermits)[0]

        # Exclude your own uid
        vpermit_uids = vpermit_uids[
            vpermit_uids
            != self.metagraph.hotkeys.index(self.wallet.hotkey.ss58_address)
        ]
        query_uids = torch.where(
            self.metagraph.S[vpermit_uids] > self.config.neuron.broadcast_stake_limit
        )[0]
        axons = [self.metagraph.axons[uid] for uid in query_uids]

        # Create synapse store
        synapse = protocol.Update(
            hotkey=hotkey,
            data_hash=data_hash,
            prev_seed=data["prev_seed"],
            size=data["size"],
            counter=data["counter"],
            encryption_payload=data["encryption_payload"],
        )

        # Send synapse to all validator axons
        responses = await self.dendrite(
            axons,
            synapse,
            deserialize=False,
        )

        # TODO: Check the responses to ensure all validaors are updated

    async def store_user_data(self, data: bytes, wallet: bt.wallet):
        """
        Stores user data using the provided wallet as an encryption key.

        Parameters:
        - data (bytes): The data to be stored.
        - wallet (bt.wallet): The wallet to be used for encrypting the data.

        Returns:
        - The result of the store_data method.
        """
        # Store user data with the user's wallet as encryption key
        return await self.store_data(data=data, wallet=wallet)

    async def store_validator_data(self, data: bytes = None):
        """
        Stores random data using the validator's public key as the encryption key.

        Parameters:
        - data (bytes, optional): The data to be stored. If not provided, random data is generated.

        Returns:
        - The result of the store_data method.
        """

        # Store random data using the validator's pubkey as the encryption key
        return await self.store_data(data=data, wallet=self.wallet)

    async def store_data(self, data: bytes = None, wallet: bt.wallet = None):
        """
        Stores data on the network and ensures it is correctly committed by the miners.

        Parameters:
        - data (bytes, optional): The data to be stored.
        - wallet (bt.wallet, optional): The wallet to be used for encrypting the data.

        Returns:
        - The status of the data storage operation.
        """
        # Setup CRS for this round of validation
        g, h = setup_CRS(curve=self.config.neuron.curve)

        # Make a random bytes file to test the miner if none provided
        data = data or make_random_file(maxsize=self.config.neuron.maxsize)

        # Encrypt the data
        encrypted_data, encryption_payload = encrypt_data(data, wallet)

        # Convert to base64 for compactness
        b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

        synapse = protocol.Store(
            encrypted_data=b64_encrypted_data,
            curve=self.config.neuron.curve,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            seed=get_random_bytes(32).hex(),  # 256-bit seed
        )

        # Select subset of miners to query (e.g. redunancy factor of N)
        uids = self.get_random_uids(k=self.config.neuron.store_redundancy)

        updated_axons = []
        axons = [self.metagraph.axons[uid] for uid in uids]
        retry_uids = [None]

        retries = 0
        while len(retry_uids) and retries < 3:
            if retry_uids == [None]:
                # initial loop
                retry_uids = []

            # Broadcast the query to selected miners on the network.
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
            )

            # Log the results for monitoring purposes.
            if self.config.neuron.verbose:
                bt.logging.debug(f"Received responses: {responses}")

            # Compute the rewards for the responses given proc time.
            rewards: torch.FloatTensor = torch.zeros(
                len(responses), dtype=torch.float32
            ).to(self.device)

            for idx, (uid, response) in enumerate(zip(uids, responses)):
                # Verify the commitment
                if not verify_store_with_seed(response):
                    bt.logging.debug(
                        f"Failed to verify store commitment from UID: {uid}"
                    )
                    rewards[idx] = 0.0
                    retry_uids.append(uid)
                    continue  # Skip trying to store the data
                else:
                    rewards[idx] = 1.0
                    updated_axons.append(self.metagraph.axons[uid])

                data_hash = hash_data(encrypted_data)

                response_storage = {
                    "prev_seed": synapse.seed,
                    "size": sys.getsizeof(encrypted_data),
                    "counter": 0,
                    "encryption_payload": encryption_payload,
                }
                bt.logging.debug(f"Storing data {response_storage}")

                # Store in the database according to the data hash and the miner hotkey
                add_metadata_to_hotkey(
                    response.axon.hotkey, data_hash, response_storage, self.database
                )
                bt.logging.debug(
                    f"Stored data in database with key: {response.axon.hotkey} | {data_hash}"
                )

                # Broadcast the update to all other validators
                # TODO: ensure this will not block
                # TODO: potentially batch update after all miners have responded?

            bt.logging.trace(f"Broadcasting update to all validators")
            await self.broadcast(response.axon.hotkey, data_hash, response_storage)

            if self.config.neuron.verbose:
                bt.logging.debug(f"responses: {responses}")

            bt.logging.trace("Applying store rewards")
            self.apply_reward_scores(uids, responses, rewards)

            # Get a new set of UIDs to query for those left behind
            if retry_uids != []:
                bt.logging.debug(f"Failed to store on uids: {retry_uids}")
                uids = self.get_random_uids(k=len(retry_uids))

                bt.logging.debug(f"Retrying with new uids: {uids}")
                axons = [self.metagraph.axons[uid] for uid in uids]
                retry_uids = []  # reset retry uids
                retries += 1

    async def handle_challenge(
        self, uid: int
    ) -> typing.Tuple[bool, protocol.Challenge]:
        """
        Handles a challenge sent to a miner and verifies the response.

        Parameters:
        - uid (int): The UID of the miner being challenged.

        Returns:
        - Tuple[bool, protocol.Challenge]: A tuple containing the verification result and the challenge.
        """
        hotkey = self.metagraph.hotkeys[uid]
        bt.logging.debug(f"Handling challenge from hotkey: {hotkey}")

        keys = self.database.hkeys(hotkey)
        if keys == []:
            # Create a dummy response to send back
            dummy_response = protocol.Challenge(
                challenge_hash="",
                chunk_size=0,
                g="",
                h="",
                curve="",
                challenge_index=0,
                seed="",
            )
            return False, [
                dummy_response
            ]  # no data found associated with this miner hotkey

        if self.config.neuron.verbose:
            bt.logging.debug(f"Challenge lookup keys: {keys}")

        data_hash = random.choice(keys).decode("utf-8")
        data = get_metadata_from_hash(hotkey, data_hash, self.database)

        if self.config.neuron.verbose:
            bt.logging.debug(f"Challenge lookup key: {data_hash}")
            bt.logging.debug(f"Challenge data: {data}")

        try:
            chunk_size = get_random_chunksize(
                minsize=self.config.neuron.min_chunk_size,
                maxsize=max(
                    self.config.neuron.min_chunk_size,
                    data["size"] // self.config.neuron.chunk_factor,
                ),
            )
        except:
            bt.logging.error(
                f"Failed to get chunk size {self.config.neuron.min_chunk_size} | {self.config.neuron.chunk_factor} | {data['size'] // self.config.neuron.chunk_factor}"
            )
            chunk_size = 0

        if (
            chunk_size == 0
            or chunk_size > data["size"]
            or self.config.neuron.override_chunk_size
        ):
            bt.logging.warning(
                f"Incompatible chunk size {chunk_size}, setting to default {self.config.neuron.override_chunk_size}"
            )
            chunk_size = self.config.neuron.override_chunk_size

        bt.logging.debug(f"chunk size {chunk_size}")
        num_chunks = data["size"] // chunk_size
        bt.logging.debug(f"num chunks {num_chunks}")
        g, h = setup_CRS()

        synapse = protocol.Challenge(
            challenge_hash=data_hash,
            chunk_size=chunk_size,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            curve="P-256",
            challenge_index=random.choice(range(num_chunks)),
            seed=get_random_bytes(32).hex(),
        )

        axon = self.metagraph.axons[uid]

        response = await self.dendrite(
            [axon],
            synapse,
            deserialize=True,
        )
        verified = verify_challenge_with_seed(response[0])

        if verified:
            data["prev_seed"] = synapse.seed
            data["counter"] += 1
            update_metadata_for_data_hash(hotkey, data_hash, data, self.database)

        return verified, response

    async def challenge(self):
        """
        Initiates a series of challenges to miners, verifying their data storage through the network's consensus mechanism.

        Asynchronously challenge and see who returns the data fastest (passes verification), and rank them highest
        """
        tasks = []
        uids = self.get_random_uids(
            k=min(self.metagraph.n, self.config.neuron.challenge_sample_size)
        )
        for uid in uids:
            tasks.append(asyncio.create_task(self.handle_challenge(uid)))

        responses = await asyncio.gather(*tasks)

        if self.config.neuron.verbose:
            bt.logging.debug(f"Challenge repsonses: {responses}")

        # Compute the rewards for the responses given the prompt.
        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        # TODO: check and see if we have a dummy synapse (e.g. no data found, shouldn't penalize)
        for idx, (uid, (verified, response)) in enumerate(zip(uids, responses)):
            if self.config.neuron.verbose:
                bt.logging.debug(
                    f"Challenge idx {idx} uid {uid} verified {verified} response {response}"
                )
            if verified:
                rewards[idx] = 1.0
            else:
                rewards[idx] = 0.0

        responses = [response[0] for (verified, response) in responses]
        bt.logging.trace("Applying challenge rewards")
        self.apply_reward_scores(uids, responses, rewards)

    async def retrieve(self, data_hash=None):
        """
        Retrieves and verifies data from the network, ensuring integrity and correctness of the data associated with the given hash.

        Parameters:
            data_hash (str): The hash of the data to be retrieved.

        Returns:
            The retrieved data if the verification is successful.
        """

        if data_hash == None:
            hashes_dict = get_all_data_hashes(self.database)
            hashes = list(hashes_dict.keys())
            data_hash = random_choice(hashes)
            hotkeys = hashes_dict[data_hash]
        else:
            hotkeys = get_all_hotkeys_for_data_hash(data_hash, self.database)

        bt.logging.debug(f"Retrieving data with hash: {data_hash}")

        # Make sure we have the most up-to-date hotkey info
        self.metagraph.sync(lite=True)

        # fetch which miners have the data
        uids = []
        axons_to_query = []
        for hotkey in hotkeys:
            hotkey = (
                hotkey.decode("utf-8") if isinstance(hotkey, bytes) else hotkey
            )  # ensure str
            uid = self.metagraph.hotkeys.index(hotkey)
            axons_to_query.append(self.metagraph.axons[uid])
            uids.append(uid)
            if self.config.neuron.verbose:
                bt.logging.debug(f"appending hotkey: {hotkey}")

        # query all N (from redundancy factor) with M challenges (x% of the total data)
        # see who returns the data fastest (passes verification), and rank them highest
        synapse = protocol.Retrieve(
            data_hash=data_hash,
            seed=get_random_bytes(32).hex(),
        )
        responses = await self.dendrite(
            axons_to_query,
            synapse,
            deserialize=False,
        )

        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        datas = []
        for idx, response in enumerate(responses):
            bt.logging.debug(f"response: {response}")
            try:
                decoded_data = base64.b64decode(response.data)
            except Exception as e:
                bt.logging.error(
                    f"Failed to decode data from UID: {uids[idx]} with error {e}"
                )
                rewards[idx] = -1.0
                continue

            if str(hash_data(decoded_data)) != data_hash:
                bt.logging.error(
                    f"Hash of received data does not match expected hash! {str(hash_data(decoded_data))} != {data_hash}"
                )
                rewards[idx] = -1.0
                continue

            if not verify_retrieve_with_seed(response):
                bt.logging.error(f"data verification failed! {response}")
                rewards[idx] = -1.0  # Losing use data is unacceptable, harsh punishment
                continue  # skip trying to decode the data
            else:
                rewards[idx] = 1.0

            try:
                bt.logging.trace(f"Decrypting from UID: {uids[idx]}")

                # Load the data for this miner from validator storage
                data = get_metadata_from_hash(hotkey, data_hash, self.database)

                # If we reach here, this miner has passed verification. Update the validator storage.
                data["prev_seed"] = synapse.seed
                data["counter"] += 1
                update_metadata_for_data_hash(hotkey, data_hash, data, self.database)

                # TODO: Add this decryption on the miner side provided the user logs in
                # with their wallet! This way miners can send back a landing/login link
                # TODO: get a temp link from the server to send back to the client instead

                # Encapsulate this function with args so only need to pass the wallet
                # The partial func decrypts the data using the validator stored encryption keys
                decrypt_user_data = partial(
                    decrypt_data,
                    encrypted_data=decoded_data,
                    encryption_payload=data["encryption_payload"],
                )
                # Pass the user back the encrypted_data along with a function to decrypt it
                # given their wallet which was used to encrypt in the first place
                datas.append((decoded_data, decrypt_user_data))
            except Exception as e:
                bt.logging.error(
                    f"Failed to decrypt data from UID: {uids[idx]} with error: {e}"
                )

        bt.logging.trace("Applying retrieve rewards")
        self.apply_reward_scores(uids, responses, rewards)

        return datas

    async def forward(self) -> torch.Tensor:
        self.step += 1
        bt.logging.info(f"forward() {self.step}")

        try:
            # Store some data
            bt.logging.info("initiating store data")
            await self.store_validator_data()
        except Exception as e:
            import pdb

            pdb.set_trace()
            bt.logging.error(f"Failed to store data with exception: {e}")
            pass

        try:
            # Challenge some data
            bt.logging.info("initiating challenge")
            await self.challenge()
        except Exception as e:
            bt.logging.error(f"Failed to challenge data with exception: {e}")
            pass

        if self.step % 3 == 0:
            try:
                # Retrieve some data
                bt.logging.info("initiating retrieve")
                await self.retrieve()
            except Exception as e:
                bt.logging.error(f"Failed to retrieve data with exception: {e}")
                pass

        time.sleep(12)

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
                        f"Validator is not registered - hotkey {self.wallet.hotkey.ss58_address} not in metagraph"
                    )

                bt.logging.info(f"step({self.step}) block({ttl_get_block( self )})")

                # Run multiple forwards.
                async def run_forward():
                    coroutines = [
                        self.forward()
                        for _ in range(self.config.neuron.num_concurrent_forwards)
                    ]
                    await asyncio.gather(*coroutines)

                self.loop.run_until_complete(run_forward())

                # Resync the network state
                bt.logging.info("Checking if should checkpoint")
                if should_checkpoint(self):
                    bt.logging.info(f"Checkpointing...")
                    checkpoint(self)

                # Set the weights on chain.
                bt.logging.info(f"Checking if should set weights")
                if should_set_weights(self):
                    bt.logging.info(f"Setting weights {self.moving_averaged_scores}")
                    set_weights(self)
                    save_state(self)

                # Rollover wandb to a new run.
                if should_reinit_wandb(self):
                    reinit_wandb(self)

                self.prev_step_block = ttl_get_block(self)
                self.step += 1
        except Exception as err:
            bt.logging.error("Error in training loop", str(err))
            bt.logging.debug(print_exception(type(err), err, err.__traceback__))


def main():
    neuron().run()


if __name__ == "__main__":
    main()
