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
        self.db_semaphore = asyncio.Semaphore()

        # Init Weights.
        bt.logging.debug("loading", "moving_averaged_scores")
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
                forward_fn=self.update_index,
            ).attach(
                forward_fn=self.retrieve_user_data,
            ).attach(
                forward_fn=self.store_user_data,
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

        # Start  starts the validator's axon, making it active on the network.
        bt.logging.info(f"Starting axon server on port: {self.config.axon.port}")
        self.axon.start()

        bt.logging.info(
            f"Served axon {self.axon} on network: {self.subtensor.chain_endpoint} with netuid: {self.config.netuid}"
        )

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

        if self.config.neuron.challenge_sample_size == 0:
            self.config.neuron.challenge_sample_size = self.metagraph.n

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
        if self.config.neuron.verbose:
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

    async def update_index(self, synapse: protocol.Update) -> protocol.Update:
        """
        Updates the validator's index with new data received from a synapse.

        Parameters:
        - synapse (protocol.Update): The synapse object containing the update information.
        """
        data = get_metadata_from_hash(synapse.data_hash, synapse.hotkey, self.database)
        bt.logging.debug(f"data retreived in update: {data}")
        entry = {
            k: v
            for k, v in synapse.dict().items()
            if k
            in [
                "prev_seed",
                "size",
                "counter",
                "encryption_payload",
            ]
        }
        bt.logging.debug(f"entry: {entry}")

        # Update the index with the new data
        # with self.db_semaphore:
        bt.logging.debug(f"Acquired semaphore for database access.")
        if not data:
            bt.logging.debug(f"Updating index with new data...")
            # Add it to the index directly
            add_metadata_to_hotkey(
                synapse.axon.hotkey, synapse.data_hash, entry, self.database
            )
            synapse.updated = True
        else:
            # Check for conflicts
            bt.logging.debug(f"checking for conflicts...")
            local_entry = json.loads(database.get(synapse.key))
            if local_entry["counter"] > synapse.counter:
                bt.logging.debug(f"Local entry has a higher counter, skipping...")
                # Do nothing, we have a newer or current version
                synapse.updated = False
            else:
                bt.logging.debug(f"Updating index with existing data...")
                # Update the index to the latest data
                update_metadata_for_data_hash(
                    synapse.axon.hotkey, synapse.data_hash, entry, self.database
                )
                synapse.updated = True

        bt.logging.debug(f"Successfully updated index.")
        return synapse

    async def broadcast(self, hotkey, data_hash, data):
        """
        Broadcasts updates to all validators on the network for creating or updating an index value.

        Parameters:
        - hotkey: The key associated with the data to broadcast.
        - data_hash: The hash of the data to broadcast.
        - data: The metadata to be broadcast to other validators.
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

        if self.config.neuron.verbose:
            bt.logging.debug(f"Broadcasting to uids: {query_uids}")
            bt.logging.debug(f"Broadcasting to axons: {axons}")

        # Create synapse store
        synapse = protocol.Update(
            hotkey=hotkey,
            data_hash=data_hash,
            prev_seed=data["prev_seed"],
            size=data["size"],
            counter=data["counter"],
            encryption_payload=data["encryption_payload"],
        )
        bt.logging.debug(f"Update synapse sending: {synapse}")

        # Send synapse to all validator axons
        responses = await self.dendrite(
            axons,
            synapse,
            deserialize=False,
        )
        if self.config.neuron.verbose:
            bt.logging.debug(f"Responses update: {responses}")

        # TODO: Check the responses to ensure all validaors are updated

    async def store_user_data(self, synapse: protocol.StoreUser) -> protocol.StoreUser:
        """
        Stores user encrypted data in the network.

        Parameters:
        - synapse (protocol.StoreUser): The synapse object containing the encrypted data.

        Returns:
        - The result of the store_data method.
        """
        # Store user data with the user's wallet as encryption key
        success = await self.store_encrypted_data(
            encrypted_data=synapse.encrypted_data,
            encryption_payload=synapse.encryption_payload,
        )

        if success:
            synapse.data_hash = hash_data(base64.b64decode(synapse.encrypted_data))
        else:
            bt.logging.error(f"Failed to store user data")

        return synapse

    async def store_encrypted_data(
        self, encrypted_data: typing.Union[bytes, str], encryption_payload: dict
    ) -> bool:
        event = EventSchema(
            task_name="Store",
            successful=[],
            completion_times=[],
            task_status_messages=[],
            task_status_codes=[],
            block=self.subtensor.get_current_block(),
            uids=[],
            step_length=0.0,
            best_uid="",
            best_hotkey="",
            rewards=[],
            moving_averaged_scores=[],
        )

        start_time = time.time()

        encrypted_data = (
            encrypted_data.encode("utf-8")
            if isinstance(encrypted_data, str)
            else encrypted_data
        )

        bt.logging.debug(f"Storing encrypted user data {encrypted_data[:24]}...")

        # Setup CRS for this round of validation
        g, h = setup_CRS(curve=self.config.neuron.curve)

        # Hash the data
        data_hash = hash_data(encrypted_data)

        # Convert to base64 for compactness
        b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")
        bt.logging.debug(f"b64 encrypted user data {b64_encrypted_data[:24]}...")

        synapse = protocol.Store(
            encrypted_data=b64_encrypted_data,
            curve=self.config.neuron.curve,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            seed=get_random_bytes(32).hex(),  # 256-bit seed
        )

        # Select subset of miners to query (e.g. redunancy factor of N)
        uids = self.get_random_uids(k=self.config.neuron.store_redundancy)

        broadcast_params = []
        axons = [self.metagraph.axons[uid] for uid in uids]
        failed_uids = [None]

        retries = 0
        while len(failed_uids) and retries < 3:
            if failed_uids == [None]:
                # initial loop
                failed_uids = []

            # Broadcast the query to selected miners on the network.
            responses = await self.dendrite(
                axons,
                synapse,
                deserialize=False,
            )

            # Log the results for monitoring purposes.
            if self.config.neuron.verbose and self.config.neuron.log_responses:
                bt.logging.debug(f"Received responses: {responses}")

            # Compute the rewards for the responses given proc time.
            rewards: torch.FloatTensor = torch.zeros(
                len(responses), dtype=torch.float32
            ).to(self.device)

            for idx, (uid, response) in enumerate(zip(uids, responses)):
                # Verify the commitment
                success = verify_store_with_seed(response)
                if success:
                    bt.logging.debug(
                        f"Successfully verified store commitment from UID: {uid}"
                    )

                    rewards[idx] = 1.0

                    # Prepare storage for the data for particular miner
                    response_storage = {
                        "prev_seed": synapse.seed,
                        "size": sys.getsizeof(encrypted_data),
                        "counter": 0,
                        "encryption_payload": encryption_payload,
                    }
                    bt.logging.debug(f"Storing data {pformat(response_storage)}")

                    # Store in the database according to the data hash and the miner hotkey
                    add_metadata_to_hotkey(
                        response.axon.hotkey, data_hash, response_storage, self.database
                    )
                    bt.logging.debug(
                        f"Stored data in database with key: {response.axon.hotkey} | {data_hash}"
                    )

                    # Collect broadcast params to send the update to all other validators
                    broadcast_params.append((response.axon.hotkey, response_storage))

                else:
                    bt.logging.debug(
                        f"Failed to verify store commitment from UID: {uid}"
                    )
                    rewards[idx] = 0.0
                    failed_uids.append(uid)

                event.successful.append(success)
                event.uids.append(uid)
                event.completion_times.append(response.dendrite.process_time)
                event.task_status_messages.append(response.dendrite.status_message)
                event.task_status_codes.append(response.dendrite.status_code)

            event.rewards.extend(rewards.tolist())

            if self.config.neuron.verbose and self.config.neuron.log_responses:
                bt.logging.debug(f"Store responses round {retries}: {responses}")

            bt.logging.trace(f"Applying store rewards for retry # {retries}")
            self.apply_reward_scores(uids, responses, rewards)

            # Get a new set of UIDs to query for those left behind
            if failed_uids != []:
                bt.logging.debug(f"Failed to store on uids: {failed_uids}")
                uids = self.get_random_uids(k=len(failed_uids))

                bt.logging.debug(f"Retrying with new uids: {uids}")
                axons = [self.metagraph.axons[uid] for uid in uids]
                failed_uids = []  # reset failed uids for next round
                retries += 1

        # Calculate step length
        end_time = time.time()
        event.step_length = end_time - start_time

        # Determine the best UID based on rewards
        if event.rewards:
            best_index = max(range(len(event.rewards)), key=event.rewards.__getitem__)
            event.best_uid = event.uids[best_index]
            event.best_hotkey = self.metagraph.hotkeys[event.best_uid]

        # Update event log with moving averaged scores
        event.moving_averaged_scores = self.moving_averaged_scores.tolist()

        # Log event
        bt.logging.debug("event:", str(event))
        if not self.config.neuron.dont_save_events:
            # import pdb; pdb.set_trace()
            logger.log("EVENTS", "events", **event.__dict__)

        # Log the event to wandb
        if not self.config.wandb.off:
            wandb_event = EventSchema.from_dict(event)
            self.wandb.log(asdict(wandb_event))

        bt.logging.trace(f"Broadcasting update to all validators")
        for hotkey, data in broadcast_params:
            await self.broadcast(hotkey, data_hash, data)

        return any(event.successful)

    async def store_random_data(self):
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
        data = make_random_file(maxsize=self.config.neuron.maxsize)

        # Encrypt the data
        encrypted_data, encryption_payload = encrypt_data(data, self.wallet)

        return await self.store_encrypted_data(encrypted_data, encryption_payload)

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
            chunk_size = (
                self.config.neuron.override_chunk_size
                if self.config.neuron.override_chunk_size > 0
                else get_random_chunksize(
                    minsize=self.config.neuron.min_chunk_size,
                    maxsize=max(
                        self.config.neuron.min_chunk_size,
                        data["size"] // self.config.neuron.chunk_factor,
                    ),
                )
            )
        except:
            bt.logging.error(
                f"Failed to get chunk size {self.config.neuron.min_chunk_size} | {self.config.neuron.chunk_factor} | {data['size'] // self.config.neuron.chunk_factor}"
            )
            chunk_size = 0

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

    async def retrieve_user_data(
        self, synapse: protocol.RetrieveUser
    ) -> protocol.RetrieveUser:
        bt.logging.debug(f"inside retrieve_user_data")

        # Return the data to the client so that they can decrypt with their bittensor wallet
        encrypted_data, encryption_payload = await self.retrieve(synapse.data_hash)
        bt.logging.debug(f"recieved encrypted_Data {encrypted_data}")
        # Return the first element, whoever is fastest wins
        synapse.encrypted_data = encrypted_data
        synapse.encryption_payload = encryption_payload
        return synapse

    async def retrieve(
        self, data_hash: str = None
    ) -> typing.Tuple[bytes, typing.Callable]:
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
                    f"Hash of recieved data does not match expected hash! {str(hash_data(decoded_data))} != {data_hash}"
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
                bt.logging.trace(f"Fetching AES payload from UID: {uids[idx]}")

                # Load the data for this miner from validator storage
                data = get_metadata_from_hash(hotkey, data_hash, self.database)

                # If we reach here, this miner has passed verification. Update the validator storage.
                data["prev_seed"] = synapse.seed
                data["counter"] += 1
                update_metadata_for_data_hash(hotkey, data_hash, data, self.database)

                # TODO: get a temp link from the server to send back to the client instead
                return response.data, data["encryption_payload"]

            except Exception as e:
                bt.logging.error(
                    f"Failed to return data from UID: {uids[idx]} with error: {e}"
                )

        bt.logging.trace("Applying retrieve rewards")
        self.apply_reward_scores(uids, responses, rewards)

    async def forward(self) -> torch.Tensor:
        self.step += 1
        bt.logging.info(f"forward step: {self.step}")

        # try:
        # Store some data
        bt.logging.info("initiating store data")
        await self.store_random_data()
        # except Exception as e:
        #     bt.logging.error(f"Failed to store data with exception: {e}")

        # try:
        #     # Challenge some data
        #     bt.logging.info("initiating challenge")
        #     await self.challenge()
        # except Exception as e:
        #     bt.logging.error(f"Failed to challenge data with exception: {e}")

        # if self.step % self.config.neuron.retrieve_epoch_steps == 0:
        #     try:
        #         # Retrieve some data
        #         bt.logging.info("initiating retrieve")
        #         await self.retrieve()
        #     except Exception as e:
        #         bt.logging.error(f"Failed to retrieve data with exception: {e}")

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
