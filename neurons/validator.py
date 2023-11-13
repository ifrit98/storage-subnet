import os
import sys
import copy
import time
import redis
import torch
import base64
import typing
import asyncio
import argparse
import traceback
import bittensor as bt
from traceback import print_exception
from random import choice as random_choice
from Crypto.Random import get_random_bytes

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


class neuron:
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
            axon = bt.axon(wallet=self.wallet, config=self.config)

            axon.attach(
                forward_fn=self.update_index,
            )

            try:
                self.subtensor.serve_axon(
                    netuid=self.config.netuid,
                    axon=axon,
                )
            except Exception as e:
                bt.logging.error(f"Failed to serve Axon with exception: {e}")
                pass

            del axon
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

        self.prev_block = ttl_get_block(self)
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
        # Scale reward by the ranking of the response time
        # If the response time is faster, the reward is higher
        # This should reflect the distribution of axon response times (minmax norm)
        scaled_rewards = scale_rewards_by_response_time(uids, responses, rewards)

        # Compute forward pass rewards, assumes followup_uids and answer_uids are mutually exclusive.
        # shape: [ metagraph.n ]
        scattered_rewards: torch.FloatTensor = self.moving_averaged_scores.scatter(
            0, uids, scaled_rewards
        ).to(self.device)

        # Update moving_averaged_scores with rewards produced by this step.
        # shape: [ metagraph.n ]
        alpha: float = self.config.neuron.moving_average_alpha
        self.moving_averaged_scores: torch.FloatTensor = alpha * scattered_rewards + (
            1 - alpha
        ) * self.moving_averaged_scores.to(self.device)

    def update_index(self, synapse: protocol.Update):
        """Update the validator index with the new data"""
        data = self.database.get(synapse.key)
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
            self.database.set(synapse.key, json.dumps(entry).encode())
        else:
            # Check for conflicts
            local_entry = json.loads(database.get(synapse.key))
            if local_entry["counter"] > synapse.counter:
                # Do nothing, we have a newer or current version
                return
            else:
                # Update the index to the latest data
                self.database.set(synapse.key, json.dumps(entry).encode())

    async def broadcast(self, lookup_key, data):
        """Send updates to all validators on the network when creating or updating in index value"""

        # Determine axons to query from metagraph
        vpermits = self.metagraph.validator_permit
        vpermit_uids = [uid for uid, permit in enumerate(vpermits) if permit]
        vpermit_uids = torch.where(vpermits)[0]

        # Exclude your own uid
        vpermit_uids = vpermit_uids[vpermit_uids != axon.hotkey.ss58_address]
        query_uids = torch.where(
            self.metagraph.S[vpermit_uids]
            > self.config.neuron.broadcast_stake_threshold
        )[0]
        axons = [self.metagraph.axons[uid] for uid in query_uids]

        # Create synapse store
        synapse = protocol.Update(
            lookup_key=lookup_key,
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
        # Store user data with the user's wallet as encryption key
        return store_data(data=data, wallet=wallet)

    async def store_validator_data(self, data: bytes):
        # Store random data using the validator's pubkey as the encryption key
        return store_data(wallet=self.wallet)

    async def store_data(self, data: bytes = None, wallet: bt.wallet = None):
        # Setup CRS for this round of validation
        g, h = setup_CRS(curve=self.config.curve)

        # Make a random bytes file to test the miner if none provided
        data = data or make_random_file(maxsize=self.config.maxsize)

        # Encrypt the data
        encrypted_data, encryption_payload = encrypt_data(data, wallet)

        # Convert to base64 for compactness
        b64_encrypted_data = base64.b64encode(encrypted_data).decode("utf-8")

        synapse = protocol.Store(
            encrypted_data=b64_encrypted_data,
            curve=curve,
            g=ecc_point_to_hex(g),
            h=ecc_point_to_hex(h),
            seed=get_random_bytes(32).hex(),  # 256-bit seed
        )

        # Select subset of miners to query (e.g. redunancy factor of N)
        uids = select_subset_uids(metagraph.uids, N=self.config.redundancy)
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
            bt.logging.info(f"Received responses: {responses}")

            # Compute the rewards for the responses given proc time.
            rewards: torch.FloatTensor = torch.zeros(
                len(responses), dtype=torch.float32
            ).to(self.device)

            for idx, (uid, response) in enumerate(zip(uids, responses)):
                # Verify the commitment
                if not verify_challenge_with_seed(response):
                    # TODO: flag this miner for 0 weight (or negative rewards?)
                    rewards[idx] = 0.0
                    retry_uids.append(uid)
                    continue  # Skip trying to store the data
                else:
                    rewards[idx] = 1.0

                data_hash = hash_data(encrypted_data)

                key = f"{data_hash}.{response.axon.hotkey}"
                response_storage = {
                    "prev_seed": synapse.seed,
                    "size": sys.getsizeof(encrypted_data),
                    "counter": 0,
                    "encryption_payload": encryption_payload,
                }
                bt.logging.debug(f"Storing data {response_storage}")
                dumped_data = json.dumps(response_storage).encode()

                # Store in the database according to the data hash and the miner hotkey
                database.set(key, dumped_data)
                bt.logging.debug(f"Stored data in database with key: {key}")

                # Broadcast the update to all other validators
                # TODO: ensure this will not block
                # TODO: potentially batch update after all miners have responded?
                broadcast(key, dumped_data)

            self.apply_reward_scores(uids, responses, rewards)

            # Get a new set of UIDs to query for those left behind
            if retry_uids != []:
                uids = select_subset_uids(metagraph.uids, N=len(retry_uids))
                bt.logging.debug(f"Retrying with new uids: {uids}")
                axons = [metagraph.axons[uid] for uid in uids]
                retry_uids = []  # reset retry uids
                retries += 1

    async def handle_challenge(
        self, hotkey: str
    ) -> typing.Tuple[bool, protocol.Challenge]:
        keys = safe_key_search(self.database, f"*.{hotkey}")
        key = random.choice(keys)
        data_hash = key.split(".")[0]

        data = json.loads(self.database.get(key).decode("utf-8"))
        chunk_size = (
            get_random_chunksize(data["size"]) // self.config.neuron.chunk_factor
        )
        num_chunks = data["size"] // chunk_size
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

        verified = verify_challenge_with_seed(response)

        data["prev_seed"] = synapse.seed
        data["counter"] += 1
        self.database.set(key, json.dumps(data).encode())

        return verified, response

    async def challenge(self):
        # Asynchronously challenge and see who returns the data
        # fastest (passes verification), and rank them highest
        # We create each challenge as a coroutine and then
        # await the results of each challenge asynchronously
        tasks = []
        uids = self.get_random_uids(k=self.config.neuron.challenge_k)
        for uid in uids:
            tasks.append(
                asyncio.create_task(self.handle_challenge(self.metagraph.hotkeys[uid]))
            )
        responses = await asyncio.gather(*tasks)

        # Compute the rewards for the responses given the prompt.
        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        # Set 0 weight if unverified
        for uid, (verified, response) in zip(uids, responses):
            if verified:
                rewards[uid] = 1.0
            else:
                rewards[uid] = 0.0

        self.apply_reward_scores(uids, responses, rewards)

    async def retrieve(self, data_hash):
        # fetch which miners have the data
        keys = safe_key_search(self.database, f"{data_hash}.*")

        uids = []
        axons_to_query = []
        for key in keys:
            hotkey = key.split(".")[1]
            uid = metagraph.hotkeys.index(hotkey)
            axons_to_query.append(metagraph.axons[uid])
            uids.append(uid)
            bt.logging.debug(f"appending hotkey: {hotkey}")

        uid_axon_map = {uid: axon for uid, axon in zip(uids, axons_to_query)}

        # query all N (from redundancy factor) with M challenges (x% of the total data)
        # see who returns the data fastest (passes verification), and rank them highest
        responses = await dendrite(
            axons_to_query,
            protocol.Retrieve(
                data_hash=data_hash,
                seed=get_random_bytes(32).hex(),
            ),
            deserialize=True,
        )

        rewards: torch.FloatTensor = torch.zeros(
            len(responses), dtype=torch.float32
        ).to(self.device)

        datas = []
        for idx, response in enumerate(responses):
            bt.logging.debug(f"response: {response}")
            decoded_data = base64.b64decode(respnonse.data)
            if hash_data(decoded_data) != data_hash:
                bt.logging.error(f"Hash of received data does not match expected hash!")
                continue

            if not verify_retrieve_with_seed(response):
                bt.logging.error(f"data verification failed! {response}")
                rewards[idx] = -1.0  # Losing use data is unacceptable, harsh punishment
                continue  # skip trying to decode the data
            else:
                rewards[idx] = 1.0

            try:
                bt.logging.debug(f"Decrypting from UID: {uids[idx]}")
                # Decrypt the data using the validator stored encryption keys
                decrypted_data = decrypt_data(decoded_data, data["encryption_payload"])
                datas.append(decrypted_data)
            except Exception as e:
                bt.logging.error(f"Failed to decrypt data from UID: {uids[idx]} {e}")

            # TODO: get a temp link from the server to send back to the client

        self.apply_reward_scores(uids, responses, rewards)

        return datas[
            0
        ]  # Return only first element of data, incase only 1 response is valid

    async def forward(self) -> torch.Tensor:
        self.step += 1
        bt.logging.info(f"forward() {self.step}")

    def run(self):
        bt.logging.info("run()")
        load_state(self)
        checkpoint(self)
        try:
            while True:
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
                if should_checkpoint(self):
                    checkpoint(self)

                # Set the weights on chain.
                if should_set_weights(self):
                    set_weights(self)
                    save_state(self)

                # Rollover wandb to a new run.
                if should_reinit_wandb(self):
                    reinit_wandb(self)

                self.prev_block = ttl_get_block(self)
                self.step += 1
        except Exception as err:
            bt.logging.error("Error in training loop", str(err))
            bt.logging.debug(print_exception(type(err), err, err.__traceback__))


def main():
    neuron().run()


if __name__ == "__main__":
    main()
