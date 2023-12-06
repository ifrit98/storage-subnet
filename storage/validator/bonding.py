import asyncio
import aioredis
import bittensor as bt

# Constants for storage limits in bytes
STORAGE_LIMIT_DIAMOND = 1024**5 * 1  # 1 PB
STORAGE_LIMIT_GOLD = 1024**4 * 100  # 100 TB
STORAGE_LIMIT_SILVER = 1024**4 * 10  # 10 TB
STORAGE_LIMIT_BRONZE = 1024**4 * 1  # 1 TB

# Requirements for each tier. These must be maintained for a miner to remain in that tier.
DIAMOND_STORE_SUCCESS_RATE = 0.995  # 1/200 chance of failure
DIAMOND_RETRIEVAL_SUCCESS_RATE = 0.995  # 1/200 chance of failure
DIAMOND_CHALLENGE_SUCCESS_RATE = 0.995  # 1/200 chance of failure

GOLD_STORE_SUCCESS_RATE = 0.99  # 1/100 chance of failure
GOLD_RETRIEVAL_SUCCESS_RATE = 0.99  # 1/100 chance of failure
GOLD_CHALLENGE_SUCCESS_RATE = 0.99  # 1/100 chance of failure

SILVER_STORE_SUCCESS_RATE = 0.975  # 1/50 chance of failure
SILVER_RETRIEVAL_SUCCESS_RATE = 0.975  # 1/50 chance of failure
SILVER_CHALLENGE_SUCCESS_RATE = 0.975  # 1/50 chance of failure

DIAMOND_TIER_REWARD_FACTOR = 1.0  # Get 100% of rewards
GOLD_TIER_REWARD_FACTOR = 0.888  # Get 88.8% of rewards
SILVER_TIER_REWARD_FACTOR = 0.555  # Get 55.5% of rewards
BRONZE_TIER_REWARD_FACTOR = 0.333  # Get 33.3% of rewards

DIAMOND_TIER_TOTAL_SUCCESSES = 10**5  # 100,000
GOLD_TIER_TOTAL_SUCCESSES = 10**4  # 10,000
SILVER_TIER_TOTAL_SUCCESSES = 10**3  # 1,000


async def miner_is_registered(ss58_address: str, database: aioredis.Redis):
    """
    Checks if a miner is registered in the database.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        True if the miner is registered, False otherwise.
    """
    return await database.exists(f"stats:{ss58_address}")


async def register_miner(ss58_address: str, database: aioredis.Redis):
    """
    Registers a new miner in the decentralized storage system, initializing their statistics.
    This function creates a new entry in the database for a miner with default values,
    setting them initially to the Bronze tier and assigning the corresponding storage limit.
    Args:
        ss58_address (str): The unique address (hotkey) of the miner to be registered.
        database (redis.Redis): The Redis client instance for database operations.
    """
    # Initialize statistics for a new miner in a separate hash
    await database.hmset(
        f"stats:{ss58_address}",
        {
            "store_attempts": 0,
            "store_successes": 0,
            "challenge_successes": 0,
            "challenge_attempts": 0,
            "retrieval_successes": 0,
            "retrieval_attempts": 0,
            "tier": "Bronze",  # Init to bronze status
            "storage_limit": STORAGE_LIMIT_BRONZE,  # in GB
        },
    )


async def update_statistics(
    ss58_address: str, success: bool, task_type: str, database: aioredis.Redis
):
    """
    Updates the statistics of a miner in the decentralized storage system.
    If the miner is not already registered, they are registered first. This function updates
    the miner's statistics based on the task performed (store, challenge, retrieve) and whether
    it was successful.
    Args:
        ss58_address (str): The unique address (hotkey) of the miner.
        success (bool): Indicates whether the task was successful or not.
        task_type (str): The type of task performed ('store', 'challenge', 'retrieve').
        database (redis.Redis): The Redis client instance for database operations.
    """
    # Check and see if this miner is registered.
    if not await miner_is_registered(ss58_address, database):
        await register_miner(ss58_address, database)

    # Update statistics in the stats hash
    stats_key = f"stats:{ss58_address}"

    if task_type == "store":
        await database.hincrby(stats_key, "store_attempts", 1)
        if success:
            await database.hincrby(stats_key, "store_successes", 1)
    elif task_type == "challenge":
        await database.hincrby(stats_key, "challenge_attempts", 1)
        if success:
            await database.hincrby(stats_key, "challenge_successes", 1)
    elif task_type == "retrieve":
        await database.hincrby(stats_key, "retrieval_attempts", 1)
        if success:
            await database.hincrby(stats_key, "retrieval_successes", 1)
    else:
        bt.logging.error(f"Invalid task type {task_type}.")


async def compute_tier(stats_key: str, database: aioredis.Redis):
    """
    Asynchronously computes the tier of a miner based on their performance statistics.
    The function calculates the success rate for each type of task and total successes,
    then updates the miner's tier if necessary. This could potentially change their storage limit.
    Args:
        stats_key (str): The key in the database where the miner's statistics are stored.
        database (redis.Redis): The Redis client instance for database operations.
    """
    data = await database.hgetall(stats_key)

    registered = await miner_is_registered(stats_key, database)
    if not data:
        bt.logging.warning(f"No statistics data found for {stats_key}! Skipping...")
        return

    # Get the number of successful challenges
    challenge_successes = int(await database.hget(stats_key, "challenge_successes"))
    # Get the number of successful retrievals
    retrieval_successes = int(await database.hget(stats_key, "retrieval_successes"))
    # Get the number of successful stores
    store_successes = int(await database.hget(stats_key, "store_successes"))
    # Get the number of total challenges
    challenge_attempts = int(await database.hget(stats_key, "challenge_attempts"))
    # Get the number of total retrievals
    retrieval_attempts = int(await database.hget(stats_key, "retrieval_attempts"))
    # Get the number of total stores
    store_attempts = int(await database.hget(stats_key, "store_attempts"))

    # Compute the success rate for each task type
    challenge_success_rate = (
        challenge_successes / challenge_attempts if challenge_attempts > 0 else 0
    )
    retrieval_success_rate = (
        retrieval_successes / retrieval_attempts if retrieval_attempts > 0 else 0
    )
    store_success_rate = store_successes / store_attempts if store_attempts > 0 else 0
    total_successes = challenge_successes + retrieval_successes + store_successes

    if (
        challenge_success_rate >= DIAMOND_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= DIAMOND_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= DIAMOND_STORE_SUCCESS_RATE
        and total_successes >= DIAMOND_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Diamond"
    elif (
        challenge_success_rate >= GOLD_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= GOLD_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= GOLD_STORE_SUCCESS_RATE
        and total_successes >= GOLD_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Gold"
    elif (
        challenge_success_rate >= SILVER_CHALLENGE_SUCCESS_RATE
        and retrieval_success_rate >= SILVER_RETRIEVAL_SUCCESS_RATE
        and store_success_rate >= SILVER_STORE_SUCCESS_RATE
        and total_successes >= SILVER_TIER_TOTAL_SUCCESSES
    ):
        tier = b"Silver"
    else:
        tier = b"Bronze"

    # (Potentially) set the new tier in the stats hash
    current_tier = await database.hget(stats_key, "tier")
    if tier != current_tier:
        await database.hset(stats_key, "tier", tier)
        bt.logging.trace(f"Updated tier for {stats_key} from {current_tier} to {tier}.")

        # Update the storage limit
        if tier == b"Diamond":
            storage_limit = STORAGE_LIMIT_DIAMOND
        elif tier == b"Gold":
            storage_limit = STORAGE_LIMIT_GOLD
        elif tier == b"Silver":
            storage_limit = STORAGE_LIMIT_SILVER
        else:
            storage_limit = STORAGE_LIMIT_BRONZE

        current_limit = await database.hget(stats_key, "storage_limit")
        await database.hset(stats_key, "storage_limit", storage_limit)
        bt.logging.trace(
            f"Storage limit for {stats_key} set from {current_limit} -> {storage_limit} bytes."
        )


async def compute_all_tiers(database: aioredis.Redis):
    # Iterate over all miners
    """
    Asynchronously computes and updates the tiers for all miners in the decentralized storage system.
    This function should be called periodically to ensure miners' tiers are up-to-date based on
    their performance. It iterates over all miners and calls `compute_tier` for each one.
    Args:
        database (redis.Redis): The Redis client instance for database operations.
    """
    miners = [miner async for miner in database.scan_iter("stats:*")]
    tasks = [compute_tier(miner, database) for miner in miners]
    await asyncio.gather(*tasks)


async def get_tier_factor(ss58_address: str, database: aioredis.Redis):
    """
    Retrieves the reward factor based on the tier of a given miner.
    This function returns a factor that represents the proportion of rewards a miner
    is eligible to receive based on their tier.
    Args:
        ss58_address (str): The unique address (hotkey) of the miner.
        database (redis.Redis): The Redis client instance for database operations.
    Returns:
        float: The reward factor corresponding to the miner's tier.
    """
    tier = await database.hget(f"stats:{ss58_address}", "tier")
    if tier == b"Diamond":
        return DIAMOND_TIER_REWARD_FACTOR
    elif tier == b"Gold":
        return GOLD_TIER_REWARD_FACTOR
    elif tier == b"Silver":
        return SILVER_TIER_REWARD_FACTOR
    else:
        return BRONZE_TIER_REWARD_FACTOR
