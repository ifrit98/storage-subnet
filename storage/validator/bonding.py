import asyncio
import bittensor as bt

# Constants for storage limits in bytes
STORAGE_LIMIT_DIAMOND = 100000 * 10**9  # 100000 GB
STORAGE_LIMIT_GOLD = 10000 * 10**9  # 10000 GB
STORAGE_LIMIT_SILVER = 1000 * 10**9  # 1000 GB
STORAGE_LIMIT_BRONZE = 100 * 10**9  # 100 GB

DIAMOND_STORE_SUCCESS_RATE = 0.995  # 1/200 chance of failure
DIAMOND_RETRIEVAL_SUCCESS_RATE = 0.9999  # 1/100000 chance of failure
DIAMOND_CHALLENGE_SUCCESS_RATE = 0.999  # 1/1000 chance of failure

GOLD_STORE_SUCCESS_RATE = 0.99  # 1/100 chance of failure
GOLD_RETRIEVAL_SUCCESS_RATE = 0.999  # 1/1000 chance of failure
GOLD_CHALLENGE_SUCCESS_RATE = 0.99  # 1/100 chance of failure

SILVER_STORE_SUCCESS_RATE = 0.98  # 1/50 chance of failure
SILVER_RETRIEVAL_SUCCESS_RATE = 0.999  # 1/1000 chance of failure
SILVER_CHALLENGE_SUCCESS_RATE = 0.999  # 1/1000 chance of failure

DIAMOND_TIER_REWARD_FACTOR = 1.0  # Get 100% of rewards
GOLD_TIER_REWARD_FACTOR = 0.888  # Get 88.8% of rewards
SILVER_TIER_REWARD_FACTOR = 0.555  # Get 55.5% of rewards
BRONZE_TIER_REWARD_FACTOR = 0.222  # Get 22.2% of rewards

DIAMOND_TIER_TOTAL_SUCCESSES = 10**7  # 10 million
GOLD_TIER_TOTAL_SUCCESSES = 10**6  # 1 million
SILVER_TIER_TOTAL_SUCCESSES = 10**5  # 100,000


def miner_is_registered(ss58_address, database):
    """
    Checks if a miner is registered in the database.

    Parameters:
        ss58_address (str): The key representing the hotkey.
        database (redis.Redis): The Redis client instance.

    Returns:
        True if the miner is registered, False otherwise.
    """
    return database.exists(f"stats:{ss58_address}")


def register_miner(ss58_address, database):
    # Initialize statistics for a new miner in a separate hash
    database.hmset(
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


def update_statistics(ss58_address, success, task_type, database):
    # Check and see if this miner is registered.
    if not miner_is_registered(ss58_address, database):
        register_miner(ss58_address, database)

    # Update statistics in the stats hash
    stats_key = f"stats:{ss58_address}"
    database.hincrby(stats_key, "store_attempts", 1)

    if task_type == "store":
        database.hincrby(stats_key, "store_attempts", 1)
        if success:
            database.hincrby(stats_key, "store_successes", 1)
    elif task_type == "challenge":
        database.hincrby(stats_key, "challenge_attempts", 1)
        if success:
            database.hincrby(stats_key, "challenge_successes", 1)
    elif task_type == "retrieve":
        database.hincrby(stats_key, "retrieval_attempts", 1)
        if success:
            database.hincrby(stats_key, "retrieval_successes", 1)
    else:
        bt.logging.error(f"Invalid task type {task_type}.")


async def compute_tier(stats_key, database):
    data = database.hgetall(stats_key)

    registered = miner_is_registered(stats_key, database)
    if not data:
        bt.logging.warning(f"No statistics data found for {stats_key}! Skipping...")
        return

    # Get the number of successful challenges
    challenge_successes = int(database.hget(stats_key, "challenge_successes"))
    # Get the number of successful retrievals
    retrieval_successes = int(database.hget(stats_key, "retrieval_successes"))
    # Get the number of successful stores
    store_successes = int(database.hget(stats_key, "store_successes"))
    # Get the number of total challenges
    challenge_attempts = int(database.hget(stats_key, "challenge_attempts"))
    # Get the number of total retrievals
    retrieval_attempts = int(database.hget(stats_key, "retrieval_attempts"))
    # Get the number of total stores
    store_attempts = int(database.hget(stats_key, "store_attempts"))

    # Compute the success rate for each task type
    challenge_success_rate = (
        challenge_successes / challenge_attempts if challenge_attempts > 0 else 0
    )
    retrieval_success_rate = (
        retrieval_successes / retrieval_attempts if retrieval_attempts > 0 else 0
    )
    store_success_rate = store_successes / store_attempts
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
    current_tier = database.hget(stats_key, "tier")
    if tier != current_tier:
        database.hset(stats_key, "tier", tier)
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

        current_limit = database.hget(stats_key, "storage_limit")
        database.hset(stats_key, "storage_limit", storage_limit)
        bt.logging.trace(
            f"Storage limit for {stats_key} set from {current_limit} -> {storage_limit} bytes."
        )


async def compute_all_tiers(database):
    # Iterate over all miners
    """
    Computes the tier for all miners in the database.

    This function should be called periodically to update the tier for all miners.
    """
    miners = [miner for miner in database.scan_iter("stats:*")]
    tasks = [compute_tier(miner, database) for miner in miners]
    await asyncio.gather(*tasks)


def get_tier_factor(ss58_address, database):
    tier = database.hget(f"stats:{ss58_address}", "tier")
    if tier == b"Diamond":
        return DIAMOND_TIER_REWARD_FACTOR
    elif tier == b"Gold":
        return GOLD_TIER_REWARD_FACTOR
    elif tier == b"Silver":
        return SILVER_TIER_REWARD_FACTOR
    else:
        return BRONZE_TIER_REWARD_FACTOR
