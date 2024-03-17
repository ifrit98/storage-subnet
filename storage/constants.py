# Failure mode negative rewards
STORE_FAILURE_REWARD = 0
CHALLENGE_FAILURE_REWARD = 0
MONITOR_FAILURE_REWARD = -0.005  # Incentivize uptime
RETRIEVAL_FAILURE_REWARD = -0.01 # Incentivize keeping all data

# Constants for storage limits in bytes
STORAGE_LIMIT_SUPER_SAIYAN = 1024**6 * 1  # 1 EB
STORAGE_LIMIT_DIAMOND = 1024**5 * 1       # 1 PB
STORAGE_LIMIT_GOLD = 1024**4 * 100        # 100 TB
STORAGE_LIMIT_SILVER = 1024**4 * 10       # 10 TB
STORAGE_LIMIT_BRONZE = 1024**4 * 1        # 1 TB

SUPER_SAIYAN_TIER_REWARD_FACTOR = 1.0
DIAMOND_TIER_REWARD_FACTOR = 0.9
GOLD_TIER_REWARD_FACTOR = 0.8
SILVER_TIER_REWARD_FACTOR = 0.7
BRONZE_TIER_REWARD_FACTOR = 0.6

SUPER_SAIYAN_TIER_TOTAL_SUCCESSES = 10**4  # 10,000 (estimated 30 epochs to reach this tier)
DIAMOND_TIER_TOTAL_SUCCESSES = 10**3 * 5   # 5,000  (estimated 15 epochs to reach this tier)
GOLD_TIER_TOTAL_SUCCESSES = 10**3 * 2      # 2,000  (estimated 6  epochs to reach this tier)
SILVER_TIER_TOTAL_SUCCESSES = 10**3        # 1,000  (estimated 3  epochs to reach this tier)

SUPER_SAIYAN_WILSON_SCORE = 0.88
DIAMOND_WILSON_SCORE = 0.77
GOLD_WILSON_SCORE = 0.66
SILVER_WILSON_SCORE = 0.55

TIER_BOOSTS = {
    b"Super Saiyan": 1.02, # 2%  -> 1.02
    b"Diamond": 1.05,      # 5%  -> 0.945
    b"Gold": 1.1,          # 10% -> 0.88
    b"Silver": 1.15,       # 15% -> 0.805
    b"Bronze": 1.2,        # 20% -> 0.72
}
