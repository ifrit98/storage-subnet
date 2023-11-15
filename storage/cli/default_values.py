from munch import munchify, Munch

# Default config for bittensor cli.
defaults: Munch = munchify(
    {
        "hash_basepath": "~/.bittensor/hashes",
        "storage_basepath": "~/.bittensor/storage",
        "netuid": "22",
        "subtensor": {"network": "finney", "chain_endpoint": None, "_mock": False},
        "wallet": {
            "name": "default",
            "hotkey": "default",
            "path": "~/.bittensor/wallets/",
        },
    }
)
