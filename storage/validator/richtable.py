from rich.console import Console
from rich.table import Table
from storage.validator.database import get_miner_statistics
import aioredis

r = aioredis.StrictRedis(db=1)

# # Your data
# data = {
#     "5DLfJeVN79Sxp8GjvFnzv8HryF9dXFdLMfq7USSuHFhQFMCv": {
#         "store_attempts": "211",
#         "store_successes": "209",
#         "challenge_successes": "574",
#         "challenge_attempts": "577",
#         "retrieval_successes": "0",
#         "retrieval_attempts": "13",
#         "tier": "Bronze",
#         "storage_limit": "1099511627776",
#     },
#     "5DFFd2Hv8K87k2fgUH79mq2zjosFYAvAeW5CtKL9AWedFUA9": {
#         "store_attempts": "81",
#         "store_successes": "66",
#         "challenge_successes": "409",
#         "challenge_attempts": "410",
#         "retrieval_successes": "0",
#         "retrieval_attempts": "12",
#         "tier": "Bronze",
#         "storage_limit": "1099511627776",
#     },
#     "5FPN3f3EP6zsBemJsMhL3zhTLqjoQnCBXfzro1uqKP4K7Lcy": {
#         "store_attempts": "70",
#         "store_successes": "0",
#         "challenge_successes": "0",
#         "challenge_attempts": "0",
#         "retrieval_successes": "0",
#         "retrieval_attempts": "0",
#         "tier": "Bronze",
#         "storage_limit": "1099511627776",
#     },
# }

data = await get_miner_statistics(r)

console = Console()

# Create a table
table = Table(show_header=True, header_style="bold magenta")
table.add_column("Hotkey", style="dim")
table.add_column("Store Attempts")
table.add_column("Store Successes")
table.add_column("Challenge Successes")
table.add_column("Challenge Attempts")
table.add_column("Retrieval Successes")
table.add_column("Retrieval Attempts")
table.add_column("Tier")
table.add_column("Storage Limit (TB)")

# Add rows to the table
for hotkey, stats in data.items():
    table.add_row(
        hotkey,
        stats["store_attempts"],
        stats["store_successes"],
        stats["challenge_successes"],
        stats["challenge_attempts"],
        stats["retrieval_successes"],
        stats["retrieval_attempts"],
        stats["tier"],
        str(int(stats["storage_limit"]) // (1024**4)),
    )

# Print the table to the console
console.print(table)
