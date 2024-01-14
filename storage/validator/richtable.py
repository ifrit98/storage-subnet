from rich.console import Console
from rich.table import Table
from storage.validator.database import get_miner_statistics, get_single_miner_statistics
import aioredis

r = aioredis.StrictRedis(db=7)


async def show_single_miner_statistics(ss58_address: str, r: aioredis.Redis):

    # ss58_address = "5CDTTsvLNyrKX9W9DF2CsvR7jpXaue8SUSntPcem1Psq9eb9"
    stats = await get_single_miner_statistics(ss58_address, r)

    console = Console()

    # Create a table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Hotkey", style="dim")
    table.add_column("Total Successes")
    table.add_column("Store Attempts")
    table.add_column("Store Successes")
    table.add_column("Challenge Successes")
    table.add_column("Challenge Attempts")
    table.add_column("Retrieval Successes")
    table.add_column("Retrieval Attempts")
    table.add_column("Tier")
    table.add_column("Storage Limit (TB)")

    # Add rows to the table
    table.add_row(
        hotkey,
        stats["total_successes"],
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


await show_single_miner_statistics("5CaFuijc2ucdoWhkjLaYgnzYrpv62KGt1fWWtUxhFHXPA3KK", r)