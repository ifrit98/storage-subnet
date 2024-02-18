import bittensor as bt
from storage import StoreUserAPI, RetrieveUserAPI, get_query_api_axons
bt.debug()

# Example usage
async def test_storage():

    wallet = bt.wallet()

    store_handler = StoreUserAPI(wallet)

    # Fetch the axons of the available API nodes, or specify UIDs directly
    metagraph = bt.subtensor("test").metagraph(netuid=22)
    axons = await get_query_api_axons(wallet=wallet, metagraph=metagraph, uids=[5, 7])

    # Store some data!
    raw_data = b"Hello FileTao!"

    bt.logging.info(f"Storing data {raw_data} on the Bittensor testnet.")
    cid = await store_handler(
        axons=axons,
        # any arguments for the proper synapse
        data=raw_data,
        encrypt=False, # optionally encrypt the data with your bittensor wallet
        ttl=60 * 60 * 24 * 30,
        encoding="utf-8",
        uid=None,
        timeout=60,
    )
    print(cid)

    bt.logging.info(f"Now retrieving data with CID: {cid}")
    retrieve_handler = RetrieveUserAPI(wallet)
    retrieve_response = await retrieve_handler(
        axons=axons,
        # Arugmnts for the proper synapse
        cid=cid, 
        timeout=60
    )
    print(retrieve_response)


if __name__ == "__main__":
    import asyncio
    asyncio.run(test_storage())
