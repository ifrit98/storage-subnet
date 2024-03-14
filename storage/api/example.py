import time
import random
import bittensor as bt
from storage.api import store, retrieve
from storage.api import StoreUserAPI, RetrieveUserAPI, get_query_api_axons
bt.trace()

# Example usage
async def test_storage_abstraction():
    # setup wallet and subtensor connection
    wallet = bt.wallet()
    subtensor = bt.subtensor("test")

    # Store some data and retrieve it
    data = b"This is a test of the API high level abstraction"
    print("Storing data on the Bittensor testnet.")
    cid, hotkeys = await store(data, wallet, subtensor, netuid=22)
    print("Stored {} with {} hotkeys".format(cid, hotkeys))

    time.sleep(5)
    print("Now retrieving data with CID: ", cid)
    rdata = await retrieve(cid, wallet, subtensor, netuid=22, hotkeys=hotkeys)
    print(rdata)
    assert data == rdata


# Example usage
async def test_storage_primitives():

    wallet = bt.wallet()

    store_handler = StoreUserAPI(wallet)

    # Fetch the axons of the available API nodes, or specify UIDs directly
    metagraph = bt.subtensor("test").metagraph(netuid=22)
    all_axons = await get_query_api_axons(wallet=wallet, metagraph=metagraph)
    axons = random.choices(all_axons, k=3)

    # Store some data!
    raw_data = b"Hello FileTao!"

    bt.logging.info(f"Storing data {raw_data} on the Bittensor testnet.")
    cid, hotkeys = await store_handler(
        axons=axons,
        # any arguments for the proper synapse
        data=raw_data,
        encrypt=False, # optionally encrypt the data with your bittensor wallet
        ttl=60 * 60 * 24 * 30,
        encoding="utf-8",
        uid=None,
        timeout=60,
    )
    print("Stored {} with {} hotkeys".format(cid, hotkeys))

    time.sleep(5)
    bt.logging.info(f"Now retrieving data with CID: {cid}")
    retrieve_handler = RetrieveUserAPI(wallet)
    rdata = await retrieve_handler(
        axons=axons,
        # Arugmnts for the proper synapse
        cid=cid,
        timeout=60,
    )
    print(rdata)
    assert raw_data == rdata


if __name__ == "__main__":
    import asyncio
    print("Starting test of high level storage abstraction")
    asyncio.run(test_storage_abstraction())
    print("Starting test of storage primitives")
    asyncio.run(test_storage_primitives())