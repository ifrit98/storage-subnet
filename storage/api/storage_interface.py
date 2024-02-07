import torch
import base64
import random
import asyncio
import bittensor
import bittensor as bt

from storage.validator.cid import generate_cid_string
from storage.validator.encryption import encrypt_data, decrypt_data_with_private_key
from storage.protocol import StoreUser, RetrieveUser


async def ping_uids(dendrite, metagraph, uids, timeout=3):
    """
    Pings a list of UIDs to check their availability on the Bittensor network.

    Args:
        dendrite (bittensor.dendrite): The dendrite instance to use for pinging.
        metagraph (bittensor.metagraph): The metagraph instance containing network information.
        uids (list): A list of UIDs (unique identifiers) to ping.
        timeout (int, optional): The timeout in seconds for each ping. Defaults to 3.

    Returns:
        tuple: A tuple containing two lists:
            - The first list contains UIDs that were successfully pinged.
            - The second list contains UIDs that failed to respond.
    """
    axons = [metagraph.axons[uid] for uid in uids]
    try:
        responses = await dendrite(
            axons,
            bt.Synapse(),  # TODO: potentially get the synapses available back?
            deserialize=False,
            timeout=timeout,
        )
        successful_uids = [
            uid
            for uid, response in zip(uids, responses)
            if response.dendrite.status_code == 200
        ]
        failed_uids = [
            uid
            for uid, response in zip(uids, responses)
            if response.dendrite.status_code != 200
        ]
    except Exception as e:
        bt.logging.error(f"Dendrite ping failed: {e}")
        successful_uids = []
        failed_uids = uids
    bt.logging.debug("ping() successful uids:", successful_uids)
    bt.logging.debug("ping() failed uids    :", failed_uids)
    return successful_uids, failed_uids


async def get_query_api_nodes(dendrite, metagraph, n=0.1, timeout=3):
    """
    Fetches the available API nodes to query for the particular subnet.

    Args:
        dendrite (bittensor.dendrite): The dendrite instance to use for querying.
        metagraph (bittensor.metagraph): The metagraph instance containing network information.
        n (float, optional): The fraction of top nodes to consider based on stake. Defaults to 0.1.
        timeout (int, optional): The timeout in seconds for pinging nodes. Defaults to 3.

    Returns:
        list: A list of UIDs representing the available API nodes.
    """
    bt.logging.debug(f"Fetching available API nodes for subnet {metagraph.netuid}")
    vtrust_uids = [
        uid.item() for uid in metagraph.uids if metagraph.validator_trust[uid] > 0
    ]
    top_uids = torch.where(metagraph.S > torch.quantile(metagraph.S, 1 - n))
    top_uids = top_uids[0].tolist()
    init_query_uids = set(top_uids).intersection(set(vtrust_uids))
    query_uids, _ = await ping_uids(
        dendrite, metagraph, init_query_uids, timeout=timeout
    )
    bt.logging.debug(
        f"Available API node UIDs for subnet {metagraph.netuid}: {query_uids}"
    )
    if len(query_uids) > 3:
        query_uids = random.sample(query_uids, 3)
    return query_uids


async def get_query_api_axons(dendrite, metagraph, n=0.1, timeout=3):
    """
    Retrieves the axons of query API nodes based on their availability and stake.

    Args:
        dendrite (bittensor.dendrite): The dendrite instance to use for querying.
        metagraph (bittensor.metagraph): The metagraph instance containing network information.
        n (float, optional): The fraction of top nodes to consider based on stake. Defaults to 0.1.
        timeout (int, optional): The timeout in seconds for pinging nodes. Defaults to 3.

    Returns:
        list: A list of axon objects for the available API nodes.
    """
    query_uids = await get_query_api_nodes(dendrite, metagraph, n=n, timeout=timeout)
    return [metagraph.axons[uid] for uid in query_uids]


async def store_data(
    data: bytes,
    wallet: "bt.wallet",
    metagraph: "bt.metagraph" = None,
    deserialize: bool = False,
    encrypt=False,
    ttl=60 * 60 * 24 * 30,  # 30 days default
    timeout=90,
    n=0.1,
    ping_timeout=3,
    encoding="utf-8",
) -> str:
    """
    Stores data on the Bittensor network, optionally encrypting it.

    Args:
        data (bytes): The data to store.
        wallet (bt.wallet): The wallet to use for transactions.
        metagraph (bt.metagraph, optional): The metagraph instance. If None, defaults to metagraph 21.
        deserialize (bool, optional): Whether to deserialize the response. Defaults to False.
        encrypt (bool, optional): Whether to encrypt the data before storing. Defaults to False.
        ttl (int, optional): Time-to-live for the stored data in seconds. Defaults to 2592000 (30 days).
        timeout (int, optional): Timeout for the store operation in seconds. Defaults to 180.
        n (float, optional): Fraction of top nodes to consider for storing data. Defaults to 0.1.
        ping_timeout (int, optional): Timeout for pinging nodes in seconds. Defaults to 3.
        encoding (str, optional): The encoding of the input data if it's a string. Defaults to "utf-8".

    Returns:
        str: The CID (Content Identifier) of the stored data, or an empty string if the operation failed.
    """
    data = bytes(data, encoding) if isinstance(data, str) else data
    encrypted_data, encryption_payload = (
        encrypt_data(data, wallet) if encrypt else (data, "{}")
    )
    expected_cid = generate_cid_string(encrypted_data)
    encoded_data = base64.b64encode(encrypted_data)

    synapse = StoreUser(
        encrypted_data=encoded_data,
        encryption_payload=encryption_payload,
        ttl=ttl,
    )

    dendrite = bt.dendrite(wallet=wallet)
    if metagraph is None:
        metagraph = bt.metagraph(21)

    axons = await get_query_api_axons(
        dendrite=dendrite,
        metagraph=metagraph,
        n=n,
        timeout=ping_timeout,
    )

    with bt.__console__.status(":satellite: Storing data..."):
        tasks = [
            asyncio.create_task(dendrite(axon, synapse, timeout=timeout, deserialize=deserialize))
            for axon in axons
        ]
        responses = await asyncio.gather(*tasks)

        bt.logging.debug(
            "axon responses:", [resp.dendrite.dict() for resp in responses]
        )

    success = False
    failure_modes = {"code": [], "message": []}
    for response in responses:
        if response.dendrite.status_code != 200:
            failure_modes["code"].append(response.dendrite.status_code)
            failure_modes["message"].append(response.dendrite.status_message)
            continue

        stored_cid = (
            response.data_hash.decode("utf-8")
            if isinstance(response.data_hash, bytes)
            else response.data_hash
        )
        bt.logging.debug("received data hash: {}".format(stored_cid))

        if stored_cid != expected_cid:
            bt.logging.warning(
                f"Received CID {stored_cid} does not match expected CID {expected_cid}."
            )
        success = True
        break

    if success:
        bt.logging.info(f"Stored data on the Bittensor network with hash {stored_cid}")
    else:
        bt.logging.error(
            f"Failed to store data. Response failure codes & messages {failure_modes}"
        )
        stored_cid = ""

    return stored_cid


async def retrieve_data(
    cid: str,
    wallet: "bt.wallet",
    metagraph: "bt.metagraph" = None,
    n=0.1,
    timeout: int = 90,
    ping_timeout: int = 3,
) -> bytes:
    """
    Retrieves data from the Bittensor network using its CID.

    Args:
        cid (str): The CID (Content Identifier) of the data to retrieve.
        wallet (bt.wallet): The wallet to use for transactions.
        metagraph (bt.metagraph, optional): The metagraph instance. If None, defaults to metagraph 21.
        n (float, optional): Fraction of top nodes to consider for retrieving data. Defaults to 0.1.
        timeout (int, optional): Timeout for the retrieve operation in seconds. Defaults to 180.
        ping_timeout (int, optional): Timeout for pinging nodes in seconds. Defaults to 3.

    Returns:
        bytes: The retrieved data, or an empty byte string if the operation failed.
    """
    synapse = RetrieveUser(data_hash=cid)
    dendrite = bt.dendrite(wallet=wallet)

    axons = await get_query_api_axons(
        dendrite=dendrite,
        metagraph=metagraph or bt.metagraph(21),
        n=n,
        timeout=ping_timeout,
    )

    with bt.__console__.status(":satellite: Retreiving data..."):
        tasks = [
            asyncio.create_task(dendrite(axon, synapse, timeout=timeout, deserialize=False))
            for axon in axons
        ]
        responses = await asyncio.gather(*tasks)

    success = False
    decrypted_data = b""
    for response in responses:
        bt.logging.trace(f"response: {response.dendrite.dict()}")
        if response.dendrite.status_code != 200 or response.encrypted_data is None:
            continue

        # Decrypt the response
        bt.logging.trace(f"encrypted_data: {response.encrypted_data[:100]}")
        encrypted_data = base64.b64decode(response.encrypted_data)
        bt.logging.debug(f"encryption_payload: {response.encryption_payload}")
        if (
            response.encryption_payload is None
            or response.encryption_payload == ""
            or response.encryption_payload == "{}"
        ):
            bt.logging.warning("No encryption payload found. Unencrypted data.")
            decrypted_data = encrypted_data
        else:
            decrypted_data = decrypt_data_with_private_key(
                encrypted_data,
                response.encryption_payload,
                bytes(wallet.coldkey.private_key.hex(), "utf-8"),
            )
        bt.logging.trace(f"decrypted_data: {decrypted_data[:100]}")
        success = True
        break

    if success:
        bt.logging.info(f"Returning retrieved data: {decrypted_data[:100]}")
    else:
        bt.logging.error("Failed to retrieve data.")

    return decrypted_data
