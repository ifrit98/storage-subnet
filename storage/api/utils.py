import torch
import random
import bittensor as bt


async def ping_uids(dendrite, metagraph, uids, timeout=3):
    """
    Pings a list of UIDs to check their availability on the Bittensor network.

    Args:
        dendrite (bittensor.dendrite): The dendrite instance to use for pinging nodes.
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
        wallet (bittensor.wallet): The wallet instance to use for querying nodes.
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
    return query_uids


async def get_query_api_axons(wallet, metagraph=None, n=0.1, timeout=3, uids=None):
    """
    Retrieves the axons of query API nodes based on their availability and stake.

    Args:
        wallet (bittensor.wallet): The wallet instance to use for querying nodes.
        metagraph (bittensor.metagraph, optional): The metagraph instance containing network information.
        n (float, optional): The fraction of top nodes to consider based on stake. Defaults to 0.1.
        timeout (int, optional): The timeout in seconds for pinging nodes. Defaults to 3.
        uids (Union[List[int], int], optional): The specific UID(s) of the API node(s) to query. Defaults to None.

    Returns:
        list: A list of axon objects for the available API nodes.
    """
    dendrite = bt.dendrite(wallet=wallet)

    if metagraph is None:
        metagraph = bt.metagraph(netuid=21)

    if uids is not None:
        query_uids = [uids] if isinstance(uids, int) else uids
    else:
        query_uids = await get_query_api_nodes(dendrite, metagraph, n=n, timeout=timeout)
    return [metagraph.axons[uid] for uid in query_uids]
