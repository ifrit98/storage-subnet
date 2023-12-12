import bittensor as bt
from .network import ping_uids


# Monitor all UIDs by ping and keep track of how many failures
async def monitor(self):
    """
    Monitor all UIDs by ping and keep track of how many failures
    occur. If a UID fails too many times, remove it from the
    list of UIDs to ping.
    """
    # Ping all UIDs
    try:
        successful_uids, failed_uids = await ping_uids(self.metagraph.uids)
    except:
        bt.logging.error("Failed to ping all uids for monitor step.")

    down_uids = []
    for uid in failed_uids:
        self.monitor_lookup[uid] += 1
        if self.monitor_lookup[uid] > self.config.validator.max_failed_pings:
            self.monitor_lookup[uid] = 0
            down_uids.append(uid)
    return down_uids
