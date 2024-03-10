import time
from math import floor
from functools import lru_cache, update_wrapper
from typing import Callable, Any


def _ttl_hash_gen(seconds: int):
    start_time = time.time()
    while 1:
        yield floor((time.time() - start_time) / seconds)


# LRU Cache with TTL
def ttl_cache(maxsize: int = 128, typed: bool = False, ttl: int = -1):
    if ttl <= 0:
        ttl = 65536
    hash_gen = _ttl_hash_gen(ttl)

    def wrapper(func: Callable) -> Callable:
        @lru_cache(maxsize, typed)
        def ttl_func(ttl_hash, *args, **kwargs):
            return func(*args, **kwargs)

        def wrapped(*args, **kwargs) -> Any:
            th = next(hash_gen)
            return ttl_func(th, *args, **kwargs)

        return update_wrapper(wrapped, func)

    return wrapper


# 12 seconds updating block.
@ttl_cache(maxsize=1, ttl=12)
def get_current_block(subtensor) -> int:
    return subtensor.get_current_block()


def get_blocks_since_last_epoch(netuid, tempo, current_block):
    return (current_block + netuid + 1) % (tempo + 1)


def is_block_first_in_new_epoch(netuid, tempo, current_block) -> int:
    return (get_blocks_since_last_epoch(netuid, tempo, current_block) == 0)


def old_miner_weights_handler(obj, update_nr, subscription_id):
    current_block = obj["header"]["number"]
    block_hash = block_handler_substrate.get_block_hash(current_block)
    bt.logging.debug(f"New block #{current_block}")

    bt.logging.debug(
        f"Blocks since epoch: {get_blocks_since_last_epoch(netuid, tempo, current_block)}"
    )

    nonlocal last_extrinsic_hash, checked_extrinsics_count, should_retry, account_nonce

    if last_extrinsic_hash is not None:
        try:
            receipt = block_handler_substrate.retrieve_extrinsic_by_hash(
                block_hash, last_extrinsic_hash
            )
            bt.logging.trace(
                f"Last set-weights call: {'Success' if receipt.is_success else format('Failure, reason: %s', receipt.error_message['name'] if receipt.error_message is not None else 'nil')}"
            )

            should_retry = False
            last_extrinsic_hash = None
            checked_extrinsics_count = 0
        except Exception:
            checked_extrinsics_count += 1
            bt.logging.trace("An error occurred, extrinsic not found in block.")
        finally:
            if checked_extrinsics_count >= 20:
                should_retry = True
                last_extrinsic_hash = None
                checked_extrinsics_count = 0

    if is_block_first_in_new_epoch(netuid, tempo, current_block) or should_retry:
        bt.logging.info("Saving request log")
        try:
            with open(self.config.miner.request_log_path, "w") as f:
                json.dump(self.request_log, f)
        except Exception as e:
            bt.logging.warning(f"Unable to save request log to disk {e}")

        bt.logging.info(
            f"New epoch started, setting weights at block {current_block}"
        )
        with self.subtensor.substrate as substrate:
            call = substrate.compose_call(
                call_module="SubtensorModule",
                call_function="set_weights",
                call_params={
                    "dests": [self.my_subnet_uid],
                    "weights": [65535],
                    "netuid": netuid,
                    "version_key": 1,
                },
            )

            # Period dictates how long the extrinsic will stay as part of waiting pool
            extrinsic = substrate.create_signed_extrinsic(
                call=call, keypair=self.wallet.hotkey, era={"period": 10}, nonce=account_nonce
            )

            dry_run = runtime_call(
                substrate=substrate,
                api="TaggedTransactionQueue",
                method="validate_transaction",
                params=["InBlock", extrinsic, block_hash],
                block_hash=block_hash,
            )
            bt.logging.trace(f"Dry run result: {dry_run}")

            try:
                response = substrate.submit_extrinsic(
                    extrinsic,
                    wait_for_inclusion=False,
                    wait_for_finalization=False,
                )

                result_data = substrate.rpc_request("author_pendingExtrinsics", [])
                for extrinsic_data in result_data["result"]:
                    extrinsic = substrate.runtime_config.create_scale_object(
                        "Extrinsic", metadata=substrate.metadata
                    )
                    extrinsic.decode(
                        ScaleBytes(extrinsic_data),
                        check_remaining=substrate.config.get("strict_scale_decode"),
                    )

                    if extrinsic.value["extrinsic_hash"] == response.extrinsic_hash:
                        bt.logging.debug(
                            "Weights transaction is in the pending transaction pool"
                        )

                last_extrinsic_hash = response.extrinsic_hash
                should_retry = False
                account_nonce = account_nonce + 1

            except BaseException as e:
                bt.logging.warning(f"Error while submitting set weights extrinsic: {e}. Retrying...")
                should_retry = True

        # --- Update the miner storage information periodically.
        if not should_retry:
            update_storage_stats(self)
            bt.logging.debug("Storage statistics updated...")

        if self.should_exit:
            return True