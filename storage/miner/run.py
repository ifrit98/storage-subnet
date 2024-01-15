# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 philanthrope

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
import time
import wandb
import bittensor as bt
import traceback
from substrateinterface import SubstrateInterface
from scalecodec import ScaleBytes
from .utils import update_storage_stats
from copy import deepcopy

tagged_tx_queue_registry = {
    "types": {
        "TransactionTag": "Vec<u8>",
        "TransactionPriority": "u64",
        "TransactionLongevity": "u64",
        "ValidTransaction": {
            "type": "struct",
            "type_mapping": [
                [
                    "priority",
                    "TransactionPriority"
                ],
                [
                    "requires",
                    "Vec<TransactionTag>"
                ],
                [
                    "provides",
                    "Vec<TransactionTag>"
                ],
                [
                    "longevity",
                    "TransactionLongevity"
                ],
                [
                    "propagate",
                    "bool"
                ]
            ]
        },
        "TransactionValidity": "Result<ValidTransaction, TransactionValidityError>",
        "TransactionSource": {
            "type": "enum",
            "value_list": [
                "InBlock",
                "Local",
                "External"
            ]
        },
    },
    "runtime_api": {
        "TaggedTransactionQueue": {
            "methods": {
                "validate_transaction": {
                    "params": [
                        {
                            "name": "source",
                            "type": "TransactionSource",
                        },
                        {
                            "name": "tx",
                            "type": "Extrinsic",
                        },
                        {
                            "name": "block_hash",
                            "type": "Hash"
                        }
                    ],
                    "type": "TransactionValidity",
                },
            },
        }
    }
}

def runtime_call(substrate: SubstrateInterface, api: str, method: str, params: list, block_hash: str):
    substrate.runtime_config.update_type_registry(tagged_tx_queue_registry)
    runtime_call_def = substrate.runtime_config.type_registry["runtime_api"][api]['methods'][method]
    runtime_api_types = substrate.runtime_config.type_registry["runtime_api"][api].get("types", {})

    # Encode params
    param_data = ScaleBytes(bytes())
    for idx, param in enumerate(runtime_call_def['params']):
        scale_obj = substrate.runtime_config.create_scale_object(param['type'])
        if type(params) is list:
            param_data += scale_obj.encode(params[idx])
        else:
            if param['name'] not in params:
                raise ValueError(f"Runtime Call param '{param['name']}' is missing")

            param_data += scale_obj.encode(params[param['name']])

    # RPC request
    result_data = substrate.rpc_request("state_call", [f'{api}_{method}', str(param_data), block_hash])

    # Decode result
    result_obj = substrate.runtime_config.create_scale_object(runtime_call_def['type'])
    result_obj.decode(ScaleBytes(result_data['result']), check_remaining=substrate.config.get('strict_scale_decode'))

    return result_obj


def run(self):
    """
    Initiates and manages the main loop for the miner on the Bittensor network.

    This function performs the following primary tasks:
    1. Check for registration on the Bittensor network.
    2. Attaches the miner's forward, blacklist, and priority functions to its axon.
    3. Starts the miner's axon, making it active on the network.
    4. Regularly updates the metagraph with the latest network state.
    5. Optionally sets weights on the network, defining how much trust to assign to other nodes.
    6. Handles graceful shutdown on keyboard interrupts and logs unforeseen errors.

    The miner continues its operations until `should_exit` is set to True or an external interruption occurs.
    During each epoch of its operation, the miner waits for new blocks on the Bittensor network, updates its
    knowledge of the network (metagraph), and sets its weights. This process ensures the miner remains active
    and up-to-date with the network's latest state.

    Note:
        - The function leverages the global configurations set during the initialization of the miner.
        - The miner's axon serves as its interface to the Bittensor network, handling incoming and outgoing requests.

    Raises:
        KeyboardInterrupt: If the miner is stopped by a manual interruption.
        Exception: For unforeseen errors during the miner's operation, which are logged for diagnosis.
    """
    block_handler_substrate = SubstrateInterface(
        ss58_format=bt.__ss58_format__,
        use_remote_preset=True,
        url=self.subtensor.chain_endpoint,
        type_registry=bt.__type_registry__,
    )

    netuid = self.config.netuid

    # --- Check for registration.
    if not self.subtensor.is_hotkey_registered(
        netuid=netuid,
        hotkey_ss58=self.wallet.hotkey.ss58_address,
    ):
        bt.logging.error(
            f"Wallet: {self.wallet} is not registered on netuid {netuid}"
            f"Please register the hotkey using `btcli subnets register` before trying again"
        )
        exit()

    tempo = block_handler_substrate.query(
        module="SubtensorModule", storage_function="Tempo", params=[netuid]
    ).value

    last_extrinsic_hash = None
    checked_extrinsics_count = 0
    should_retry = False

    def handler(obj, update_nr, subscription_id):
        current_block = obj["header"]["number"]
        block_hash = block_handler_substrate.get_block_hash(current_block)
        bt.logging.debug(f"New block #{current_block}")

        bt.logging.debug(
            f"Blocks since epoch: {(current_block + netuid + 1) % (tempo + 1)}"
        )

        nonlocal last_extrinsic_hash
        nonlocal checked_extrinsics_count
        nonlocal should_retry

        if last_extrinsic_hash != None:
            try:
                receipt = block_handler_substrate.retrieve_extrinsic_by_hash(block_hash, last_extrinsic_hash)
                bt.logging.debug(f"Last set-weights call: {'Success' if receipt.is_success else format('Failure, reason: %s', receipt.error_message['name'] if receipt.error_message != None else 'nil')}")

                should_retry = False
                last_extrinsic_hash = None
                checked_extrinsics_count = 0
            except Exception as e:
                checked_extrinsics_count += 1
                bt.logging.debug(f"An error occurred, extrinsic not found in block.")
            finally:
                if checked_extrinsics_count >= 20:
                    should_retry = True
                    last_extrinsic_hash = None
                    checked_extrinsics_count = 0

        if ((current_block + netuid + 1) % (tempo + 1) == 0) or should_retry:
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
                    call=call, keypair=self.wallet.hotkey, era={"period": 1000}
                )

                dry_run = runtime_call(substrate=substrate, api="TaggedTransactionQueue", method="validate_transaction", params=["InBlock", extrinsic, block_hash], block_hash=block_hash)
                bt.logging.debug(dry_run)

                response = substrate.submit_extrinsic(
                    extrinsic,
                    wait_for_inclusion=False,
                    wait_for_finalization=False,
                )

                print(response, call, self.wallet.hotkey)

                result_data = substrate.rpc_request("author_pendingExtrinsics", [])
                for extrinsic_data in result_data['result']:
                    extrinsic = substrate.runtime_config.create_scale_object('Extrinsic', metadata=substrate.metadata)
                    extrinsic.decode(ScaleBytes(extrinsic_data), check_remaining=substrate.config.get('strict_scale_decode'))

                    if extrinsic.value["extrinsic_hash"] == response.extrinsic_hash:
                        bt.logging.debug("Weights transaction is in the pending transaction pool")

                last_extrinsic_hash = response.extrinsic_hash
                should_retry = False

            # --- Update the miner storage information periodically.
            if not should_retry:
                update_storage_stats(self)
                bt.logging.debug("Storage statistics updated...")

            if self.should_exit:
                return True

    block_handler_substrate.subscribe_block_headers(handler)
