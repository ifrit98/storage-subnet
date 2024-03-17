# The MIT License (MIT)
# Copyright © 2021 Yuma Rao
# Copyright © 2023 Opentensor Foundation
# Copyright © 2024 Philanthrope

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

import torch
import base64
import bittensor as bt
from typing import Any, List, Union
from storage.protocol import RetrieveUser
from storage.validator.encryption import decrypt_data_with_private_key
from storage.api.utils import get_query_api_axons


class RetrieveUserAPI(bt.SubnetsAPI):
    def __init__(self, wallet: "bt.wallet"):
        super().__init__(wallet)
        self.netuid = 21

    def prepare_synapse(self, cid: str) -> RetrieveUser:
        synapse = RetrieveUser(data_hash=cid)
        return synapse

    def process_responses(self, responses: List[Union["bt.Synapse", Any]]) -> bytes:
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
                    bytes(self.wallet.coldkey.private_key.hex(), "utf-8"),
                )
            bt.logging.trace(f"decrypted_data: {decrypted_data[:100]}")
            success = True
            break

        if success:
            bt.logging.info(f"Returning retrieved data: {decrypted_data[:100]}")
        else:
            bt.logging.error("Failed to retrieve data.")

        return decrypted_data


async def retrieve(
    cid: str,
    wallet: "bt.wallet",
    subtensor: "bt.subtensor" = None,
    chain_endpoint: str = "finney",
    netuid: int = 21,
    timeout: int = 60,
    uids: List[int] = None,
    hotkeys: List[str] = None,
) -> bytes:
    retrieve_handler = RetrieveUserAPI(wallet)

    subtensor = subtensor or bt.subtensor(chain_endpoint)
    metagraph = subtensor.metagraph(netuid=netuid)

    if uids is None and hotkeys is not None:
        uids = [metagraph.hotkeys.index(hotkey) for hotkey in hotkeys]

    axons = await get_query_api_axons(wallet=wallet, metagraph=metagraph, uids=uids)

    data = await retrieve_handler(
        axons=axons,
        cid=cid,
        timeout=timeout,
    )

    return data