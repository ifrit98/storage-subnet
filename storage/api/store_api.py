# The MIT License (MIT)
# Copyright © 2021 Yuma Rao
# Copyright © 2023 Opentensor Foundation
# Copyright © 2024 Philantrope

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
import random
import bittensor as bt
from abc import ABC, abstractmethod
from typing import Any, List, Union
from storage.protocol import StoreUser
from storage.validator.cid import generate_cid_string
from storage.validator.encryption import encrypt_data
from storage.api.utils import get_query_api_axons


class StoreUserAPI(bt.SubnetsAPI):
    def __init__(self, wallet: "bt.wallet"):
        super().__init__(wallet)
        self.netuid = 21

    def prepare_synapse(
        self, data: bytes, encrypt=False, ttl=60 * 60 * 24 * 30, encoding="utf-8"
    ) -> StoreUser:
        data = bytes(data, encoding) if isinstance(data, str) else data
        encrypted_data, encryption_payload = (
            encrypt_data(data, self.wallet) if encrypt else (data, "{}")
        )
        expected_cid = generate_cid_string(encrypted_data)
        encoded_data = base64.b64encode(encrypted_data)

        synapse = StoreUser(
            encrypted_data=encoded_data,
            encryption_payload=encryption_payload,
            ttl=ttl,
        )

        return synapse

    def process_responses(self, responses: List[Union["bt.Synapse", Any]], return_failures: bool = False) -> Union[str, List[str]]:
        success = False
        successful_hotkeys = []
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
            success = True
            bt.logging.debug(f"Successfully stored CID {stored_cid} with hotkey {response.axon.hotkey}")
            successful_hotkeys.append(response.axon.hotkey)

        if success:
            bt.logging.info(
                f"Stored data on the Bittensor network with CID {stored_cid}"
            )
        else:
            bt.logging.error(
                f"Failed to store data. Response failure codes & messages {failure_modes}"
            )
            stored_cid = ""

        if return_failures:
            return stored_cid, successful_hotkeys, failure_modes

        return stored_cid, successful_hotkeys


async def store(
    data: bytes,
    wallet: "bt.wallet",
    subtensor: "bt.subtensor" = None,
    chain_endpoint: str = "finney",
    netuid: int = 21,
    ttl: int = 60 * 60 * 24 * 30,
    encrypt: bool = False,
    encoding: str = "utf-8",
    timeout: int = 60,
    uid: int = None,
):

    """
    Stores data on the Bittensor network.
    
    Args:
        data (bytes): The data to store.
        wallet (bittensor.wallet): The wallet instance to use for storing data.
        subtensor (bittensor.subtensor, optional): The subtensor instance to use for storing data. Defaults to None.
        chain_endpoint (str, optional): The chain endpoint to use for storing data. Defaults to "finney".
        netuid (int, optional): The netuid to use for storing data. Defaults to 21.
        ttl (int, optional): The time-to-live for the stored data. Defaults to 60 * 60 * 24 * 30.
        encrypt (bool, optional): Whether to encrypt the data. Defaults to False.
        encoding (str, optional): The encoding of the data. Defaults to "utf-8".
        timeout (int, optional): The timeout in seconds for storing data. Defaults to 60.
        uid (int, optional): The UID of a specific API node to use for storing data. Defaults to None.

    Returns:
        str: The CID of the stored data.
        hotkeys: The hotkeys of the successfully stored data.
    """
    store_handler = StoreUserAPI(wallet)

    subtensor = subtensor or bt.subtensor(chain_endpoint)
    metagraph = subtensor.metagraph(netuid=netuid)

    uids = None
    if uid is not None:
        uids = [uid]

    all_axons = await get_query_api_axons(wallet=wallet, metagraph=metagraph, uids=uids)
    axons = random.choices(all_axons, k=3)

    cid, hotkeys = await store_handler(
        axons=axons,
        data=data,
        encrypt=encrypt,
        ttl=ttl,
        encoding=encoding,
        uid=uid,
        timeout=timeout,
    )

    return cid, hotkeys
