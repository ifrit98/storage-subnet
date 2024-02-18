# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2023 Opentensor Foundation

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

# Bittensor Validator Template:

import csv
import os
import torch
import argparse
import traceback
import pkg_resources
import bittensor as bt
import random
from typing import List, Optional
import copy
import anyio
import anyio.to_thread
from dataclasses import dataclass
import threading
from queue import SimpleQueue, Empty
from bittranslate import Validator
from bittranslate.logging import log_elapsed_time
from bittranslate.save_scores import save_scores
from neurons.auto_update import check_for_updates
from neurons.protocol import Translate
from neurons.api_server import ApiServer

def get_config():

    parser = argparse.ArgumentParser()
    parser.add_argument('--device', default="cuda", help="The device used for the validator's components.")
    # Adds override arguments for network and netuid.
    parser.add_argument( '--netuid', type = int, default = 2, help = "The chain subnet uid." )

    parser.add_argument(
        "--max_char",
        type=int,
        default=1024,
        help="The maximum allowed characters for an incoming request.",
    )

    parser.add_argument(
        "--batch_size",
        type=int,
        default=2,
        help="Number of source texts to send to each miner."
    )

    parser.add_argument(
        "--step_delay",
        type=int,
        default=12,
        help="Number of seconds to sleep between steps."
    )

    parser.add_argument(
        "--miners_per_step",
        type=int,
        default=8,
        help="Number of miners query in each step."
    )

    parser.add_argument(
        "--track_steps",
        type=int,
        default=100,
        help="Number of steps before tracked scores and texts are saved."
    )

    parser.add_argument(
        "--out_dir",
        type=str,
        default="bittranslate_out/",
        help="Output directory for tracked results."
    )

    parser.add_argument(
        "--enable_api",
        action="store_true",
        help="If set, a callable API will be activated."
    )

    parser.add_argument(
        "--score_api",
        action="store_true",
        help="If set,  responses from API requests will be used to modify scores."
    )


    parser.add_argument(
        "--api_json",
        type=str,
        default="neurons/api.json",
        help="A path to a a config file for the API."
    )

    parser.add_argument(
        "--no_artificial_eval",
        action="store_true",
        help="If set, artificial data will not be sent to miners for the purpose of scoring. We only recommend setting this to true to when debugging the API."
    )

    parser.add_argument(
        "--ngrok_domain",
        help=(
            "If set, expose the API over 'ngrok' to the specified domain."
        )
    )

    parser.add_argument(
        "--update_steps",
        type=int,
        default=500,
        help=(
            "The number of steps until we check if there has been a new version. If 0, no searching will be performed."
        )
    )

    parser.add_argument(
        "--score_logging_steps",
        type=int,
        default=0,
        help=(
            "The number of steps until we log the scores by UID. If 0, no logging will be performed."
        )
    )

    parser.add_argument(
        "--score_logging_file",
        type=str,
        default="scores.csv",

    )

    parser.add_argument(
        "--no_restart",
        help=(
            "If set, the process is not restarted when a new version is detected."
        )
    )


    # Adds subtensor specific arguments i.e. --subtensor.chain_endpoint ... --subtensor.network ...
    bt.subtensor.add_args(parser)
    # Adds logging specific arguments i.e. --logging.debug ..., --logging.trace .. or --logging.logging_dir ...
    bt.logging.add_args(parser)
    # Adds wallet specific arguments i.e. --wallet.name ..., --wallet.hotkey ./. or --wallet.path ...
    bt.wallet.add_args(parser)
    bt.axon.add_args(parser)
    # Parse the config (will take command-line arguments if provided)
    # To print help message, run python3 template/miner.py --help
    config =  bt.config(parser)

    # Logging is crucial for monitoring and debugging purposes.
    config.full_path = os.path.expanduser(
        "{}/{}/{}/netuid{}/{}".format(
            config.logging.logging_dir,
            config.wallet.name,
            config.wallet.hotkey,
            config.netuid,
            'validator',
        )
    )
    # Ensure the logging directory exists.
    if not os.path.exists(config.full_path): os.makedirs(config.full_path, exist_ok=True)

    # Return the parsed config.
    return config

def clamp(min: int, max: int, x: int) -> int:
    """ Clamp `x` into the range `[min,max]`. """

    if x<min:
        return min
    if x>max:
        return max
    return x

def translation_for_source_text_in_response(
        response: Translate,
        source_text_index: int
) -> str:
    """ Get the translated text corresponding
        to a particular source text on a miner's response. """

    if source_text_index >= len(response.translated_texts):
        return "BLANK"

    response_text = response.translated_texts[source_text_index]

    if len(response_text) > config.max_char:
        # TODO log
        return "BLANK"
    if type(response_text) != str:
        # TODO log
        return "BLANK"

    return response_text

def translations_for_source_text(
        responses: List[Translate],
        source_text_index: int
) -> List[str]:
    """ Return a list of translations for a given source text,
        from a set of responses.
        Each translation corresponds to a different miner. """

    return [
        translation_for_source_text_in_response(
            response=response,
            source_text_index=source_text_index
        )
        for response in responses
    ]

def build_translations_per_source_text(
        responses: List[Translate]
) -> List[List[str]]:
    """ Assemble a list of lists, where if viewed as a matrix,
        each row corresponds to different miner's responses
        to the same source text.

        Returns `translations`,
        where `translations[source_index][miner_index]=...`
    """
    return [
        translations_for_source_text(
            responses=responses,
            source_text_index=source_text_index
        )
        # It is OK to trust this arbitrary response's "source_texts" field
        # because we set `allow_mutation=False` in the protocol.
        for source_text_index, _ in enumerate(responses[0].source_texts)
    ]

# source: https://github.com/opentensor/text-prompting/blob/6c493cbce0c621e28ded203d947ce47a9ae062ea/prompting/validators/utils.py#L102
def update_scores_from_metagraph(
        scores: torch.FloatTensor,
        metagraph: bt.metagraph,
        hotkeys: List[str]
) -> List[float]:
    """ Update the per-UID scores based on recent metagraph updates.

        Inputs are current scores, recently synced metagraph,
        and list of hotkeys from before metagraph sync.

        Output is updated scores.
    """
    # For any UIDs which have a new hotkey,
    # set the score to the median.
    median = scores.median()
    for uid, hotkey in enumerate(hotkeys):
        if hotkey != metagraph.hotkeys[uid]:
            scores[uid] = median
            bt.logging.debug(f"New hotkey: {uid}. Setting score to {median}")

    # Did the most recent metagraph update increase the number of UIDs?
    # Occurs during creation of subnet as registrations fill up.
    if len(hotkeys) < len(metagraph.hotkeys):
        # Create new list of scores with correct length.
        new_scores = torch.zeros((metagraph.n))
        # Copy scores we do have onto new scores.
        min_len = min(len(hotkeys), len(scores))
        new_scores[:min_len] = scores[:min_len]

        bt.logging.debug(f"UID length increased. Previous scores: {scores}. New scores: {new_scores}")

        # Update scores.
        scores = new_scores

    return scores

@dataclass
class SynapseWithEvent:
    """ Object that API server can send to main thread to be serviced. """

    input_synapse: Translate
    event: threading.Event
    output_synapse: Translate

api_queue = SimpleQueue() # Queue of SynapseEventPair

async def forward(synapse: Translate) -> Translate:
    """ Forward function for API server. """

    synapse_with_event = SynapseWithEvent(
        input_synapse=synapse,
        event=threading.Event(),
        output_synapse=Translate(source_lang="en", target_lang="pl", source_texts=["sample"])
    )
    api_queue.put(synapse_with_event)

    # Wait until the main thread marks this synapse as processed.
    await anyio.to_thread.run_sync(synapse_with_event.event.wait)

    return synapse_with_event.output_synapse

def main( config ):
    # Set up logging with the provided configuration and directory.
    bt.logging(config=config, logging_dir=config.full_path)
    bt.logging.info(f"Running validator for subnet: {config.netuid} on network: {config.subtensor.chain_endpoint} with config:")
    # Log the configuration for reference.
    bt.logging.info(config)

    # These are core Bittensor classes to interact with the network.
    bt.logging.info("Setting up bittensor objects.")

    # The wallet holds the cryptographic key pairs for the validator.
    wallet = bt.wallet( config = config )
    bt.logging.info(f"Wallet: {wallet}")

    # The subtensor is our connection to the Bittensor blockchain.
    subtensor = bt.subtensor( config = config )
    bt.logging.info(f"Subtensor: {subtensor}")

    # Dendrite is the RPC client; it lets us send messages to other nodes (axons) in the network.
    dendrite = bt.dendrite( wallet = wallet )
    bt.logging.info(f"Dendrite: {dendrite}")

    # The metagraph holds the state of the network, letting us know about other miners.
    metagraph = subtensor.metagraph( config.netuid )
    bt.logging.info(f"Metagraph: {metagraph}")
    hotkeys: List[str] = copy.deepcopy(metagraph.hotkeys)



    if wallet.hotkey.ss58_address not in metagraph.hotkeys:
        bt.logging.error(f"\nYour validator: {wallet} if not registered to chain connection: {subtensor} \nRun btcli register and try again.")
        exit()
    else:
        # Each miner gets a unique identity (UID) in the network for differentiation.
        my_subnet_uid = metagraph.hotkeys.index(wallet.hotkey.ss58_address)
        bt.logging.info(f"Running validator on uid: {my_subnet_uid}")

    bt.logging.info("Building validation weights.")


    scores = torch.zeros_like(metagraph.S, dtype=torch.float32)
    bt.logging.info(f"Weights: {scores}")

    alpha = 0.999

    ## Custom Initialization
    bt.logging.info(f"Loading validator components...")

    validator = Validator(device=config.device, out_dir=config.out_dir)

    bt.logging.info(f"Done validator components.")

    if config.enable_api:
        # external requests
        api_server = ApiServer(
            axon_port=config.axon.port,
            forward_fn=forward,
            api_json=config.api_json,
            lang_pairs=validator._lang_pairs,
            max_char=config.max_char,
            ngrok_domain=config.ngrok_domain
        )
        api_server.start()


    bt.logging.info("Starting validator loop.")
    step = 0

    uid_score_history = {}
    uid_score_steps =  []

    while True:
        try:
            bt.logging.info(f"\n\nStep: {step}")
            # We sleep at the top of the loop such that the queue access is more readable.
            # This results in one extra delay at the beginning of a validator's startup,
            # which is not a significant issue.
            with log_elapsed_time("sleeping"):
                synapse_with_event: Optional[SynapseWithEvent] = None
                try:
                    synapse_with_event = api_queue.get(timeout=config.step_delay)
                except Empty:
                    # No synapse from API server.
                    pass

            if synapse_with_event is not None:
                bt.logging.info("Processing synapse from API server")
            else:
                if config.no_artificial_eval:
                    bt.logging.info("Since there are no API request  and '--no_artificial_eval' is True, no request are sent to miners")
                    continue
            # Sample axons by UID such that we can easily
            # look them up later for rewards.
            bt.logging.debug(f"metagraph.n.item(): {metagraph.n.item()}")
            available_uids = [
                uid
                for uid in range(metagraph.n.item())
                if check_uid_availability(
                    metagraph=metagraph,
                    uid=uid
                )
            ]

            bt.logging.trace(f"available_uids: {available_uids}")

            chosen_uids = random.sample(
                available_uids,
                k=clamp(min=1, max=config.miners_per_step, x=len(available_uids))
            )
            bt.logging.debug(f"len(chosen_uids): {len(chosen_uids)}")
            bt.logging.debug(f"chosen_uids: {chosen_uids}")

            chosen_axons = [
                metagraph.axons[uid]
                for uid in chosen_uids
            ]

            bt.logging.trace(f"chosen_axons: {chosen_axons}")

            if synapse_with_event is None:
                with log_elapsed_time("generate_case"):
                    source_lang, target_lang, source_texts = (
                        validator.generate_cases(count=config.batch_size)
                    )
            else:
                source_lang = synapse_with_event.input_synapse.source_lang
                target_lang = synapse_with_event.input_synapse.target_lang
                source_texts = synapse_with_event.input_synapse.source_texts

            bt.logging.debug(f"source_lang: {source_lang}")
            bt.logging.debug(f"target_lang: {target_lang}")

            try:
                bt.logging.debug(f"source_texts[0][0:50]: {source_texts[0][:50]}")
            except Exception as e:
                bt.logging.debug("source_texts[0][0:50]: INVALID")

            bt.logging.trace(f"source_texts: {source_texts}")


            with log_elapsed_time("dendrite.query"):
                # Broadcast a query to all miners on the network.
                responses = dendrite.query(
                    # Send the query to all axons in the network.
                    chosen_axons,
                    # Construct a query.
                    Translate(
                        source_texts=source_texts,
                        source_lang=source_lang,
                        target_lang=target_lang
                    ),
                    # All responses have the deserialize function called on them before returning.
                    deserialize=True,
                    timeout=10.0
                )
                bt.logging.debug(f"len(responses): {len(responses)}")
                try:
                    bt.logging.debug(f"responses[0].translated_texts[0][0:50]: {responses[0].translated_texts[0][0:50]}")
                except Exception as e:
                    bt.logging.debug("responses[0].translated_texts[0][0:50]: INVALID")

                bt.logging.trace(f"responses: {responses}")



            # We only skip scoring if:
            # a) we are currently servicing an API/user request
            # and b) the "--score_api" flag has not been set
            skip_scoring = (
                (synapse_with_event is not None)
                and not config.score_api
            )

            # Reorganize so that we have a list of lists,
            # where  each sublist contains the translations
            # for a given source text.
            translations = build_translations_per_source_text(responses)
            bt.logging.trace(f"translations: {translations}")

            # Run the Filtering and Reward Models
            with log_elapsed_time("score_responses"):
                # These scores align to chosen_axons, NOT miner UIDs.
                raw_scores, top_translations, top_scores = validator.score(
                    source_texts,
                    translations=translations,
                    source_lang=source_lang,
                    target_lang=target_lang
                )

            bt.logging.debug(f"raw_scores: {raw_scores=}")
            bt.logging.trace(f"top_translations: {top_translations=}")
            bt.logging.trace(f"top_scores: {top_scores=}")

            if not skip_scoring:
                bt.logging.debug(f"before: {scores=}")

                # Update score by 1-alpha amount
                for uid, score in zip(chosen_uids,raw_scores):
                    # These scores align to miner UIDs, NOT chosen_axons.
                    scores[uid] = alpha * scores[uid] + (1 - alpha) * score

                bt.logging.debug(f"after: {scores=}")

                if config.score_logging_steps > 0:
                    if (step + 1) % config.score_logging_steps == 0:
                        save_scores(step=step,
                                    scores=scores,
                                    uid_score_history=uid_score_history,
                                    uid_score_steps=uid_score_steps,
                                    score_logging_file=config.score_logging_file,
                                    metagraph=metagraph)


            # Save outputs to object shared with API server
            # and flag event such that API server
            # knows these outputs are ready.
            if synapse_with_event is not None:
                synapse_with_event.output_synapse = Translate(source_lang=source_lang,
                                                              target_lang=target_lang,
                                                              source_texts=source_texts,
                                                              translated_texts=top_translations)
                synapse_with_event.event.set()

            if config.update_steps != 0:
                if (step + 1) % config.update_steps == 0:
                    check_for_updates(no_restart=config.no_restart)

            if (step + 1) % 100 == 0:
                weights = torch.nn.functional.normalize(scores, p=1.0, dim=0)
                # We set these normalized scores back,
                # such that miner weights eventually decay
                # if no rewards are achieved.
                scores = weights
                bt.logging.info(f"Setting weights: {weights}")

                processed_weight_uids,  processed_weights, = bt.utils.weight_utils.process_weights_for_netuid(
                    uids=metagraph.uids.to("cpu"),
                    weights=weights.to("cpu"),
                    netuid=config.netuid,
                    subtensor=subtensor,
                    metagraph=metagraph,
                )
                bt.logging.trace(f"processed_weight_uids: {processed_weight_uids=}")
                bt.logging.trace(f"processed_weights: {processed_weights=}")


                with log_elapsed_time("set_weights"):
                    result = subtensor.set_weights(
                        netuid = config.netuid, # Subnet to set weights on.
                        wallet = wallet, # Wallet to sign set weights using hotkey.
                        uids = processed_weight_uids, # Uids of the miners to set weights for.
                        weights = processed_weights, # Weights to set for the miners.
                        wait_for_inclusion=False,
                    )
                if result: bt.logging.success('Successfully set weights.')
                else: bt.logging.error('Failed to set weights.')

            # End the current step and prepare for the next iteration.
            step += 1

            # Resync our local state with the latest state from the blockchain.
            if (step + 1) % 20 == 0:
                with log_elapsed_time("sync_metagraph"):
                    metagraph = subtensor.metagraph(config.netuid)
                    bt.logging.trace(f"metagraph: {metagraph=}")

                scores = update_scores_from_metagraph(
                    scores=scores,
                    metagraph=metagraph,
                    hotkeys=hotkeys
                )
                hotkeys=copy.deepcopy(metagraph.hotkeys)

            if (step + 1) % config.track_steps == 0:
                with log_elapsed_time("save_tracked_results"):
                    try:
                        validator.save_tracked_results()
                    except Exception as e:
                        bt.logging.error("save_tracked_results:",  e)
                        traceback.print_exc()

        # If we encounter an unexpected error, log it for debugging.
        except Exception as e:
            bt.logging.error(e)
            traceback.print_exc()

        # If the user interrupts the program, gracefully exit.
        except KeyboardInterrupt:
            bt.logging.success("Keyboard interrupt detected. Exiting validator.")
            exit()

def check_uid_availability(
        metagraph: "bt.metagraph", uid: int
) -> bool:
    """Check if uid is available. The UID should be available if it is serving and has less than vpermit_tao_limit stake
    Args:
        metagraph (:obj: bt.metagraph.Metagraph): Metagraph object
        uid (int): uid to be checked
        vpermit_tao_limit (int): Validator permit tao limit
    Returns:
        bool: True if uid is available, False otherwise

    source: https://github.com/opentensor/text-prompting/blob/main/prompting/validators/utils.p
    """
    # Filter non serving axons.
    if not metagraph.axons[uid].is_serving:
        return False
    # Available otherwise.
    return True

# The main function parses the configuration and runs the validator.
if __name__ == "__main__":
    # Parse the configuration.
    config = get_config()
    version = pkg_resources.get_distribution('bittranslate').version
    bt.logging.info(f"BitTranslate Version: {version}")
    if config.update_steps != 0:
        check_for_updates(no_restart=config.no_restart)

    # Run the main function.
    main( config )