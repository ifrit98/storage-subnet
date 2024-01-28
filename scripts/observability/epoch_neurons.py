''' 
    Emission data graphing example.
'''

from threading import Thread
import json
import bittensor as bt
from threading import Lock
#import matplotlib.pyplot as plt


def threaded(fn):
    """ To be used as a decorator for threaded function calls. """
    def wrapper(*args, **kwargs):
        thread = Thread(target=fn, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper

class EmissionData:
    """
    Represents emission data for a specific network.

    Args:
        subtensor (object): The Subtensor object.

    Attributes:
        subtensor (object): The Subtensor object.
        netuid (int): The network UID.
        cache (dict): A dictionary to store cached neuron data.

    Methods:
        get_current_epoch(): Calculate the current epoch based on the last mechanism step, network registration time, and tempo.
        cache_neuron_data(): Caches neuron data for each epoch and block.
        extract_emission_data(): Extracts emission data from the cache and does something with the data.
        get_block_events(): Get the block events from the cache.
    """
    
    def __init__(self, subtensor):
        self.subtensor = subtensor
        self.netuid = 21
        self.cache = {}
        self.cache_lock = Lock()

    def get_current_epoch(self):
        """
        Calculate the current epoch based on the last mechanism step, 
        network registration time, and tempo.
        
        Returns:
            float: The current epoch.
        """
        last_mechanism_step = self.subtensor.substrate.query(
            module="SubtensorModule", storage_function="LastMechansimStepBlock", params=[self.netuid]
        ).value

        network_registered = self.subtensor.substrate.query(
            module="SubtensorModule", storage_function="NetworkRegisteredAt", params=[self.netuid]
        ).value

        tempo = self.subtensor.substrate.query(
            module="SubtensorModule", storage_function="Tempo", params=[self.netuid]
        ).value

        return ((last_mechanism_step - network_registered) / tempo)

    @threaded
    def cache_neuron_data(self):
        """
        Caches neuron data for each epoch and block.

        This function continuously checks for new blocks since the last epoch and caches the neuron data for each block.
        The cached data is stored in the `cache` dictionary, where the keys are the epoch numbers and the values are
        dictionaries containing the block numbers and the corresponding neuron data.

        Note:
        - The `subtensor` object must be initialized before calling this method.
        - The `netuid` attribute must be set to the desired network UID before calling this method.

        Returns:
        None
        """
        while True:
            prev_block = 0
            blocks_since_epoch = self.subtensor.blocks_since_epoch(self.netuid)
            #print(blocks_since_epoch)

            if blocks_since_epoch > prev_block:
                prev_block = blocks_since_epoch

                current_epoch = str(self.get_current_epoch()).split('.', maxsplit=1)[0]
                current_block = self.subtensor.get_current_block()

                with self.cache_lock:
                    if current_epoch not in self.cache:
                        self.cache[current_epoch] = {
                            current_block: self.subtensor.neurons(21, current_block)
                        }

                    self.cache[current_epoch][current_block] = self.subtensor.neurons(21, current_block)


    @threaded
    def extract_emission_data(self):
        """
        Extracts emission data from the cache and does something with the data.

        Returns:
            None
        """
        old_block_counts = {}
        epoch_data = {}
        
        while True:
            with self.cache_lock:
                if bool(self.cache):
                    epoch_data = {
                        current_epoch: {
                            current_block: {
                                neuron.uid: neuron.emission for neuron in neurons_by_block
                            } for current_block, neurons_by_block in blocks.items()
                        } for current_epoch, blocks in self.cache.items()
                    }

                    for current_epoch, blocks in epoch_data.items():
                        current_block_count = len(blocks)
                        old_block_count = old_block_counts.get(current_epoch, 0)

                        if current_block_count > old_block_count:
                            with open("scripts/observability/emission_data.json", "w", encoding="utf-8") as f:
                                json.dump(epoch_data, f, indent=4)

                        old_block_counts[current_epoch] = current_block_count
                        
                

    @threaded
    def get_block_events(self):
        """
        Get the block events from the cache.

        Returns:
            None
        """
        blocks = list(self.cache.keys())
        for block in blocks:
            block_hash = self.subtensor.get_block_hash(block)
            events = self.subtensor.substrate.get_events(block_hash)
            for event in events:
                event_dict = event["event"].decode()
                if event_dict["event_id"] == "NeuronRegistered":
                    netuid, uid, hotkey = event_dict["attributes"]
                    if int(netuid) == 21:
                        print(f"NeuronRegistered: netuid: {netuid}, uid: {uid}, hotkey: {hotkey}")


if __name__ == "__main__":
    sub = bt.subtensor()

    data = EmissionData(sub)
    CACHE_HANDLE = data.cache_neuron_data()
    EXTRACT_HANDLE = data.extract_emission_data()
    CACHE_HANDLE.join()
    EXTRACT_HANDLE.join()
       #handle.join()
    # Add your main code logic here
