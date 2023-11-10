import random


def safe_key_search(database, pattern):
    """This cursor-based method uses SCAN under the hood and is non-blocking"""
    return [key for key in database.scan_iter(pattern)]


# TODO: select a subset of miners to store given the redundancy factor N
def select_subset_uids(uids: list, N: int):
    return random.choices(uids, k=N)


def store_file_data(metagraph, directory=None, file_bytes=None):
    # TODO: write this to be a mirror of store_random_data
    # it will not be random but use real data from the validator filesystem or client data
    # possibly textbooks, pdfs, audio files, pictures, etc. to mimick user data
    pass
