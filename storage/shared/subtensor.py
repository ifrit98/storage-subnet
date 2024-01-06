import time
from math import floor
from functools import lru_cache, update_wrapper
from typing import Callable, Any


def _ttl_hash_gen(seconds: int):
    start_time = time.time()
    while True:
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
