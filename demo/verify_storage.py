with open("test.txt", "rb") as f:
    x1 = f.read()

with open("/home/phil/.bittensor/storage/test.txt", "rb") as f:
    x2 = f.read()

print("Original:", x1)
print("Stored  :", x2)
print("Test text file equivalent?:", x1 == x2)


with open("test100mb", "rb") as f:
    x1 = f.read()

with open("/home/phil/.bittensor/storage/test100mb", "rb") as f:
    x2 = f.read()

print("\nOriginal:", x1[:64])
print("Stored  :", x2[:64])
print("Test 100mb file equivalent?:", x1 == x2)


# Clear storage
import aioredis

r0 = aioredis.StrictRedis(db=0)
r1 = aioredis.StrictRedis(db=1)


async def flush():
    await r0.flushdb()
    await r1.flushdb()


# await flush()


print(await r0.keys())
print(await r1.keys())

from storage.validator.database import *
from storage.validator.utils import *

full_hash = (
    "10640854667234103088456065167400853561871673685400658931716168102369399248095"
)
md = await get_ordered_metadata(full_hash, r1)
print(md)

for d in md:
    print(d["chunk_hash"], d["hotkeys"])
