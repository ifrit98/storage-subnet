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
