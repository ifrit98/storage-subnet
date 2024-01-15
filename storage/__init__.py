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


class StorageVersion:
    def __init__(self, major, minor, patch):
        self.major = major
        self.minor = minor
        self.patch = patch

    @classmethod
    def from_string(cls, version_str):
        parts = version_str.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid version string format")
        return cls(int(parts[0]), int(parts[1]), int(parts[2]))

    def to_spec_version(self):
        return (100 * self.major) + (10 * self.minor) + (1 * self.patch)

    def __str__(self):
        return f"{self.major}.{self.minor}.{self.patch}"

    def __eq__(self, other):
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
        )

    def __lt__(self, other):
        return (self.major, self.minor, self.patch) < (
            other.major,
            other.minor,
            other.patch,
        )


__version__ = "1.3.0"
version = StorageVersion.from_string(__version__)
__spec_version__ = version.to_spec_version()

# Import all submodules.
from . import protocol
from . import validator
from . import miner
from . import cli
