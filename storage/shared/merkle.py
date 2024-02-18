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

import json
import hashlib
import binascii


class MerkleTree(object):
    """
    Represents a Merkle Tree, a data structure used for efficiently summarizing and verifying the
    integrity of large sets of data. The Merkle Tree is a binary tree where each leaf node is the hash
    of a data block and every non-leaf node is the hash of its children nodes.

    Attributes:
        hash_function (callable): The hash function used for generating hashes of the blocks
                                  and non-leaf nodes in the Merkle Tree.
        leaves (list): A list where each element is a bytearray representing the hashed value of a leaf.
        levels (list of lists): A list of lists where each sublist represents a level of the tree, starting
                                from the leaves up to the root.
        is_ready (bool): Indicates whether the tree has been fully constructed and is ready to provide
                         the Merkle root and proofs.

    Methods:
        add_leaf(values, do_hash=False): Adds one or multiple leaves to the tree. If `do_hash` is True,
                                         it will hash the values before adding them as leaves.
        get_leaf(index): Retrieves the hexadecimal string representation of a leaf at the given index.
        get_leaf_count(): Returns the total number of leaves in the tree.
        get_tree_ready_state(): Checks if the tree has been fully constructed.
        make_tree(): Constructs the Merkle Tree from the current leaves. This method must be called
                     after all leaves are added and before retrieving the Merkle root or proofs.
        get_merkle_root(): Retrieves the Merkle root as a hexadecimal string if the tree is ready.
        get_proof(index): Generates a proof of inclusion for the leaf at the given index. This proof
                          consists of a list of sibling hashes that, when combined with the target leaf,
                          can reproduce the Merkle root.
        update_leaf(index, new_value): Updates the value of the leaf at the given index with `new_value`
                                      and recalculates the hashes up the tree to reflect this change.
        serialize(): Converts the Merkle Tree into a JSON-formatted string for storage or transmission.
        deserialize(json_data, hash_type="sha3_256"): Reconstructs the Merkle Tree from a JSON string,
                                                      using the specified hash function.

    Raises:
        Exception: If the `hash_type` provided during initialization is not supported or recognized.

    Example:
        # Create a Merkle tree using the SHA3-256 hash function
        merkle_tree = MerkleTree(hash_type='sha3_256')

        # Add data blocks (as leaves) to the tree
        merkle_tree.add_leaf(['block1', 'block2', 'block3'], do_hash=True)

        # Construct the tree
        merkle_tree.make_tree()

        # Retrieve the Merkle root
        root = merkle_tree.get_merkle_root()

        # Get proof of inclusion for the first data block
        proof = merkle_tree.get_proof(0)

        # Update the value of the first leaf and reconstruct the tree
        merkle_tree.update_leaf(0, 'new_block1_hashed_value')
        merkle_tree.make_tree()

        # Serialize the tree for storage
        serialized_tree = merkle_tree.serialize()

        # Deserialize the tree for later use
        deserialized_tree = MerkleTree.deserialize(serialized_tree, hash_type='sha3_256')

    Note:
        The hash_function attribute is determined by the hash_type parameter provided at initialization.
        Only hash types supported by the `hashlib` library can be used. Attempting to use an unsupported
        hash type will result in an exception.
    """

    def __init__(self, hash_type="sha3_256"):
        hash_type = hash_type.lower()
        if hash_type in ["sha3_256"]:
            self.hash_function = getattr(hashlib, hash_type)
        else:
            raise Exception("`hash_type` {} nor supported".format(hash_type))

        self.reset_tree()

    def __eq__(self, other):
        if not isinstance(other, MerkleTree):
            return False
        return self.serialize() == other.serialize()

    def _to_hex(self, x):
        try:  # python3
            return x.hex()
        except:  # python2 # TODO: do not use bare except
            return binascii.hexlify(x)

    def reset_tree(self):
        self.leaves = list()
        self.levels = None
        self.is_ready = False

    def add_leaf(self, values, do_hash=False):
        self.is_ready = False
        # check if single leaf
        if not isinstance(values, tuple) and not isinstance(values, list):
            values = [values]
        for v in values:
            if do_hash:
                v = v.encode("utf-8")
                v = self.hash_function(v).hexdigest()
            v = bytearray.fromhex(v)
            self.leaves.append(v)

    def get_leaf(self, index):
        return self._to_hex(self.leaves[index])

    def get_leaf_count(self):
        return len(self.leaves)

    def get_tree_ready_state(self):
        return self.is_ready

    def _calculate_next_level(self):
        solo_leave = None
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l + r).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [
            new_level,
        ] + self.levels  # prepend new level

    def make_tree(self):
        """
        Constructs the Merkle Tree from the leaves that have been added.

        This must be called after adding all the leaves and before calling
        get_merkle_root or get_proof to ensure the tree is constructed.
        """
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [
                self.leaves,
            ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    def get_merkle_root(self):
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0][0])
            else:
                return None
        else:
            return None

    def get_proof(self, index):
        """
        Generates the proof for the existence of a leaf at the specified index within the Merkle Tree.

        A Merkle proof is a collection of sibling hashes on the path from a leaf to the root of the tree.
        This proof can be used to independently verify that a leaf is indeed part of the Merkle tree without
        needing the entire tree. Each element of the proof shows the direction ('left' or 'right') and the
        corresponding hash that pairs with the path to the root.

        Parameters:
            index (int): The index of the target leaf for which to generate the Merkle proof. The index must
                         correspond to the position of the leaf in the original list of leaves when the tree
                         was constructed.

        Returns:
            list of dicts: A list where each dictionary contains a single key-value pair. The key is either
                           'left' or 'right', indicating the side of the sibling hash, and the value is a
                           string representing the hexadecimal hash value of the sibling. If the tree is not
                           ready or the index is out of bounds, None is returned.

        Raises:
            IndexError: If the index provided is not within the range of the leaves in the tree.
            ValueError: If the tree has not been constructed by calling `make_tree` method, or the index
                        is not an integer.

        Example:
            # Assuming `merkle_tree` is an instance of `MerkleTree` and has been populated with leaves and made ready
            proof = merkle_tree.get_proof(2)
            print(proof)  # Outputs something like [{'left': 'abcd...'}, {'right': 'ef01...'}]

        Note:
            The Merkle proof is only valid if the tree is in the ready state (`is_ready` attribute is True),
            which occurs after the `make_tree` method has been called. If the tree is not ready or the index
            is not valid, the method will return None.
        """
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves) - 1 or index < 0:
            return None
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (
                    level_len % 2 == 1
                ):  # skip if this is an odd end node
                    index = int(index / 2.0)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.0)
            return proof

    def update_leaf(self, index, new_value):
        """
        Updates the value of a leaf at a given index in the Merkle Tree and recalculates the hashes along
        the path from the updated leaf to the root of the tree to reflect the change.

        This method allows the Merkle Tree to maintain integrity by ensuring that any updates to the leaf
        nodes are propagated upwards, resulting in a new Merkle root that represents the current state of
        the leaves.

        Parameters:
            index (int): The index of the leaf to update. The index is zero-based and must be less than
                         the number of leaves in the tree.
            new_value (str): The new value in hexadecimal format to which the leaf should be updated. This
                             value should be a valid hexadecimal string that represents the hashed data
                             if hashing was applied to the leaves upon tree construction.

        Returns:
            None

        Raises:
            ValueError: If the tree is not ready for updates (i.e., `is_ready` is False), if the index is
                        not an integer, if the new_value is not a hexadecimal string, or if the index is
                        out of bounds (less than 0 or greater than or equal to the number of leaves).
            IndexError: If the index is out of the range of current leaves.

        Example:
            # Assuming `merkle_tree` is an instance of `MerkleTree`, populated with leaves and made ready.
            merkle_tree.update_leaf(0, 'a1b2c3d4e5f67890')
            # The leaf at index 0 is updated, and changes are propagated to the root.

        Note:
            The tree must have been constructed and be in a ready state before calling this method. If the
            tree has not been made by calling the `make_tree` method, or the index is invalid, this method
            will not perform an update and will return None.
        """
        if not self.is_ready:
            return None
        new_value = bytearray.fromhex(new_value)
        self.levels[-1][index] = new_value
        for x in range(len(self.levels) - 1, 0, -1):
            parent_index = index // 2
            left_child = self.levels[x][parent_index * 2]
            try:
                right_child = self.levels[x][parent_index * 2 + 1]
            except IndexError:
                right_child = bytearray()
            self.levels[x - 1][parent_index] = self.hash_function(
                left_child + right_child
            ).digest()
            index = parent_index

    def serialize(self):
        """
        Serializes the MerkleTree object into a JSON string.
        """
        # Convert the bytearray leaves and levels to hex strings for serialization
        leaves = [self._to_hex(leaf) for leaf in self.leaves]
        levels = None
        if self.levels is not None:
            levels = []
            for level in self.levels:
                levels.append([self._to_hex(item) for item in level])

        # Construct a dictionary with the MerkleTree properties
        merkle_tree_data = {
            "leaves": leaves,
            "levels": levels,
            "is_ready": self.is_ready,
        }

        # Convert the dictionary to a JSON string
        return json.dumps(merkle_tree_data)

    @classmethod
    def deserialize(cls, json_data, hash_type="sha3_256"):
        """
        Deserializes the JSON string into a MerkleTree object.
        """
        # Convert the JSON string back to a dictionary
        merkle_tree_data = json.loads(json_data)

        # Create a new MerkleTree object
        m_tree = cls(hash_type)

        # Convert the hex strings back to bytearrays and set the leaves and levels
        m_tree.leaves = [bytearray.fromhex(leaf) for leaf in merkle_tree_data["leaves"]]
        if merkle_tree_data["levels"] is not None:
            m_tree.levels = []
            for level in merkle_tree_data["levels"]:
                m_tree.levels.append([bytearray.fromhex(item) for item in level])
        m_tree.is_ready = merkle_tree_data["is_ready"]

        return m_tree


def validate_merkle_proof(proof, target_hash, merkle_root, hash_type="sha3_256"):
    """
    Validates a Merkle proof, verifying that a target element is part of a Merkle tree with a given root.

    A Merkle proof is a sequence of hashes that, when combined with the target hash through the hash function
    specified by `hash_type`, should result in the Merkle root if the target hash is indeed part of the tree.

    Parameters:
        proof (list of dicts): A list of dictionaries where each dictionary has one key, either 'left' or 'right',
            corresponding to whether the sibling hash at that level in the tree is to the left or right of the path
            leading to the target hash.
        target_hash (str): The hexadecimal string representation of the target hash being proven as part of the tree.
        merkle_root (str): The hexadecimal string representation of the Merkle root of the tree to which the target
            hash is being validated against.
        hash_type (str, optional): The type of hash function used to construct the Merkle tree. This must match the
            hash function used in constructing the original Merkle tree. Defaults to "sha3_256", and it must be an
            attribute of the `hashlib` module that takes a bytes object and returns a hash object that has a `digest`
            method.

    Returns:
        bool: Returns True if the Merkle proof is valid and the target hash is part of the tree with the given root.
              Returns False otherwise.

    Raises:
        AttributeError: If the `hash_type` specified is not an attribute of the `hashlib` module.
        KeyError: If one of the dictionaries in `proof` does not have a 'left' or 'right' key.
        ValueError: If `target_hash` or `merkle_root` or any of the sibling hashes in the proof dictionaries are not
                    valid hexadecimal strings.

    Example:
        # Example of validating a Merkle proof
        valid_proof = [{'left': 'abc...'}, {'right': 'def...'}]
        target = 'a1b2c3...'
        root = '123abc...'
        is_valid = validate_merkle_proof(valid_proof, target, root)
        print(is_valid)  # Outputs True if the proof is valid, False otherwise
    """
    hash_func = getattr(hashlib, hash_type)
    merkle_root = bytearray.fromhex(merkle_root)
    target_hash = bytearray.fromhex(target_hash)
    if len(proof) == 0:
        return target_hash == merkle_root
    else:
        proof_hash = target_hash
        for p in proof:
            try:
                # the sibling is a left node
                sibling = bytearray.fromhex(p["left"])
                proof_hash = hash_func(sibling + proof_hash).digest()
            except:  # TODO: do not use bare except
                # the sibling is a right node
                sibling = bytearray.fromhex(p["right"])
                proof_hash = hash_func(proof_hash + sibling).digest()
        return proof_hash == merkle_root
