# Subnet 21
Subnet 21 implements a novel, multi-layered zero-knowledge interactive proof-of-spacetime algorithm by cleverly using Pedersen commitments, random challenges using elliptic curve cryptography, sequential seed-based chained hash verification, and merkle proofs to achieve an efficient, robust, secure, and highly available decetralized storage system on the Bittensor network. The system validates on encrypted user data, such that miners are unaware of what data they are storing, and only end-users may encrypt/decrypt the data they provide with their bittensor wallet coldkey.

We consider this system to be an important stepping stone so that bittensor can fulfill it's mission of democratizing intelligence, and a decentralized AWS platform is a key brick in this wall. 

## Zero Knowledge Proof-of-Spacetime

The algorithm comprises three phases:
- **Storage**: Miners store data locally and prove to the verifier (Validator) that they have commited to the entire data block
- **Challenge**: Random challenges are issued by validators without advance warning, and miners must recommit to the entire data in order respond with the correct merkle proof.
- **Retrieval**: Upon retrieving data, miners are challenged to generate an efficient proof based on a random seed value that is sent back with the original data for verification.

> Note: The storage subnet is in an alpha stage and is subject to rapid development.

### Storage Phase

In the Store phase, the goal is to securely store data and create a commitment to prove its storage without revealing the data itself. The mathematical steps are:

Validators query miners to store user data that is encrypted by the end-user coldkey pubkey. The encrypted data is sent to miners along with a random seed, which the miners use to initiate a sequential chain of seed + hash verification proofs. The previous seed value and the data is required for each subsequent commitment proof. The miner then applies a Pedersen committment to the entire data using the random seed, and forwards the proofs to the validator.

Upon receipt, validators verify the commitment and the initial hash chain, storing the associated metadata.


1. **Data Encryption**:
   - Data `D` is encrypted using a symmetric encryption scheme whos keys are .
   - Encrypted Data: `encrypted_D = encrypt(D, key)`.

2. **Hashing and Commitment**:
   - Hash the encoded data with a unique random seed to create a unique identifier for the data.
   - Data Hash: `data_hash = hash(encrypted_D + r_seed)`.
   - Create a cryptographic commitment using an Elliptic Curve Commitment Scheme (ECC), which involves a commitment function `commit` with curve points `g` and `h`.
   - Pedersen Commitment: `(c, m, r) = commit(encrypted_D + seed)`, where `c` is the commitment, `m` is the message (or commitment hash), and `r` is the randomness used in the commitment.
   - Chained Hash Proof: `m` is used as the initial `C_0`, which contains the initial random seed and the data itself. The random seed is stored for the next challenge in the chain.

3. **Storage**:
   - Store the data (`E`) and the random seed (`r_seed`) in local storage.


### Challenge Phase
In the Challenge phase, the system verifies the possession of the data without actually retrieving the data itself.

Validators request the miner prove that it currently stores the data claimed by issuing an index-based challenge, where the miner must apply Pedersen committments to the entire data table given a random seed and a chunk size. 

Data is chunked according to the chunk size, and each slice is committed using a Pederson commitment with the random seed. Each commitment is appended to a merkle tree, and a subsequent proof is generated to obtain the path along the merkle tree such that a validator can verify the random seed was indeed used to commit to each data chunk at challenge time, thus proving the miner has the data at time of the challenge. 

The mathematical operations involved in the "Store", "Challenge", and "Retrieve" phases of this data storage and verification system can be broken down into a few key steps. Here's a simplified explanation for each phase:


1. **Chunking Data**:
   - The encrypted data is split into chunks: `chunks = chunk(encrypted_D, chunk_size)`.

2. **Selecting a Chunk for Challenge**:
   - A random chunk is selected for the challenge.
   - Selected Chunk: `chunk_j = chunks[j]`.

3. **Computing Commitment for the Chunk**:
   - A commitment is computed for the selected chunk.
   - Commitment for Chunk: `(c_j, m_j, r_j) = commit(chunk_j + seed)`.

4. **Creating a Merkle Tree**:
   - A Merkle tree is constructed using all chunk commitments.
   - Merkle Tree: `merkle_tree = MerkleTree([c_1, c_2, ..., c_n])`.

5. **Generating Merkle Proof**:
   - A Merkle proof is generated for the selected chunk to recreate the path along the merkle tree to the leaf that represents `chunk_j`.
   - Merkle Proof: `proof_j = merkle_tree.get_proof(j)`.

6. **Generating chained commitment**:
   - Compute commitment hash `Cn = hash( hash( encrypted_D + prev_seed ) + new_seed )`
   - Update previous seed `prev_seed = new_seed`

7. **Response**:
   - The challenge response includes the Pedersen elliptic curve commitment, the chained commitment hash, the Merkle proof, and the Merkle tree root.
   - The validator verifies the triple of proofs: chained commitment, elliptic-curve commitment, and the merkle proof.
 

### Retrieval Phase

In this phase, the data is retrieved, decrypted, and its integrity is verified.

1. **Fetching Encrypted Data**:
   - The encrypted data is fetched from the database based on its hash.
   - `encrypted_D = fetch(data_hash)`.

2. **Chained Verification Challenge**:
   - A new commitment is computed on the encrypted data with a new seed and the previous seed.
       - `Ch = hash( hash( encrypted_D + prev_seed ) + new_seed )`.

3. **Data Integrity Check**:
   - The retrieved data's integrity is verified by checking if the newly computed commitment matches the expected value.
   - `verify_chained(commitment, expected_commitment) == True`.

5. **Decryption**:
   - The data is decrypted using the symmetric encryption key and returned to the end-user.
   - Decrypted Data: `D = decrypt(encrypted_D, key)`.

In each phase, cryptographic primitives ensure data integrity and confidentiality. The encryption and commitment schemes ensure the data's security, while Merkle trees and random challenges provide a robust method for verifying data possession without revealing the actual data.

In each phase, cryptographic primitives like hashing, commitment schemes (e.g., Elliptic Curve Cryptography and Pedersen commitments), and data structures like Merkle trees are employed to ensure the integrity, confidentiality, and availability of the data. The use of seeds and randomness in commitments adds an additional layer of security and ensures that each instance of data storage and retrieval is unique and verifiable.



## Installation
```bash
git clone https://github.com/ifrit98/storage-subnet
cd storage-subnet
python -m pip install -e .
```

### Running a miner
```bash
python neurons/miner.py --wallet.name <NAME> --wallet.hotkey <HOTKEY>
```

### Running a validator
```bash
python neurons/validator.py --wallet.name <NAME> --wallet.hotkey <HOTKEY>
```