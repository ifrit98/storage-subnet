# Subnet 21

![Subnet21](assets/Subnet21.png)

Subnet 21 implements a novel, multi-layered zero-knowledge interactive proof-of-spacetime algorithm by cleverly using Pedersen commitments, random challenges using elliptic curve cryptography, sequential seed-based chained hash verification, and merkle proofs to achieve an efficient, robust, secure, and highly available decetralized storage system on the Bittensor network. The system validates on encrypted user data, such that miners are unaware of what data they are storing, and only end-users may encrypt/decrypt the data they provide with their bittensor wallet coldkey.

We consider this system to be an important stepping stone so that bittensor can fulfill it's mission of democratizing intelligence, and a decentralized AWS platform is a key brick in this wall. 

> Note: The storage subnet is in an alpha stage and is subject to rapid development.

# Table of Contents for Subnet 21 Documentation

1. [Overview](#overview)
2. [What is a Decentralized Storage Network (DSN)?](#what-is-a-decentralized-storage-network-dsn)
   - [Role of a Miner (Prover)](#role-of-a-miner-prover)
   - [Role of a Validator (Verifier)](#role-of-a-validator-verifier)
3. [Main Features of Subnet 21](#main-features-of-subnet-21)
   - [Zero-Knowledge Proof of Space-Time System](#zero-knowledge-proof-of-space-time-system)
   - [Chained Proof Challenges](#chained-proof-challenges)
   - [Data Encryption and Zero-Knowledge Proofs for Privacy Preservation](#data-encryption-and-zero-knowledge-proofs-for-privacy-preservation)
   - [Scalability and Reliability](#scalability-and-reliability)
   - [Advanced Cryptographic Techniques](#advanced-cryptographic-techniques)
   - [User-Centric Approach](#user-centric-approach)
4. [Zero Knowledge Proof-of-Spacetime](#zero-knowledge-proof-of-spacetime)
   - [Storage Phase](#storage-phase)
   - [Challenge Phase](#challenge-phase)
   - [Retrieval Phase](#retrieval-phase)
5. [Installation](#installation)
   - [Running a Miner](#running-a-miner)
   - [Running a Validator](#running-a-validator)
6. [Documentation for Storage CLI Interface](#documentation-for-storage-cli-interface)
   - [Prerequisites](#prerequisites)
   - [Installation](#installation-1)
   - [Commands](#commands)
     - [Store: Storing Data on the Network](#store-storing-data-on-the-network)
     - [Retrieve: Retrieving Data from the Network](#retrieve-retrieving-data-from-the-network)
     - [Listing Stored Data](#listing-stored-data)
   - [Examples](#examples)
   - [General Options](#general-options)
   - [Notes](#notes)




## What is a Decentralized Storage Network (DSN)?
A DSN is a network architecture where data storage and management are distributed across various locations, controlled by multiple participants rather than a single entity. This approach enhances data security, availability, and resistance to censorship.

### Role of a Miner (Prover)
A miner in this context refers to a network participant responsible for storing and managing data. They prove the integrity and availability of the data they store through cryptographic methods, ensuring compliance with network protocols.

### Role of a Validator (Verifier)
A validator, on the other hand is a consumer of the proofs generated by the miner. They are responsible for maintaining an index of where data is stored and associated metadata for managing the system and maintainng data integrity and security.

## Main Features of Subnet 21

### Zero-Knowledge Proof of Space-Time System
- **Proof of Space-Time:** At its core, the application is built around a novel Zero-Knowledge Proof of Space-Time (ZK-PoST) algorithm. This algorithm allows validators to confirm that miners have consistently stored data over a period of time, offering a robust measure of data availability and integrity across the network.

### Chained Proof Challenges
- **Continuous Verification via Chained Challenges:** Validators issue sequential cryptographic challenges to miners. These challenges are linked or 'chained' together, ensuring that miners cannot predict future challenges and must consistently store the data to pass ongoing verifications.
- **Dynamic Challenge-Response Protocol:** This protocol is crucial for maintaining an ongoing verification system. Each challenge is dependent on the response to the previous one, forming a chain of trust and verification over time.

### Data Encryption and Zero-Knowledge Proofs for Privacy Preservation
- **Data Privacy Through Zero-Knowledge Proofs:** Validators verify the presence and integrity of data without accessing the actual content. This approach ensures data privacy, as miners are required to prove data storage without revealing the entire data itself.
- **Data Encryption:** All data is encrypted using bittensor wallet coldkey public/private key pairs, providing plug-n-play data storage for existing bittensor users.
- **Efficient and Secure Validation:** The system is designed to perform these verifications efficiently, minimizing computational overhead while maximizing security and privacy.

### Scalability and Reliability
- **Scalable Network Design:** The system is built to scale, capable of handling increasing storage demands and network growth without compromising performance.
- **High Data Availability and Fault Tolerance:** Data redundancy across multiple miners and continuous verification ensures high data availability and robustness against node failures.

### Advanced Cryptographic Techniques
- **Elliptic Curve Cryptography and Pedersen Commitments:** The application utilizes advanced cryptographic techniques, including ECC for efficient cryptographic operations, Pedersen Commitments for secure and private data commitments, and Merkle Trees for efficient proof of ownership verification.

### User-Centric Approach
- **Simplified User Experience:** Despite the underlying complexity, the system provides a straightforward interface for users to store and manage their data.
- **Assurance of Data Integrity and Availability:** Users can be confident in the integrity and availability of their data, backed by continuous cryptographic verification.

This ZK Proof of Space-Time system represents a significant advancement in decentralized storage, offering an efficient, secure, and private solution for data storage needs. It ensures that miners are honest and data is securely stored, while maintaining user privacy and system integrity.

## Zero Knowledge Proof-of-Spacetime

The algorithm comprises three phases:
- **Storage**: Miners store data locally and prove to the verifier (validator) that they have commited to the entire data block
- **Challenge**: Random challenges are issued by validators without advance warning, and miners must recommit to the entire data in order respond with the correct merkle proof.
- **Retrieval**: Upon retrieving data, miners are challenged to generate an efficient proof based on a random seed value that is sent back with the original data for verification.

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

# Documentation for Storage CLI Interface

## Overview
The Storage CLI provides a user-friendly command-line interface for storing and retrieving data on the Bittensor network. It simplifies the process of data encryption, storage, and retrieval, ensuring security and ease of use. This tool is ideal for users who need to manage data securely on a decentralized network.

## Prerequisites
Before using the Storage CLI, ensure that Bittensor is installed and your wallet (hotkey and coldkey) is properly configured.

## Commands

### 1. Store: Storing Data on the Network
This command encrypts and stores data on the Bittensor network.

#### Subcommands
- `put`: Encrypt and store data.

#### Usage
```bash
stcli store put --filepath <path-to-data> [options]
```

#### Options
- `--filepath <path-to-data>`: Path to the data file to be stored.
- `--hash_basepath <path>`: (Optional) Path to store the data hashes.
- `--stake_limit <float>`: (Optional) Stake limit to filter validator axons.
- `--wallet.name <name>`: (Optional) Wallet coldkey name.
- `--wallet.hotkey <name>`: (Optional) Hotkey name.

### 2. Retrieve: Retrieving Data from the Network
This command retrieves previously stored data from the Bittensor network.

#### Subcommands
- `list`: Lists all data associated with a specific coldkey.
- `get`: Retrieve and decrypt data.

#### Usage
```bash
stcli retrieve get --data_hash <hash> [options]
```

#### Options
- `--data_hash <hash>`: Hash of the data to retrieve.
- `--hash_basepath <path>`: (Optional) Path where data hashes are stored.
- `--stake_limit <float>`: (Optional) Stake limit for validator axons.
- `--storage_basepath <path>`: (Optional) Path to store retrieved data.
- `--wallet.name <name>`: (Optional) Wallet coldkey name.
- `--wallet.hotkey <name>`: (Optional) Hotkey name.

### Listing Stored Data
Lists all data hashes stored on the network associated with the specified coldkey.

#### Usage
```bash
stcli retrieve list [options]
```

#### Options
- `--hash_basepath <path>`: (Optional) Path where data hashes are stored.
- `--wallet.name <name>`: (Optional) Wallet coldkey name.

## Examples

### Storing Data
```bash
stcli store put --filepath ./example.txt --wallet.name mywallet --wallet.hotkey myhotkey
```

### Retrieving Data
```bash
stcli retrieve get --data_hash 123456789 --storage_basepath ./retrieved --wallet.name mywallet --wallet.hotkey myhotkey
```

### Listing Data
```bash
stcli retrieve list --wallet.name mywallet
```

## General Options
- `--help`: Displays help information about CLI commands and options.

## Notes
- Ensure your wallet is configured and accessible.
- File paths should be absolute or relative to your current directory.
- Data hashes are unique identifiers for your stored data on the Bittensor network.

For detailed instructions and more information, visit the [Bittensor Documentation](https://bittensor.com/docs).