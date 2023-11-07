"""
To ensure that the prover uses the whole data `D` in each commitment while not overburdening the verifier with the need to keep a history of all seeds, you can modify the protocol slightly. The key is to require the prover to perform an operation that cryptographically combines the new seed with both the original data and the previous commitment or seed. This operation should be constructed in such a way that it cannot be computed without possessing the original data.

Here's a protocol that achieves this:

1. **Initial Commitment**:
   - The verifier sends the initial random seed `S0` to the prover.
   - The prover has data `D`.
   - The prover computes the initial commitment `C0 = hash(D || S0)` (where `||` denotes concatenation) and sends `C0` to the verifier.

2. **Subsequent Commitments**:
   - For each new challenge, the verifier sends a new random seed `Sn` to the prover.
   - The prover computes the new commitment as `Cn = hash(hash(D || S(n-1)) || Sn)` and sends `Cn` to the verifier.
   - The `hash(D || S(n-1))` part ensures that the prover must use the original data `D` in combination with the last seed `S(n-1)` to create the new commitment.
   - The prover only needs to store the latest seed `S(n-1)` between challenges, not the entire history of seeds.

3. **Verification**:
   - To verify `Cn`, the verifier takes the previous commitment `C(n-1)` (which they have stored) and checks it against `hash(hash(D || S(n-1)) || Sn)`.
   - The prover should provide the verifier with the `hash(D || S(n-1))` part (as a proof) and the new commitment `Cn`. The verifier can then check that `Cn = hash(proof || Sn)`.
   - If `Cn` matches the verifier's computation, it is assured that the prover used the correct `D` and `S(n-1)`.

4. **Continuing the Chain**:
   - The process repeats for each new challenge issued by the verifier, with each new commitment depending on the original data and the last seed, but the verifier only needs to keep the current seed and the last commitment.

In this revised protocol, the verifier does not need to keep all the seeds—just the current seed and the last commitment. At the same time, the prover is required to use the original data `D` for every new commitment, ensuring that they continuously store the data.

It is crucial to note that for this to work as intended, the prover must not be able to precompute future commitments without receiving the next seed `Sn` from the verifier. Therefore, the verifier must ensure that seeds are unpredictable and securely communicated to the prover.

As with all cryptographic protocols, careful analysis is essential to ensure security. Such a protocol would need to be vetted for potential vulnerabilities, preferably by a security expert with experience in cryptographic protocols.
"""


import hashlib
import os


def hash_data(data):
    """Hash the data using SHA-256."""
    return hashlib.sha256(data).hexdigest()


def generate_random_seed():
    """Generate a random seed."""
    return os.urandom(16)  # 128-bit random seed


def compute_initial_commitment(data, seed):
    """Compute the initial commitment from the data and seed."""
    return hash_data(data + seed)


def compute_subsequent_commitment(data, previous_seed, new_seed):
    """Compute a subsequent commitment based on the original data, previous seed, and new seed."""
    proof = hash_data(data + previous_seed)
    return hash_data(proof.encode("utf-8") + new_seed)


def verify_commitment(proof, seed, commitment):
    """Verify a commitment using the proof, seed, and commitment."""
    return hash_data(proof.encode("utf-8") + seed) == commitment


# Example usage
# Verifier side
data = b"The original data to be committed to."
initial_seed = generate_random_seed()
initial_commitment = compute_initial_commitment(data, initial_seed)
print(f"Initial Commitment: {initial_commitment}")

# Prover side
# Subsequent commitment, assuming the prover receives a new seed from the verifier
new_seed = generate_random_seed()
subsequent_commitment = compute_subsequent_commitment(data, initial_seed, new_seed)
proof = hash_data(data + initial_seed)  # This would be provided to the verifier
print(f"Subsequent Commitment: {subsequent_commitment}")

# Verifier side
# Verifier verifies the new commitment using the proof and new seed
if verify_commitment(proof, new_seed, subsequent_commitment):
    print("Commitment verified successfully.")
else:
    print("Commitment verification failed.")
