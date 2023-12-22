#!/bin/bash

# Install dependencies
sudo apt-get update && sudo apt-get install -y curl build-essential protobuf-compiler clang git

# Install rust
curl https://sh.rustup.rs -sSf | sh -s -- -y

# Activate the rust environment and setup path
source "$HOME/.cargo/env"

# Get the subtensor repo
git clone https://github.com/opentensor/subtensor.git
cd subtensor

# Update to nightly rust/cargo 
./scripts/init.sh

# Build subtensor. This may take 5-10 minutes.
cargo build --release --features runtime-benchmarks --locked

# Return to storage-subnet directory
cd ../