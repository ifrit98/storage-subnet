ARG BASE_IMAGE=python:3.10.12-slim
FROM $BASE_IMAGE AS builder-prod

# This is being set so that no interactive components are allowed when updating.
ARG DEBIAN_FRONTEND=noninteractive

# Create directory to copy files to
RUN mkdir /install/
WORKDIR /install

# Copy our sources
COPY ./neurons /install/neurons
COPY ./storage /install/storage
COPY ./scripts /install/scripts
COPY ./setup.py /install/setup.py
COPY ./requirements.txt /install/requirements.txt
COPY ./requirements-dev.txt /install/requirements-dev.txt
COPY ./README.md /install/README.md

RUN python -m pip install --prefix=/install .

#
# Stage for running filetao on productive servers
#
FROM $BASE_IMAGE AS filetao-prod

ARG NEURON_TYPE=miner
ARG WANDB_API_KEY

COPY --from=builder-prod /install/bin/ /usr/local/bin
COPY --from=builder-prod /install/lib/ /usr/local/lib

RUN mkdir -p ~/.bittensor/wallets && \
    mkdir -p /etc/redis/

ENV PATH="${PATH}:/usr/local/bin:/usr/local/lib"
ENV WANDB_API_KEY=$WANDB_API_KEY
ENV REBALANCE_SCRIPT_PATH=/install/scripts/rebalance_deregistration.sh

#RUN wandb login
