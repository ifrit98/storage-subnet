FROM python:3.10.12-slim
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

RUN apt-get update && \
    apt-get install -y git lsb-release curl gpg

RUN curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg

RUN echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list

RUN apt-get update && \
    apt-get install -y redis

RUN python3.10 -m venv venv

ENV PATH=/app/venv/bin:$PATH

WORKDIR /root/.bittensor
COPY . /root/.bittensor

RUN python -m pip install -e .

ARG WANDB_API_KEY
ENV WANDB_API_KEY=$WANDB_API_KEY
RUN wandb login

RUN git config --global --add safe.directory /root/.bittensor
