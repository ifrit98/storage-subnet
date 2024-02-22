# Run filetao with docker

- To run the defined docker compose services {filetao-miner-prod, filetao-validator-prod, redis} you will need the followings environment variables:
    - `BT_WALLETS_BASE_PATH`: The base path of your bittensor wallets. Typically equivalent to `$HOME`.
    - `REDIS_PASSWORD`: Your redis instance password.
    - `REDIS_PORT`: Port to run redis within a docker container (same port is exposed)
    - `REDIS_CONF`: Your redis conf path. If you use the base one provided in this repository it could be `./config/redis-docker.conf`.
    - `FILETAO_NODE`: Type of node you want to run. To be miner, validator or api.
    - `FILETAO_WALLET`: Bittensor wallet name to use.
    - `FILETAO_HOTKEY`: Bittensor hotkey name to use.
    - `FILETAO_NETUID`: Net UID of the bittensor subnet to connect.
    - `FILETAO_SUBTENSOR`: Subtensor network to connect.
    - `FILETAO_EXTERNAL_PORT`: Port to be used externally (in the host) by the neuron's container.
    - `FILETAO_API_EXTERNAL_PORT`: Port to be used externally (in the host) by the api neuron's container
    - `FILETAO_MINER_DATA_DIR`: Host data directory to be mapped to the neuron's container (used in the miner neuron)
    - `FILETAO_EXTRA_OPTIONS`: Extra options to be added, not specified in the rest of the ENVVARs, like `--wandb.off` or `--logging.debug`.
- Since some of env vars could be shared between containers, if you run validator or miner or the api in the same host, we recommend you to have 2 environment files:
    - common.env
    - filetao-(miner|validator|api)-prod.env
- Once you have the needed env files, you can run the docker compose containers defined. If you have followed the suggested steps, you can use the following commands:
    - Running miner: `sudo docker compose --env-file common.env --env-file filetao-miner.env up --build filetao-miner-prod`
    - Running validator: `sudo docker compose --env-file common.env --env-file filetao-validator.env up --build filetao-validator-prod`
    - Running api: `sudo docker compose --env-file common.env --env-file filetao-api.env up --build filetao-api-prod`

> If you just use one env file you would need just one --env-file option :)