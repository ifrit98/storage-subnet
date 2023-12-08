# Setup miners on the network
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner1 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner6   --axon.port 11111
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner2 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner7   --axon.port 11112
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner3 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner41  --axon.port 11113
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner4 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner44  --axon.port 11114
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner5 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner46  --axon.port 11115
pm2 start ../neurons/miner.py --interpreter /home/phil/miniconda3/envs/storage/bin/python --name miner6 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey default  --axon.port 11118

# Run an api node in a separate shell
python neurons/api.py --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey validator --wandb.off --logging.debug --axon.port 11118


## Start with a simple text file
# Store precomputed file 100mb of random data
stcli store put --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --filepath test100mb --noencrypt

# Retrieve the file from the network
stcli retrieve get --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --data_hash 43743967328039940218946614201037467529006670990033448026544300869494786726721

## Now do a 100mb file
# Store precomputed file 100mb of random data
stcli store put --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --filepath test100mb --noencrypt

# Retrieve the file from the network
stcli retrieve get --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --data_hash 10640854667234103088456065167400853561871673685400658931716168102369399248095

# Verify the storage using a python script
python verify_storage.py