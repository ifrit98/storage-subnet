# Setup miners on the network
PYTHON_PATH=$(which python)

pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner1 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner6   --axon.port 11111
pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner2 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner7   --axon.port 11112
pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner3 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner41  --axon.port 11113
pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner4 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner44  --axon.port 11114
pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner5 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey miner46  --axon.port 11115
pm2 start ../neurons/miner.py --interpreter "$PYTHON_PATH" --name miner6 -- --netuid 22 --subtensor.network test --wandb.off --logging.debug --wallet.name default --wallet.hotkey default  --axon.port 11116

# Run an api node in a separate shell
python neurons/api.py --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey validator --wandb.off --logging.debug --axon.port 11118


## Start with a simple text file
# Store precomputed text
ftcli store put --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --filepath test.txt --noencrypt

# Retrieve the file from the network
ftcli retrieve get --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --data_hash 38866360490337421968271411759171270733697519958661904670309117221177014022402

## Now do a 100mb file
# Store precomputed file 100mb of random data
ftcli store put --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --filepath test100mb --noencrypt

# Retrieve the file from the network
ftcli retrieve get --subtensor.network test --netuid 22 --wallet.name default --wallet.hotkey default --data_hash 15772073926083259344852907111708835015326625089316697045050481472999350095520

# Verify the storage using a python script
python verify_storage.py