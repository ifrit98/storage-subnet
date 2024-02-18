#!/bin/bash

REDIS_CONF="/etc/redis/redis.conf"
REDIS_PASSWORD=$(sudo grep -Po '^requirepass \K.*' $REDIS_CONF)

# Insert data into Redis
redis-cli -a $REDIS_PASSWORD SET testkey "Hello, FileTao!"

# Restart Redis server
sudo systemctl restart redis-server.service

# Wait a bit to ensure Redis has restarted
sleep 5

# Retrieve data from Redis
value=$(redis-cli -a $REDIS_PASSWORD GET testkey)

# Check if the value is what we expect
if [ "$value" = "Hello, FileTao!" ]; then
    echo "Test passed: Data persisted across restart."
else
    echo "Test failed: Data did not persist."
fi
