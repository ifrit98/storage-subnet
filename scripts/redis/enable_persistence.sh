#!/bin/bash

REDIS_CONF="/etc/redis/redis.conf"

if [ "$1" != "" ]; then
    REDIS_CONF="$1"
fi

# Backup original configuration file
sudo cp $REDIS_CONF "${REDIS_CONF}.bak"

# Enable AOF persistence
sudo sed -i 's/^appendonly no/appendonly yes/' $REDIS_CONF
sudo sed -i 's/^# appendfsync everysec/appendfsync everysec/' $REDIS_CONF

echo "Redis persistence configuration updated."

# Restart Redis server
sudo systemctl restart redis-server.service
echo "Redis restarted."

sudo systemctl status redis-server.service
