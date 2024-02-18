#!/bin/bash

REDIS_CONF="/etc/redis/redis.conf"

if [ "$1" != "" ]; then
    REDIS_CONF="$1"
fi

sudo cp $REDIS_CONF "${REDIS_CONF}.bak"

sudo sed -i '/^save /d' $REDIS_CONF

sudo sed -i 's/^appendonly no/appendonly yes/' $REDIS_CONF

echo "RDB snapshots disabled, AOF persistence remains enabled."

sudo systemctl restart redis-server.service
echo "Redis restarted."

sudo systemctl status redis-server.service