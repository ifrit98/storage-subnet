#!/bin/bash

REDIS_CONF="/etc/redis/redis.conf"

check_redis_access() {
    # Test access with password
    if redis-cli -a $1 PING &> /dev/null; then
        echo "Access with password: Success"
    else
        echo "Access with password: Failure"
    fi

    # Test access without password
    output=$(redis-cli PING 2>&1)
    if [[ $output == *"NOAUTH Authentication required."* ]]; then
        echo "Access without password: Failure (AUTH required, as expected.)"
    else
        echo "Access without password: Success (AUTH not required! Lock down your Redis.)"
    fi
}

REDIS_PASSWORD=$(sudo grep -Po '^requirepass \K.*' $REDIS_CONF)

echo "Testing Redis access..."
check_redis_access $REDIS_PASSWORD
