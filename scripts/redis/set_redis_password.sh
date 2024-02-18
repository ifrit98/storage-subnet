#!/bin/bash

generate_password() {
    openssl rand -base64 20
}

REDIS_CONF="/etc/redis/redis.conf"

REDIS_PASSWORD=$(generate_password)

# Backup the config file
sudo cp $REDIS_CONF "${REDIS_CONF}.bak"

# Update Redis configuration with the password
if sudo grep -q "^requirepass " $REDIS_CONF; then
    # Update the existing requirepass line
    sudo sed -i "/^requirepass /c\requirepass $REDIS_PASSWORD" $REDIS_CONF
elif sudo grep -q "^# *requirepass " $REDIS_CONF; then
    # Uncomment and update the requirepass line
    sudo sed -i "s/^# *requirepass .*/requirepass $REDIS_PASSWORD/" $REDIS_CONF
else
    # Add a new requirepass line at the end of the file
    echo "requirepass $REDIS_PASSWORD" | sudo tee -a $REDIS_CONF > /dev/null
fi

# Restart Redis server using systemctl
sudo systemctl restart redis-server.service

# Export password for current session (optional)
export REDIS_PASSWORD

# Check the status of Redis
sudo systemctl status redis-server.service

# Verify that the password was set in the configuration file
echo "Password set in Redis config:"

# Set the password as an environment variable for the current session
export REDIS_PASSWORD=$(sudo grep -Po '^requirepass \K.*' $REDIS_CONF)