#!/bin/bash

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
    echo "UFW is not installed. Exiting."
    exit 1
fi

# Ensure UFW is enabled
ufw status | grep -q inactive && ufw enable

# Deny all external traffic to port 6379
ufw deny 6379

# Allow all local traffic to port 6379
ufw allow from 127.0.0.1 to any port 6379

# Reload UFW to apply changes
ufw reload

echo "UFW rules updated."
