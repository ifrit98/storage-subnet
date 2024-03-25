import subprocess
import time
import asyncio
import re
import os
import bittensor as bt
from redis import asyncio as aioredis

from storage.shared.utils import is_running_in_docker


async def check_environment(
    redis_conf_path: str = "/etc/redis/redis.conf",
    redis_host: str = "localhost",
    redis_port: int = 6379,
    redis_password: str = "nopasswd"
):
    _check_redis_config(redis_conf_path)
    _check_redis_settings(redis_conf_path)
    _assert_setting_exists(redis_conf_path, "requirepass")
    await _check_redis_connection(redis_conf_path, redis_host, redis_port, redis_password)
    if not is_running_in_docker:
        await _check_data_persistence(redis_conf_path, redis_host, redis_port, redis_password)


def _check_redis_config(path):
    cmd = ["test", "-f", path] if is_running_in_docker() else ["sudo", "test", "-f", path]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        raise AssertionError(f"Redis config file path: '{path}' does not exist.")


def _check_redis_settings(redis_conf_path):
    settings_to_check = [
        ("appendonly", ["appendonly yes"]),
    ]

    for setting, expected_values in settings_to_check:
        _check_redis_setting(redis_conf_path, setting, expected_values)


async def _check_redis_connection(redis_conf_path, host, port, passwd):
    assert port is not None, "Redis server port not found"
    try:
        client = aioredis.StrictRedis(
            host=host,
            port=port, db=0,
            password=passwd, socket_connect_timeout=1
        )
        await client.ping()
    except Exception as e:
        assert False, f"Redis connection failed. ConnectionError'{e}'"


async def _check_data_persistence(redis_conf_path, host, port, passwd):
    assert port is not None, "Redis server port not found"
    client = aioredis.StrictRedis(host=host, port=port, db=0, password=passwd)

    # Insert data into Redis
    await client.set("testkey", "Hello, Redis!")

    # Restart Redis server
    cmd = ["systemctl", "restart", "redis-server.service"] if is_running_in_docker() else [
        "sudo", "systemctl", "restart", "redis-server.service"
    ]
    subprocess.run(cmd, check=True)

    # Wait a bit to ensure Redis has restarted
    await asyncio.sleep(5)

    # Reconnect to Redis
    assert port is not None, "Redis server port not found after restart"
    new_redis = aioredis.StrictRedis(port=port, db=0, password=passwd)

    # Retrieve data from Redis
    value = await new_redis.get("testkey")

    # Clean up
    await new_redis.delete("testkey")

    await new_redis.aclose()
    del new_redis

    # Check if the value is what we expect
    assert (
        value.decode("utf-8") == "Hello, Redis!"
    ), "Data did not persist across restart."


def _check_redis_setting(file_path, setting, expected_values):
    """Check if Redis configuration contains all expected values for a given setting."""
    actual_values = _assert_setting_exists(file_path, setting)
    assert sorted(actual_values) == sorted(
        expected_values
    ), f"Configuration for '{setting}' does not match expected values. Got '{actual_values}', expected '{expected_values}'"


def _assert_setting_exists(file_path, setting):
    actual_values = _get_redis_setting(file_path, setting)
    assert actual_values is not None, f"Redis config missing setting '{setting}'"
    return actual_values


def _get_redis_setting(file_path, setting):
    """Retrieve specific settings from the Redis configuration file."""
    cmd = ["grep", f"^{setting}", file_path] if is_running_in_docker() else [
        "sudo", "grep", f"^{setting}", file_path
    ]
    try:
        result = subprocess.check_output(
            cmd, text=True
        )
        return result.strip().split("\n")
    except subprocess.CalledProcessError:
        return None


def _get_redis_password(redis_conf_path):
    try:
        cmd = f"sudo grep -Po '^requirepass \K.*' {redis_conf_path}"
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        assert False, f"Command failed: {e}"
    except Exception as e:
        assert False, f"An error occurred: {e}"

    return None


def check_registration(subtensor, wallet, netuid):
    if not subtensor.is_hotkey_registered(
        netuid=netuid,
        hotkey_ss58=wallet.hotkey.ss58_address,
    ):
        bt.logging.error(
            f"Wallet: {wallet} is not registered on netuid {netuid}"
            f"Please register the hotkey using `btcli subnets register` before trying again"
        )
        exit()

    pass
