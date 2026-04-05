# monitor.py
from config import ALL_MONITOR_KEYS
from utils import read_registry_key, hive_name


def take_snapshot():
    snap = {}
    for hive, subkey in ALL_MONITOR_KEYS:
        key_id = f"{hive_name(hive)}\\{subkey}"
        snap[key_id] = read_registry_key(hive, subkey) or {}
    return snap
