# baseline.py
import json
import os
from config import ALL_MONITOR_KEYS, BASELINE_FILE
from utils import read_registry_key, hive_name, timestamp


def capture_baseline():
    snapshot = {}
    for hive, subkey in ALL_MONITOR_KEYS:
        key_id = f"{hive_name(hive)}\\{subkey}"
        vals = read_registry_key(hive, subkey)
        snapshot[key_id] = vals if vals is not None else {}
    with open(BASELINE_FILE, "w") as f:
        json.dump({"timestamp": timestamp(), "snapshot": snapshot}, f, indent=2)
    return snapshot


def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE) as f:
        data = json.load(f)
    return data.get("snapshot", data)
