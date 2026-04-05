# utils.py
import winreg
import os
from datetime import datetime

HIVE_NAMES = {
    winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
    winreg.HKEY_CURRENT_USER:  "HKEY_CURRENT_USER",
}


def hive_name(hive):
    return HIVE_NAMES.get(hive, str(hive))


def read_registry_key(hive, subkey):
    values = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    values[name] = str(data)
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        return None
    except PermissionError:
        return None
    return values


def ensure_dirs():
    os.makedirs("data/logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("data", exist_ok=True)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
