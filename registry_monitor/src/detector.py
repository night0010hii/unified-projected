# detector.py
from config import MALWARE_PATTERNS
from utils import timestamp


def check_malware_patterns(key_path, values):
    alerts = []
    if not values:
        return alerts
    for value_name, (bad_value, message) in MALWARE_PATTERNS.items():
        if value_name in values:
            current = values[value_name]
            if bad_value is None or current == bad_value:
                alert = f"[{timestamp()}] {key_path} | {value_name}={current} | {message}"
                alerts.append(alert)
    return alerts


def diff_snapshots(old_snap, new_snap):
    changes = []
    all_keys = set(old_snap.keys()) | set(new_snap.keys())
    for key in all_keys:
        old_vals = old_snap.get(key) or {}
        new_vals = new_snap.get(key) or {}
        if key not in old_snap:
            changes.append({"type": "KEY_ADDED",   "key": key,
                           "name": None, "old": None, "new": str(new_vals)})
            continue
        if key not in new_snap:
            changes.append({"type": "KEY_DELETED", "key": key,
                           "name": None, "old": str(old_vals), "new": None})
            continue
        for vname in set(old_vals) | set(new_vals):
            ov, nv = old_vals.get(vname), new_vals.get(vname)
            if ov is None and nv is not None:
                changes.append({"type": "VALUE_ADDED",    "key": key,
                               "name": vname, "old": None, "new": nv})
            elif ov is not None and nv is None:
                changes.append({"type": "VALUE_DELETED",  "key": key,
                               "name": vname, "old": ov,   "new": None})
            elif ov != nv:
                changes.append({"type": "VALUE_MODIFIED", "key": key,
                               "name": vname, "old": ov,   "new": nv})
    return changes
