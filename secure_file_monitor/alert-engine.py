"""
Secure File Transfer Monitoring System
Alert Engine Module
"""

import json
import os
from datetime import datetime

ALERT_FILE = "logs/alerts.json"

ALERT_TYPES = {
    "UNAUTHORIZED_TRANSFER": "🔴 CRITICAL",
    "INTEGRITY_VIOLATION":   "🔴 CRITICAL",
    "SENSITIVE_FILE_DELETED": "🟠 HIGH",
    "BULK_TRANSFER":         "🟠 HIGH",
    "SUSPICIOUS_PROCESS":    "🟡 MEDIUM",
    "UNKNOWN_DESTINATION":   "🟡 MEDIUM",
    "INFO":                  "🟢 INFO",
}


def load_alerts() -> list:
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            return json.load(f)
    return []


def save_alerts(alerts: list):
    os.makedirs("logs", exist_ok=True)
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=2)


def raise_alert(alert_type: str, message: str, details: dict = None):
    """Create and save an alert."""
    severity = ALERT_TYPES.get(alert_type, "🟢 INFO")
    alert = {
        "id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:17]}",
        "timestamp": datetime.now().isoformat(),
        "type": alert_type,
        "severity": severity,
        "message": message,
        "details": details or {},
        "acknowledged": False,
    }
    alerts = load_alerts()
    alerts.append(alert)
    save_alerts(alerts)
    print(f"\n{severity} ALERT [{alert_type}]")
    print(f"   {message}")
    return alert


def acknowledge_alert(alert_id: str):
    """Mark an alert as acknowledged."""
    alerts = load_alerts()
    for a in alerts:
        if a["id"] == alert_id:
            a["acknowledged"] = True
            print(f"✅ Alert {alert_id} acknowledged.")
    save_alerts(alerts)


def list_alerts(unacknowledged_only: bool = False):
    """Print all alerts."""
    alerts = load_alerts()
    if unacknowledged_only:
        alerts = [a for a in alerts if not a["acknowledged"]]

    if not alerts:
        print("No alerts found.")
        return

    print("\n" + "═" * 60)
    print("  ALERT LOG")
    print("═" * 60)
    for a in alerts:
        ack = "[ACK]" if a["acknowledged"] else "[NEW]"
        print(f"\n  {ack} {a['severity']} — {a['type']}")
        print(f"       ID   : {a['id']}")
        print(f"       Time : {a['timestamp']}")
        print(f"       Msg  : {a['message']}")
    print("═" * 60)


def detect_bulk_transfer(log_file: str = "logs/file_transfer_log.json", threshold: int = 50):
    """Check if bulk transfer is happening in a short window."""
    if not os.path.exists(log_file):
        return
    with open(log_file, "r") as f:
        logs = json.load(f)

    # Count events in last 60 seconds
    now = datetime.now()
    recent = []
    for ev in logs:
        try:
            t = datetime.fromisoformat(ev["timestamp"])
            if (now - t).seconds <= 60:
                recent.append(ev)
        except Exception:
            pass

    if len(recent) >= threshold:
        raise_alert(
            "BULK_TRANSFER",
            f"{len(recent)} file events detected in the last 60 seconds.",
            {"event_count": len(recent), "threshold": threshold}
        )


if __name__ == "__main__":
    list_alerts()
