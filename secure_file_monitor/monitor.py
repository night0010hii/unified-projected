"""
Secure File Transfer Monitoring System
Core Monitor Module
"""

import os
import time
import hashlib
import json
import shutil
import logging
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────
SENSITIVE_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
]

SENSITIVE_EXTENSIONS = [".pdf", ".docx", ".xlsx",
                        ".csv", ".txt", ".pptx", ".db", ".sql"]

SUSPICIOUS_DESTINATIONS = [
    os.path.expanduser("~/Downloads"),
    "/tmp",
    "/media",       # USB mounts on Linux
    "/mnt",
]

LOG_FILE = "logs/file_transfer_log.json"
ALERT_FILE = "logs/alerts.json"
HASH_DB_FILE = "logs/hash_db.json"
REPORT_FILE = "logs/audit_report.txt"

# ─── Setup Logging ─────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureMonitor")

# ─── Utility Functions ─────────────────────────────────────────────────────────


def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Compute SHA256 or MD5 hash of a file."""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        logger.warning(f"Cannot hash {filepath}: {e}")
        return "UNREADABLE"


def load_json(filepath: str) -> list | dict:
    """Load JSON file or return empty structure."""
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return [] if "log" in filepath or "alert" in filepath else {}


def save_json(filepath: str, data):
    """Save data to JSON file."""
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)


def is_sensitive(filepath: str) -> bool:
    """Check if file is sensitive based on path or extension."""
    path = Path(filepath)
    ext = path.suffix.lower()
    if ext in SENSITIVE_EXTENSIONS:
        return True
    for sensitive_dir in SENSITIVE_DIRS:
        if filepath.startswith(sensitive_dir):
            return True
    return False


def is_suspicious_destination(filepath: str) -> bool:
    """Check if destination is a suspicious/outbound location."""
    for dest in SUSPICIOUS_DESTINATIONS:
        if filepath.startswith(dest):
            return True
    return False


def log_event(event_data: dict):
    """Append event to the log file."""
    logs = load_json(LOG_FILE)
    logs.append(event_data)
    save_json(LOG_FILE, logs)


def log_alert(alert_data: dict):
    """Append alert to the alert file."""
    alerts = load_json(ALERT_FILE)
    alerts.append(alert_data)
    save_json(ALERT_FILE, alerts)
    logger.warning(f"🚨 ALERT: {alert_data['message']}")


def update_hash_db(filepath: str, file_hash: str):
    """Update the hash database for a file."""
    db = load_json(HASH_DB_FILE)
    db[filepath] = {"hash": file_hash, "timestamp": datetime.now().isoformat()}
    save_json(HASH_DB_FILE, db)


def check_integrity(filepath: str) -> dict:
    """Check file integrity against stored hash."""
    db = load_json(HASH_DB_FILE)
    current_hash = compute_hash(filepath)
    result = {
        "filepath": filepath,
        "current_hash": current_hash,
        "stored_hash": None,
        "status": "NEW",
    }
    if filepath in db:
        stored = db[filepath]["hash"]
        result["stored_hash"] = stored
        result["status"] = "OK" if current_hash == stored else "TAMPERED"
    return result


# ─── Event Handler ─────────────────────────────────────────────────────────────

class FileTransferHandler(FileSystemEventHandler):

    def _build_event(self, event_type: str, src: str, dest: str = None) -> dict:
        return {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source_path": src,
            "destination_path": dest or "N/A",
            "sensitive": is_sensitive(src),
            "suspicious_dest": is_suspicious_destination(dest or ""),
            "file_hash": compute_hash(src) if os.path.isfile(src) else "N/A",
        }

    def on_created(self, event):
        if event.is_directory:
            return
        ev = self._build_event("CREATED", event.src_path)
        log_event(ev)
        update_hash_db(event.src_path, ev["file_hash"])
        if ev["sensitive"]:
            logger.info(f"📁 Sensitive file created: {event.src_path}")

    def on_modified(self, event):
        if event.is_directory:
            return
        integrity = check_integrity(event.src_path)
        ev = self._build_event("MODIFIED", event.src_path)
        ev["integrity_status"] = integrity["status"]
        log_event(ev)

        if integrity["status"] == "TAMPERED":
            log_alert({
                "timestamp": datetime.now().isoformat(),
                "type": "INTEGRITY_VIOLATION",
                "message": f"File tampered: {event.src_path}",
                "details": integrity,
            })
        update_hash_db(event.src_path, ev["file_hash"])

    def on_deleted(self, event):
        if event.is_directory:
            return
        ev = self._build_event("DELETED", event.src_path)
        log_event(ev)
        if ev["sensitive"]:
            log_alert({
                "timestamp": datetime.now().isoformat(),
                "type": "SENSITIVE_FILE_DELETED",
                "message": f"Sensitive file deleted: {event.src_path}",
                "details": ev,
            })

    def on_moved(self, event):
        if event.is_directory:
            return
        ev = self._build_event("MOVED", event.src_path, event.dest_path)
        log_event(ev)

        if ev["sensitive"] and ev["suspicious_dest"]:
            log_alert({
                "timestamp": datetime.now().isoformat(),
                "type": "UNAUTHORIZED_TRANSFER",
                "message": f"Sensitive file moved to suspicious location: {event.dest_path}",
                "details": ev,
            })
        update_hash_db(event.dest_path, ev["file_hash"])


# ─── Baseline Hash Snapshot ────────────────────────────────────────────────────

def take_baseline_snapshot(directories: list):
    """Hash all files in monitored directories for baseline."""
    logger.info("📸 Taking baseline snapshot...")
    db = {}
    for directory in directories:
        if not os.path.exists(directory):
            continue
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                h = compute_hash(fpath)
                db[fpath] = {"hash": h,
                             "timestamp": datetime.now().isoformat()}
    save_json(HASH_DB_FILE, db)
    logger.info(f"✅ Baseline snapshot: {len(db)} files hashed.")


# ─── Audit Report Generator ────────────────────────────────────────────────────

def generate_report():
    """Generate a plain-text audit report."""
    logs = load_json(LOG_FILE)
    alerts = load_json(ALERT_FILE)

    total = len(logs)
    sensitive_events = [e for e in logs if e.get("sensitive")]
    tampered = [e for e in logs if e.get("integrity_status") == "TAMPERED"]
    unauthorized = [a for a in alerts if a.get(
        "type") == "UNAUTHORIZED_TRANSFER"]

    report = f"""
╔══════════════════════════════════════════════════════════════╗
║       SECURE FILE TRANSFER MONITORING — AUDIT REPORT        ║
╚══════════════════════════════════════════════════════════════╝
Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total File Events        : {total}
  Sensitive File Events    : {len(sensitive_events)}
  Integrity Violations     : {len(tampered)}
  Unauthorized Transfers   : {len(unauthorized)}
  Total Alerts             : {len(alerts)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ALERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    if alerts:
        for a in alerts:
            report += f"\n  [{a['timestamp']}] {a['type']}\n  → {a['message']}\n"
    else:
        report += "\n  No alerts recorded.\n"

    report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 RECENT FILE EVENTS (Last 10)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    for ev in logs[-10:]:
        report += (
            f"\n  [{ev['timestamp']}] {ev['event_type']}"
            f"\n  Source : {ev['source_path']}"
            f"\n  Hash   : {ev['file_hash'][:32]}..."
            f"\n  Sensitive: {ev['sensitive']} | Suspicious Dest: {ev['suspicious_dest']}\n"
        )

    report += "\n══════════════════════════════════════════════════════════════\n"

    with open(REPORT_FILE, "w") as f:
        f.write(report)
    print(report)
    logger.info(f"📄 Report saved to {REPORT_FILE}")


# ─── Main Entry Point ──────────────────────────────────────────────────────────

def start_monitor(watch_dirs: list, duration: int = None):
    """Start the file system monitor."""
    take_baseline_snapshot(watch_dirs)

    event_handler = FileTransferHandler()
    observer = Observer()

    for d in watch_dirs:
        if os.path.exists(d):
            observer.schedule(event_handler, d, recursive=True)
            logger.info(f"👁  Watching: {d}")
        else:
            logger.warning(f"Directory not found, skipping: {d}")

    observer.start()
    logger.info(
        "🛡  Secure File Transfer Monitor STARTED. Press Ctrl+C to stop.\n")

    try:
        if duration:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping monitor...")
    finally:
        observer.stop()
        observer.join()
        generate_report()
        logger.info("✅ Monitor stopped. Report generated.")


if __name__ == "__main__":
    # Monitor the current working directory for demo purposes
    watch_targets = [os.getcwd(), os.path.expanduser("~/Documents")]
    start_monitor(watch_targets)
