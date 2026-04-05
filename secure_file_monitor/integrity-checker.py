"""
Secure File Transfer Monitoring System
File Integrity Checker Module
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path

HASH_DB_FILE = "logs/hash_db.json"
REPORT_FILE = "logs/integrity_report.json"


def compute_hash(filepath: str, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "UNREADABLE"


def load_db() -> dict:
    if os.path.exists(HASH_DB_FILE):
        with open(HASH_DB_FILE, "r") as f:
            return json.load(f)
    return {}


def save_db(db: dict):
    os.makedirs("logs", exist_ok=True)
    with open(HASH_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def scan_directory(directory: str) -> dict:
    """Scan directory and return {filepath: hash} mapping."""
    result = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            result[fpath] = compute_hash(fpath)
    return result


def baseline(directories: list):
    """Create a new baseline snapshot."""
    db = {}
    for d in directories:
        if os.path.exists(d):
            scanned = scan_directory(d)
            for path, h in scanned.items():
                db[path] = {"hash": h, "timestamp": datetime.now().isoformat()}
            print(f"✅ baseline {len(scanned)} files in {d}")
    save_db(db)
    print(f"\n📦 Baseline saved to {HASH_DB_FILE}")


def verify(directories: list) -> list:
    """Compare current state against baseline."""
    db = load_db()
    results = []

    for d in directories:
        if not os.path.exists(d):
            continue
        current = scan_directory(d)

        for fpath, current_hash in current.items():
            if fpath not in db:
                results.append({
                    "file": fpath,
                    "status": "NEW",
                    "current_hash": current_hash,
                    "stored_hash": None,
                    "timestamp": datetime.now().isoformat()
                })
            else:
                stored_hash = db[fpath]["hash"]
                status = "OK" if current_hash == stored_hash else "TAMPERED"
                results.append({
                    "file": fpath,
                    "status": status,
                    "current_hash": current_hash,
                    "stored_hash": stored_hash,
                    "timestamp": datetime.now().isoformat()
                })

        # Check for deleted files
        for fpath in db:
            if fpath.startswith(d) and not os.path.exists(fpath):
                results.append({
                    "file": fpath,
                    "status": "DELETED",
                    "current_hash": None,
                    "stored_hash": db[fpath]["hash"],
                    "timestamp": datetime.now().isoformat()
                })

    # Save report
    with open(REPORT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary
    ok = sum(1 for r in results if r["status"] == "OK")
    tampered = [r for r in results if r["status"] == "TAMPERED"]
    new_files = [r for r in results if r["status"] == "NEW"]
    deleted = [r for r in results if r["status"] == "DELETED"]

    print("\n" + "═" * 50)
    print("  INTEGRITY VERIFICATION REPORT")
    print("═" * 50)
    print(f"  ✅ OK         : {ok}")
    print(f"  🆕 New Files  : {len(new_files)}")
    print(f"  ⚠️  Tampered   : {len(tampered)}")
    print(f"  🗑️  Deleted    : {len(deleted)}")
    print("═" * 50)

    if tampered:
        print("\n🚨 TAMPERED FILES:")
        for r in tampered:
            print(f"   {r['file']}")
            print(f"     Expected : {r['stored_hash'][:32]}...")
            print(f"     Got      : {r['current_hash'][:32]}...")

    if deleted:
        print("\n🗑️  DELETED FILES:")
        for r in deleted:
            print(f"   {r['file']}")

    return results


if __name__ == "__main__":
    import sys
    targets = [os.getcwd()]

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        baseline(targets)
    else:
        verify(targets)
