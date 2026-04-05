"""
Secure File Monitor — Demo Data Generator
Run this script to automatically test all features of the GUI.
Just run: python demo_data.py
"""

import os
import sys
import json
import time
import shutil
import hashlib
from datetime import datetime, timedelta
import random

# ── Setup paths ───────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DEMO_DIR = os.path.join(BASE_DIR, "demo_files")
SAFE_DIR = os.path.join(DEMO_DIR, "safe")
SENSITIVE_DIR = os.path.join(DEMO_DIR, "sensitive")
OUTBOX_DIR = os.path.join(DEMO_DIR, "outbox")

LOG_FILE = os.path.join(LOG_DIR, "file_transfer_log.json")
ALERT_FILE = os.path.join(LOG_DIR, "alerts.json")
HASH_DB = os.path.join(LOG_DIR, "hash_db.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(SAFE_DIR, exist_ok=True)
os.makedirs(SENSITIVE_DIR, exist_ok=True)
os.makedirs(OUTBOX_DIR, exist_ok=True)

# ── Colors for terminal output ─────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def p(color, icon, msg):
    print(f"{color}{BOLD}{icon}{RESET} {msg}")


def compute_hash(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return "UNREADABLE"


def now_iso():
    return datetime.now().isoformat()


def now_str():
    return datetime.now().strftime("%H:%M:%S")


def load_json(path, default=None):
    if default is None:
        default = []
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except:
        pass
    return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def add_log(event_type, src, dest="", sensitive=False):
    logs = load_json(LOG_FILE)
    h = compute_hash(src) if os.path.isfile(src) else "N/A"
    logs.append({
        "timestamp": now_iso(),
        "time_display": now_str(),
        "event_type": event_type,
        "source_path": src,
        "destination_path": dest,
        "sensitive": sensitive,
        "file_hash": h,
        "filename": os.path.basename(src),
        "integrity": "",
    })
    save_json(LOG_FILE, logs)


def add_alert(atype, msg, details=None):
    alerts = load_json(ALERT_FILE)
    alerts.append({
        "id": f"ALT-{len(alerts)+1:04d}",
        "timestamp": now_iso(),
        "time_display": now_str(),
        "type": atype,
        "severity": "CRITICAL" if atype in ("UNAUTHORIZED", "INTEGRITY") else "HIGH",
        "message": msg,
        "details": details or {},
        "acknowledged": False,
    })
    save_json(ALERT_FILE, alerts)

# ─────────────────────────────────────────────────────────────────────────────
# DEMO STEPS
# ─────────────────────────────────────────────────────────────────────────────


def step_banner():
    print()
    print(f"{BOLD}{CYAN}{'═'*58}{RESET}")
    print(f"{BOLD}{CYAN}   SECURE FILE MONITOR — DEMO DATA GENERATOR{RESET}")
    print(f"{BOLD}{CYAN}{'═'*58}{RESET}")
    print(f"  Demo folder : {DEMO_DIR}")
    print(f"  Logs folder : {LOG_DIR}")
    print()


def step1_create_normal_files():
    p(BLUE, "►", "STEP 1 — Creating normal (non-sensitive) files...")
    files = [
        ("readme.txt",       "This is a readme file.\nProject version: 1.0"),
        ("config.ini",       "[settings]\ntheme=dark\ndebug=false\nport=8080"),
        ("build.sh",         "#!/bin/bash\npip install -r requirements.txt\npython gui.py"),
        ("notes.txt",
         "Meeting notes:\n- Review security policy\n- Update hashes\n- Deploy v2"),
        ("index.html",       "<html><body><h1>Hello World</h1></body></html>"),
    ]
    for fname, content in files:
        fpath = os.path.join(SAFE_DIR, fname)
        with open(fpath, "w") as f:
            f.write(content)
        add_log("CREATED", fpath, sensitive=False)
        p(GREEN, "  ✓", f"Created: {fname}")
        time.sleep(0.1)
    print()


def step2_create_sensitive_files():
    p(BLUE, "►", "STEP 2 — Creating SENSITIVE files (these trigger yellow rows)...")
    files = [
        ("employees.csv",
         "Name,Department,Salary,SSN\nAlice Johnson,Engineering,95000,123-45-6789\nBob Smith,HR,72000,987-65-4321\nCarol White,Finance,88000,456-78-9012"),

        ("database_backup.sql",
         "-- Production DB Backup\nCREATE TABLE users (id INT, email VARCHAR, password_hash VARCHAR);\nINSERT INTO users VALUES (1,'admin@company.com','$2b$12$hash...');\nINSERT INTO users VALUES (2,'cfo@company.com','$2b$12$hash2...');"),

        ("financial_report.xlsx",
         "CONFIDENTIAL FINANCIAL DATA\nQ1 Revenue: $4,200,000\nQ2 Revenue: $5,100,000\nNet Profit: $1,850,000"),

        ("api_keys.env",
         "# PRODUCTION SECRETS\nAWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_PASSWORD=Sup3rS3cr3tP@ss!\nSTRIPE_KEY=sk_live_abc123xyz789"),

        ("contract_2024.pdf",
         "%PDF-1.4 CONFIDENTIAL CONTRACT\nClient: Acme Corp\nValue: $500,000\nSigned: 2024-01-15"),

        ("medical_records.docx",
         "PATIENT RECORD — CONFIDENTIAL\nPatient: John Doe\nDOB: 1985-03-22\nDiagnosis: Hypertension\nMedication: Lisinopril 10mg"),
    ]
    for fname, content in files:
        fpath = os.path.join(SENSITIVE_DIR, fname)
        with open(fpath, "w") as f:
            f.write(content)
        add_log("CREATED", fpath, sensitive=True)
        p(YELLOW, "  ⚠", f"Sensitive file created: {fname}")
        time.sleep(0.15)
    print()


def step3_take_baseline():
    p(BLUE, "►", "STEP 3 — Taking baseline hash snapshot...")
    db = {}
    for folder in [SAFE_DIR, SENSITIVE_DIR]:
        for root, _, files in os.walk(folder):
            for fname in files:
                fpath = os.path.join(root, fname)
                h = compute_hash(fpath)
                db[fpath] = {"hash": h, "timestamp": now_iso()}
                p(CYAN, "  #", f"Hashed: {fname}  →  {h[:20]}...")
                time.sleep(0.05)
    save_json(HASH_DB, db)
    p(GREEN, "  ✓", f"Baseline saved — {len(db)} files hashed\n")


def step4_modify_files():
    p(BLUE, "►", "STEP 4 — Modifying files (triggers INTEGRITY VIOLATION alert)...")

    # Modify a sensitive file — this will appear TAMPERED in integrity check
    csv_path = os.path.join(SENSITIVE_DIR, "employees.csv")
    with open(csv_path, "a") as f:
        f.write("\nEVE HACKER,Unknown,999999,000-00-0000  ← INJECTED ROW")

    logs = load_json(LOG_FILE)
    h_new = compute_hash(csv_path)
    db = load_json(HASH_DB, {})
    h_old = db.get(csv_path, {}).get("hash", "")
    entry = {
        "timestamp": now_iso(),
        "time_display": now_str(),
        "event_type": "MODIFIED",
        "source_path": csv_path,
        "destination_path": "",
        "sensitive": True,
        "file_hash": h_new,
        "filename": "employees.csv",
        "integrity": "TAMPERED",
    }
    logs.append(entry)
    save_json(LOG_FILE, logs)
    add_alert("INTEGRITY",
              "File tampered: employees.csv",
              {"stored_hash": h_old[:20]+"...", "current_hash": h_new[:20]+"..."})
    p(RED, "  ✗", f"employees.csv TAMPERED  (hash changed)")

    # Modify env file too
    env_path = os.path.join(SENSITIVE_DIR, "api_keys.env")
    with open(env_path, "a") as f:
        f.write("\nMALICIOUS_KEY=exfiltrated_data_here")
    h2 = compute_hash(env_path)
    entry2 = {**entry, "source_path": env_path,
              "filename": "api_keys.env", "file_hash": h2}
    logs = load_json(LOG_FILE)
    logs.append(entry2)
    save_json(LOG_FILE, logs)
    add_alert("INTEGRITY", "File tampered: api_keys.env",
              {"stored_hash": "abc...", "current_hash": h2[:20]+"..."})
    p(RED, "  ✗", f"api_keys.env TAMPERED  (unauthorized append detected)\n")


def step5_move_sensitive():
    p(BLUE, "►", "STEP 5 — Moving sensitive file to outbox (UNAUTHORIZED TRANSFER)...")
    src = os.path.join(SENSITIVE_DIR, "financial_report.xlsx")
    dst = os.path.join(OUTBOX_DIR, "financial_report.xlsx")
    shutil.copy(src, dst)
    add_log("MOVED", src, dest=dst, sensitive=True)
    add_alert("UNAUTHORIZED",
              "Sensitive file moved to suspicious location: outbox/financial_report.xlsx",
              {"source": src, "destination": dst})
    p(RED, "  ✗", f"financial_report.xlsx → outbox/  (UNAUTHORIZED TRANSFER alert)\n")


def step6_delete_sensitive():
    p(BLUE, "►", "STEP 6 — Deleting sensitive files (SENSITIVE_FILE_DELETED alert)...")
    target = os.path.join(SENSITIVE_DIR, "contract_2024.pdf")
    add_log("DELETED", target, sensitive=True)
    add_alert("SENSITIVE_FILE_DELETED",
              "Sensitive file deleted: contract_2024.pdf",
              {"path": target, "hash": compute_hash(target)})
    if os.path.exists(target):
        os.remove(target)
    p(RED, "  ✗", f"contract_2024.pdf deleted  (alert fired)\n")


def step7_bulk_transfer():
    p(BLUE, "►", "STEP 7 — Simulating BULK TRANSFER (60 files rapidly)...")
    bulk_dir = os.path.join(DEMO_DIR, "bulk_transfer")
    os.makedirs(bulk_dir, exist_ok=True)
    logs = load_json(LOG_FILE)
    for i in range(1, 61):
        fname = f"data_export_{i:03d}.csv"
        fpath = os.path.join(bulk_dir, fname)
        with open(fpath, "w") as f:
            f.write(
                f"id,value,secret\n{i},{random.randint(1000, 9999)},confidential_data_{i}")
        logs.append({
            "timestamp": now_iso(),
            "time_display": now_str(),
            "event_type": "CREATED",
            "source_path": fpath,
            "destination_path": "",
            "sensitive": True,
            "file_hash": compute_hash(fpath),
            "filename": fname,
            "integrity": "",
        })
    save_json(LOG_FILE, logs)
    add_alert("BULK_TRANSFER",
              "60 file events in under 60 seconds — possible data exfiltration",
              {"event_count": 60, "threshold": 50, "directory": bulk_dir})
    p(RED, "  ✗", f"60 CSV files created rapidly  (BULK_TRANSFER alert fired)\n")


def step8_more_events():
    p(BLUE, "►", "STEP 8 — Adding varied event history for Log Explorer...")
    extra = [
        ("server_config.env",  True,  "CREATED"),
        ("backup_2024.sql",    True,  "CREATED"),
        ("output.log",         False, "MODIFIED"),
        ("temp_cache.tmp",     False, "DELETED"),
        ("invoice_099.pdf",    True,  "CREATED"),
        ("report_draft.docx",  True,  "MODIFIED"),
        ("styles.css",         False, "CREATED"),
        ("package.json",       False, "MODIFIED"),
        ("user_data.xlsx",     True,  "MOVED"),
        ("credentials.env",    True,  "CREATED"),
    ]
    logs = load_json(LOG_FILE)
    for fname, sensitive, etype in extra:
        fpath = os.path.join(SENSITIVE_DIR if sensitive else SAFE_DIR, fname)
        fake_hash = hashlib.sha256(fname.encode()).hexdigest()
        logs.append({
            "timestamp": now_iso(),
            "time_display": now_str(),
            "event_type": etype,
            "source_path": fpath,
            "destination_path": "",
            "sensitive": sensitive,
            "file_hash": fake_hash,
            "filename": fname,
            "integrity": "",
        })
        p(CYAN, "  +",
          f"{etype:10}  {'[SENSITIVE]' if sensitive else '          '}  {fname}")
        time.sleep(0.05)
    save_json(LOG_FILE, logs)
    print()


def step_summary():
    logs = load_json(LOG_FILE)
    alerts = load_json(ALERT_FILE)
    db = load_json(HASH_DB, {})

    print(f"\n{BOLD}{GREEN}{'═'*58}{RESET}")
    print(f"{BOLD}{GREEN}   DEMO DATA READY — OPEN YOUR GUI NOW{RESET}")
    print(f"{BOLD}{GREEN}{'═'*58}{RESET}")
    print(f"\n  {BOLD}Stats you should see in the GUI:{RESET}")
    print(f"  {'Total Events':<22} {len(logs)}")
    print(
        f"  {'Alerts (unacked)':<22} {len([a for a in alerts if not a.get('acknowledged')])}")
    print(
        f"  {'Sensitive Events':<22} {len([e for e in logs if e.get('sensitive')])}")
    print(
        f"  {'Integrity Fails':<22} {len([e for e in logs if e.get('integrity') == 'TAMPERED'])}")
    print(f"  {'Hashed Files':<22} {len(db)}")

    print(f"\n  {BOLD}Demo folder location:{RESET}")
    print(f"  {DEMO_DIR}")

    print(f"\n  {BOLD}What to check in each tab:{RESET}")
    print(f"  {YELLOW}Live Feed{RESET}     — {len(logs)} events, yellow=sensitive, red=deleted/tampered")
    print(f"  {RED}Alerts{RESET}        — {len(alerts)} alerts: INTEGRITY x2, UNAUTHORIZED x1,")
    print(f"               BULK_TRANSFER x1, SENSITIVE_FILE_DELETED x1")
    print(
        f"  {GREEN}Integrity{RESET}     — click 'Run Integrity Check' → see TAMPERED files")
    print(f"  {CYAN}Log Explorer{RESET}  — search 'csv' or 'employees' to filter")

    print(f"\n  {BOLD}To add demo_files/ folder to the GUI:{RESET}")
    print(f"  Sidebar → '+ Add Dir' → select:  {DEMO_DIR}")
    print(f"\n{BOLD}{GREEN}{'═'*58}{RESET}\n")


# ── Run all steps ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    step_banner()
    step1_create_normal_files()
    step2_create_sensitive_files()
    step3_take_baseline()
    step4_modify_files()
    step5_move_sensitive()
    step6_delete_sensitive()
    step7_bulk_transfer()
    step8_more_events()
    step_summary()
