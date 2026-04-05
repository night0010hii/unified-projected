# reporter.py
from config import LOG_FILE, REPORT_FILE
from utils import timestamp


def log_change(change, extra_alerts=None):
    line = (f"[{timestamp()}] TYPE={change['type']} | KEY={change['key']} | "
            f"VALUE={change.get('name', 'N/A')} | OLD={change.get('old', 'N/A')} | NEW={change.get('new', 'N/A')}\n")
    with open(LOG_FILE, "a") as f:
        f.write(line)
        if extra_alerts:
            for a in extra_alerts:
                f.write(f"  >> {a}\n")


def generate_report(all_changes, all_alerts):
    with open(REPORT_FILE, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("   REGWATCH PRO — REGISTRY CHANGE REPORT\n")
        f.write(f"   Generated: {timestamp()}\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Total Changes : {len(all_changes)}\n")
        f.write(f"Alerts        : {len(all_alerts)}\n\n")
        f.write("─" * 60 + "\n CHANGES\n" + "─" * 60 + "\n")
        for c in all_changes:
            f.write(f"  [{c['type']}] {c['key']} | {c.get('name', 'N/A')} | "
                    f"OLD={c.get('old', 'N/A')} → NEW={c.get('new', 'N/A')}\n")
        if all_alerts:
            f.write("\n" + "─" * 60 + "\n MALWARE ALERTS\n" + "─" * 60 + "\n")
            for a in all_alerts:
                f.write(f"  {a}\n")
        f.write("\n" + "=" * 60 + "\nEND OF REPORT\n")
