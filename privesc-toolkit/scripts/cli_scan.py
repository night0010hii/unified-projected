#!/usr/bin/env python3
"""
Linux PrivEsc Toolkit — CLI Version
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.

Usage:
  python3 cli_scan.py
  python3 cli_scan.py --json
  python3 cli_scan.py --output report.html
"""

from utils.report_generator import ReportGenerator
from scanner.sudo_scan import SudoScanner
from scanner.kernel_scan import KernelScanner
from scanner.service_scan import ServiceScanner
from scanner.cron_scan import CronScanner
from scanner.permission_scan import PermissionScanner
from scanner.suid_scan import SuidScanner
import sys
import os
import json
import uuid
import shutil
import argparse

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../backend")
)


R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
ORG = "\033[93m"
YLW = "\033[33m"
GRN = "\033[92m"
CYN = "\033[96m"
GRY = "\033[90m"

SEV_C = {
    "CRITICAL": RED,
    "HIGH":     ORG,
    "MEDIUM":   YLW,
    "LOW":      GRN,
}


def banner():
    print(f"""{CYN}
╔══════════════════════════════════════════════════════╗
║   Linux Privilege Escalation Automation Toolkit      ║
║   FOR EDUCATIONAL AND AUTHORIZED USE ONLY            ║
╚══════════════════════════════════════════════════════╝{R}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Linux PrivEsc Scanner CLI"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output raw JSON"
    )
    parser.add_argument(
        "--output", help="Save HTML report to this path"
    )
    args = parser.parse_args()

    banner()

    modules = [
        ("SUID/SGID Binaries",     SuidScanner()),
        ("File Permissions",        PermissionScanner()),
        ("Cron Jobs",               CronScanner()),
        ("System Services",         ServiceScanner()),
        ("Kernel Vulnerabilities",  KernelScanner()),
        ("Sudo Misconfigurations",  SudoScanner()),
    ]

    all_findings = []
    for name, scanner in modules:
        print(f"{CYN}[*] Scanning: {name}...{R}")
        try:
            results = scanner.scan()
            all_findings.extend(results)
            print(f"{GRN}    Found {len(results)} issue(s){R}")
        except Exception as e:
            print(f"{RED}    Failed: {e}{R}")

    if args.json:
        print(json.dumps(all_findings, indent=2))
        return

    sev_w = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    counts = {
        s: sum(1 for f in all_findings if f.get("severity") == s)
        for s in sev_w
    }
    score = min(
        100,
        sum(sev_w.get(f.get("severity", "LOW"), 0)
            for f in all_findings) * 3
    )
    rc = GRN if score < 30 else ORG if score < 70 else RED

    print(f"\n{BOLD}{'=' * 52}")
    print(f"  SCAN SUMMARY")
    print(f"{'=' * 52}{R}")
    print(f"  Total     : {BOLD}{len(all_findings)}{R}")
    print(f"  {RED}CRITICAL  : {counts['CRITICAL']}{R}")
    print(f"  {ORG}HIGH      : {counts['HIGH']}{R}")
    print(f"  {YLW}MEDIUM    : {counts['MEDIUM']}{R}")
    print(f"  {GRN}LOW       : {counts['LOW']}{R}")
    print(f"  Risk Score: {rc}{BOLD}{score}/100{R}\n")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = [f for f in all_findings if f.get("severity") == sev]
        if not group:
            continue
        print(f"{SEV_C[sev]}{BOLD}── {sev} ({len(group)}) ──{R}")
        for f in group:
            print(f"  {SEV_C[sev]}{BOLD}[{sev}]{R} {f.get('title', '')}")
            desc = f.get("description", "")
            print(f"  {GRY}{desc[:110]}{'...' if len(desc) > 110 else ''}{R}")
            mit = f.get("mitigation", "")
            print(f"  {CYN}Fix:{R} {mit[:90]}\n")

    if args.output:
        sid = str(uuid.uuid4())[:8]
        data = {
            "findings": all_findings,
            "summary": {
                **counts,
                "total":      len(all_findings),
                "risk_score": score,
            },
        }
        rg = ReportGenerator(sid, data)
        tmp = rg.generate_html()
        shutil.copy(tmp, args.output)
        print(f"{GRN}[+] HTML report saved: {args.output}{R}")


if __name__ == "__main__":
    main()
