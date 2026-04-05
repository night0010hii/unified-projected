"""
Cron Job Scanner
Detects writable cron scripts, suspicious cron entries, weak permissions.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import os
import stat
import glob
from typing import List, Dict

CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]

CRON_FILES = ["/etc/crontab", "/etc/anacrontab"]


class CronScanner:
    def scan(self) -> List[Dict]:
        findings = []
        findings.extend(self._check_cron_files())
        findings.extend(self._check_cron_dirs())
        findings.extend(self._check_writable_scripts())
        findings.extend(self._check_user_crontabs())
        return findings

    def _check_cron_files(self) -> List[Dict]:
        findings = []
        for cf in CRON_FILES:
            if not os.path.exists(cf):
                continue
            try:
                st = os.stat(cf)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o002:
                    findings.append({
                        "module": "Cron Job Scanner",
                        "title": f"World-Writable Cron File: {cf}",
                        "description": (
                            f"'{cf}' is world-writable. An attacker can modify cron "
                            "entries to execute arbitrary commands with elevated privileges."
                        ),
                        "severity": "CRITICAL",
                        "path": cf,
                        "exploitation_possible": True,
                        "mitigation": f"Run: chmod 644 {cf} and ensure root ownership.",
                    })
                with open(cf) as f:
                    for lineno, line in enumerate(f, 1):
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        findings.extend(
                            self._analyze_cron_line(line, cf, lineno)
                        )
            except (PermissionError, FileNotFoundError):
                pass
            except Exception:
                pass
        return findings

    def _check_cron_dirs(self) -> List[Dict]:
        findings = []
        for d in CRON_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                st = os.stat(d)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o002:
                    findings.append({
                        "module": "Cron Job Scanner",
                        "title": f"World-Writable Cron Directory: {d}",
                        "description": (
                            f"Cron directory '{d}' is world-writable. "
                            "Attackers can add malicious cron scripts."
                        ),
                        "severity": "CRITICAL",
                        "path": d,
                        "exploitation_possible": True,
                        "mitigation": f"Run: chmod 755 {d} and ensure root ownership.",
                    })
            except Exception:
                pass
        return findings

    def _check_writable_scripts(self) -> List[Dict]:
        findings = []
        for script in self._extract_cron_scripts():
            if not os.path.exists(script):
                findings.append({
                    "module": "Cron Job Scanner",
                    "title": f"Missing Cron Script: {script}",
                    "description": (
                        f"Cron job references '{script}' but the file does not exist. "
                        "An attacker who creates this file gains code execution."
                    ),
                    "severity": "HIGH",
                    "path": script,
                    "exploitation_possible": True,
                    "mitigation": (
                        "Remove the cron entry or create the script "
                        "with correct permissions."
                    ),
                })
                continue
            try:
                st = os.stat(script)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o002:
                    findings.append({
                        "module": "Cron Job Scanner",
                        "title": f"Writable Cron Script: {script}",
                        "description": (
                            f"'{script}' is referenced by a cron job and is "
                            "world-writable. Modifying it allows code execution."
                        ),
                        "severity": "CRITICAL",
                        "path": script,
                        "exploitation_possible": True,
                        "mitigation": f"Run: chmod o-w {script}",
                    })
                elif mode & 0o020:
                    findings.append({
                        "module": "Cron Job Scanner",
                        "title": f"Group-Writable Cron Script: {script}",
                        "description": (
                            f"'{script}' is group-writable. "
                            "Group members can modify it."
                        ),
                        "severity": "MEDIUM",
                        "path": script,
                        "exploitation_possible": True,
                        "mitigation": f"Run: chmod g-w {script}",
                    })
            except Exception:
                pass
        return findings

    def _extract_cron_scripts(self) -> List[str]:
        scripts = []
        all_files = list(CRON_FILES)
        for d in CRON_DIRS:
            if os.path.isdir(d):
                all_files.extend(glob.glob(os.path.join(d, "*")))
        for cf in all_files:
            try:
                with open(cf) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line:
                            continue
                        for part in line.split():
                            if part.startswith("/") and os.path.splitext(part)[1] in (
                                ".sh", ".py", ".pl", ".rb", ".php", ""
                            ):
                                if not any(
                                    p in part for p in ("proc", "sys", "dev")
                                ):
                                    scripts.append(part)
            except Exception:
                pass
        return list(set(scripts))

    def _analyze_cron_line(
        self, line: str, source: str, lineno: int
    ) -> List[Dict]:
        findings = []
        if "PATH=" in line and ("." in line or "::" in line):
            findings.append({
                "module": "Cron Job Scanner",
                "title": f"Suspicious PATH in Cron: {source}:{lineno}",
                "description": (
                    f"Cron entry at line {lineno} sets a suspicious PATH "
                    "that includes relative directories. Enables PATH hijacking."
                ),
                "severity": "HIGH",
                "path": source,
                "exploitation_possible": True,
                "mitigation": (
                    "Use absolute paths in cron jobs. "
                    "Never include '.' in cron PATH."
                ),
            })
        if (
            any(cmd in line for cmd in ["wget", "curl"])
            and "|" in line
            and "sh" in line
        ):
            findings.append({
                "module": "Cron Job Scanner",
                "title": f"Remote Code Exec in Cron: {source}:{lineno}",
                "description": (
                    "Cron entry downloads and pipes to shell. "
                    "Severe misconfiguration allowing remote code injection."
                ),
                "severity": "CRITICAL",
                "path": source,
                "exploitation_possible": True,
                "mitigation": (
                    "Never pipe downloaded content directly to a shell."
                ),
            })
        return findings

    def _check_user_crontabs(self) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                for lineno, line in enumerate(result.stdout.splitlines(), 1):
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    findings.extend(
                        self._analyze_cron_line(line, "user-crontab", lineno)
                    )
        except Exception:
            pass
        return findings
