"""
File Permission Scanner
Detects world-writable files and weak permissions on sensitive files.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import os
import stat
from typing import List, Dict

SENSITIVE_FILES = {
    "/etc/passwd":                {"expected_mode": 0o644, "severity_if_wrong": "HIGH"},
    "/etc/shadow":                {"expected_mode": 0o640, "severity_if_wrong": "CRITICAL"},
    "/etc/sudoers":               {"expected_mode": 0o440, "severity_if_wrong": "CRITICAL"},
    "/etc/hosts":                 {"expected_mode": 0o644, "severity_if_wrong": "MEDIUM"},
    "/etc/crontab":               {"expected_mode": 0o644, "severity_if_wrong": "HIGH"},
    "/etc/ssh/sshd_config":       {"expected_mode": 0o600, "severity_if_wrong": "HIGH"},
    "/root/.bashrc":              {"expected_mode": 0o644, "severity_if_wrong": "HIGH"},
    "/root/.ssh":                 {"expected_mode": 0o700, "severity_if_wrong": "CRITICAL"},
    "/root/.ssh/authorized_keys": {"expected_mode": 0o600, "severity_if_wrong": "CRITICAL"},
    "/etc/passwd-":               {"expected_mode": 0o600, "severity_if_wrong": "MEDIUM"},
    "/etc/gshadow":               {"expected_mode": 0o640, "severity_if_wrong": "CRITICAL"},
}


class PermissionScanner:
    def scan(self) -> List[Dict]:
        findings = []
        findings.extend(self._check_sensitive_files())
        findings.extend(self._find_world_writable())
        findings.extend(self._check_home_dirs())
        return findings

    def _check_sensitive_files(self) -> List[Dict]:
        findings = []
        for filepath, meta in SENSITIVE_FILES.items():
            if not os.path.exists(filepath):
                continue
            try:
                st = os.stat(filepath)
                actual_mode = stat.S_IMODE(st.st_mode)
                expected = meta["expected_mode"]
                if actual_mode != expected:
                    findings.append({
                        "module": "File Permission Scanner",
                        "title": f"Weak Permissions: {filepath}",
                        "description": (
                            f"'{filepath}' has permissions {oct(actual_mode)} "
                            f"but expected {oct(expected)}. "
                            "This may allow unauthorized read/write access to sensitive data."
                        ),
                        "severity": meta["severity_if_wrong"],
                        "path": filepath,
                        "actual_permissions": oct(actual_mode),
                        "expected_permissions": oct(expected),
                        "exploitation_possible": actual_mode & 0o002 > 0,
                        "mitigation": (
                            f"Run: chmod {oct(expected)[2:]} {filepath}"
                        ),
                    })
            except Exception:
                pass
        return findings

    def _find_world_writable(self) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(
                ["find", "/", "-xdev", "-not", "-path", "*/proc/*", "-not",
                    "-path", "*/sys/*", "-perm", "-0002", "-type", "f"],
                capture_output=True, text=True, timeout=45
            )
            files = [l.strip()
                     for l in result.stdout.splitlines() if l.strip()]
            ignore = ("/tmp/", "/var/tmp/", "/dev/", "/proc/", "/sys/")
            files = [f for f in files if not any(
                f.startswith(p) for p in ignore)]
            for f in files[:50]:
                findings.append({
                    "module": "File Permission Scanner",
                    "title": f"World-Writable File: {f}",
                    "description": (
                        f"'{f}' is writable by any user. If executed by a privileged "
                        "process or cron job, it can be used for privilege escalation."
                    ),
                    "severity": "HIGH",
                    "path": f,
                    "exploitation_possible": True,
                    "mitigation": f"Run: chmod o-w {f}",
                })
        except Exception:
            pass
        return findings

    def _check_home_dirs(self) -> List[Dict]:
        findings = []
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) < 7:
                        continue
                    home = parts[5]
                    if not home or not os.path.isdir(home):
                        continue
                    try:
                        st = os.stat(home)
                        mode = stat.S_IMODE(st.st_mode)
                        if mode & 0o077:
                            findings.append({
                                "module": "File Permission Scanner",
                                "title": f"Insecure Home Directory: {home}",
                                "description": (
                                    f"Home directory '{home}' has permissions {oct(mode)}, "
                                    "allowing group or world access. "
                                    "SSH keys and config files inside may be exposed."
                                ),
                                "severity": "MEDIUM",
                                "path": home,
                                "actual_permissions": oct(mode),
                                "exploitation_possible": False,
                                "mitigation": f"Run: chmod 700 {home}",
                            })
                    except Exception:
                        pass
        except Exception:
            pass
        return findings
