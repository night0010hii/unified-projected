"""
Service Scanner
Detects misconfigured systemd services.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import os
import stat
import glob
from typing import List, Dict

SYSTEMD_DIRS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
]


class ServiceScanner:
    def scan(self) -> List[Dict]:
        findings = []
        findings.extend(self._check_service_files())
        findings.extend(self._check_running_services())
        return findings

    def _check_service_files(self) -> List[Dict]:
        findings = []
        for d in SYSTEMD_DIRS:
            if not os.path.isdir(d):
                continue
            for filepath in glob.glob(os.path.join(d, "*.service")):
                findings.extend(self._analyze_service_file(filepath))
        return findings

    def _analyze_service_file(self, filepath: str) -> List[Dict]:
        findings = []
        try:
            st = os.stat(filepath)
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o002:
                findings.append({
                    "module": "Service Scanner",
                    "title": f"World-Writable Service File: {filepath}",
                    "description": (
                        f"Service unit file '{filepath}' is world-writable. "
                        "An attacker can modify ExecStart to run code as root."
                    ),
                    "severity": "CRITICAL",
                    "path": filepath,
                    "exploitation_possible": True,
                    "mitigation": (
                        f"Run: chmod 644 {filepath} "
                        "then: systemctl daemon-reload"
                    ),
                })

            with open(filepath) as f:
                content = f.read()

            exec_start = None
            user = None
            has_no_new_privs = False

            for line in content.splitlines():
                line = line.strip()
                if line.lower().startswith("execstart="):
                    exec_start = line.split("=", 1)[1].strip()
                elif line.lower().startswith("user="):
                    user = line.split("=", 1)[1].strip()
                elif "NoNewPrivileges=yes" in line:
                    has_no_new_privs = True
                elif "Environment=" in line and "PATH" in line:
                    path_val = line.split("PATH=")[-1].strip("\"'")
                    if (
                        path_val.startswith(".")
                        or ":." in path_val
                        or path_val.endswith(":")
                    ):
                        findings.append({
                            "module": "Service Scanner",
                            "title": f"Relative PATH in Service: {filepath}",
                            "description": (
                                f"Service has a relative PATH: '{path_val}'. "
                                "Vulnerable to PATH hijacking."
                            ),
                            "severity": "HIGH",
                            "path": filepath,
                            "exploitation_possible": True,
                            "mitigation": (
                                "Use only absolute paths in "
                                "service Environment= directives."
                            ),
                        })

            if exec_start:
                binary = exec_start.split()[0]
                if binary and not binary.startswith("/"):
                    findings.append({
                        "module": "Service Scanner",
                        "title": f"Relative ExecStart Path: {filepath}",
                        "description": (
                            f"Service uses relative ExecStart path: '{binary}'. "
                            "Vulnerable to PATH hijacking."
                        ),
                        "severity": "CRITICAL",
                        "path": filepath,
                        "exploitation_possible": True,
                        "mitigation": "Use absolute path in ExecStart.",
                    })
                elif binary and os.path.exists(binary):
                    try:
                        bst = os.stat(binary)
                        bmode = stat.S_IMODE(bst.st_mode)
                        if bmode & 0o002:
                            findings.append({
                                "module": "Service Scanner",
                                "title": f"Writable Service Binary: {binary}",
                                "description": (
                                    f"Binary '{binary}' executed by this service "
                                    "is world-writable. Replacing it allows "
                                    "arbitrary code execution."
                                ),
                                "severity": "CRITICAL",
                                "path": binary,
                                "exploitation_possible": True,
                                "mitigation": f"Run: chmod o-w {binary}",
                            })
                    except Exception:
                        pass

            sname = os.path.basename(filepath)
            if (user is None or user.lower() == "root") and not has_no_new_privs:
                if not any(
                    sname.startswith(p)
                    for p in ("systemd-", "dbus", "network", "udev")
                ):
                    findings.append({
                        "module": "Service Scanner",
                        "title": f"Unhardened Root Service: {sname}",
                        "description": (
                            f"Service '{sname}' runs as root without "
                            "'NoNewPrivileges=yes'. If exploited, "
                            "attacker gains full root access."
                        ),
                        "severity": "LOW",
                        "path": filepath,
                        "exploitation_possible": False,
                        "mitigation": (
                            "Add to [Service]: NoNewPrivileges=yes, "
                            "PrivateTmp=yes, ProtectSystem=full"
                        ),
                    })

        except (PermissionError, FileNotFoundError):
            pass
        except Exception:
            pass
        return findings

    def _check_running_services(self) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(
                [
                    "systemctl", "list-units",
                    "--type=service", "--state=running",
                    "--no-pager", "--no-legend",
                ],
                capture_output=True, text=True, timeout=10,
            )
            running = [
                line.split()[0]
                for line in result.stdout.splitlines()
                if line.split()
            ]
            risky = {
                "docker.service",
                "containerd.service",
                "lxd.service",
                "snapd.service",
                "avahi-daemon.service",
            }
            for svc in running:
                if svc in risky:
                    findings.append({
                        "module": "Service Scanner",
                        "title": f"Risky Service Running: {svc}",
                        "description": (
                            f"'{svc}' is running and can be abused for privilege "
                            "escalation if the current user is in the associated group."
                        ),
                        "severity": "MEDIUM",
                        "path": svc,
                        "exploitation_possible": True,
                        "mitigation": (
                            "Ensure non-privileged users are not in "
                            "the associated group."
                        ),
                    })
        except Exception:
            pass
        return findings
