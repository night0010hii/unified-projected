"""
SUID/SGID Binary Scanner
Detects setuid/setgid binaries and cross-references with GTFOBins.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import os
from typing import List, Dict

GTFOBINS = {
    "bash", "sh", "dash", "zsh", "python", "python2", "python3",
    "perl", "ruby", "lua", "php", "node", "nodejs",
    "find", "vim", "vi", "nano", "less", "more", "man",
    "awk", "gawk", "nawk", "mawk",
    "cp", "mv", "cat", "tee", "head", "tail", "sort",
    "dd", "xxd", "od", "strings",
    "env", "xargs", "strace", "ltrace",
    "curl", "wget", "nmap",
    "tar", "zip", "unzip", "gzip", "bzip2",
    "openssl", "base64",
    "git", "svn",
    "mysql", "sqlite3",
    "journalctl", "systemctl",
    "docker", "kubectl",
    "mount", "umount",
    "pkexec", "sudo",
    "passwd", "chsh", "newgrp",
    "ping", "traceroute",
    "at", "crontab",
    "screen", "tmux",
    "expect",
    "socat", "netcat", "nc",
}


class SuidScanner:
    def scan(self) -> List[Dict]:
        findings = []
        findings.extend(self._scan_suid())
        findings.extend(self._scan_sgid())
        return findings

    def _run_find(self, flag: str) -> List[str]:
        try:
            result = subprocess.run(
                ["find", "/", "-perm", flag, "-type", "f",
                 "-not", "-path", "*/proc/*"],
                capture_output=True, text=True, timeout=30
            )
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
        except Exception:
            return []

    def _scan_suid(self) -> List[Dict]:
        findings = []
        binaries = self._run_find("-4000")
        for path in binaries:
            name = os.path.basename(path)
            exploitable = name.lower() in GTFOBINS
            severity = "CRITICAL" if exploitable else "MEDIUM"
            findings.append({
                "module": "SUID/SGID Scanner",
                "title": f"SUID Binary: {path}",
                "description": (
                    f"The binary '{path}' has the SUID bit set, meaning it runs with "
                    f"the file owner's (usually root) privileges. "
                    + (
                        f"'{name}' is listed on GTFOBins and can be abused for privilege escalation."
                        if exploitable else
                        "Not in GTFOBins list but should be reviewed."
                    )
                ),
                "severity": severity,
                "path": path,
                "binary_name": name,
                "gtfobins_match": exploitable,
                "exploitation_possible": exploitable,
                "mitigation": (
                    f"Remove SUID bit if not required: chmod u-s {path}. "
                    "Only binaries that explicitly require SUID should retain it."
                ),
            })
        return findings

    def _scan_sgid(self) -> List[Dict]:
        findings = []
        binaries = self._run_find("-2000")
        for path in binaries:
            name = os.path.basename(path)
            exploitable = name.lower() in GTFOBINS
            severity = "HIGH" if exploitable else "LOW"
            findings.append({
                "module": "SUID/SGID Scanner",
                "title": f"SGID Binary: {path}",
                "description": (
                    f"The binary '{path}' has the SGID bit set, "
                    "running with group owner privileges."
                    + (f" '{name}' is listed on GTFOBins." if exploitable else "")
                ),
                "severity": severity,
                "path": path,
                "binary_name": name,
                "gtfobins_match": exploitable,
                "exploitation_possible": exploitable,
                "mitigation": f"Remove SGID bit if not required: chmod g-s {path}",
            })
        return findings
