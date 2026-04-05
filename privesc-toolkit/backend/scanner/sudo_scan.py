"""
Sudo Misconfiguration Scanner
Parses sudo -l output to detect dangerous privileges.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import re
from typing import List, Dict

DANGEROUS_SUDO_CMDS = {
    "find":      "CRITICAL", "vim":      "CRITICAL", "vi":       "CRITICAL",
    "nano":      "CRITICAL", "less":     "CRITICAL", "more":     "HIGH",
    "man":       "HIGH",     "awk":      "CRITICAL", "perl":     "CRITICAL",
    "python":    "CRITICAL", "python2":  "CRITICAL", "python3":  "CRITICAL",
    "ruby":      "CRITICAL", "lua":      "CRITICAL", "php":      "CRITICAL",
    "bash":      "CRITICAL", "sh":       "CRITICAL", "dash":     "CRITICAL",
    "zsh":       "CRITICAL", "env":      "CRITICAL", "cp":       "HIGH",
    "mv":        "HIGH",     "tee":      "HIGH",     "dd":       "HIGH",
    "cat":       "HIGH",     "chmod":    "HIGH",     "chown":    "HIGH",
    "curl":      "HIGH",     "wget":     "HIGH",     "nmap":     "HIGH",
    "tar":       "HIGH",     "zip":      "MEDIUM",   "docker":   "CRITICAL",
    "kubectl":   "HIGH",     "git":      "HIGH",     "openssl":  "HIGH",
    "base64":    "MEDIUM",   "systemctl": "HIGH",     "journalctl": "MEDIUM",
    "apt":       "CRITICAL", "apt-get":  "CRITICAL", "pip":      "HIGH",
    "npm":       "HIGH",     "make":     "HIGH",     "gcc":      "HIGH",
    "strace":    "HIGH",     "gdb":      "HIGH",     "su":       "CRITICAL",
    "pkexec":    "CRITICAL", "passwd":   "HIGH",     "useradd":  "CRITICAL",
    "usermod":   "CRITICAL", "mount":    "HIGH",     "nc":       "HIGH",
    "netcat":    "HIGH",     "socat":    "HIGH",     "screen":   "HIGH",
    "tmux":      "HIGH",
}


class SudoScanner:
    def scan(self) -> List[Dict]:
        output = self._run_sudo_l()
        if not output:
            return []
        return self._analyze_sudo_output(output)

    def _run_sudo_l(self) -> str:
        try:
            result = subprocess.run(
                ["sudo", "-l"],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout
        except Exception:
            return ""

    def _analyze_sudo_output(self, output: str) -> List[Dict]:
        findings = []

        all_nopasswd = re.compile(
            r"\(ALL\s*:\s*ALL\)\s*NOPASSWD\s*:\s*ALL", re.IGNORECASE
        )
        all_cmds = re.compile(
            r"\(ALL\s*:\s*ALL\)\s*ALL", re.IGNORECASE
        )
        nopasswd_pat = re.compile(r"NOPASSWD\s*:\s*(.+)", re.IGNORECASE)

        if all_nopasswd.search(output):
            findings.append({
                "module": "Sudo Scanner",
                "title": "Full Root Sudo Without Password",
                "description": (
                    "Current user can run ALL commands as root WITHOUT a "
                    "password (NOPASSWD: ALL). Equivalent to having root access."
                ),
                "severity": "CRITICAL",
                "sudo_entry": "(ALL:ALL) NOPASSWD: ALL",
                "exploitation_possible": True,
                "mitigation": (
                    "Remove NOPASSWD: ALL from sudoers. "
                    "Use visudo to edit safely."
                ),
            })
            return findings

        if all_cmds.search(output) and "NOPASSWD" not in output:
            findings.append({
                "module": "Sudo Scanner",
                "title": "Full Root Sudo (Password Required)",
                "description": (
                    "Current user can run ALL commands as root. "
                    "Once authenticated, grants full root access."
                ),
                "severity": "HIGH",
                "sudo_entry": "(ALL:ALL) ALL",
                "exploitation_possible": True,
                "mitigation": (
                    "Restrict sudo to only specific commands. "
                    "Edit with: visudo"
                ),
            })

        for match in nopasswd_pat.finditer(output):
            cmds = [c.strip() for c in match.group(1).strip().split(",")]
            for cmd in cmds:
                binary = cmd.split()[0] if cmd.split() else ""
                bname = binary.split("/")[-1].lower()
                if bname in DANGEROUS_SUDO_CMDS:
                    findings.append({
                        "module": "Sudo Scanner",
                        "title": f"Dangerous NOPASSWD Sudo: {bname}",
                        "description": (
                            f"User can run '{cmd}' as root without a password. "
                            f"'{bname}' can be abused via GTFOBins techniques."
                        ),
                        "severity": DANGEROUS_SUDO_CMDS[bname],
                        "sudo_entry": cmd,
                        "binary": binary,
                        "exploitation_possible": True,
                        "mitigation": (
                            f"Remove NOPASSWD: {cmd} from sudoers. "
                            "If required, at minimum require a password."
                        ),
                    })

        if "env_keep" in output.lower() or "SETENV" in output:
            findings.append({
                "module": "Sudo Scanner",
                "title": "Sudo Environment Variable Preservation",
                "description": (
                    "Sudoers allows env_keep or SETENV. Enables LD_PRELOAD "
                    "or PYTHONPATH-based privilege escalation."
                ),
                "severity": "HIGH",
                "sudo_entry": "env_keep / SETENV",
                "exploitation_possible": True,
                "mitigation": (
                    "Remove env_keep and SETENV. "
                    "Ensure 'Defaults env_reset' is set."
                ),
            })

        if re.search(r"sudo\s+-[si]", output):
            findings.append({
                "module": "Sudo Scanner",
                "title": "Sudo Shell Access Permitted",
                "description": (
                    "Sudoers allows sudo -s or sudo -i, "
                    "spawning an interactive root shell."
                ),
                "severity": "CRITICAL",
                "sudo_entry": "sudo -s / sudo -i",
                "exploitation_possible": True,
                "mitigation": "Remove shell escalation from sudoers.",
            })

        return findings
