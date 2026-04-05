"""
Kernel Scanner
Detects outdated kernels and maps to known CVEs.
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

import subprocess
import re
from typing import List, Dict

KERNEL_CVES = [
    ((3, 8, 0),  (3, 8, 999),  "CVE-2013-2094", "CRITICAL",
     "perf_swevent_init local root exploit"),
    ((2, 6, 22), (3, 9, 0),    "CVE-2012-0056", "HIGH",
     "Mempodipper /proc/self/mem privilege escalation"),
    ((4, 4, 0),  (4, 4, 999),  "CVE-2016-5195", "CRITICAL",
     "Dirty COW: race condition in mm/gup.c"),
    ((4, 5, 0),  (4, 10, 0),   "CVE-2016-5195", "CRITICAL",
     "Dirty COW: race condition in mm/gup.c"),
    ((2, 6, 0),  (4, 15, 0),   "CVE-2018-8897", "HIGH",
     "POP SS debug exception privilege escalation"),
    ((4, 0, 0),  (4, 16, 0),   "CVE-2017-16995", "CRITICAL",
     "eBPF verifier arbitrary read/write"),
    ((5, 0, 0),  (5, 5, 0),    "CVE-2019-13272", "HIGH",
     "PTRACE_TRACEME pkexec local privilege escalation"),
    ((5, 5, 0),  (5, 11, 0),   "CVE-2021-3156",  "CRITICAL",
     "Sudo Baron Samedit heap overflow"),
    ((5, 0, 0),  (5, 15, 0),   "CVE-2021-22555", "HIGH",
     "Heap out-of-bounds write in netfilter"),
    ((5, 14, 0), (5, 16, 0),   "CVE-2022-0847",  "CRITICAL",
     "Dirty Pipe: PIPE_BUF_FLAG_CAN_MERGE"),
    ((5, 8, 0),  (5, 16, 15),  "CVE-2022-27666", "HIGH",
     "Heap overflow in xfrm6 transform"),
    ((5, 15, 0), (6, 1, 0),    "CVE-2022-2588",  "HIGH",
     "net_cls_filter use-after-free"),
    ((6, 0, 0),  (6, 2, 0),    "CVE-2023-0179",  "HIGH",
     "nftables stack overflow privilege escalation"),
    ((5, 4, 0),  (6, 3, 0),    "CVE-2023-32233", "CRITICAL",
     "Netfilter nf_tables use-after-free"),
]


def _parse_version(version_str: str):
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if m:
        return tuple(int(x) for x in m.groups())
    m = re.match(r"(\d+)\.(\d+)", version_str)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    return None


class KernelScanner:
    def scan(self) -> List[Dict]:
        findings = []
        info = self._get_kernel_info()
        if not info:
            return findings
        findings.extend(self._check_cves(info))
        findings.extend(self._check_kernel_params(info))
        return findings

    def _get_kernel_info(self) -> Dict:
        try:
            r1 = subprocess.run(
                ["uname", "-a"], capture_output=True, text=True, timeout=5
            )
            r2 = subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, timeout=5
            )
            kv = r2.stdout.strip()
            return {
                "uname": r1.stdout.strip(),
                "kernel_version": kv,
                "parsed": _parse_version(kv),
            }
        except Exception:
            return None

    def _check_cves(self, info: Dict) -> List[Dict]:
        findings = []
        parsed = info.get("parsed")
        if not parsed:
            return findings
        matched = set()
        for min_v, max_v, cve, severity, desc in KERNEL_CVES:
            if min_v <= parsed < max_v and cve not in matched:
                matched.add(cve)
                findings.append({
                    "module": "Kernel Scanner",
                    "title": f"Kernel Vulnerability: {cve}",
                    "description": (
                        f"Kernel {info['kernel_version']} may be vulnerable "
                        f"to {cve}: {desc}."
                    ),
                    "severity": severity,
                    "cve": cve,
                    "kernel_version": info["kernel_version"],
                    "exploitation_possible": severity in ("CRITICAL", "HIGH"),
                    "mitigation": (
                        "Update the kernel immediately. "
                        f"Reference: https://nvd.nist.gov/vuln/detail/{cve}"
                    ),
                })
        if not matched:
            major, minor = parsed[0], parsed[1]
            if major < 5 or (major == 5 and minor < 15):
                findings.append({
                    "module": "Kernel Scanner",
                    "title": f"Outdated Kernel: {info['kernel_version']}",
                    "description": (
                        f"Kernel {info['kernel_version']} is older than "
                        "recommended minimum 5.15 LTS."
                    ),
                    "severity": "MEDIUM",
                    "kernel_version": info["kernel_version"],
                    "exploitation_possible": False,
                    "mitigation": (
                        "Update to the latest LTS kernel "
                        "for your distribution."
                    ),
                })
        return findings

    def _check_kernel_params(self, info: Dict) -> List[Dict]:
        findings = []
        params = {
            "/proc/sys/kernel/dmesg_restrict": (
                "0", "HIGH",
                "dmesg_restrict=0 leaks kernel memory addresses "
                "to unprivileged users.",
            ),
            "/proc/sys/kernel/kptr_restrict": (
                "0", "HIGH",
                "kptr_restrict=0 exposes kernel pointers, aiding KASLR bypass.",
            ),
            "/proc/sys/kernel/perf_event_paranoid": (
                "-1", "HIGH",
                "perf_event_paranoid=-1 allows unprivileged access "
                "to performance events.",
            ),
            "/proc/sys/kernel/yama/ptrace_scope": (
                "0", "MEDIUM",
                "ptrace_scope=0 allows any process to trace "
                "another of the same user.",
            ),
            "/proc/sys/fs/suid_dumpable": (
                "2", "MEDIUM",
                "suid_dumpable=2 allows core dumps of setuid binaries.",
            ),
        }
        for path, (bad_val, severity, desc) in params.items():
            try:
                with open(path) as f:
                    val = f.read().strip()
                if val == bad_val:
                    param_name = path.split("/")[-1]
                    findings.append({
                        "module": "Kernel Scanner",
                        "title": f"Insecure Kernel Parameter: {param_name}={val}",
                        "description": desc,
                        "severity": severity,
                        "path": path,
                        "current_value": val,
                        "exploitation_possible": severity in ("HIGH", "CRITICAL"),
                        "mitigation": (
                            f"Add to /etc/sysctl.conf: "
                            f"{path.replace('/proc/sys/', '').replace('/', '.')}"
                            " = <safer_value>"
                        ),
                    })
            except Exception:
                pass
        return findings
