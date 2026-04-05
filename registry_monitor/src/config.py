# config.py
import winreg

AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

SECURITY_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\System"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
]

ALL_MONITOR_KEYS = AUTORUN_KEYS + SECURITY_KEYS

MALWARE_PATTERNS = {
    "DisableAntiSpyware":        ("1", "⚠ Windows Defender AntiSpyware DISABLED"),
    "DisableRealtimeMonitoring": ("1", "⚠ Windows Defender Real-Time Monitoring DISABLED"),
    "EnableFirewall":            ("0", "⚠ Windows Firewall DISABLED"),
    "EnableLUA":                 ("0", "⚠ UAC (User Account Control) DISABLED"),
    "Shell":                     (None, "⚠ Shell replacement detected (possible hijack)"),
    "Userinit":                  (None, "⚠ Userinit modified (possible persistence)"),
}

POLL_INTERVAL = 10
BASELINE_FILE = "data/baseline.json"
LOG_FILE = "data/logs/registry_changes.log"
REPORT_FILE = "reports/change_report.txt"
