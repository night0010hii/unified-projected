# RegWatch Pro

### Windows Registry Change Monitoring  System

A **Blue Team defensive toolkit** that monitors your Windows Registry in real-time,
detects malware-like modifications, and alerts you to unauthorized changes — all through
a clean, professional GUI built with Python and Tkinter.

---

## Table of Contents

- [RegWatch Pro](#regwatch-pro)
    - [Windows Registry Change Monitoring  System](#windows-registry-change-monitoring--system)
  - [Table of Contents](#table-of-contents)
  - [What This Tool Does](#what-this-tool-does)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [Step 1 — Install Python](#step-1--install-python)
    - [Step 2 — Download / Clone the Project](#step-2--download--clone-the-project)
    - [Step 3 — (Optional) Install Extra Features](#step-3--optional-install-extra-features)
  - [How to Run](#how-to-run)
  - [How to Use — Step by Step](#how-to-use--step-by-step)
    - [First Time Setup](#first-time-setup)
    - [Next Sessions](#next-sessions)
  - [GUI Tabs Explained](#gui-tabs-explained)
    - [🖥 Live Console](#-live-console)
    - [Changes](#changes)
    - [⚠ Alerts](#-alerts)
    - [Watched Keys](#watched-keys)
    - [Baseline](#baseline)
    - [Report](#report)
  - [Sidebar Controls](#sidebar-controls)
  - [What Keys Are Monitored](#what-keys-are-monitored)
    - [Autorun / Persistence Keys](#autorun--persistence-keys)
    - [Security \& Malware-Target Keys](#security--malware-target-keys)
  - [Malware Patterns Detected](#malware-patterns-detected)
  - [Output Files](#output-files)
  - [Project File Structure](#project-file-structure)
  - [Tips \& Best Practices](#tips--best-practices)
  - [❗ Common Errors \& Fixes](#-common-errors--fixes)
  - [Who Is This For?](#who-is-this-for)
  - [License](#license)

---

## What This Tool Does

The Windows Registry stores critical system settings — startup programs, security policies,
firewall rules, and more. Malware frequently targets the registry to:

- **Persist across reboots** (adding entries to Run/RunOnce keys)
- **Disable Windows Defender** or the Firewall
- **Bypass UAC** (User Account Control)
- **Replace the Windows Shell** for hijacking

RegWatch Pro watches these high-value registry paths continuously. It takes a "baseline"
snapshot of your clean system, then compares every future state against it. Any addition,
deletion, or modification is instantly logged, colour-coded, and flagged.

---

## Features

| Feature | Description |

|  Baseline Capture | Snapshot your registry in its current (trusted) state |
|  Load Baseline | Load a previously saved baseline from any session |
|  Real-Time Monitor | Poll registry keys every N seconds and detect changes live |
|  Integrity Check | One-shot compare — current state vs baseline |
| ⚠ Malware Detection | Flag known bad patterns (Defender off, UAC bypass, shell hijack) |
|  Colour Coding | Green = added, Red = deleted, Amber = modified |
|  Change Table | Searchable, filterable log of every chae with timestamps |
|  Key Manager | View, add, or remove watched registry paths on the fly |
|  Baseline Viewer | See the full JSON snapshot of your baseline inside the app |
|  Report Generator | Export a full change report as a `.txt` file |
|  Poll Interval Slider | Adjust monitoring speed from 5 to 120 seconds |
|  Clear & Reset | Wipe all logs and counters without restarting |
|  Alert Feed | Dedicated tab for all malware-pattern hits |
|  Live Stats | Real-time counters for Changes, Alerts, Polls, Keys Watched |

---

## Requirements

| Requirement | Details |

| Operating System | **Windows 10 or Windows 11 only** |
| Python Version | **Python 3.8 or newer** |
| Admin Rights | **Recommended** — needed to read HKEY_LOCAL_MACHINE keys |
| Python Libraries | **None** — uses only built-in modules (`tkinter`, `winreg`, `json`, `threading`) |

> This tool only works on Windows. The `winreg` module does not exist on Linux or macOS.

---

## Installation

### Step 1 — Install Python

Download from <https://python.org> and install.
During install, tick **"Add Python to PATH"**.

Verify it works:

```bash
python --version
```

### Step 2 — Download / Clone the Project

```bash
git clone https://github.com/yourname/regwatch_pro.git
cd regwatch_pro
```

Or download the ZIP from GitHub and extract it.

### Step 3 — (Optional) Install Extra Features

For the v2.0 new features only:

```bash
pip install schedule plyer reportlab
```

- `schedule` — needed for `scheduler.py` (auto-scan tasks)
- `plyer` — needed for `notifier.py` (desktop toast notifications)
- `reportlab` — needed for `exporter.py` (PDF export)

The core monitoring tool works **without any pip installs**.

---

## How to Run

Open a terminal (Command Prompt or PowerShell) inside the project folder.

**Recommended — run as Administrator for full access:**

```bash
# Right-click on VS Code or CMD → "Run as Administrator"
python src/gui_app.py
```

That's it. The GUI window opens immediately.

> If you see a "Permission denied" message for some keys, it means you need
> to run as Administrator. The tool still works — it will skip those locked keys.

---

## How to Use — Step by Step

### First Time Setup

**Step 1 — Capture a Baseline**

Click **Capture Baseline** in the left sidebar.

This reads all monitored registry keys and saves their current values to
`data/baseline.json`. Do this on a clean, trusted system — this is your
"known good" state that all future checks compare against.

You will see a confirmation in the Live Console tab.

---

**Step 2 — Start Monitoring**

Click **▶ Start Monitoring**.

The tool now polls the registry every N seconds (default: 10 seconds, adjustable
with the slider). The status indicator in the top-right turns green and shows
"MONITORING".

Leave it running in the background.

---

**Step 3 — Watch for Changes**

Any registry change will appear instantly in:

- **Live Console tab** — colour-coded output stream
- **Changes tab** — sortable table with old vs new values
- **Alerts tab** — if the change matches a known malware pattern

---

**Step Run an Integrity Check (optional)**

Click **Integrity Check** for a one-shot compare at any time.

This is useful after an incident — run it without starting the monitor to get
a full snapshot of what changed since your baseline.

---

**Step 5 — Export Your Report**

Click **Export Report** to save a full text report of all detected changes
and alerts to a file of your choosing.

---

### Next Sessions

On your next session, the app auto-loads `data/baseline.json` if it exists.
You can also click **Load Baseline** to load any saved baseline JSON file.

---

## GUI Tabs Explained

### 🖥 Live Console

Real-time colour-coded terminal output.

- Green = value added or key created
- Red = value deleted or key removed
- Amber = value modified
- Cyan = system info (baseline loaded, monitoring started)
- Dim = timestamps and labels

### Changes

A full searchable table of every registry change detected.
Use the filter box at the top to search by key path, value name, or change type.
New changes appear at the top of the table.

### ⚠ Alerts

Shows only changes that matched a known malware behaviour pattern.
Each entry includes the key path, value name, current value, and threat description.

### Watched Keys

Lists every registry path currently being monitored with a ✓ Found / ✗ Missing status.
Use the **Add Watch Key** box in the sidebar to add your own custom paths.
Select a row and click **Remove Selected Key** to stop watching it.

### Baseline

Shows the full JSON content of your loaded baseline — useful for inspecting
exactly what values were captured and what the tool compares against.

### Report

Preview your generated change report inside the app.
Click **Refresh** to update it, or **Save Report** to export it.

---

## Sidebar Controls

| Button | What it does |

|  Capture Baseline | Read all watched keys NOW and save as your reference point |
|  Load Baseline | Open a baseline JSON file from disk |
|  Start Monitoring | Begin continuous polling (turns into  Stop when active) |
|  Integrity Check | One-shot compare: current registry vs baseline |
|  Export Report | Save change report as a `.txt` file |
|  Clear Logs | Reset all logs, counters, and the change table |
| Poll Interval Slider | Drag to set how often the registry is polled (5–120 seconds) |
| Add Watch Key field | Type any registry subkey path and click **+ Add Key** |

---

## What Keys Are Monitored

### Autorun / Persistence Keys

These are the most common targets for malware persistence:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### Security & Malware-Target Keys

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\...\FirewallPolicy
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

You can add any additional keys using the **Add Watch Key** field in the sidebar.

---

## Malware Patterns Detected

The tool flags these specific registry value changes as high-risk:

| Value Name | Dangerous Value | What It Means |
|---|---|---|
| `DisableAntiSpyware` | `1` | Windows Defender AntiSpyware is disabled |
| `DisableRealtimeMonitoring` | `1` | Defender real-time protection is off |
| `EnableFirewall` | `0` | Windows Firewall has been disabled |
| `EnableLUA` | `0` | UAC (User Account Control) is disabled — privilege escalation risk |
| `Shell` | any change | The Windows shell has been replaced — possible hijack |
| `Userinit` | any change | Login initialiser modified — common persistence technique |

---

## Output Files

| File | Location | Description |
|---|---|---|
| `baseline.json` | `data/` | Your saved registry snapshot |
| `registry_changes.log` | `data/logs/` | Timestamped log of every detected change |
| `change_report.txt` | `reports/` | Full formatted change and alert report |

---

## Project File Structure

```
regwatch_pro/
│
├── src/
│   ├── gui_app.py          ← Main GUI window (run this)
│   ├── config.py           ← Registry keys to watch + malware patterns
│   ├── utils.py            ← Shared helpers (winreg reader, timestamps)
│   ├── baseline.py         ← Snapshot capture and load
│   ├── monitor.py          ← Live registry reader
│   ├── detector.py         ← Change diff engine + malware pattern matcher
│   ├── reporter.py         ← Log writer and report generator
│   │
│   ├── notifier.py         ← (v2) Email + desktop alert notifications
│   ├── scheduler.py        ← (v2) Scheduled auto-scan tasks
│   ├── remediation.py      ← (v2) One-click rollback to baseline
│   └── exporter.py         ← (v2) PDF / CSV / JSON export engine
│
├── data/
│   ├── baseline.json       ← Saved baseline (auto-created)
│   └── logs/
│       └── registry_changes.log
│
├── reports/
│   └── change_report.txt
│
└── requirements.txt
```

---

## Tips & Best Practices

**Always capture your baseline on a clean system.**
If you capture a baseline after malware has already made changes, those changes
will look "normal" to the tool. Run baseline capture right after a fresh Windows
install or a trusted clean state.

**Run as Administrator.**
Many HKEY_LOCAL_MACHINE keys require elevated permissions. Right-click your
terminal or VS Code and choose "Run as Administrator" before launching the tool.

**Lower the poll interval for active investigations.**
During an incident response, set the slider to 5 seconds so changes are caught
almost immediately.

**Use Integrity Check for post-incident forensics.**
After suspecting a compromise, run an integrity check rather than the monitor.
It gives you a full diff report instantly without needing to watch in real time.

**Save your baseline file.**
Copy `data/baseline.json` somewhere safe (a USB drive or cloud storage). If your
system is compromised, you can load that known-good baseline later for comparison.

**Add custom keys for deeper coverage.**
If you know a specific application or malware family targets certain registry paths,
add them via the sidebar. Any `HKCU\...` or `HKLM\...` path works.

---

## ❗ Common Errors & Fixes

| Error | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: winreg` | Running on Linux/Mac | This tool is Windows-only |
| `PermissionError` on some keys | Not running as admin | Right-click terminal → Run as Administrator |
| `No baseline found` on startup | First run, no baseline yet | Click 📸 Capture Baseline first |
| GUI window doesn't open | Tkinter missing | Reinstall Python and tick "tcl/tk" during setup |
| `schedule not found` | v2 module not installed | Run `pip install schedule` |

---

## Who Is This For?

- **Students** learning Windows security, malware analysis, or blue team defence
- **SOC analysts** who want a quick desktop tool for registry monitoring
- **Incident responders** performing forensic analysis of suspicious systems
- **IT administrators** monitoring workstations for unauthorised configuration changes
- **CTF players** practising Windows forensics and registry analysis

---

## License

This project is for educational and defensive security use only.
Do not use this tool on systems you do not own or have permission to monitor.
