"""
Secure File Transfer Monitoring System
Beautiful GUI Dashboard — customtkinter
"""

import os
import sys
import json
import time
import hashlib
import threading
import platform
from datetime import datetime
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk

# ── watchdog (optional — graceful fallback if not installed) ──────────────────
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("watchdog not installed — run: pip install watchdog")

# ── psutil (optional) ─────────────────────────────────────────────────────────
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ── Theme ─────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION = "1.0.0"
APP_NAME = "SecureMonitor"

SENSITIVE_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".csv", ".txt", ".pptx",
                        ".db", ".sql", ".key", ".pem", ".env", ".json"}

COLORS = {
    "bg_dark":     "#0d1117",
    "bg_card":     "#161b22",
    "bg_input":    "#1c2128",
    "border":      "#30363d",
    "accent":      "#58a6ff",
    "accent2":     "#3fb950",
    "accent3":     "#d29922",
    "danger":      "#f85149",
    "muted":       "#8b949e",
    "text":        "#e6edf3",
    "text_dim":    "#6e7681",
    "tag_blue":    "#1f3a5f",
    "tag_green":   "#1a3a2a",
    "tag_amber":   "#3a2f0a",
    "tag_red":     "#3a1414",
}

LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "file_transfer_log.json")
ALERT_FILE = os.path.join(LOG_DIR, "alerts.json")
HASH_DB_FILE = os.path.join(LOG_DIR, "hash_db.json")
REPORT_FILE = os.path.join(LOG_DIR, "audit_report.txt")

os.makedirs(LOG_DIR, exist_ok=True)

# ── Helpers ───────────────────────────────────────────────────────────────────


def load_json(path, default=None):
    if default is None:
        default = []
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return default


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def compute_hash(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "UNREADABLE"


def is_sensitive(path):
    return Path(path).suffix.lower() in SENSITIVE_EXTENSIONS


def now_str():
    return datetime.now().strftime("%H:%M:%S")


def now_iso():
    return datetime.now().isoformat()

# ── Event Handler ─────────────────────────────────────────────────────────────


class MonitorHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, callback):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.callback = callback

    def _emit(self, etype, src, dest=None):
        sensitive = is_sensitive(src)
        h = compute_hash(src) if os.path.isfile(src) else "N/A"
        ev = {
            "timestamp": now_iso(),
            "time_display": now_str(),
            "event_type": etype,
            "source_path": src,
            "destination_path": dest or "",
            "sensitive": sensitive,
            "file_hash": h,
            "filename": os.path.basename(src),
        }
        logs = load_json(LOG_FILE)
        logs.append(ev)
        save_json(LOG_FILE, logs)

        # Integrity check on modify
        if etype == "MODIFIED":
            db = load_json(HASH_DB_FILE, {})
            if src in db and db[src]["hash"] != h and h != "UNREADABLE":
                ev["integrity"] = "TAMPERED"
                self._raise_alert(
                    "INTEGRITY", f"File tampered: {os.path.basename(src)}", ev)
            if isinstance(db, dict):
                db[src] = {"hash": h, "timestamp": now_iso()}
                save_json(HASH_DB_FILE, db)

        # Unauthorized move
        if etype == "MOVED" and sensitive:
            self._raise_alert(
                "UNAUTHORIZED", f"Sensitive file moved: {os.path.basename(src)}", ev)

        if etype == "DELETED" and sensitive:
            self._raise_alert(
                "DELETED", f"Sensitive file deleted: {os.path.basename(src)}", ev)

        self.callback(ev)

    def _raise_alert(self, atype, msg, details):
        alerts = load_json(ALERT_FILE)
        alert = {
            "id": f"ALT-{len(alerts)+1:04d}",
            "timestamp": now_iso(),
            "time_display": now_str(),
            "type": atype,
            "message": msg,
            "details": details,
            "acknowledged": False,
        }
        alerts.append(alert)
        save_json(ALERT_FILE, alerts)

    def on_created(self, event):
        if not event.is_directory:
            self._emit("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit("MOVED", event.src_path, event.dest_path)

# ── Main App ──────────────────────────────────────────────────────────────────


class SecureMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{VERSION}")
        self.geometry("1280x820")
        self.minsize(1000, 680)
        self.configure(fg_color=COLORS["bg_dark"])

        self.observer = None
        self.is_monitoring = False
        self.watch_dirs = []
        self.event_count = tk.IntVar(value=0)
        self.alert_count = tk.IntVar(value=0)
        self.sensitive_count = tk.IntVar(value=0)
        self.integrity_count = tk.IntVar(value=0)

        self._build_ui()
        self._refresh_from_disk()
        self._start_auto_refresh()

    # ── UI Build ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top bar
        topbar = ctk.CTkFrame(self, fg_color=COLORS["bg_card"],
                              border_color=COLORS["border"], border_width=1, height=56, corner_radius=0)
        topbar.pack(fill="x", side="top")
        topbar.pack_propagate(False)

        ctk.CTkLabel(topbar, text="⬡  SECURE MONITOR",
                     font=ctk.CTkFont("Courier", 18, "bold"),
                     text_color=COLORS["accent"]).pack(side="left", padx=20)
        ctk.CTkLabel(topbar, text=f"v{VERSION}  ·  {platform.system()}",
                     font=ctk.CTkFont("Courier", 11),
                     text_color=COLORS["muted"]).pack(side="left", padx=4)

        self.status_dot = ctk.CTkLabel(topbar, text="● IDLE",
                                       font=ctk.CTkFont("Courier", 12, "bold"),
                                       text_color=COLORS["muted"])
        self.status_dot.pack(side="right", padx=20)

        self.clock_lbl = ctk.CTkLabel(topbar, text="",
                                      font=ctk.CTkFont("Courier", 12),
                                      text_color=COLORS["text_dim"])
        self.clock_lbl.pack(side="right", padx=12)
        self._tick_clock()

        # ── Body: sidebar + main
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)
        self._build_main(body)

    def _build_sidebar(self, parent):
        sidebar = ctk.CTkFrame(parent, fg_color=COLORS["bg_card"],
                               border_color=COLORS["border"], border_width=1,
                               width=260, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        ctk.CTkLabel(sidebar, text="WATCH DIRECTORIES",
                     font=ctk.CTkFont("Courier", 11, "bold"),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=16, pady=(16, 6))

        self.dir_listbox = tk.Listbox(sidebar,
                                      bg=COLORS["bg_input"], fg=COLORS["text"],
                                      selectbackground=COLORS["tag_blue"], selectforeground=COLORS["text"],
                                      font=("Courier", 10), borderwidth=0, highlightthickness=0,
                                      relief="flat", activestyle="none")
        self.dir_listbox.pack(fill="x", padx=12, ipady=4)

        btn_row = ctk.CTkFrame(sidebar, fg_color="transparent")
        btn_row.pack(fill="x", padx=12, pady=6)

        ctk.CTkButton(btn_row, text="+ Add Dir", width=110, height=30,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_blue"], hover_color="#1a3060",
                      text_color=COLORS["accent"],
                      command=self._add_dir).pack(side="left")
        ctk.CTkButton(btn_row, text="Remove", width=90, height=30,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      text_color=COLORS["muted"],
                      command=self._remove_dir).pack(side="left", padx=6)

        divider(sidebar)

        # Sensitive extensions config
        ctk.CTkLabel(sidebar, text="SENSITIVE EXTENSIONS",
                     font=ctk.CTkFont("Courier", 11, "bold"),
                     text_color=COLORS["muted"]).pack(anchor="w", padx=16, pady=(12, 4))

        self.ext_var = tk.StringVar(
            value=" ".join(sorted(SENSITIVE_EXTENSIONS)))
        ext_entry = ctk.CTkEntry(sidebar, textvariable=self.ext_var,
                                 font=ctk.CTkFont("Courier", 10),
                                 fg_color=COLORS["bg_input"],
                                 border_color=COLORS["border"],
                                 text_color=COLORS["text"])
        ext_entry.pack(fill="x", padx=12)

        ctk.CTkButton(sidebar, text="Apply Extensions", height=30,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_green"], hover_color="#152e1f",
                      text_color=COLORS["accent2"],
                      command=self._apply_extensions).pack(fill="x", padx=12, pady=6)

        divider(sidebar)

        # Control buttons
        self.start_btn = ctk.CTkButton(sidebar, text="▶  START MONITOR",
                                       height=40, corner_radius=6,
                                       font=ctk.CTkFont("Courier", 13, "bold"),
                                       fg_color=COLORS["accent2"], hover_color="#2ea043",
                                       text_color="#0d1117",
                                       command=self.start_monitoring)
        self.start_btn.pack(fill="x", padx=12, pady=(12, 6))

        self.stop_btn = ctk.CTkButton(sidebar, text="⏹  STOP MONITOR",
                                      height=40, corner_radius=6,
                                      font=ctk.CTkFont("Courier", 13, "bold"),
                                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                                      text_color=COLORS["muted"],
                                      state="disabled",
                                      command=self.stop_monitoring)
        self.stop_btn.pack(fill="x", padx=12, pady=6)

        ctk.CTkButton(sidebar, text="⬡  Take Baseline",
                      height=34, corner_radius=6,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_amber"], hover_color="#2e2508",
                      text_color=COLORS["accent3"],
                      command=self._take_baseline).pack(fill="x", padx=12, pady=6)

        ctk.CTkButton(sidebar, text="⊞  Verify Integrity",
                      height=34, corner_radius=6,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_blue"], hover_color="#1a3060",
                      text_color=COLORS["accent"],
                      command=self._verify_integrity).pack(fill="x", padx=12)

        ctk.CTkButton(sidebar, text="⊟  Export Report",
                      height=34, corner_radius=6,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      text_color=COLORS["muted"],
                      command=self._export_report).pack(fill="x", padx=12, pady=6)

        ctk.CTkButton(sidebar, text="⊠  Clear All Logs",
                      height=34, corner_radius=6,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_red"], hover_color="#2e0e0e",
                      text_color=COLORS["danger"],
                      command=self._clear_logs).pack(fill="x", padx=12)

    def _build_main(self, parent):
        main = ctk.CTkFrame(parent, fg_color="transparent")
        main.pack(side="left", fill="both", expand=True, padx=12, pady=12)

        # ── Stats row
        stats = ctk.CTkFrame(main, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 10))

        self.stat_cards = {}
        stats_data = [
            ("TOTAL EVENTS",    self.event_count,
             COLORS["accent"],  COLORS["tag_blue"]),
            ("ALERTS",          self.alert_count,
             COLORS["danger"],  COLORS["tag_red"]),
            ("SENSITIVE FILES", self.sensitive_count,
             COLORS["accent3"], COLORS["tag_amber"]),
            ("INTEGRITY FAILS", self.integrity_count,
             COLORS["accent2"], COLORS["tag_green"]),
        ]
        for i, (label, var, color, bg) in enumerate(stats_data):
            card = self._stat_card(stats, label, var, color, bg)
            card.grid(row=0, column=i, padx=(0, 8), sticky="ew")
            stats.columnconfigure(i, weight=1)

        # ── Notebook (tabs)
        tabview = ctk.CTkTabview(main,
                                 fg_color=COLORS["bg_card"],
                                 segmented_button_fg_color=COLORS["bg_input"],
                                 segmented_button_selected_color=COLORS["accent"],
                                 segmented_button_selected_hover_color="#4090e0",
                                 segmented_button_unselected_color=COLORS["bg_input"],
                                 segmented_button_unselected_hover_color=COLORS["border"],
                                 text_color=COLORS["text"],
                                 border_color=COLORS["border"],
                                 border_width=1)
        tabview.pack(fill="both", expand=True)

        tabview.add("Live Feed")
        tabview.add("Alerts")
        tabview.add("Integrity")
        tabview.add("Log Explorer")

        self._build_live_tab(tabview.tab("Live Feed"))
        self._build_alerts_tab(tabview.tab("Alerts"))
        self._build_integrity_tab(tabview.tab("Integrity"))
        self._build_log_explorer_tab(tabview.tab("Log Explorer"))

    def _stat_card(self, parent, label, var, color, bg):
        card = ctk.CTkFrame(parent, fg_color=bg,
                            border_color=color, border_width=1,
                            corner_radius=8, height=84)
        card.pack_propagate(False)
        ctk.CTkLabel(card, text=label, font=ctk.CTkFont("Courier", 10, "bold"),
                     text_color=color).pack(anchor="w", padx=12, pady=(10, 0))
        ctk.CTkLabel(card, textvariable=var, font=ctk.CTkFont("Courier", 30, "bold"),
                     text_color=COLORS["text"]).pack(anchor="w", padx=12)
        return card

    # ── Live Feed Tab ──────────────────────────────────────────────────────────

    def _build_live_tab(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(header, text="REAL-TIME FILE EVENTS",
                     font=ctk.CTkFont("Courier", 12, "bold"),
                     text_color=COLORS["accent"]).pack(side="left")

        self.filter_var = tk.StringVar(value="ALL")
        for fval in ["ALL", "CREATED", "MODIFIED", "MOVED", "DELETED"]:
            ctk.CTkButton(header, text=fval, width=80, height=26,
                          font=ctk.CTkFont("Courier", 10),
                          fg_color=COLORS["bg_input"] if fval != "ALL" else COLORS["tag_blue"],
                          hover_color=COLORS["border"],
                          text_color=COLORS["accent"] if fval == "ALL" else COLORS["muted"],
                          command=lambda v=fval: self._filter_events(v)).pack(side="left", padx=3)

        # Table
        cols = ("Time", "Event", "Filename", "Sensitive", "Hash")
        self.event_tree = self._build_table(
            parent, cols, (80, 90, 340, 80, 220))
        self.event_tree.bind("<Double-1>", self._show_event_detail)

    # ── Alerts Tab ────────────────────────────────────────────────────────────

    def _build_alerts_tab(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(header, text="SECURITY ALERTS",
                     font=ctk.CTkFont("Courier", 12, "bold"),
                     text_color=COLORS["danger"]).pack(side="left")
        ctk.CTkButton(header, text="Acknowledge All", width=140, height=26,
                      font=ctk.CTkFont("Courier", 10),
                      fg_color=COLORS["tag_red"], hover_color="#2e0e0e",
                      text_color=COLORS["danger"],
                      command=self._ack_all_alerts).pack(side="right")

        cols = ("ID", "Time", "Type", "Message", "Ack")
        self.alert_tree = self._build_table(
            parent, cols, (70, 80, 120, 400, 60))
        self.alert_tree.bind("<Double-1>", self._show_alert_detail)

    # ── Integrity Tab ─────────────────────────────────────────────────────────

    def _build_integrity_tab(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(header, text="FILE INTEGRITY SCANNER",
                     font=ctk.CTkFont("Courier", 12, "bold"),
                     text_color=COLORS["accent2"]).pack(side="left")

        btn_row = ctk.CTkFrame(parent, fg_color="transparent")
        btn_row.pack(fill="x", padx=8, pady=(0, 8))

        ctk.CTkButton(btn_row, text="Take Baseline Snapshot", width=180, height=32,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_amber"], hover_color="#2e2508",
                      text_color=COLORS["accent3"],
                      command=self._take_baseline).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Run Integrity Check", width=160, height=32,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["tag_green"], hover_color="#152e1f",
                      text_color=COLORS["accent2"],
                      command=self._verify_integrity).pack(side="left")

        self.integrity_status = ctk.CTkLabel(btn_row, text="No scan run yet",
                                             font=ctk.CTkFont("Courier", 11),
                                             text_color=COLORS["muted"])
        self.integrity_status.pack(side="right", padx=8)

        cols = ("Status", "Filename", "Path", "Current Hash", "Stored Hash")
        self.integrity_tree = self._build_table(
            parent, cols, (80, 180, 220, 180, 180))

    # ── Log Explorer Tab ──────────────────────────────────────────────────────

    def _build_log_explorer_tab(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(header, text="LOG EXPLORER",
                     font=ctk.CTkFont("Courier", 12, "bold"),
                     text_color=COLORS["accent"]).pack(side="left")

        ctk.CTkLabel(header, text="Search:",
                     font=ctk.CTkFont("Courier", 11),
                     text_color=COLORS["muted"]).pack(side="left", padx=(20, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search)
        ctk.CTkEntry(header, textvariable=self.search_var, width=260, height=28,
                     font=ctk.CTkFont("Courier", 11),
                     fg_color=COLORS["bg_input"],
                     border_color=COLORS["border"],
                     text_color=COLORS["text"],
                     placeholder_text="filename, path, hash...").pack(side="left")

        ctk.CTkButton(header, text="Refresh", width=80, height=28,
                      font=ctk.CTkFont("Courier", 10),
                      fg_color=COLORS["tag_blue"], hover_color="#1a3060",
                      text_color=COLORS["accent"],
                      command=self._refresh_from_disk).pack(side="right")

        cols = ("Timestamp", "Event", "Filename",
                "Source Path", "Sensitive", "Hash")
        self.log_tree = self._build_table(
            parent, cols, (140, 90, 160, 240, 80, 160))

    # ── Table Builder ─────────────────────────────────────────────────────────

    def _build_table(self, parent, columns, widths):
        import tkinter.ttk as ttk

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Treeview",
                        background=COLORS["bg_input"],
                        fieldbackground=COLORS["bg_input"],
                        foreground=COLORS["text"],
                        rowheight=28,
                        font=("Courier", 10),
                        borderwidth=0,
                        )
        style.configure("Dark.Treeview.Heading",
                        background=COLORS["bg_card"],
                        foreground=COLORS["muted"],
                        font=("Courier", 10, "bold"),
                        relief="flat",
                        borderwidth=0,
                        )
        style.map("Dark.Treeview",
                  background=[("selected", COLORS["tag_blue"])],
                  foreground=[("selected", COLORS["text"])],
                  )
        style.layout("Dark.Treeview", [
                     ('Treeview.treearea', {'sticky': 'nswe'})])

        frame = ctk.CTkFrame(parent, fg_color=COLORS["bg_input"],
                             corner_radius=6,
                             border_color=COLORS["border"], border_width=1)
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        scrolly = ctk.CTkScrollbar(frame)
        scrolly.pack(side="right", fill="y")
        scrollx = ctk.CTkScrollbar(frame, orientation="horizontal")
        scrollx.pack(side="bottom", fill="x")

        tree = ttk.Treeview(frame, columns=columns, show="headings",
                            style="Dark.Treeview",
                            yscrollcommand=scrolly.set,
                            xscrollcommand=scrollx.set)
        for col, w in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=40, anchor="w")

        tree.tag_configure("sensitive",  background="#1a1f0a",
                           foreground=COLORS["accent3"])
        tree.tag_configure("critical",   background="#1f0d0d",
                           foreground=COLORS["danger"])
        tree.tag_configure("ok",         background="#0d1a0e",
                           foreground=COLORS["accent2"])
        tree.tag_configure("new",        background="#0d0f1a",
                           foreground=COLORS["accent"])
        tree.tag_configure("deleted",    background="#1f0d0d",
                           foreground=COLORS["danger"])
        tree.tag_configure(
            "tampered",   background="#1f1205", foreground="#f0883e")
        tree.tag_configure(
            "ack",        background=COLORS["bg_input"], foreground=COLORS["muted"])

        scrolly.configure(command=tree.yview)
        scrollx.configure(command=tree.xview)
        tree.pack(fill="both", expand=True)
        return tree

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add_dir(self):
        d = filedialog.askdirectory(title="Select directory to monitor")
        if d and d not in self.watch_dirs:
            self.watch_dirs.append(d)
            self.dir_listbox.insert("end", f"  {d}")

    def _remove_dir(self):
        sel = self.dir_listbox.curselection()
        if sel:
            idx = sel[0]
            self.dir_listbox.delete(idx)
            if idx < len(self.watch_dirs):
                self.watch_dirs.pop(idx)

    def _apply_extensions(self):
        global SENSITIVE_EXTENSIONS
        raw = self.ext_var.get().split()
        SENSITIVE_EXTENSIONS = {e if e.startswith(".") else "."+e for e in raw}
        self._toast("Extensions updated!")

    def start_monitoring(self):
        if not self.watch_dirs:
            messagebox.showwarning(
                "No Directories", "Please add at least one directory to monitor.")
            return
        if not WATCHDOG_AVAILABLE:
            messagebox.showerror(
                "Missing Package", "Install watchdog:\n  pip install watchdog")
            return
        if self.is_monitoring:
            return

        self._take_baseline_silent()

        handler = MonitorHandler(self._on_event)
        self.observer = Observer()
        for d in self.watch_dirs:
            if os.path.exists(d):
                self.observer.schedule(handler, d, recursive=True)
        self.observer.start()
        self.is_monitoring = True

        self.status_dot.configure(
            text="● MONITORING", text_color=COLORS["accent2"])
        self.start_btn.configure(state="disabled", fg_color=COLORS["bg_input"],
                                 text_color=COLORS["muted"])
        self.stop_btn.configure(state="normal", fg_color=COLORS["danger"],
                                text_color="white")
        self._toast("Monitoring started!")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.is_monitoring = False
        self.status_dot.configure(text="● IDLE", text_color=COLORS["muted"])
        self.start_btn.configure(state="normal", fg_color=COLORS["accent2"],
                                 text_color="#0d1117")
        self.stop_btn.configure(state="disabled", fg_color=COLORS["bg_input"],
                                text_color=COLORS["muted"])
        self._toast("Monitoring stopped.")

    def _on_event(self, ev):
        self.after(0, lambda: self._insert_event_row(ev))
        self.after(0, self._update_stats)

    def _insert_event_row(self, ev):
        etype = ev.get("event_type", "")
        sensitive = ev.get("sensitive", False)
        h = ev.get("file_hash", "")[:16] + "..." if ev.get("file_hash") else ""

        tag = "sensitive" if sensitive else ""
        if etype == "DELETED":
            tag = "deleted"

        row = (ev.get("time_display", ""), etype,
               ev.get("filename", ""), "YES" if sensitive else "no", h)

        self.event_tree.insert("", 0, values=row, tags=(tag,))
        self.log_tree.insert("", 0,
                             values=(ev.get("timestamp", ""), etype, ev.get("filename", ""),
                                     ev.get("source_path",
                                            ""), "YES" if sensitive else "no",
                                     ev.get("file_hash", "")[:20] + "..."),
                             tags=(tag,))

        alerts = load_json(ALERT_FILE)
        unacked = [a for a in alerts if not a.get("acknowledged")]
        if unacked:
            self._insert_alert_row(unacked[-1])

    def _insert_alert_row(self, alert):
        atype = alert.get("type", "")
        ack = "YES" if alert.get("acknowledged") else "NO"
        tag = "ack" if alert.get("acknowledged") else "critical"
        self.alert_tree.insert("", 0,
                               values=(alert.get("id", ""), alert.get("time_display", ""),
                                       atype, alert.get("message", ""), ack),
                               tags=(tag,))

    def _update_stats(self):
        logs = load_json(LOG_FILE)
        alerts = load_json(ALERT_FILE)
        self.event_count.set(len(logs))
        self.alert_count.set(
            len([a for a in alerts if not a.get("acknowledged")]))
        self.sensitive_count.set(len([e for e in logs if e.get("sensitive")]))
        self.integrity_count.set(
            len([e for e in logs if e.get("integrity") == "TAMPERED"]))

    def _take_baseline(self):
        if not self.watch_dirs:
            messagebox.showwarning("No Dirs", "Add directories first.")
            return
        self._take_baseline_silent()
        self._toast("Baseline snapshot taken!")

    def _take_baseline_silent(self):
        db = {}
        for d in self.watch_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    db[fpath] = {"hash": compute_hash(
                        fpath), "timestamp": now_iso()}
        save_json(HASH_DB_FILE, db)

    def _verify_integrity(self):
        if not self.watch_dirs:
            messagebox.showwarning("No Dirs", "Add directories first.")
            return

        self.integrity_tree.delete(*self.integrity_tree.get_children())
        db = load_json(HASH_DB_FILE, {})
        if not db:
            messagebox.showinfo("No Baseline", "Take a baseline first.")
            return

        results = {"ok": 0, "tampered": 0, "new": 0, "deleted": 0}

        for d in self.watch_dirs:
            if not os.path.exists(d):
                continue
            for root, _, files in os.walk(d):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    curr = compute_hash(fpath)
                    if fpath not in db:
                        status = "NEW"
                        stored = ""
                        results["new"] += 1
                        tag = "new"
                    else:
                        stored = db[fpath]["hash"]
                        if curr == stored:
                            status = "OK"
                            results["ok"] += 1
                            tag = "ok"
                        else:
                            status = "TAMPERED"
                            results["tampered"] += 1
                            tag = "tampered"
                    self.integrity_tree.insert("", "end",
                                               values=(status, fname, root,
                                                       curr[:20]+"...", stored[:20]+"..." if stored else "—"),
                                               tags=(tag,))

        for fpath in db:
            if any(fpath.startswith(d) for d in self.watch_dirs):
                if not os.path.exists(fpath):
                    results["deleted"] += 1
                    self.integrity_tree.insert("", "end",
                                               values=("DELETED", os.path.basename(fpath),
                                                       os.path.dirname(
                                                           fpath), "—",
                                                       db[fpath]["hash"][:20]+"..."),
                                               tags=("deleted",))

        self.integrity_status.configure(
            text=f"OK:{results['ok']}  NEW:{results['new']}  TAMPERED:{results['tampered']}  DELETED:{results['deleted']}",
            text_color=COLORS["danger"] if results["tampered"] else COLORS["accent2"])
        self.integrity_count.set(results["tampered"])
        self._toast(
            f"Integrity check done — {results['tampered']} tampered file(s)")

    def _filter_events(self, fval):
        logs = load_json(LOG_FILE)
        self.event_tree.delete(*self.event_tree.get_children())
        for ev in reversed(logs):
            if fval != "ALL" and ev.get("event_type") != fval:
                continue
            sensitive = ev.get("sensitive", False)
            etype = ev.get("event_type", "")
            tag = "sensitive" if sensitive else ""
            if etype == "DELETED":
                tag = "deleted"
            h = ev.get("file_hash", "")[:16] + \
                "..." if ev.get("file_hash") else ""
            self.event_tree.insert("", "end",
                                   values=(ev.get("time_display", ""), etype,
                                           ev.get("filename", ""), "YES" if sensitive else "no", h),
                                   tags=(tag,))

    def _ack_all_alerts(self):
        alerts = load_json(ALERT_FILE)
        for a in alerts:
            a["acknowledged"] = True
        save_json(ALERT_FILE, alerts)
        self._refresh_from_disk()
        self.alert_count.set(0)
        self._toast("All alerts acknowledged.")

    def _export_report(self):
        logs = load_json(LOG_FILE)
        alerts = load_json(ALERT_FILE)
        tampered = [e for e in logs if e.get("integrity") == "TAMPERED"]
        unauth = [a for a in alerts if a.get("type") == "UNAUTHORIZED"]

        report = f"""
╔══════════════════════════════════════════════════════════════╗
║         SECURE FILE TRANSFER MONITORING — AUDIT REPORT      ║
╚══════════════════════════════════════════════════════════════╝
Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Directories: {', '.join(self.watch_dirs) or 'N/A'}

━━━  SUMMARY
  Total Events         : {len(logs)}
  Sensitive Events     : {len([e for e in logs if e.get('sensitive')])}
  Integrity Violations : {len(tampered)}
  Unauthorized Moves   : {len(unauth)}
  Total Alerts         : {len(alerts)}
  Unacknowledged       : {len([a for a in alerts if not a.get('acknowledged')])}

━━━  ALERTS
"""
        for a in alerts:
            ack = "[ACK]" if a.get("acknowledged") else "[NEW]"
            report += f"\n  {ack} [{a.get('timestamp', '')}] {a.get('type', '')} — {a.get('message', '')}"

        report += "\n\n━━━  RECENT EVENTS (last 20)\n"
        for ev in logs[-20:]:
            report += (f"\n  [{ev.get('timestamp', '')}] {ev.get('event_type', '')}"
                       f"  {ev.get('source_path', '')}"
                       f"  {'(SENSITIVE)' if ev.get('sensitive') else ''}")

        report += "\n\n══════════════════════════════════════════════════════\n"

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All", "*.*")],
            initialfile=f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            with open(path, "w") as f:
                f.write(report)
            self._toast(f"Report saved!")

    def _clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Delete all logs and alerts? This cannot be undone."):
            for f in [LOG_FILE, ALERT_FILE]:
                save_json(f, [])
            self._refresh_from_disk()
            self._toast("Logs cleared.")

    def _show_event_detail(self, event):
        sel = self.event_tree.selection()
        if not sel:
            return
        vals = self.event_tree.item(sel[0], "values")
        win = DetailWindow(self, "Event Detail", {
            "Time": vals[0], "Event": vals[1],
            "Filename": vals[2], "Sensitive": vals[3], "Hash": vals[4]})

    def _show_alert_detail(self, event):
        sel = self.alert_tree.selection()
        if not sel:
            return
        vals = self.alert_tree.item(sel[0], "values")
        win = DetailWindow(self, "Alert Detail", {
            "ID": vals[0], "Time": vals[1],
            "Type": vals[2], "Message": vals[3], "Acknowledged": vals[4]})

    def _on_search(self, *args):
        q = self.search_var.get().lower()
        logs = load_json(LOG_FILE)
        self.log_tree.delete(*self.log_tree.get_children())
        for ev in reversed(logs):
            row_text = " ".join([
                ev.get("filename", ""), ev.get("source_path", ""), ev.get("file_hash", "")]).lower()
            if q and q not in row_text:
                continue
            sensitive = ev.get("sensitive", False)
            tag = "sensitive" if sensitive else ""
            self.log_tree.insert("", "end",
                                 values=(ev.get("timestamp", ""), ev.get("event_type", ""),
                                         ev.get("filename", ""), ev.get(
                                             "source_path", ""),
                                         "YES" if sensitive else "no",
                                         ev.get("file_hash", "")[:20]+"..."),
                                 tags=(tag,))

    def _refresh_from_disk(self):
        logs = load_json(LOG_FILE)
        alerts = load_json(ALERT_FILE)

        self.event_tree.delete(*self.event_tree.get_children())
        self.alert_tree.delete(*self.alert_tree.get_children())
        self.log_tree.delete(*self.log_tree.get_children())

        for ev in reversed(logs[-200:]):
            sensitive = ev.get("sensitive", False)
            etype = ev.get("event_type", "")
            tag = "sensitive" if sensitive else ""
            if etype == "DELETED":
                tag = "deleted"
            h = ev.get("file_hash", "")[:16] + \
                "..." if ev.get("file_hash") else ""
            self.event_tree.insert("", "end",
                                   values=(ev.get("time_display", ""), etype,
                                           ev.get("filename", ""), "YES" if sensitive else "no", h),
                                   tags=(tag,))
            self.log_tree.insert("", "end",
                                 values=(ev.get("timestamp", ""), etype, ev.get("filename", ""),
                                         ev.get(
                                             "source_path", ""), "YES" if sensitive else "no",
                                         ev.get("file_hash", "")[:20]+"..."),
                                 tags=(tag,))

        for alert in reversed(alerts[-100:]):
            ack = "YES" if alert.get("acknowledged") else "NO"
            tag = "ack" if alert.get("acknowledged") else "critical"
            self.alert_tree.insert("", "end",
                                   values=(alert.get("id", ""), alert.get("time_display", ""),
                                           alert.get("type", ""), alert.get("message", ""), ack),
                                   tags=(tag,))

        self._update_stats()

    def _start_auto_refresh(self):
        self._update_stats()
        self.after(5000, self._start_auto_refresh)

    def _tick_clock(self):
        self.clock_lbl.configure(
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _toast(self, msg):
        toast = ctk.CTkLabel(self, text=f"  {msg}  ",
                             font=ctk.CTkFont("Courier", 12),
                             fg_color=COLORS["tag_blue"],
                             text_color=COLORS["accent"],
                             corner_radius=6)
        toast.place(relx=0.5, rely=0.96, anchor="center")
        self.after(2500, toast.destroy)


# ── Detail popup ──────────────────────────────────────────────────────────────

class DetailWindow(ctk.CTkToplevel):
    def __init__(self, parent, title, data: dict):
        super().__init__(parent)
        self.title(title)
        self.geometry("560x320")
        self.configure(fg_color=COLORS["bg_card"])
        self.grab_set()

        ctk.CTkLabel(self, text=title,
                     font=ctk.CTkFont("Courier", 14, "bold"),
                     text_color=COLORS["accent"]).pack(anchor="w", padx=20, pady=(16, 8))

        for key, val in data.items():
            row = ctk.CTkFrame(self, fg_color=COLORS["bg_input"],
                               corner_radius=4, height=36)
            row.pack(fill="x", padx=20, pady=2)
            row.pack_propagate(False)
            ctk.CTkLabel(row, text=f"{key}:", width=120,
                         font=ctk.CTkFont("Courier", 11, "bold"),
                         text_color=COLORS["muted"]).pack(side="left", padx=10)
            ctk.CTkLabel(row, text=str(val),
                         font=ctk.CTkFont("Courier", 11),
                         text_color=COLORS["text"]).pack(side="left", padx=4)

        ctk.CTkButton(self, text="Close", width=100, height=32,
                      font=ctk.CTkFont("Courier", 11),
                      fg_color=COLORS["bg_input"], hover_color=COLORS["border"],
                      text_color=COLORS["muted"],
                      command=self.destroy).pack(pady=16)


# ── Divider helper ────────────────────────────────────────────────────────────

def divider(parent):
    ctk.CTkFrame(parent, height=1, fg_color=COLORS["border"], corner_radius=0).pack(
        fill="x", padx=12, pady=8)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = SecureMonitorApp()
    app.mainloop()
