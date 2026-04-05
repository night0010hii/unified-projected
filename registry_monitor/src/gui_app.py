"""
gui_app.py - Main GUI Application
Windows Registry Change Monitoring System - Advanced Edition
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import queue
import time
import json
import os
import sys
from datetime import datetime

# Import our modules
from config import ALL_MONITOR_KEYS, MALWARE_PATTERNS, POLL_INTERVAL, BASELINE_FILE, LOG_FILE, REPORT_FILE
from utils import ensure_dirs, timestamp, hive_name, read_registry_key
from baseline import capture_baseline, load_baseline
from monitor import take_snapshot
from detector import diff_snapshots, check_malware_patterns
from reporter import log_change, generate_report

# ── Color Palette (Cyberpunk/Terminal Dark Theme) ──────────────────────────
COLORS = {
    "bg_dark":      "#0a0d14",
    "bg_panel":     "#0f1420",
    "bg_card":      "#141926",
    "bg_hover":     "#1a2133",
    "accent_cyan":  "#00d4ff",
    "accent_green": "#00ff88",
    "accent_red":   "#ff3355",
    "accent_amber": "#ffaa00",
    "accent_blue":  "#4488ff",
    "text_primary": "#e8edf5",
    "text_dim":     "#6b7fa3",
    "text_muted":   "#3d4f6e",
    "border":       "#1e2d47",
    "border_glow":  "#00d4ff33",
    "success":      "#00ff88",
    "warning":      "#ffaa00",
    "danger":       "#ff3355",
    "info":         "#4488ff",
}

FONTS = {
    "title":    ("Consolas", 18, "bold"),
    "heading":  ("Consolas", 12, "bold"),
    "body":     ("Consolas", 10),
    "small":    ("Consolas", 9),
    "mono":     ("Courier New", 10),
    "status":   ("Consolas", 11, "bold"),
}


class RegistryMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        ensure_dirs()
        self.title("RegWatch Pro — Registry Monitoring System")
        self.geometry("1280x820")
        self.minsize(1100, 700)
        self.configure(bg=COLORS["bg_dark"])

        # State
        self.monitoring = False
        self.monitor_thread = None
        self.msg_queue = queue.Queue()
        self.baseline_data = None
        self.change_count = 0
        self.alert_count = 0
        self.poll_interval = tk.IntVar(value=POLL_INTERVAL)
        self.all_changes = []
        self.all_alerts = []

        # Build UI
        self._setup_styles()
        self._build_header()
        self._build_main_layout()
        self._build_status_bar()

        # Start queue processor
        self.after(200, self._process_queue)

        # Try loading existing baseline on start
        self.after(500, self._auto_load_baseline)

    # ── Style Setup ───────────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Dark.TFrame", background=COLORS["bg_dark"])
        style.configure("Panel.TFrame", background=COLORS["bg_panel"])
        style.configure("Card.TFrame", background=COLORS["bg_card"])
        style.configure(
            "Cyber.TButton",
            background=COLORS["bg_card"],
            foreground=COLORS["accent_cyan"],
            bordercolor=COLORS["accent_cyan"],
            focuscolor=COLORS["accent_cyan"],
            font=FONTS["body"],
            padding=(12, 6),
            relief="flat",
        )
        style.map("Cyber.TButton",
                  background=[("active", COLORS["bg_hover"]),
                              ("pressed", COLORS["bg_dark"])],
                  foreground=[("active", COLORS["accent_cyan"])],
                  )
        style.configure(
            "Green.TButton",
            background="#003322",
            foreground=COLORS["accent_green"],
            bordercolor=COLORS["accent_green"],
            font=FONTS["body"],
            padding=(12, 6),
            relief="flat",
        )
        style.map("Green.TButton",
                  background=[("active", "#004433")],
                  )
        style.configure(
            "Red.TButton",
            background="#220011",
            foreground=COLORS["accent_red"],
            bordercolor=COLORS["accent_red"],
            font=FONTS["body"],
            padding=(12, 6),
            relief="flat",
        )
        style.map("Red.TButton",
                  background=[("active", "#330022")],
                  )
        style.configure(
            "Amber.TButton",
            background="#221100",
            foreground=COLORS["accent_amber"],
            bordercolor=COLORS["accent_amber"],
            font=FONTS["body"],
            padding=(12, 6),
            relief="flat",
        )
        style.map("Amber.TButton",
                  background=[("active", "#332200")],
                  )
        style.configure(
            "TNotebook",
            background=COLORS["bg_dark"],
            borderwidth=0,
            tabmargins=[0, 0, 0, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=COLORS["bg_panel"],
            foreground=COLORS["text_dim"],
            font=FONTS["body"],
            padding=[18, 8],
            borderwidth=0,
        )
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["bg_card"])],
                  foreground=[("selected", COLORS["accent_cyan"])],
                  )
        style.configure(
            "Treeview",
            background=COLORS["bg_card"],
            foreground=COLORS["text_primary"],
            fieldbackground=COLORS["bg_card"],
            rowheight=28,
            font=FONTS["small"],
            borderwidth=0,
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["bg_panel"],
            foreground=COLORS["accent_cyan"],
            font=FONTS["small"],
            relief="flat",
        )
        style.map("Treeview",
                  background=[("selected", COLORS["bg_hover"])],
                  foreground=[("selected", COLORS["accent_cyan"])],
                  )
        style.configure("TScale",
                        background=COLORS["bg_card"],
                        troughcolor=COLORS["border"],
                        sliderrelief="flat",
                        )
        style.configure("TScrollbar",
                        background=COLORS["bg_panel"],
                        troughcolor=COLORS["bg_dark"],
                        bordercolor=COLORS["border"],
                        arrowcolor=COLORS["text_dim"],
                        )

    # ── Header ─────────────────────────────────────────────────────────────

    def _build_header(self):
        hdr = tk.Frame(self, bg=COLORS["bg_panel"], height=64)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        # Left: logo + title
        left = tk.Frame(hdr, bg=COLORS["bg_panel"])
        left.pack(side="left", padx=20, pady=8)

        tk.Label(left, text="⬡", font=("Consolas", 22, "bold"),
                 fg=COLORS["accent_cyan"], bg=COLORS["bg_panel"]).pack(side="left", padx=(0, 10))

        title_block = tk.Frame(left, bg=COLORS["bg_panel"])
        title_block.pack(side="left")
        tk.Label(title_block, text="RegWatch Pro",
                 font=("Consolas", 15, "bold"),
                 fg=COLORS["text_primary"], bg=COLORS["bg_panel"]).pack(anchor="w")
        tk.Label(title_block, text="Windows Registry Change Monitoring System",
                 font=FONTS["small"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_panel"]).pack(anchor="w")

        # Right: live clock + status indicator
        right = tk.Frame(hdr, bg=COLORS["bg_panel"])
        right.pack(side="right", padx=20)

        self.status_dot = tk.Label(right, text="●", font=("Consolas", 14),
                                   fg=COLORS["text_muted"], bg=COLORS["bg_panel"])
        self.status_dot.pack(side="left", padx=(0, 6))

        self.status_label = tk.Label(right, text="IDLE",
                                     font=FONTS["status"],
                                     fg=COLORS["text_dim"], bg=COLORS["bg_panel"])
        self.status_label.pack(side="left", padx=(0, 20))

        self.clock_label = tk.Label(right, text="",
                                    font=FONTS["small"],
                                    fg=COLORS["text_dim"], bg=COLORS["bg_panel"])
        self.clock_label.pack(side="left")
        self._update_clock()

        # Separator line with glow effect
        sep = tk.Frame(self, bg=COLORS["accent_cyan"], height=1)
        sep.pack(fill="x")

    def _update_clock(self):
        self.clock_label.config(
            text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.after(1000, self._update_clock)

    # ── Main Layout ────────────────────────────────────────────────────────

    def _build_main_layout(self):
        main = tk.Frame(self, bg=COLORS["bg_dark"])
        main.pack(fill="both", expand=True, padx=0, pady=0)

        # Left sidebar
        self._build_sidebar(main)

        # Right content
        content = tk.Frame(main, bg=COLORS["bg_dark"])
        content.pack(side="left", fill="both",
                     expand=True, padx=(0, 10), pady=10)

        # Stats row
        self._build_stats_row(content)

        # Notebook tabs
        self._build_notebook(content)

    # ── Sidebar ────────────────────────────────────────────────────────────

    def _build_sidebar(self, parent):
        sb = tk.Frame(parent, bg=COLORS["bg_panel"], width=220)
        sb.pack(side="left", fill="y", padx=(10, 0), pady=10)
        sb.pack_propagate(False)

        # Section: Controls
        self._sb_section(sb, "CONTROLS")

        ttk.Button(sb, text="📸  Capture Baseline", style="Cyber.TButton",
                   command=self._capture_baseline).pack(fill="x", padx=12, pady=3)
        ttk.Button(sb, text="📂  Load Baseline", style="Cyber.TButton",
                   command=self._load_baseline).pack(fill="x", padx=12, pady=3)

        tk.Frame(sb, bg=COLORS["border"], height=1).pack(
            fill="x", padx=12, pady=8)

        self.btn_start = ttk.Button(sb, text="▶  Start Monitoring", style="Green.TButton",
                                    command=self._toggle_monitor)
        self.btn_start.pack(fill="x", padx=12, pady=3)

        ttk.Button(sb, text="🔍  Integrity Check", style="Amber.TButton",
                   command=self._integrity_check).pack(fill="x", padx=12, pady=3)

        tk.Frame(sb, bg=COLORS["border"], height=1).pack(
            fill="x", padx=12, pady=8)

        ttk.Button(sb, text="📄  Export Report", style="Cyber.TButton",
                   command=self._export_report).pack(fill="x", padx=12, pady=3)
        ttk.Button(sb, text="🗑  Clear Logs", style="Red.TButton",
                   command=self._clear_logs).pack(fill="x", padx=12, pady=3)

        # Section: Poll Interval
        tk.Frame(sb, bg=COLORS["border"], height=1).pack(
            fill="x", padx=12, pady=8)
        self._sb_section(sb, "POLL INTERVAL")

        self.interval_label = tk.Label(sb, text=f"{self.poll_interval.get()}s",
                                       font=FONTS["heading"],
                                       fg=COLORS["accent_cyan"], bg=COLORS["bg_panel"])
        self.interval_label.pack()

        slider = ttk.Scale(sb, from_=5, to=120, orient="horizontal",
                           variable=self.poll_interval, command=self._on_interval_change)
        slider.pack(fill="x", padx=12, pady=4)

        # Section: Baseline info
        tk.Frame(sb, bg=COLORS["border"], height=1).pack(
            fill="x", padx=12, pady=8)
        self._sb_section(sb, "BASELINE")

        self.baseline_status = tk.Label(sb, text="No baseline loaded",
                                        font=FONTS["small"], wraplength=190,
                                        fg=COLORS["accent_red"], bg=COLORS["bg_panel"])
        self.baseline_status.pack(padx=12, pady=4, anchor="w")

        # Section: Quick key adder
        tk.Frame(sb, bg=COLORS["border"], height=1).pack(
            fill="x", padx=12, pady=8)
        self._sb_section(sb, "ADD WATCH KEY")

        self.new_key_entry = tk.Entry(sb, bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                                      insertbackground=COLORS["accent_cyan"],
                                      font=FONTS["small"], bd=0,
                                      highlightthickness=1,
                                      highlightcolor=COLORS["accent_cyan"],
                                      highlightbackground=COLORS["border"])
        self.new_key_entry.pack(fill="x", padx=12, pady=4)
        self.new_key_entry.insert(0, "e.g. SOFTWARE\\...")

        ttk.Button(sb, text="+ Add Key", style="Cyber.TButton",
                   command=self._add_custom_key).pack(fill="x", padx=12, pady=3)

    def _sb_section(self, parent, title):
        tk.Label(parent, text=title, font=("Consolas", 8, "bold"),
                 fg=COLORS["text_muted"], bg=COLORS["bg_panel"],
                 anchor="w").pack(fill="x", padx=14, pady=(6, 2))

    # ── Stats Row ──────────────────────────────────────────────────────────

    def _build_stats_row(self, parent):
        row = tk.Frame(parent, bg=COLORS["bg_dark"])
        row.pack(fill="x", pady=(0, 8))

        stats = [
            ("CHANGES",    "0", COLORS["accent_cyan"],  "changes_val"),
            ("ALERTS",     "0", COLORS["accent_red"],   "alerts_val"),
            ("POLLS",      "0", COLORS["accent_blue"],  "polls_val"),
            ("KEYS WATCHED", "0", COLORS["accent_amber"], "keys_val"),
        ]

        for label, val, color, attr in stats:
            card = tk.Frame(row, bg=COLORS["bg_card"],
                            highlightthickness=1,
                            highlightbackground=COLORS["border"])
            card.pack(side="left", fill="x", expand=True, padx=4)

            tk.Label(card, text=label, font=("Consolas", 8, "bold"),
                     fg=COLORS["text_muted"], bg=COLORS["bg_card"]).pack(pady=(10, 0))
            lbl = tk.Label(card, text=val, font=("Consolas", 22, "bold"),
                           fg=color, bg=COLORS["bg_card"])
            lbl.pack(pady=(0, 10))
            setattr(self, attr, lbl)

        self.keys_val.config(text=str(len(ALL_MONITOR_KEYS)))

    # ── Notebook ───────────────────────────────────────────────────────────

    def _build_notebook(self, parent):
        self.nb = ttk.Notebook(parent)
        self.nb.pack(fill="both", expand=True)

        self._build_tab_live()
        self._build_tab_changes()
        self._build_tab_alerts()
        self._build_tab_keys()
        self._build_tab_baseline()
        self._build_tab_report()

    def _tab_frame(self, title):
        frame = tk.Frame(self.nb, bg=COLORS["bg_card"])
        self.nb.add(frame, text=f"  {title}  ")
        return frame

    # Tab: Live Console
    def _build_tab_live(self):
        f = self._tab_frame("🖥  Live Console")

        toolbar = tk.Frame(f, bg=COLORS["bg_panel"])
        toolbar.pack(fill="x", padx=12, pady=(8, 0))
        tk.Label(toolbar, text="LIVE OUTPUT", font=("Consolas", 8, "bold"),
                 fg=COLORS["text_muted"], bg=COLORS["bg_panel"]).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Clear", style="Cyber.TButton",
                   command=lambda: self.console.delete(1.0, "end")).pack(side="right", padx=4)

        self.console = scrolledtext.ScrolledText(
            f, bg=COLORS["bg_dark"], fg=COLORS["accent_green"],
            font=("Courier New", 10), bd=0,
            insertbackground=COLORS["accent_cyan"],
            selectbackground=COLORS["bg_hover"],
            wrap="word", state="disabled",
            highlightthickness=1,
            highlightbackground=COLORS["border"]
        )
        self.console.pack(fill="both", expand=True, padx=12, pady=8)

        # Tag colors for console
        self.console.tag_config("cyan",   foreground=COLORS["accent_cyan"])
        self.console.tag_config("green",  foreground=COLORS["accent_green"])
        self.console.tag_config("red",    foreground=COLORS["accent_red"])
        self.console.tag_config("amber",  foreground=COLORS["accent_amber"])
        self.console.tag_config("blue",   foreground=COLORS["accent_blue"])
        self.console.tag_config("dim",    foreground=COLORS["text_dim"])

    # Tab: Changes
    def _build_tab_changes(self):
        f = self._tab_frame("📋  Changes")

        # Filter bar
        bar = tk.Frame(f, bg=COLORS["bg_panel"])
        bar.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(bar, text="Filter:", font=FONTS["small"],
                 fg=COLORS["text_dim"], bg=COLORS["bg_panel"]).pack(side="left", padx=8)
        self.filter_var = tk.StringVar()
        self.filter_var.trace("w", self._filter_changes)
        e = tk.Entry(bar, textvariable=self.filter_var, bg=COLORS["bg_card"],
                     fg=COLORS["text_primary"], insertbackground=COLORS["accent_cyan"],
                     font=FONTS["small"], bd=0, highlightthickness=1,
                     highlightcolor=COLORS["accent_cyan"],
                     highlightbackground=COLORS["border"], width=30)
        e.pack(side="left", padx=4)

        cols = ("Time", "Type", "Key", "Value", "Old", "New")
        self.change_tree = ttk.Treeview(
            f, columns=cols, show="headings", selectmode="browse")
        widths = [120, 110, 320, 140, 140, 140]
        for col, w in zip(cols, widths):
            self.change_tree.heading(col, text=col)
            self.change_tree.column(col, width=w, minwidth=60)

        sb_y = ttk.Scrollbar(f, orient="vertical",
                             command=self.change_tree.yview)
        sb_x = ttk.Scrollbar(f, orient="horizontal",
                             command=self.change_tree.xview)
        self.change_tree.configure(
            yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)

        sb_y.pack(side="right", fill="y", padx=(0, 12), pady=4)
        self.change_tree.pack(fill="both", expand=True, padx=(12, 0), pady=4)
        sb_x.pack(fill="x", padx=12, pady=(0, 8))

        self.change_tree.tag_configure(
            "added",    background="#001a0d", foreground=COLORS["accent_green"])
        self.change_tree.tag_configure(
            "deleted",  background="#1a0008", foreground=COLORS["accent_red"])
        self.change_tree.tag_configure(
            "modified", background="#1a1000", foreground=COLORS["accent_amber"])

    # Tab: Alerts
    def _build_tab_alerts(self):
        f = self._tab_frame("⚠  Alerts")

        self.alert_list = scrolledtext.ScrolledText(
            f, bg=COLORS["bg_dark"], fg=COLORS["accent_red"],
            font=("Courier New", 10), bd=0,
            state="disabled", wrap="word",
            highlightthickness=1,
            highlightbackground=COLORS["border"]
        )
        self.alert_list.pack(fill="both", expand=True, padx=12, pady=12)
        self.alert_list.tag_config(
            "header",  foreground=COLORS["accent_amber"], font=("Courier New", 10, "bold"))
        self.alert_list.tag_config("pattern", foreground=COLORS["accent_red"])
        self.alert_list.tag_config(
            "normal",  foreground=COLORS["text_primary"])

    # Tab: Watched Keys
    def _build_tab_keys(self):
        f = self._tab_frame("🔑  Watched Keys")

        cols = ("Hive", "Subkey", "Status")
        self.keys_tree = ttk.Treeview(f, columns=cols, show="headings")
        self.keys_tree.heading("Hive",   text="Hive")
        self.keys_tree.heading("Subkey", text="Subkey")
        self.keys_tree.heading("Status", text="Status")
        self.keys_tree.column("Hive",   width=160)
        self.keys_tree.column("Subkey", width=520)
        self.keys_tree.column("Status", width=100)

        sb = ttk.Scrollbar(f, orient="vertical", command=self.keys_tree.yview)
        self.keys_tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0, 12), pady=8)
        self.keys_tree.pack(fill="both", expand=True, padx=12, pady=8)

        self.keys_tree.tag_configure(
            "ok",      foreground=COLORS["accent_green"])
        self.keys_tree.tag_configure(
            "missing", foreground=COLORS["accent_red"])

        self._populate_keys_tree()

        # Remove key button
        ttk.Button(f, text="Remove Selected Key", style="Red.TButton",
                   command=self._remove_selected_key).pack(pady=6)

    def _populate_keys_tree(self):
        self.keys_tree.delete(*self.keys_tree.get_children())
        for hive, subkey in ALL_MONITOR_KEYS:
            vals = read_registry_key(hive, subkey)
            status = "✓ Found" if vals is not None else "✗ Missing"
            tag = "ok" if vals is not None else "missing"
            self.keys_tree.insert("", "end",
                                  values=(hive_name(hive), subkey, status),
                                  tags=(tag,))

    # Tab: Baseline Viewer
    def _build_tab_baseline(self):
        f = self._tab_frame("📊  Baseline")

        self.baseline_text = scrolledtext.ScrolledText(
            f, bg=COLORS["bg_dark"], fg=COLORS["accent_blue"],
            font=("Courier New", 9), bd=0,
            state="disabled", wrap="none",
            highlightthickness=1,
            highlightbackground=COLORS["border"]
        )
        self.baseline_text.pack(fill="both", expand=True, padx=12, pady=12)

    # Tab: Report
    def _build_tab_report(self):
        f = self._tab_frame("📑  Report")

        toolbar = tk.Frame(f, bg=COLORS["bg_panel"])
        toolbar.pack(fill="x", padx=12, pady=(8, 0))
        ttk.Button(toolbar, text="🔄 Refresh", style="Cyber.TButton",
                   command=self._refresh_report).pack(side="left", padx=4)
        ttk.Button(toolbar, text="💾 Save Report", style="Green.TButton",
                   command=self._export_report).pack(side="left", padx=4)

        self.report_text = scrolledtext.ScrolledText(
            f, bg=COLORS["bg_dark"], fg=COLORS["text_primary"],
            font=("Courier New", 9), bd=0,
            state="disabled", wrap="none",
            highlightthickness=1,
            highlightbackground=COLORS["border"]
        )
        self.report_text.pack(fill="both", expand=True, padx=12, pady=8)

    # ── Status Bar ─────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=COLORS["bg_panel"], height=28)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.statusbar_text = tk.Label(bar, text="Ready. Capture or load a baseline to begin.",
                                       font=FONTS["small"],
                                       fg=COLORS["text_dim"], bg=COLORS["bg_panel"],
                                       anchor="w")
        self.statusbar_text.pack(side="left", padx=12, fill="x", expand=True)

        tk.Label(bar, text="v2.0 Advanced", font=FONTS["small"],
                 fg=COLORS["text_muted"], bg=COLORS["bg_panel"]).pack(side="right", padx=12)

    def _set_status(self, msg, color=None):
        self.statusbar_text.config(text=msg, fg=color or COLORS["text_dim"])

    # ── Console Logging ────────────────────────────────────────────────────

    def _log(self, msg, tag="green"):
        self.console.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.insert("end", f"[{ts}] ", "dim")
        self.console.insert("end", msg + "\n", tag)
        self.console.see("end")
        self.console.config(state="disabled")

    # ── Actions ────────────────────────────────────────────────────────────

    def _capture_baseline(self):
        def run():
            self.msg_queue.put(
                ("log", ("Capturing baseline snapshot...", "cyan")))
            self.msg_queue.put(("status_set", "WORKING"))
            try:
                snap = capture_baseline()
                self.baseline_data = snap
                self.msg_queue.put(
                    ("log", (f"Baseline captured: {len(snap)} keys", "green")))
                self.msg_queue.put(("baseline_loaded", snap))
                self.msg_queue.put(("status_set", "IDLE"))
            except Exception as e:
                self.msg_queue.put(("log", (f"Error: {e}", "red")))
                self.msg_queue.put(("status_set", "ERROR"))

        threading.Thread(target=run, daemon=True).start()

    def _load_baseline(self):
        path = filedialog.askopenfilename(
            title="Load Baseline File",
            initialdir="data",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return

        def run():
            try:
                with open(path) as f:
                    data = json.load(f)
                snap = data.get("snapshot", data)
                self.baseline_data = snap
                self.msg_queue.put(
                    ("log", (f"Baseline loaded from: {path}", "cyan")))
                self.msg_queue.put(("baseline_loaded", snap))
            except Exception as e:
                self.msg_queue.put(("log", (f"Load error: {e}", "red")))

        threading.Thread(target=run, daemon=True).start()

    def _auto_load_baseline(self):
        if os.path.exists(BASELINE_FILE):
            snap = load_baseline()
            if snap:
                self.baseline_data = snap
                self._on_baseline_loaded(snap)
                self._log(
                    f"Auto-loaded existing baseline ({BASELINE_FILE})", "cyan")

    def _toggle_monitor(self):
        if not self.monitoring:
            if self.baseline_data is None:
                messagebox.showwarning("No Baseline",
                                       "Please capture or load a baseline first.")
                return
            self._start_monitor()
        else:
            self._stop_monitor()

    def _start_monitor(self):
        self.monitoring = True
        self.btn_start.config(text="⏹  Stop Monitoring", style="Red.TButton")
        self.status_dot.config(fg=COLORS["accent_green"])
        self.status_label.config(text="MONITORING", fg=COLORS["accent_green"])
        self._set_status("Monitoring active...", COLORS["accent_green"])
        self._log("Monitoring started.", "green")

        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _stop_monitor(self):
        self.monitoring = False
        self.btn_start.config(text="▶  Start Monitoring",
                              style="Green.TButton")
        self.status_dot.config(fg=COLORS["text_muted"])
        self.status_label.config(text="IDLE", fg=COLORS["text_dim"])
        self._set_status("Monitoring stopped.")
        self._log("Monitoring stopped.", "amber")

    def _monitor_loop(self):
        polls = 0
        current = self.baseline_data.copy()
        interval = self.poll_interval.get()

        while self.monitoring:
            time.sleep(interval)
            if not self.monitoring:
                break

            interval = self.poll_interval.get()
            polls += 1
            new_snap = take_snapshot()

            self.msg_queue.put(("poll", polls))

            changes = diff_snapshots(current, new_snap)
            for change in changes:
                self.all_changes.append(change)
                key_vals = new_snap.get(change["key"], {})
                alerts = check_malware_patterns(change["key"], key_vals)
                self.all_alerts.extend(alerts)
                log_change(change, alerts)
                self.msg_queue.put(("change", (change, alerts)))

            current = new_snap

        generate_report(self.all_changes, self.all_alerts)

    def _integrity_check(self):
        if self.baseline_data is None:
            messagebox.showwarning(
                "No Baseline", "Load or capture a baseline first.")
            return

        def run():
            self.msg_queue.put(("log", ("Running integrity check...", "cyan")))
            new_snap = take_snapshot()
            changes = diff_snapshots(self.baseline_data, new_snap)
            if not changes:
                self.msg_queue.put(
                    ("log", ("✓ INTEGRITY OK — No changes from baseline", "green")))
                self.msg_queue.put(
                    ("msgbox", ("Integrity Check", "✓ No changes detected.\nRegistry matches baseline.")))
            else:
                self.msg_queue.put(
                    ("log", (f"⚠ INTEGRITY FAIL — {len(changes)} change(s) detected", "red")))
                for c in changes:
                    self.all_changes.append(c)
                    alerts = check_malware_patterns(
                        c["key"], new_snap.get(c["key"], {}))
                    self.all_alerts.extend(alerts)
                    self.msg_queue.put(("change", (c, alerts)))
            generate_report(self.all_changes, self.all_alerts)

        threading.Thread(target=run, daemon=True).start()

    def _export_report(self):
        generate_report(self.all_changes, self.all_alerts)
        path = filedialog.asksaveasfilename(
            title="Save Report",
            initialfile="registry_report.txt",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            import shutil
            shutil.copy(REPORT_FILE, path)
            self._log(f"Report saved to: {path}", "cyan")
            self._set_status(f"Report exported: {path}")

    def _clear_logs(self):
        if messagebox.askyesno("Clear Logs", "Clear all change logs and reset counters?"):
            self.all_changes.clear()
            self.all_alerts.clear()
            self.change_count = 0
            self.alert_count = 0
            self.changes_val.config(text="0")
            self.alerts_val.config(text="0")
            self.polls_val.config(text="0")
            self.change_tree.delete(*self.change_tree.get_children())
            self.console.config(state="normal")
            self.console.delete(1.0, "end")
            self.console.config(state="disabled")
            self.alert_list.config(state="normal")
            self.alert_list.delete(1.0, "end")
            self.alert_list.config(state="disabled")
            self._log("Logs cleared.", "amber")

    def _add_custom_key(self):
        import winreg
        raw = self.new_key_entry.get().strip()
        if not raw or raw.startswith("e.g."):
            return
        # Default to HKCU
        ALL_MONITOR_KEYS.append((winreg.HKEY_CURRENT_USER, raw))
        self._populate_keys_tree()
        self.keys_val.config(text=str(len(ALL_MONITOR_KEYS)))
        self._log(f"Added watch key: HKCU\\{raw}", "cyan")
        self.new_key_entry.delete(0, "end")

    def _remove_selected_key(self):
        sel = self.keys_tree.selection()
        if not sel:
            return
        item = self.keys_tree.item(sel[0])
        hive_str, subkey, _ = item["values"]
        import winreg
        hive_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER":  winreg.HKEY_CURRENT_USER,
        }
        hive = hive_map.get(hive_str)
        if hive and (hive, subkey) in ALL_MONITOR_KEYS:
            ALL_MONITOR_KEYS.remove((hive, subkey))
            self._populate_keys_tree()
            self.keys_val.config(text=str(len(ALL_MONITOR_KEYS)))
            self._log(f"Removed key: {hive_str}\\{subkey}", "amber")

    def _refresh_report(self):
        generate_report(self.all_changes, self.all_alerts)
        if os.path.exists(REPORT_FILE):
            with open(REPORT_FILE) as f:
                content = f.read()
            self.report_text.config(state="normal")
            self.report_text.delete(1.0, "end")
            self.report_text.insert("end", content)
            self.report_text.config(state="disabled")

    def _filter_changes(self, *_):
        q = self.filter_var.get().lower()
        for item in self.change_tree.get_children():
            vals = self.change_tree.item(item)["values"]
            match = any(q in str(v).lower() for v in vals)
            # Treeview doesn't support hide easily; we rebuild
        # Rebuild with filter
        self._rebuild_changes_tree()

    def _rebuild_changes_tree(self):
        q = self.filter_var.get().lower()
        self.change_tree.delete(*self.change_tree.get_children())
        for c in self.all_changes:
            row = (
                c.get("ts", ""),
                c["type"],
                c["key"],
                c.get("name", ""),
                str(c.get("old", "")),
                str(c.get("new", "")),
            )
            if q and not any(q in str(v).lower() for v in row):
                continue
            tag = ("added" if "ADDED" in c["type"] else
                   "deleted" if "DELETED" in c["type"] else "modified")
            self.change_tree.insert("", "end", values=row, tags=(tag,))

    def _on_interval_change(self, val):
        self.interval_label.config(text=f"{int(float(val))}s")

    # ── Queue Processor ────────────────────────────────────────────────────

    def _process_queue(self):
        try:
            while True:
                msg, data = self.msg_queue.get_nowait()

                if msg == "log":
                    self._log(*data)

                elif msg == "status_set":
                    if data == "WORKING":
                        self.status_label.config(
                            text="WORKING", fg=COLORS["accent_amber"])
                        self.status_dot.config(fg=COLORS["accent_amber"])
                    elif data == "IDLE":
                        self.status_label.config(
                            text="IDLE", fg=COLORS["text_dim"])
                        self.status_dot.config(fg=COLORS["text_muted"])
                    elif data == "ERROR":
                        self.status_label.config(
                            text="ERROR", fg=COLORS["accent_red"])
                        self.status_dot.config(fg=COLORS["accent_red"])

                elif msg == "baseline_loaded":
                    self._on_baseline_loaded(data)

                elif msg == "change":
                    change, alerts = data
                    self._on_change(change, alerts)

                elif msg == "poll":
                    self.polls_val.config(text=str(data))

                elif msg == "msgbox":
                    title, body = data
                    messagebox.showinfo(title, body)

        except queue.Empty:
            pass
        self.after(200, self._process_queue)

    def _on_baseline_loaded(self, snap):
        count = len(snap)
        self.baseline_status.config(
            text=f"✓ {count} keys loaded",
            fg=COLORS["accent_green"]
        )
        # Show in baseline tab
        self.baseline_text.config(state="normal")
        self.baseline_text.delete(1.0, "end")
        self.baseline_text.insert("end", json.dumps(snap, indent=2))
        self.baseline_text.config(state="disabled")
        self._set_status(f"Baseline loaded — {count} keys tracked.")

    def _on_change(self, change, alerts):
        self.change_count += 1
        self.changes_val.config(text=str(self.change_count))
        change["ts"] = timestamp()

        # Log to console
        icons = {
            "VALUE_ADDED":    ("🟢 ADDED",    "green"),
            "VALUE_DELETED":  ("🔴 DELETED",  "red"),
            "VALUE_MODIFIED": ("🟡 MODIFIED", "amber"),
            "KEY_ADDED":      ("🟢 KEY+",     "green"),
            "KEY_DELETED":    ("🔴 KEY-",     "red"),
        }
        label, color = icons.get(change["type"], (change["type"], "cyan"))
        self._log(
            f"{label}  {change['key']} | {change.get('name', '')}", color)
        if change.get("old"):
            self._log(f"  OLD: {change['old']}", "dim")
        if change.get("new"):
            self._log(f"  NEW: {change['new']}", "cyan")

        # Add to change tree
        row = (
            change["ts"],
            change["type"],
            change["key"],
            change.get("name", ""),
            str(change.get("old", "")),
            str(change.get("new", "")),
        )
        tag = ("added" if "ADDED" in change["type"] else
               "deleted" if "DELETED" in change["type"] else "modified")
        self.change_tree.insert("", 0, values=row, tags=(tag,))

        # Alerts
        if alerts:
            self.alert_count += len(alerts)
            self.alerts_val.config(text=str(self.alert_count))
            self.alert_list.config(state="normal")
            for a in alerts:
                self.alert_list.insert("end", f"{'─'*60}\n", "normal")
                self.alert_list.insert("end", f"{a}\n", "pattern")
            self.alert_list.see("end")
            self.alert_list.config(state="disabled")
            # Flash alert tab
            self._log(f"ALERT: {alerts[0]}", "red")


def main():
    app = RegistryMonitorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
