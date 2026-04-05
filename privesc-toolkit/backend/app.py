"""
Linux Privilege Escalation Automation Toolkit — Flask Backend
FOR EDUCATIONAL AND AUTHORIZED USE ONLY.
"""

from flask import Flask, jsonify
from flask_cors import CORS
import threading
import uuid
import time
import logging
import os

from scanner.suid_scan import SuidScanner
from scanner.permission_scan import PermissionScanner
from scanner.cron_scan import CronScanner
from scanner.service_scan import ServiceScanner
from scanner.kernel_scan import KernelScanner
from scanner.sudo_scan import SudoScanner
from utils.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("toolkit.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

scans = {}


def run_scan(scan_id: str):
    scans[scan_id]["status"] = "running"
    scans[scan_id]["started_at"] = time.time()
    findings = []

    modules = [
        ("SUID/SGID Binaries",     SuidScanner()),
        ("File Permissions",        PermissionScanner()),
        ("Cron Jobs",               CronScanner()),
        ("System Services",         ServiceScanner()),
        ("Kernel Vulnerabilities",  KernelScanner()),
        ("Sudo Misconfigurations",  SudoScanner()),
    ]

    for module_name, scanner in modules:
        scans[scan_id]["current_module"] = module_name
        logger.info(f"[{scan_id}] Running: {module_name}")
        try:
            findings.extend(scanner.scan())
        except Exception as e:
            logger.error(f"[{scan_id}] {module_name} failed: {e}")

    sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    total_score = sum(
        sev_weight.get(f.get("severity", "LOW"), 0) for f in findings
    )

    scans[scan_id]["findings"] = findings
    scans[scan_id]["summary"] = {
        "total":      len(findings),
        "critical":   sum(1 for f in findings if f.get("severity") == "CRITICAL"),
        "high":       sum(1 for f in findings if f.get("severity") == "HIGH"),
        "medium":     sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "low":        sum(1 for f in findings if f.get("severity") == "LOW"),
        "risk_score": min(100, total_score * 3),
    }
    scans[scan_id]["status"] = "complete"
    scans[scan_id]["completed_at"] = time.time()

    try:
        rg = ReportGenerator(scan_id, scans[scan_id])
        rg.generate_json()
        rg.generate_html()
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

    logger.info(
        f"[{scan_id}] Done — {len(findings)} findings."
    )


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "id":             scan_id,
        "status":         "pending",
        "current_module": None,
        "findings":       [],
        "summary":        {},
        "started_at":     None,
        "completed_at":   None,
    }
    threading.Thread(
        target=run_scan, args=(scan_id,), daemon=True
    ).start()
    logger.info(f"Scan {scan_id} started")
    return jsonify({"scan_id": scan_id, "status": "pending"})


@app.route("/api/scan/status/<scan_id>", methods=["GET"])
def scan_status(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    s = scans[scan_id]
    return jsonify({
        "id":             s["id"],
        "status":         s["status"],
        "current_module": s["current_module"],
        "summary":        s.get("summary", {}),
    })


@app.route("/api/scan/results/<scan_id>", methods=["GET"])
def scan_results(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    s = scans[scan_id]
    if s["status"] != "complete":
        return jsonify({"error": "Not complete", "status": s["status"]}), 202
    return jsonify(s)


@app.route("/api/scan/list", methods=["GET"])
def list_scans():
    return jsonify([
        {
            "id":      v["id"],
            "status":  v["status"],
            "summary": v.get("summary", {}),
        }
        for v in scans.values()
    ])


if __name__ == "__main__":
    os.makedirs("../reports", exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
