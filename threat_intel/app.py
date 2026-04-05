#!/usr/bin/env python3
# =============================================================================
# app.py — Flask Web Dashboard for the Threat Intelligence Aggregator
# =============================================================================

import json
import logging
import os
from datetime import datetime

from flask import Flask, jsonify, render_template, request

import config

# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("app")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: str):
    """Load a JSON file; return None if missing or malformed."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(f"Could not load {path}: {exc}")
        return None


def _load_correlated():
    return _load_json(config.CORRELATED_JSON) or []


def _load_report():
    return _load_json(config.REPORT_JSON) or {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    """Main dashboard page."""
    report     = _load_report()
    correlated = _load_correlated()

    summary = report.get("summary", {})
    high_iocs = [r for r in correlated if r.get("severity") == "HIGH"]

    return render_template(
        "dashboard.html",
        summary=summary,
        high_iocs=high_iocs[:50],          # cap at 50 for initial render
        refresh_interval=config.DASHBOARD_REFRESH_S,
        generated_at=report.get("generated_at", "N/A"),
    )


@app.route("/api/stats")
def api_stats():
    """JSON endpoint — summary statistics (used by auto-refresh)."""
    report  = _load_report()
    summary = report.get("summary", {})
    return jsonify(
        {
            "total":      summary.get("total_unique_iocs", 0),
            "high":       summary.get("high_severity", 0),
            "medium":     summary.get("medium_severity", 0),
            "low":        summary.get("low_severity", 0),
            "repeated":   summary.get("repeated_indicators", 0),
            "sources":    summary.get("sources_ingested", []),
            "breakdown":  summary.get("ioc_type_breakdown", {}),
            "generated":  report.get("generated_at", ""),
        }
    )


@app.route("/api/iocs")
def api_iocs():
    """
    JSON endpoint — paginated, filterable IOC list.

    Query params:
        q        — search string (matches value or type)
        severity — HIGH | MEDIUM | LOW
        type     — ip | domain | url | md5 | sha256
        page     — page number (1-based, default 1)
        per_page — items per page (default 50, max 200)
    """
    correlated = _load_correlated()

    q        = request.args.get("q", "").strip().lower()
    severity = request.args.get("severity", "").strip().upper()
    ioc_type = request.args.get("type", "").strip().lower()

    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        page, per_page = 1, 50

    # ---- Filter ------------------------------------------------------------
    filtered = correlated
    if q:
        filtered = [r for r in filtered if q in r.get("value", "")]
    if severity:
        filtered = [r for r in filtered if r.get("severity") == severity]
    if ioc_type:
        filtered = [r for r in filtered if r.get("type") == ioc_type]

    # ---- Paginate ----------------------------------------------------------
    total   = len(filtered)
    start   = (page - 1) * per_page
    end     = start + per_page
    page_data = filtered[start:end]

    return jsonify(
        {
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    max(1, -(-total // per_page)),   # ceiling division
            "iocs":     page_data,
        }
    )


@app.route("/api/search")
def api_search():
    """Lightweight search endpoint used by the dashboard search bar."""
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 2:
        return jsonify({"results": [], "total": 0})

    correlated = _load_correlated()
    results = [
        r for r in correlated
        if q in r.get("value", "") or q in r.get("type", "")
    ][:100]   # cap at 100 results

    return jsonify({"results": results, "total": len(results)})


@app.route("/api/blocklist/<ioc_type>")
def api_blocklist(ioc_type: str):
    """Serve a blocklist file as plain text."""
    file_map = {
        "ip":     config.IP_BLOCKLIST_TXT,
        "domain": config.DOMAIN_BLOCKLIST_TXT,
        "url":    config.URL_BLOCKLIST_TXT,
    }
    path = file_map.get(ioc_type.lower())
    if not path or not os.path.isfile(path):
        return f"# No {ioc_type} blocklist found\n", 404, {"Content-Type": "text/plain"}

    with open(path, "r", encoding="utf-8") as fh:
        content = fh.read()
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/api/run-pipeline", methods=["POST"])
def api_run_pipeline():
    """Trigger a fresh pipeline run (synchronous — fine for demo)."""
    try:
        from main import run_pipeline
        report = run_pipeline(include_remote=False)   # skip remote in web trigger
        return jsonify({"status": "ok", "summary": report.get("summary", {})})
    except Exception as exc:
        logger.error(f"Pipeline error: {exc}")
        return jsonify({"status": "error", "message": str(exc)}), 500


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Run the pipeline once on startup if no output exists yet
    if not os.path.isfile(config.CORRELATED_JSON):
        logger.info("No prior pipeline output found — running pipeline first …")
        try:
            from main import run_pipeline
            run_pipeline(include_remote=False)
        except Exception as exc:
            logger.warning(f"Startup pipeline failed: {exc}")

    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
    )
