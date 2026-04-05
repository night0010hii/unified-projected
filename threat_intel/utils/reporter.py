# =============================================================================
# utils/reporter.py — Generates the final JSON intelligence report
# =============================================================================

import json
import logging
import os
from datetime import datetime, timezone
from typing import List

import config

logger = logging.getLogger(__name__)


def generate_report(
    correlated_iocs: List[dict],
    blocklists: dict,
) -> dict:
    """
    Produce a structured JSON report summarising the pipeline run.

    Args:
        correlated_iocs: Full output of core.correlator.correlate().
        blocklists:      Output of core.blocklist.generate_blocklists().

    Returns:
        The report as a Python dict (also written to disk).
    """
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    # ---- Counts by severity -------------------------------------------------
    high_iocs   = [r for r in correlated_iocs if r["severity"] == "HIGH"]
    medium_iocs = [r for r in correlated_iocs if r["severity"] == "MEDIUM"]
    low_iocs    = [r for r in correlated_iocs if r["severity"] == "LOW"]

    # ---- Counts by type -----------------------------------------------------
    type_counts: dict = {}
    for r in correlated_iocs:
        type_counts[r["type"]] = type_counts.get(r["type"], 0) + 1

    # ---- Repeated indicators (seen in 2+ sources) ---------------------------
    repeated = [r for r in correlated_iocs if r["count"] >= 2]

    # ---- All sources seen ---------------------------------------------------
    all_sources: set = set()
    for r in correlated_iocs:
        all_sources.update(r["sources"])

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_unique_iocs":   len(correlated_iocs),
            "high_severity":       len(high_iocs),
            "medium_severity":     len(medium_iocs),
            "low_severity":        len(low_iocs),
            "repeated_indicators": len(repeated),
            "sources_ingested":    sorted(all_sources),
            "ioc_type_breakdown":  type_counts,
        },
        "blocklist_counts": {
            "ips":     len(blocklists.get("ips", [])),
            "domains": len(blocklists.get("domains", [])),
            "urls":    len(blocklists.get("urls", [])),
        },
        "high_risk_iocs": [
            {
                "type":    r["type"],
                "value":   r["value"],
                "sources": r["sources"],
                "count":   r["count"],
            }
            for r in high_iocs
        ],
        "medium_risk_iocs": [
            {
                "type":    r["type"],
                "value":   r["value"],
                "sources": r["sources"],
                "count":   r["count"],
            }
            for r in medium_iocs
        ],
        "repeated_indicators": [
            {
                "type":    r["type"],
                "value":   r["value"],
                "sources": r["sources"],
                "count":   r["count"],
            }
            for r in repeated
        ],
    }

    # ---- Write to disk ------------------------------------------------------
    with open(config.REPORT_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    logger.info(f"[reporter] Report written → {config.REPORT_JSON}")

    return report


def save_normalized(ioc_records: List[dict]) -> None:
    """Persist the full normalised IOC list to disk."""
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    with open(config.NORMALIZED_JSON, "w", encoding="utf-8") as fh:
        json.dump(ioc_records, fh, indent=2)
    logger.info(
        f"[reporter] Normalised IOCs written → {config.NORMALIZED_JSON} "
        f"({len(ioc_records)} records)"
    )


def save_correlated(correlated_iocs: List[dict]) -> None:
    """Persist the full correlated IOC list to disk."""
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    with open(config.CORRELATED_JSON, "w", encoding="utf-8") as fh:
        json.dump(correlated_iocs, fh, indent=2)
    logger.info(
        f"[reporter] Correlated IOCs written → {config.CORRELATED_JSON} "
        f"({len(correlated_iocs)} records)"
    )
