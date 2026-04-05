# =============================================================================
# core/correlator.py — Cross-source correlation and severity assignment
# =============================================================================

import logging
from collections import defaultdict
from typing import List

import config

logger = logging.getLogger(__name__)


def correlate(ioc_records: List[dict]) -> List[dict]:
    """
    Group IOC records by (value, type), count distinct sources, and assign
    a severity level.

    Severity rules (from config):
        - HIGH   → distinct source count >= SEVERITY_HIGH   (default 3)
        - MEDIUM → distinct source count >= SEVERITY_MEDIUM (default 2)
        - LOW    → single source

    Args:
        ioc_records: Flat list of normalised IOC dicts.

    Returns:
        List of correlated IOC dicts, each shaped:
        {
            "type":       str,
            "value":      str,
            "sources":    [str, ...],    # unique sources
            "count":      int,           # number of distinct sources
            "severity":   str,           # HIGH | MEDIUM | LOW
            "first_seen": str,           # earliest timestamp
            "last_seen":  str,           # latest timestamp
        }
    """
    # Bucket records by (value, type)
    bucket: dict = defaultdict(list)
    for rec in ioc_records:
        key = (rec["value"], rec["type"])
        bucket[key].append(rec)

    correlated: List[dict] = []

    for (value, ioc_type), records in bucket.items():
        sources = sorted({r["source"] for r in records})
        source_count = len(sources)

        # Timestamps (ISO strings sort lexicographically)
        timestamps = sorted(r["timestamp"] for r in records)
        first_seen = timestamps[0]
        last_seen  = timestamps[-1]

        # Severity assignment
        if source_count >= config.SEVERITY_HIGH:
            severity = "HIGH"
        elif source_count >= config.SEVERITY_MEDIUM:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        correlated.append(
            {
                "type":       ioc_type,
                "value":      value,
                "sources":    sources,
                "count":      source_count,
                "severity":   severity,
                "first_seen": first_seen,
                "last_seen":  last_seen,
            }
        )

    # Sort: HIGH first, then MEDIUM, then LOW; within group sort by count desc
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    correlated.sort(key=lambda r: (severity_order[r["severity"]], -r["count"]))

    high   = sum(1 for r in correlated if r["severity"] == "HIGH")
    medium = sum(1 for r in correlated if r["severity"] == "MEDIUM")
    low    = sum(1 for r in correlated if r["severity"] == "LOW")

    logger.info(
        f"[correlator] {len(correlated)} unique IOCs — "
        f"HIGH={high}, MEDIUM={medium}, LOW={low}"
    )
    return correlated
