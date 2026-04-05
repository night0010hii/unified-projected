# =============================================================================
# core/blocklist.py — Generates IP / Domain / URL blocklists from correlated
#                      IOCs and writes them to disk in TXT and CSV formats.
# =============================================================================

import csv
import logging
import os
from typing import List

import config

logger = logging.getLogger(__name__)


def _ensure_output_dir() -> None:
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)


def _write_txt(path: str, lines: List[str], header_comment: str) -> None:
    """Write a plain-text blocklist with a comment header."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# {header_comment}\n")
        fh.write(f"# Total entries: {len(lines)}\n")
        fh.write("#\n")
        for line in lines:
            fh.write(line + "\n")
    logger.info(f"[blocklist] TXT → {path}  ({len(lines)} entries)")


def _write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    """Write a CSV blocklist."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info(f"[blocklist] CSV → {path}  ({len(rows)} entries)")


def generate_blocklists(correlated_iocs: List[dict]) -> dict:
    """
    Build and write IP, Domain, and URL blocklists.

    Args:
        correlated_iocs: Output from core.correlator.correlate().

    Returns:
        Dict with keys 'ips', 'domains', 'urls', each containing a list of
        value strings that made it into the respective blocklist.
    """
    _ensure_output_dir()

    ips:     List[dict] = []
    domains: List[dict] = []
    urls:    List[dict] = []

    for ioc in correlated_iocs:
        entry = {
            "value":    ioc["value"],
            "severity": ioc["severity"],
            "sources":  "|".join(ioc["sources"]),
            "count":    ioc["count"],
        }
        if ioc["type"] == "ip":
            ips.append(entry)
        elif ioc["type"] == "domain":
            domains.append(entry)
        elif ioc["type"] == "url":
            urls.append(entry)

    csv_fields = ["value", "severity", "sources", "count"]

    # ---- IP blocklist -------------------------------------------------------
    _write_txt(
        config.IP_BLOCKLIST_TXT,
        [e["value"] for e in ips],
        "Threat Intel Aggregator — IP Blocklist",
    )
    _write_csv(config.IP_BLOCKLIST_CSV, ips, csv_fields)

    # ---- Domain blocklist ---------------------------------------------------
    _write_txt(
        config.DOMAIN_BLOCKLIST_TXT,
        [e["value"] for e in domains],
        "Threat Intel Aggregator — Domain Blocklist",
    )
    _write_csv(config.DOMAIN_BLOCKLIST_CSV, domains, csv_fields)

    # ---- URL blocklist ------------------------------------------------------
    _write_txt(
        config.URL_BLOCKLIST_TXT,
        [e["value"] for e in urls],
        "Threat Intel Aggregator — URL Blocklist",
    )
    _write_csv(config.URL_BLOCKLIST_CSV, urls, csv_fields)

    return {
        "ips":     [e["value"] for e in ips],
        "domains": [e["value"] for e in domains],
        "urls":    [e["value"] for e in urls],
    }
