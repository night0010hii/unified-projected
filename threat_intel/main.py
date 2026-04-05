#!/usr/bin/env python3
# =============================================================================
# main.py — Threat Intelligence Aggregator — Pipeline Entry Point
# =============================================================================
#
# Execution order:
#   1. Load local feeds (txt / csv / json files)
#   2. Fetch remote OSINT feeds (optional; skipped on network failure)
#   3. Parse every feed into (value, type) candidate pairs
#   4. Validate and discard invalid candidates
#   5. Normalise into unified IOC records
#   6. Merge all records into one flat list
#   7. Correlate across sources and assign severity
#   8. (Optional) Enrich with GeoIP / WHOIS
#   9. Generate IP / Domain / URL blocklists
#  10. Write JSON report
# =============================================================================

import logging
import os
import sys

# ---------------------------------------------------------------------------
# Logging setup — must happen before any module imports that log
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")

# ---------------------------------------------------------------------------
# Project imports
# ---------------------------------------------------------------------------
import config
from api.feed_fetcher      import fetch_all_remote_feeds
from core.blocklist        import generate_blocklists
from core.correlator       import correlate
from core.normalizer       import merge, normalize
from parser.ioc_parser     import parse_auto
from parser.validator      import validate_and_classify
from utils.enrichment      import enrich_all
from utils.file_loader     import load_all_local_feeds
from utils.reporter        import generate_report, save_correlated, save_normalized


def _process_feed(feed: dict) -> list:
    """
    Parse → validate → normalise a single feed dict.

    Args:
        feed: {source, format, raw_text}

    Returns:
        List of normalised IOC records.
    """
    source   = feed["source"]
    fmt      = feed["format"]
    raw_text = feed["raw_text"]

    # Step 1 — parse raw text into (value, hint_type) candidates
    candidates = parse_auto(raw_text, fmt)

    # Step 2 — validate each candidate
    valid_pairs = []
    for value, hint_type in candidates:
        result = validate_and_classify(value, hint_type)
        if result:
            valid_pairs.append(result)

    logger.info(
        f"  Feed '{source}': {len(candidates)} parsed → "
        f"{len(valid_pairs)} valid"
    )

    # Step 3 — normalise into unified dicts
    return normalize(valid_pairs, source=source)


def run_pipeline(
    include_remote: bool = True,
    verbose: bool = False,
) -> dict:
    """
    Execute the full threat intelligence pipeline.

    Args:
        include_remote: Attempt to fetch remote OSINT feeds.
        verbose:        Enable DEBUG-level logging.

    Returns:
        The generated report dict.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    os.makedirs(config.OUTPUT_DIR, exist_ok=True)

    logger.info("=" * 60)
    logger.info("  THREAT INTELLIGENCE AGGREGATOR — PIPELINE START")
    logger.info("=" * 60)

    # ------------------------------------------------------------------
    # PHASE 1: Feed ingestion
    # ------------------------------------------------------------------
    logger.info("[Phase 1] Loading local feeds …")
    local_feeds = load_all_local_feeds(config.LOCAL_FEEDS)

    remote_feeds = []
    if include_remote:
        logger.info("[Phase 1] Fetching remote feeds …")
        remote_feeds = fetch_all_remote_feeds(config.REMOTE_FEEDS)
    else:
        logger.info("[Phase 1] Remote feeds skipped (include_remote=False)")

    all_feeds = local_feeds + remote_feeds
    logger.info(
        f"[Phase 1] Total feeds ingested: {len(all_feeds)} "
        f"(local={len(local_feeds)}, remote={len(remote_feeds)})"
    )

    if not all_feeds:
        logger.error("[Phase 1] No feeds available — aborting pipeline.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # PHASE 2–3: Parse, validate, normalise
    # ------------------------------------------------------------------
    logger.info("[Phase 2-3] Parsing, validating and normalising …")
    all_normalised_lists = []
    for feed in all_feeds:
        normalised = _process_feed(feed)
        all_normalised_lists.append(normalised)

    merged_iocs = merge(all_normalised_lists)
    save_normalized(merged_iocs)

    # ------------------------------------------------------------------
    # PHASE 4: Correlation
    # ------------------------------------------------------------------
    logger.info("[Phase 4] Correlating indicators …")
    correlated = correlate(merged_iocs)
    save_correlated(correlated)

    # ------------------------------------------------------------------
    # PHASE 5 (optional): Enrichment
    # ------------------------------------------------------------------
    if config.ENABLE_GEOIP or config.ENABLE_WHOIS:
        logger.info("[Phase 5] Enriching IOCs …")
        correlated = enrich_all(correlated)

    # ------------------------------------------------------------------
    # PHASE 6: Blocklist generation
    # ------------------------------------------------------------------
    logger.info("[Phase 6] Generating blocklists …")
    blocklists = generate_blocklists(correlated)

    # ------------------------------------------------------------------
    # PHASE 7: Reporting
    # ------------------------------------------------------------------
    logger.info("[Phase 7] Generating report …")
    report = generate_report(correlated, blocklists)

    # ------------------------------------------------------------------
    # Summary printout
    # ------------------------------------------------------------------
    s = report["summary"]
    logger.info("=" * 60)
    logger.info("  PIPELINE COMPLETE — SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Total unique IOCs  : {s['total_unique_iocs']}")
    logger.info(f"  HIGH severity      : {s['high_severity']}")
    logger.info(f"  MEDIUM severity    : {s['medium_severity']}")
    logger.info(f"  LOW severity       : {s['low_severity']}")
    logger.info(f"  Repeated (2+ src)  : {s['repeated_indicators']}")
    logger.info(f"  Sources ingested   : {', '.join(s['sources_ingested'])}")
    logger.info(f"  Output dir         : {config.OUTPUT_DIR}")
    logger.info("=" * 60)

    return report


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(
        description="Threat Intelligence Aggregator — run the full pipeline"
    )
    ap.add_argument(
        "--no-remote",
        action="store_true",
        help="Skip fetching remote OSINT feeds",
    )
    ap.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    args = ap.parse_args()

    run_pipeline(
        include_remote=not args.no_remote,
        verbose=args.verbose,
    )
