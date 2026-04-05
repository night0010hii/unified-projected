# =============================================================================
# core/normalizer.py — Converts validated (value, type) tuples into a
#                       unified IOC record dict.
# =============================================================================

import logging
from datetime import datetime, timezone
from typing import List, Tuple

logger = logging.getLogger(__name__)


def normalize(
    candidates: List[Tuple[str, str]],
    source: str,
    timestamp: str = None,
) -> List[dict]:
    """
    Transform a list of validated (value, ioc_type) pairs into normalised
    IOC records.

    Each record has the shape:
        {
            "type":      str,   # 'ip' | 'domain' | 'url' | 'md5' | 'sha256'
            "value":     str,   # the indicator (lower-cased for consistency)
            "source":    str,   # feed / file name
            "timestamp": str,   # ISO-8601 UTC string
        }

    Args:
        candidates: Validated (value, type) pairs from the parser/validator.
        source:     Label identifying where this batch came from.
        timestamp:  Optional ISO-8601 string; defaults to *now* (UTC).

    Returns:
        List of normalised IOC dicts (duplicates within the same source are
        de-duplicated here).
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    seen_in_source: set = set()
    records: List[dict] = []

    for value, ioc_type in candidates:
        # Normalise value: lowercase for consistency
        clean_value = value.strip().lower()
        dedup_key = (clean_value, ioc_type)

        if dedup_key in seen_in_source:
            continue  # skip within-source duplicates
        seen_in_source.add(dedup_key)

        records.append(
            {
                "type":      ioc_type,
                "value":     clean_value,
                "source":    source,
                "timestamp": timestamp,
            }
        )

    logger.info(
        f"[normalizer] '{source}' → {len(records)} unique normalised IOCs "
        f"(from {len(candidates)} candidates)"
    )
    return records


def merge(ioc_lists: List[List[dict]]) -> List[dict]:
    """
    Merge multiple lists of normalised IOC records into one flat list.

    Args:
        ioc_lists: List of normalised IOC record lists.

    Returns:
        Combined flat list.
    """
    merged = [ioc for lst in ioc_lists for ioc in lst]
    logger.info(f"[normalizer] Merged total: {len(merged)} IOC records")
    return merged
