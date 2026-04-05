# =============================================================================
# parser/ioc_parser.py — Extracts raw IOC strings from various text formats
# =============================================================================

import csv
import io
import json
import logging
import re
from typing import List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns for candidate extraction
# ---------------------------------------------------------------------------

# IPv4 address (catches candidates; strict validation happens in validator)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Domain name (2-6 label levels, TLD 2-12 chars; no scheme)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,12}\b"
)

# URL (http/https/ftp)
_RE_URL = re.compile(
    r"https?://[^\s,\"'<>\]\[(){}]+"
    r"|ftp://[^\s,\"'<>\]\[(){}]+",
    re.IGNORECASE,
)

# MD5 (exactly 32 hex chars)
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SHA256 (exactly 64 hex chars)
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Lines that are clearly comments or metadata
_RE_COMMENT = re.compile(r"^\s*#")


# ---------------------------------------------------------------------------
# Public parsing API
# ---------------------------------------------------------------------------

def parse_txt(raw_text: str) -> List[Tuple[str, str]]:
    """
    Parse a plain-text feed (one indicator per line).

    Returns:
        List of (raw_value, candidate_type) tuples.
    """
    candidates: List[Tuple[str, str]] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or _RE_COMMENT.match(line):
            continue
        candidates.extend(_extract_candidates(line))
    logger.debug(f"[ioc_parser:txt] Extracted {len(candidates)} candidates")
    return candidates


def parse_csv(raw_text: str) -> List[Tuple[str, str]]:
    """
    Parse a CSV feed.  Every cell value is scanned for indicators.

    Returns:
        List of (raw_value, candidate_type) tuples.
    """
    candidates: List[Tuple[str, str]] = []
    reader = csv.reader(io.StringIO(raw_text))
    for row in reader:
        for cell in row:
            cell = cell.strip()
            if not cell or _RE_COMMENT.match(cell):
                continue
            candidates.extend(_extract_candidates(cell))
    logger.debug(f"[ioc_parser:csv] Extracted {len(candidates)} candidates")
    return candidates


def parse_json(raw_text: str) -> List[Tuple[str, str]]:
    """
    Parse a JSON feed.  Walks every string value in the structure.

    Returns:
        List of (raw_value, candidate_type) tuples.
    """
    candidates: List[Tuple[str, str]] = []
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning(f"[ioc_parser:json] JSON decode error: {exc}")
        return candidates

    for value in _walk_json(data):
        candidates.extend(_extract_candidates(value))

    logger.debug(f"[ioc_parser:json] Extracted {len(candidates)} candidates")
    return candidates


def parse_auto(raw_text: str, fmt: str) -> List[Tuple[str, str]]:
    """
    Dispatch to the correct parser based on the format string.

    Args:
        raw_text: Raw feed content.
        fmt:      One of 'txt', 'csv', 'json'.

    Returns:
        List of (raw_value, candidate_type) tuples.
    """
    fmt = fmt.lower().strip()
    if fmt == "csv":
        return parse_csv(raw_text)
    if fmt == "json":
        return parse_json(raw_text)
    return parse_txt(raw_text)   # default / txt


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_candidates(text: str) -> List[Tuple[str, str]]:
    """
    Scan a single string and return every (value, type) match found.

    Priority: URL > IP > Domain > SHA256 > MD5
    (URLs are checked before IPs/domains to avoid partial matches)
    """
    found: List[Tuple[str, str]] = []

    # Extract URLs first (may contain IPs/domains)
    url_spans: List[Tuple[int, int]] = []
    for m in _RE_URL.finditer(text):
        found.append((m.group(), "url"))
        url_spans.append((m.start(), m.end()))

    # Build a mask so we don't re-match inside URL spans
    def _in_url_span(start: int, end: int) -> bool:
        return any(us <= start and end <= ue for us, ue in url_spans)

    # IPs
    for m in _RE_IPV4.finditer(text):
        if not _in_url_span(m.start(), m.end()):
            found.append((m.group(), "ip"))

    # Domains (only if no IP match at same position)
    ip_values = {v for v, t in found if t == "ip"}
    for m in _RE_DOMAIN.finditer(text):
        if not _in_url_span(m.start(), m.end()) and m.group() not in ip_values:
            found.append((m.group(), "domain"))

    # SHA256 before MD5 (longer match takes priority)
    for m in _RE_SHA256.finditer(text):
        found.append((m.group().lower(), "sha256"))

    sha_values = {v for v, t in found if t == "sha256"}
    for m in _RE_MD5.finditer(text):
        val = m.group().lower()
        if val not in sha_values:
            found.append((val, "md5"))

    return found


def _walk_json(obj, depth: int = 0) -> List[str]:
    """Recursively yield all string leaf values from a JSON object."""
    if depth > 20:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_walk_json(item, depth + 1))
        return out
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_walk_json(v, depth + 1))
        return out
    return []
