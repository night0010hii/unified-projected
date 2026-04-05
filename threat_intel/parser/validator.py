# =============================================================================
# parser/validator.py — Validates and classifies raw IOC candidates
# =============================================================================

import ipaddress
import logging
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled validation patterns
# ---------------------------------------------------------------------------

# Strict domain: labels 1-63 chars, TLD 2-12 alpha chars, no trailing dot
_RE_DOMAIN_STRICT = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,12}$"
)

# Strict URL (must begin with http/https/ftp)
_RE_URL_STRICT = re.compile(
    r"^(https?|ftp)://"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)$",
    re.IGNORECASE,
)

# MD5 — exactly 32 hex chars
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")

# SHA256 — exactly 64 hex chars
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

# Private / non-routable IP prefixes we want to discard
_PRIVATE_RANGES = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
)

# Generic/benign domains to skip
_BENIGN_DOMAINS = {
    "localhost",
    "example.com",
    "example.net",
    "example.org",
    "test.com",
    "invalid",
    "local",
}


def validate_ip(value: str) -> bool:
    """
    Return True if *value* is a valid, publicly routable IPv4 address.
    """
    try:
        addr = ipaddress.ip_address(value)
        if not isinstance(addr, ipaddress.IPv4Address):
            return False  # skip IPv6 for now
        # Discard private / non-routable ranges
        for net in _PRIVATE_RANGES:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


def validate_domain(value: str) -> bool:
    """
    Return True if *value* looks like a real, external domain name.
    """
    if not value or len(value) > 253:
        return False
    if not _RE_DOMAIN_STRICT.match(value):
        return False
    lower = value.lower()
    # Reject pure IPs disguised as domains
    try:
        ipaddress.ip_address(lower)
        return False
    except ValueError:
        pass
    # Reject known-benign/generic domains
    if any(lower == bd or lower.endswith("." + bd) for bd in _BENIGN_DOMAINS):
        return False
    return True


def validate_url(value: str) -> bool:
    """
    Return True if *value* is a syntactically valid http/https/ftp URL.
    """
    if not value or len(value) > 2048:
        return False
    return bool(_RE_URL_STRICT.match(value))


def validate_md5(value: str) -> bool:
    """Return True if *value* is a valid MD5 hex digest."""
    return bool(_RE_MD5.match(value))


def validate_sha256(value: str) -> bool:
    """Return True if *value* is a valid SHA-256 hex digest."""
    return bool(_RE_SHA256.match(value))


# Map candidate type → validation function
_VALIDATORS = {
    "ip":     validate_ip,
    "domain": validate_domain,
    "url":    validate_url,
    "md5":    validate_md5,
    "sha256": validate_sha256,
}


def validate(value: str, ioc_type: str) -> bool:
    """
    Validate a single IOC given its type.

    Args:
        value:    The raw indicator string.
        ioc_type: One of 'ip', 'domain', 'url', 'md5', 'sha256'.

    Returns:
        True if the indicator passes validation, False otherwise.
    """
    fn = _VALIDATORS.get(ioc_type.lower())
    if fn is None:
        logger.debug(f"[validator] Unknown type '{ioc_type}' — skipping")
        return False
    result = fn(value.strip())
    if not result:
        logger.debug(f"[validator] Invalid {ioc_type}: '{value}'")
    return result


def validate_and_classify(
    value: str, hint_type: str
) -> Optional[Tuple[str, str]]:
    """
    Validate *value* against its hinted type.

    Returns:
        (clean_value, type) if valid, or None if invalid.
    """
    clean = value.strip()
    if validate(clean, hint_type):
        return (clean, hint_type)
    return None
