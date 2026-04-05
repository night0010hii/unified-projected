# =============================================================================
# utils/enrichment.py — Optional GeoIP and WHOIS enrichment
# =============================================================================

import logging
from typing import Optional

import config

logger = logging.getLogger(__name__)


def geoip_lookup(ip: str) -> Optional[dict]:
    """
    Look up geographic information for an IP address using MaxMind GeoLite2.

    Requires:
        - pip install geoip2
        - GeoLite2-City.mmdb database file (path in config.GEOIP_DB_PATH)

    Returns:
        Dict with 'country', 'city', 'latitude', 'longitude' or None.
    """
    if not config.ENABLE_GEOIP:
        return None
    try:
        import geoip2.database  # type: ignore

        with geoip2.database.Reader(config.GEOIP_DB_PATH) as reader:
            resp = reader.city(ip)
            return {
                "country":   resp.country.name,
                "city":      resp.city.name,
                "latitude":  resp.location.latitude,
                "longitude": resp.location.longitude,
            }
    except Exception as exc:
        logger.debug(f"[enrichment] GeoIP lookup failed for {ip}: {exc}")
        return None


def whois_lookup(value: str) -> Optional[dict]:
    """
    Perform a WHOIS lookup for a domain or IP.

    Requires:
        - pip install python-whois

    Returns:
        Dict with 'registrar', 'creation_date', 'expiration_date' or None.
    """
    if not config.ENABLE_WHOIS:
        return None
    try:
        import whois  # type: ignore  (python-whois)

        w = whois.whois(value)
        return {
            "registrar":       str(w.registrar),
            "creation_date":   str(w.creation_date),
            "expiration_date": str(w.expiration_date),
        }
    except Exception as exc:
        logger.debug(f"[enrichment] WHOIS lookup failed for {value}: {exc}")
        return None


def enrich_ioc(ioc: dict) -> dict:
    """
    Add enrichment data to a single correlated IOC dict in-place.

    Args:
        ioc: A correlated IOC dict (modified in-place).

    Returns:
        The same dict with an 'enrichment' key added.
    """
    enrichment: dict = {}

    if ioc["type"] == "ip":
        geo = geoip_lookup(ioc["value"])
        if geo:
            enrichment["geoip"] = geo
        w = whois_lookup(ioc["value"])
        if w:
            enrichment["whois"] = w

    elif ioc["type"] == "domain":
        w = whois_lookup(ioc["value"])
        if w:
            enrichment["whois"] = w

    ioc["enrichment"] = enrichment
    return ioc


def enrich_all(iocs: list) -> list:
    """Run enrichment over a list of correlated IOC dicts."""
    if not (config.ENABLE_GEOIP or config.ENABLE_WHOIS):
        return iocs
    logger.info(f"[enrichment] Enriching {len(iocs)} IOCs …")
    return [enrich_ioc(ioc) for ioc in iocs]
