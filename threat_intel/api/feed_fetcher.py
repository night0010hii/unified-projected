# =============================================================================
# api/feed_fetcher.py — Fetches remote OSINT threat feeds via HTTP
# =============================================================================

import requests
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Default request timeout (seconds)
REQUEST_TIMEOUT = 15
# User-agent to identify our tool
USER_AGENT = "ThreatIntelAggregator/1.0 (research; non-commercial)"


def fetch_url(url: str, source_name: str = "remote") -> Optional[str]:
    """
    Perform an HTTP GET request and return the response body as a string.

    Args:
        url:         The URL to fetch.
        source_name: A human-readable label used in log messages.

    Returns:
        Response text on success, or None on failure.
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        logger.info(f"[feed_fetcher] Fetching '{source_name}' from {url}")
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        logger.info(
            f"[feed_fetcher] ✓ '{source_name}' — {len(resp.text)} chars received"
        )
        return resp.text
    except requests.exceptions.Timeout:
        logger.warning(f"[feed_fetcher] Timeout fetching '{source_name}': {url}")
    except requests.exceptions.ConnectionError as exc:
        logger.warning(f"[feed_fetcher] Connection error for '{source_name}': {exc}")
    except requests.exceptions.HTTPError as exc:
        logger.warning(
            f"[feed_fetcher] HTTP {exc.response.status_code} for '{source_name}': {url}"
        )
    except Exception as exc:
        logger.error(f"[feed_fetcher] Unexpected error for '{source_name}': {exc}")
    return None


def fetch_all_remote_feeds(remote_configs: list) -> list:
    """
    Fetch every remote feed defined in the config list.

    Args:
        remote_configs: List of dicts with keys 'url', 'format', 'source'.

    Returns:
        List of dicts: {source, format, raw_text}  (failed feeds are skipped)
    """
    results = []
    for cfg in remote_configs:
        raw = fetch_url(cfg["url"], source_name=cfg.get("source", "unknown"))
        if raw:
            results.append(
                {
                    "source": cfg.get("source", "remote"),
                    "format": cfg.get("format", "txt"),
                    "raw_text": raw,
                }
            )
        else:
            logger.warning(
                f"[feed_fetcher] Skipping feed '{cfg.get('source')}' — fetch failed."
            )
    return results
