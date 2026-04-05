# =============================================================================
# config.py — Central configuration for the Threat Intelligence Aggregator
# =============================================================================

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Feed paths (local)
# ---------------------------------------------------------------------------
FEEDS_DIR = os.path.join(BASE_DIR, "feeds")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

LOCAL_FEEDS = [
    os.path.join(FEEDS_DIR, "sample_ips.txt"),
    os.path.join(FEEDS_DIR, "sample_domains.txt"),
    os.path.join(FEEDS_DIR, "sample_mixed.csv"),
    os.path.join(FEEDS_DIR, "sample_feed.json"),
]

# ---------------------------------------------------------------------------
# Remote / OSINT feeds (publicly available, no auth required)
# ---------------------------------------------------------------------------
REMOTE_FEEDS = [
    {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
        "format": "txt",
        "source": "ipsum-level3",
    },
    {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "format": "txt",
        "source": "feodotracker-ips",
    },
    {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "format": "txt",
        "source": "urlhaus",
    },
]

# ---------------------------------------------------------------------------
# Severity thresholds (number of distinct sources an IOC appears in)
# ---------------------------------------------------------------------------
SEVERITY_HIGH   = 3   # appears in 3 or more sources → HIGH
SEVERITY_MEDIUM = 2   # appears in exactly 2 sources   → MEDIUM
# anything else → LOW

# ---------------------------------------------------------------------------
# Output file names
# ---------------------------------------------------------------------------
IP_BLOCKLIST_TXT     = os.path.join(OUTPUT_DIR, "ip_blocklist.txt")
DOMAIN_BLOCKLIST_TXT = os.path.join(OUTPUT_DIR, "domain_blocklist.txt")
URL_BLOCKLIST_TXT    = os.path.join(OUTPUT_DIR, "url_blocklist.txt")
IP_BLOCKLIST_CSV     = os.path.join(OUTPUT_DIR, "ip_blocklist.csv")
DOMAIN_BLOCKLIST_CSV = os.path.join(OUTPUT_DIR, "domain_blocklist.csv")
URL_BLOCKLIST_CSV    = os.path.join(OUTPUT_DIR, "url_blocklist.csv")
REPORT_JSON          = os.path.join(OUTPUT_DIR, "report.json")
NORMALIZED_JSON      = os.path.join(OUTPUT_DIR, "normalized_iocs.json")
CORRELATED_JSON      = os.path.join(OUTPUT_DIR, "correlated_iocs.json")

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------
FLASK_HOST          = "0.0.0.0"
FLASK_PORT          = 5000
FLASK_DEBUG         = False
DASHBOARD_REFRESH_S = 30   # seconds between auto-refresh on dashboard

# ---------------------------------------------------------------------------
# Enrichment toggles (set True to enable; require extra deps / network)
# ---------------------------------------------------------------------------
ENABLE_GEOIP   = False   # requires GeoLite2-City.mmdb
GEOIP_DB_PATH  = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")
ENABLE_WHOIS   = False   # slow; enable only when running full pipeline
