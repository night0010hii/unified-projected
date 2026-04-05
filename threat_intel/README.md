# Threat Intelligence Aggregator (Non-AI)

A production-style, modular threat intelligence pipeline that collects, parses,
normalises, correlates, and visualises IOCs (Indicators of Compromise) from
multiple feeds — with zero AI/ML.

---

## Architecture

threat_intel/
├── main.py               ← Pipeline entry point
├── app.py                ← Flask web dashboard
├── config.py             ← Central configuration
├── requirements.txt
│
├── api/
│   └── feed_fetcher.py   ← Remote OSINT feed fetcher (requests)
│
├── parser/
│   ├── ioc_parser.py     ← Regex-based IOC extraction (IP/domain/URL/hash)
│   └── validator.py      ← Strict validation (ipaddress module + regex)
│
├── core/
│   ├── normalizer.py     ← Unified IOC record format
│   ├── correlator.py     ← Cross-source correlation + severity scoring
│   └── blocklist.py      ← TXT/CSV blocklist generator
│
├── utils/
│   ├── file_loader.py    ← Local feed file reader
│   ├── reporter.py       ← JSON report writer
│   └── enrichment.py     ← Optional GeoIP + WHOIS enrichment
│
├── feeds/                ← Sample input feeds
│   ├── sample_ips.txt
│   ├── sample_domains.txt
│   ├── sample_mixed.csv
│   └── sample_feed.json
│
├── output/               ← Generated artefacts (auto-created)
│   ├── ip_blocklist.txt / .csv
│   ├── domain_blocklist.txt / .csv
│   ├── url_blocklist.txt / .csv
│   ├── normalized_iocs.json
│   ├── correlated_iocs.json
│   └── report.json
│
└── templates/
    └── dashboard.html

---

## Quick Start

### 1. Install dependencies

```bash
cd threat_intel
pip install -r requirements.txt
```

### 2. Run the pipeline (CLI)

```bash
# Run with local feeds only (fast, no network needed)
python main.py --no-remote

# Run with remote OSINT feeds (requires internet)
python main.py

# Verbose / debug output
python main.py --no-remote --verbose
```

Pipeline output lands in `output/`.

### 3. Launch the web dashboard

```bash
python app.py
```

Then open: **<http://localhost:5000>**

The dashboard auto-refreshes every 30 seconds.  
Click **RUN PIPELINE** to re-ingest feeds from the browser.

---

## Pipeline Stages

| # | Stage | Module |
| 1 | Load local feeds (TXT / CSV / JSON) | `utils/file_loader.py` |
| 2 | Fetch remote OSINT feeds | `api/feed_fetcher.py` |
| 3 | Extract IOC candidates (regex) | `parser/ioc_parser.py` |
| 4 | Validate & discard invalid IOCs | `parser/validator.py` |
| 5 | Normalise into unified records | `core/normalizer.py` |
| 6 | Correlate across sources + severity | `core/correlator.py` |
| 7 | Generate blocklists | `core/blocklist.py` |
| 8 | Write JSON report | `utils/reporter.py` |

---

## Severity Rules

| Level | Condition |

| **HIGH** | IOC appears in 3+ distinct sources |
| **MEDIUM** | IOC appears in exactly 2 distinct sources |
| **LOW** | IOC appears in 1 source only |

Thresholds are configurable in `config.py`.

---

## Supported IOC Types

| Type | Detection | Validation |

| IPv4 | Regex | `ipaddress` module; rejects RFC-1918/loopback/multicast |
| Domain | Regex | Strict label/TLD check; rejects benign/generic domains |
| URL | Regex | Requires `http/https/ftp` scheme; length cap 2048 |
| MD5 | Regex | Exactly 32 hex chars |
| SHA-256 | Regex | Exactly 64 hex chars |

---

## Remote OSINT Feeds (default)

| Feed | Format | Source |

| ipsum level-3 | TXT | github.com/stamparm/ipsum |
| Feodo Tracker IP blocklist | TXT | feodotracker.abuse.ch |
| URLhaus malicious URLs | TXT | urlhaus.abuse.ch |

Edit `config.py → REMOTE_FEEDS` to add your own.

---

## Optional Enrichment

**GeoIP** (MaxMind GeoLite2):

1. Download `GeoLite2-City.mmdb` from maxmind.com
2. Place it in the project root
3. Set `ENABLE_GEOIP = True` in `config.py`

**WHOIS**:

1. `pip install python-whois`
2. Set `ENABLE_WHOIS = True` in `config.py`

---

## Dashboard Features

- **Stats bar** — live totals: total / HIGH / MEDIUM / LOW / repeated
- **Type breakdown** — animated bar chart per IOC type
- **Source list** — all ingested feeds
- **Blocklist downloads** — one-click TXT exports (IP / Domain / URL)
- **IOC table** — sortable, filterable, paginated (50/page)
- **Live search** — debounced client-side + server-side filter
- **Auto-refresh** — every 30 s (configurable)
- **Run Pipeline** — trigger a fresh ingest from the browser

---

## Configuration (`config.py`)

| Key | Default | Description |

| `LOCAL_FEEDS` | `feeds/*.txt/csv/json` | Local feed file paths |
| `REMOTE_FEEDS` | 3 OSINT sources | Remote feed definitions |
| `SEVERITY_HIGH` | `3` | Min sources for HIGH |
| `SEVERITY_MEDIUM` | `2` | Min sources for MEDIUM |
| `OUTPUT_DIR` | `output/` | Where to write artefacts |
| `FLASK_PORT` | `5000` | Dashboard port |
| `DASHBOARD_REFRESH_S` | `30` | Auto-refresh interval |
| `ENABLE_GEOIP` | `False` | Toggle GeoIP enrichment |
| `ENABLE_WHOIS` | `False` | Toggle WHOIS enrichment |

---

## Tech Stack

- **Python 3.8+**
- **Flask 3** — web dashboard
- **requests** — remote feed fetching
- **re, ipaddress, csv, json** — parsing & validation (stdlib only)
- **geoip2** *(optional)* — GeoIP enrichment
- **python-whois** *(optional)* — WHOIS enrichment

No AI. No ML. Rule-based correlation only.
