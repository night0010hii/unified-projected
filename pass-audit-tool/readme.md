# PassAudit v2.0 — Password Security Assessment Toolkit

> **ETHICAL USE ONLY** — For authorized security testing in controlled lab environments.

---

## File Structure

```
passaudit/
├── modules/
│   ├── __init__.py                ← package init
│   ├── dictionary_generator.py   ← wordlist builder + mutations
│   ├── hash_extractor.py         ← Linux shadow / Windows SAM parser
│   ├── bruteforce_simulator.py   ← attack simulation + crack-time estimation
│   ├── strength_analyzer.py      ← entropy + complexity + pattern scoring
│   ├── entropy_calculator.py     ← Shannon entropy analysis
│   ├── hash_identifier.py        ← auto-detect algorithm from hash string
│   ├── policy_checker.py         ← NIST / OWASP / enterprise policy validator
│   └── report_generator.py       ← .txt + .json audit report output
│
├── gui/
│   └── index.html                ← browser GUI (open directly in browser)
│
├── data/
│   ├── common_passwords.txt      ← top 10K common passwords
│   ├── sample_shadow.txt         ← demo Linux shadow file
│   └── sample_hashes.txt         ← demo hash list
│
├── output/                       ← generated reports and wordlists
│
├── tests/
│   └── test_all.py               ← full unit test suite (pytest)
│
├── main.py                       ← CLI entry point
├── config.json                   ← all settings
├── requirements.txt              ← pip dependencies
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run interactive CLI

```bash
python main.py
```

### 3. Run full pipeline automatically

```bash
python main.py --mode pipeline --keywords "john,smith,company,2024"
```

### 4. Open GUI

Open `gui/index.html` directly in your browser — no server needed.

---

## Module Usage (Python API)

```python
from modules import (
    DictionaryGenerator, HashExtractor, BruteForceSimulator,
    StrengthAnalyzer, EntropyCalculator, HashIdentifier,
    PolicyChecker, ReportGenerator
)

import json
config = json.load(open('config.json'))

# ── 1. Generate wordlist ─────────────────────────────────────────
gen      = DictionaryGenerator(config)
wordlist = gen.generate(['admin', 'john', 'company2024'])

# ── 2. Extract / analyze hashes ─────────────────────────────────
ext    = HashExtractor(config)
hashes = ext.run_demo()           # use sample data
# OR: hashes = ext.parse_file('/path/to/shadow')

# ── 3. Identify a hash ───────────────────────────────────────────
hi     = HashIdentifier()
result = hi.identify('5f4dcc3b5aa765d61d8327deb882cf99')
# → MD5 / NTLM — CRITICAL

# ── 4. Simulate brute-force ──────────────────────────────────────
bf = BruteForceSimulator(config)
bf.simulate('demo', mode='dictionary', wordlist=wordlist)

# ── 5. Analyze password strength ────────────────────────────────
sa     = StrengthAnalyzer(config)
result = sa.analyze('MyP@ssw0rd!')
print(result['score'], result['rating'])

# ── 6. Calculate entropy ─────────────────────────────────────────
ec     = EntropyCalculator()
result = ec.calculate('SecureP@ss!')
print(result['pool_entropy'], 'bits')

# ── 7. Check policy compliance ───────────────────────────────────
pc     = PolicyChecker(config)
result = pc.check('Admin@2024', policy_name='enterprise')
print(result['verdict'])          # COMPLIANT / NON-COMPLIANT

# ── 8. Generate audit report ─────────────────────────────────────
session  = {'hashes': hashes, 'wordlist': wordlist, 'analysis': [result]}
reporter = ReportGenerator(config)
reporter.generate(session)
```

---

## Run Tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=modules
```

---

## Configuration (`config.json`)

| Key | Default | Description |
|-----|---------|-------------|
| `output_dir` | `output` | Directory for generated files |
| `common_passwords` | `data/common_passwords.txt` | Common password list path |
| `max_wordlist_size` | `50000` | Max words in generated wordlist |
| `max_attempts` | `100000` | Ethical brute-force attempt cap |
| `default_hash` | `md5` | Hash algorithm for simulations |
| `report_format` | `both` | `text`, `json`, or `both` |

---

## Modules Summary

| Module | Key Features |

| `dictionary_generator` | Leet, upper, numeric/symbol suffixes, DOB combos, keyword permutations |
| `hash_extractor` | shadow parser, NTLM dump parser, algorithm ID, demo mode |
| `bruteforce_simulator` | Dictionary / incremental / hybrid attack, GPU crack-time estimation |
| `strength_analyzer` | 0–100 score, entropy bits, pattern detection, bulk audit |
| `entropy_calculator` | Shannon entropy, pool entropy, charset size, frequency map |
| `hash_identifier` | 15+ algorithm patterns, bcrypt/Argon2/NTLM/MD5/SHA-* |
| `policy_checker` | NIST / OWASP / Enterprise / PCI-DSS / custom presets |
| `report_generator` | .txt + .json, executive summary, distributions, recommendations |

---

## Ethical Use Statement

This toolkit is designed for:

- Academic study and university coursework
- Authorized penetration testing within your own lab
- Security team password policy auditing (with written authorization)

**Never use this toolkit against systems you do not own or have explicit written permission to test.**
