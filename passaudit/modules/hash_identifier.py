"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Hash Identifier                   ║
║   File: modules/hash_identifier.py                      ║
╚══════════════════════════════════════════════════════════╝

Auto-detects password hash algorithms from:
  - Hash length + character set
  - Linux crypt() prefix patterns
  - Windows NTLM / LM patterns
  - LDAP / Django / Wordpress prefixes
  - bcrypt, Argon2, scrypt, yescrypt
"""

import re


# ─── Hash database ──────────────────────────────────────────────────────────────
# Each entry: (identifier_fn, name, security, crackability, description, recommendation)
HASH_DB = [
    # ── yescrypt / scrypt / modern KDFs ──────────────────────────────────────
    {
        'prefix': '$y$',
        'name': 'yescrypt',
        'security': 'VERY STRONG',
        'crack': 'Practically impossible (memory-hard)',
        'desc': 'Modern memory-hard KDF. Default in Fedora 35+, Debian 11+. Resists GPU/ASIC attacks.',
        'rec': 'Excellent. No action needed.',
        'len_range': None,
    },
    {
        'prefix': '$7$',
        'name': 'scrypt',
        'security': 'VERY STRONG',
        'crack': 'Practically impossible (memory-hard)',
        'desc': 'scrypt is a memory-hard KDF designed to resist GPU cracking.',
        'rec': 'Excellent choice for password storage.',
        'len_range': None,
    },
    # ── bcrypt ────────────────────────────────────────────────────────────────
    {
        'prefix': '$2b$',
        'name': 'bcrypt',
        'security': 'STRONG',
        'crack': 'Very hard (years with GPU, cost 12+)',
        'desc': 'Purpose-built adaptive password hash. Uses Blowfish cipher. Built-in salting. Work factor is tunable.',
        'rec': 'Recommended. Use cost factor ≥ 12.',
        'len_range': (59, 60),
    },
    {
        'prefix': '$2a$',
        'name': 'bcrypt (legacy $2a$)',
        'security': 'STRONG',
        'crack': 'Very hard',
        'desc': 'Older bcrypt variant. Functionally identical to $2b$ on most systems.',
        'rec': 'Consider migrating to $2b$ prefix.',
        'len_range': (59, 60),
    },
    {
        'prefix': '$2y$',
        'name': 'bcrypt (PHP $2y$)',
        'security': 'STRONG',
        'crack': 'Very hard',
        'desc': 'PHP-specific bcrypt variant introduced to fix a bug in $2a$.',
        'rec': 'Good. Equivalent to $2b$.',
        'len_range': (59, 60),
    },
    # ── SHA-512crypt ──────────────────────────────────────────────────────────
    {
        'prefix': '$6$',
        'name': 'SHA-512crypt',
        'security': 'STRONG',
        'crack': 'Hard (weeks to months with GPU)',
        'desc': 'Linux crypt() using SHA-512 with configurable rounds. Default for modern Linux systems.',
        'rec': 'Good. Ensure rounds ≥ 100,000.',
        'len_range': None,
    },
    # ── SHA-256crypt ──────────────────────────────────────────────────────────
    {
        'prefix': '$5$',
        'name': 'SHA-256crypt',
        'security': 'MODERATE',
        'crack': 'Moderate (days to weeks)',
        'desc': 'Linux crypt() using SHA-256. Less secure than SHA-512crypt due to smaller hash size.',
        'rec': 'Upgrade to SHA-512crypt ($6$) or bcrypt.',
        'len_range': None,
    },
    # ── MD5crypt ──────────────────────────────────────────────────────────────
    {
        'prefix': '$1$',
        'name': 'MD5crypt',
        'security': 'WEAK',
        'crack': 'Easy (hours to days)',
        'desc': 'FreeBSD MD5-based crypt. Deprecated and considered insecure.',
        'rec': 'Replace immediately with bcrypt or SHA-512crypt.',
        'len_range': None,
    },
    {
        'prefix': '$apr1$',
        'name': 'APR-MD5 (Apache)',
        'security': 'WEAK',
        'crack': 'Easy (hours to days)',
        'desc': 'Apache variant of MD5crypt. Used in .htpasswd files.',
        'rec': 'Replace with bcrypt ($2y$) in Apache 2.4+.',
        'len_range': None,
    },
    # ── Argon2 ────────────────────────────────────────────────────────────────
    {
        'prefix': '$argon2id$',
        'name': 'Argon2id',
        'security': 'VERY STRONG',
        'crack': 'Practically impossible (memory-hard)',
        'desc': 'Winner of Password Hashing Competition 2015. Memory-hard, highly configurable. Recommended by OWASP.',
        'rec': 'Best practice. No action needed.',
        'len_range': None,
    },
    {
        'prefix': '$argon2i$',
        'name': 'Argon2i',
        'security': 'VERY STRONG',
        'crack': 'Practically impossible',
        'desc': 'Argon2 variant optimized for side-channel resistance.',
        'rec': 'Excellent. Prefer Argon2id for general use.',
        'len_range': None,
    },
    # ── Django prefixes ───────────────────────────────────────────────────────
    {
        'prefix': 'pbkdf2_sha256$',
        'name': 'PBKDF2-SHA256 (Django)',
        'security': 'MODERATE',
        'crack': 'Difficult with sufficient iterations',
        'desc': 'Django default hasher. PBKDF2 with SHA-256 and high iteration count.',
        'rec': 'Acceptable. Ensure iterations ≥ 600,000 (Django 4.2+ default).',
        'len_range': None,
    },
    # ── WordPress ─────────────────────────────────────────────────────────────
    {
        'prefix': '$P$',
        'name': 'phpass (WordPress / phpBB)',
        'security': 'WEAK',
        'crack': 'Easy to moderate',
        'desc': 'Portable PHP password hashing framework using MD5 with stretching. Widely deployed but outdated.',
        'rec': 'Upgrade to bcrypt-based hasher (WordPress 6.3+ option).',
        'len_range': (34, 34),
    },
    {
        'prefix': '$H$',
        'name': 'phpass (phpBB3)',
        'security': 'WEAK',
        'crack': 'Easy to moderate',
        'desc': 'phpBB3 variant of phpass.',
        'rec': 'Migrate to modern KDF.',
        'len_range': (34, 34),
    },
]

# ─── Plain hex hashes by length ─────────────────────────────────────────────────
HEX_HASHES = [
    (8,   'CRC32',   'CRITICAL', 'Trivially reversible',
     'Not a cryptographic hash. Do not use.', 'Use bcrypt or Argon2.'),
    (13,  'DES crypt', 'CRITICAL', 'Trivially crackable',
     'Legacy Unix DES crypt. Only 8 chars used.', 'Replace immediately.'),
    (32,  'MD5 / NTLM', 'CRITICAL', '< 1 minute (GPU)',
     'MD5 is cryptographically broken. NTLM is Microsoft\'s NT hash.', 'Replace with bcrypt or Argon2.'),
    (40,  'SHA-1',   'HIGH',     'Minutes to hours',
     'SHA-1 is deprecated. Vulnerable to collision attacks.', 'Migrate to SHA-256 minimum.'),
    (56,  'SHA-224', 'MODERATE', 'Days to weeks',
     'SHA-224 is truncated SHA-256. Rarely used for passwords.', 'Use bcrypt or Argon2 instead.'),
    (64,  'SHA-256', 'MODERATE', 'Hours to days (GPU)',
     'Cryptographically secure but too fast for password hashing.', 'Use bcrypt, scrypt, or Argon2.'),
    (96,  'SHA-384', 'MODERATE', 'Days to weeks',
     'Truncated SHA-512. Fast algorithm, not designed for passwords.', 'Pair with salting; use a proper KDF.'),
    (128, 'SHA-512', 'MODERATE', 'Weeks to months',
     'Very secure hash but still a fast algorithm (billions/sec on GPU).', 'Add adaptive work factor via KDF.'),
]

COLOR_MAP = {
    'VERY STRONG': '\033[96m',
    'STRONG': '\033[92m',
    'MODERATE': '\033[93m',
    'HIGH': '\033[91m',
    'WEAK': '\033[91m',
    'CRITICAL': '\033[91m\033[1m',
    'UNKNOWN': '\033[2m',
}
RESET = '\033[0m'


class HashIdentifier:
    """Auto-identifies password hash algorithm from hash string."""

    def identify(self, hash_str: str) -> dict:
        """
        Identify the hash algorithm.

        Args:
            hash_str: raw hash string to analyze

        Returns:
            dict with name, security, crack difficulty, description, recommendation
        """
        h = hash_str.strip()
        result = None

        # ── Prefix-based matching ──────────────────────────────────────────────
        for entry in HASH_DB:
            if h.startswith(entry['prefix']):
                result = entry.copy()
                break

        # ── Hex-length matching ────────────────────────────────────────────────
        if result is None and re.fullmatch(r'[a-fA-F0-9]+', h):
            for length, name, sec, crack, desc, rec in HEX_HASHES:
                if len(h) == length:
                    result = {
                        'name': name, 'security': sec,
                        'crack': crack, 'desc': desc, 'rec': rec,
                        'prefix': None, 'len_range': (length, length),
                    }
                    break

        # ── Unknown ────────────────────────────────────────────────────────────
        if result is None:
            result = {
                'name': 'Unknown / Custom',
                'security': 'UNKNOWN',
                'crack': 'Cannot determine',
                'desc': 'Hash pattern not recognized. Could be a custom scheme, salted format, or encoded value.',
                'rec': 'Investigate the source application for algorithm details.',
                'prefix': None,
                'len_range': None,
            }

        color = COLOR_MAP.get(result['security'], '')
        print(f"""
  ╔══ HASH IDENTIFIER ══════════════════════════════════════════╗
  ║  Input Hash     : {h[:60]}{'...' if len(h) > 60 else ''}
  ║  Hash Length    : {len(h)} characters
  ╠══ RESULT ═══════════════════════════════════════════════════╣
  ║  Algorithm      : {result['name']}
  ║  Security Level : {color}{result['security']}{RESET}
  ║  Crack Difficulty: {result['crack']}
  ╠══ DETAILS ══════════════════════════════════════════════════╣
  ║  {result['desc']}
  ╠══ RECOMMENDATION ═══════════════════════════════════════════╣
  ║  {result['rec']}
  ╚═════════════════════════════════════════════════════════════╝""")

        result['input'] = h
        result['input_len'] = len(h)
        return result

    def identify_many(self, hashes: list) -> list:
        """Identify multiple hashes and return summary."""
        results = []
        print(f"\n  {'BULK HASH IDENTIFICATION':═^60}")
        print(f"  {'#':<4} {'HASH PREVIEW':<36} {'ALGORITHM':<18} {'SECURITY':<12}")
        print(f"  {'─'*70}")
        for i, h in enumerate(hashes, 1):
            r = self.identify(h)
            color = COLOR_MAP.get(r['security'], '')
            print(
                f"  {i:<4} {h[:34]+'...':<36} {r['name']:<18} {color}{r['security']}{RESET}")
            results.append(r)
        return results
