"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Hash Extractor                    ║
║   File: modules/hash_extractor.py                       ║
╚══════════════════════════════════════════════════════════╝

Parses and identifies password hashes from:
  - Linux /etc/shadow format
  - Windows SAM (NTLM hex hashes)
  - Plain hash lists
  - Auto-detect mixed input

DEMO MODE: uses built-in sample data only.
No real system files are accessed automatically.
"""

import re
import hashlib
import os


# ─── Algorithm prefix map (Linux crypt format) ──────────────────────────────────
CRYPT_PREFIXES = {
    '$y$': ('yescrypt',     'VERY STRONG'),
    '$gy$': ('gost-yescrypt', 'VERY STRONG'),
    '$7$': ('scrypt',       'VERY STRONG'),
    '$2b$': ('bcrypt',       'STRONG'),
    '$2a$': ('bcrypt',       'STRONG'),
    '$2y$': ('bcrypt',       'STRONG'),
    '$6$': ('SHA-512crypt', 'STRONG'),
    '$5$': ('SHA-256crypt', 'MODERATE'),
    '$md5': ('SunMD5',       'WEAK'),
    '$3$': ('NT-hash',      'CRITICAL'),
    '$1$': ('MD5crypt',     'WEAK'),
    '$apr1$': ('APR-MD5',     'WEAK'),
}

# ─── Demo shadow file content ────────────────────────────────────────────────────
DEMO_SHADOW = """\
root:$6$rounds=5000$saltrootxyz$FAKEHASHVALUE111111111111111111111111111111111111111111111111111111111111111111111:19000:0:99999:7:::
john:$1$saltyxyz$FAKEHASHMD5VALUE12345678:19100:0:99999:7:::
alice:$2b$12$saltalicehashbcryptvaluexxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:19200:0:99999:7:::
bob:$5$rounds=5000$saltbobxyz$FAKESHA256VALUE111111111111111111111111111111111111111:19300:0:99999:7:::
charlie:5f4dcc3b5aa765d61d8327deb882cf99:19400:0:99999:7:::
dave:!:19500:0:99999:7:::
eve:*:19600:0:99999:7:::
"""

# ─── Demo plain NTLM hashes ──────────────────────────────────────────────────────
DEMO_NTLM = """\
Administrator:500:NOPASSWD:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:NOPASSWD:31d6cfe0d16ae931b73c59d7e0c089c0:::
john:1001:NOPASSWD:5f4dcc3b5aa765d61d8327deb882cf99:::
alice:1002:NOPASSWD:0d107d09f5bbe40cade3de5c71e9e9b7:::
"""


class HashExtractor:
    """Extracts and identifies password hashes from various sources."""

    def __init__(self, config: dict):
        self.shadow_file = config.get('shadow_file', 'data/sample_shadow.txt')

    # ── Algorithm identification ───────────────────────────────────────────────
    @staticmethod
    def identify_algorithm(hash_str: str) -> tuple:
        """
        Identify algorithm from hash string.

        Returns:
            (algorithm_name, security_level)
        """
        # Linux crypt prefixes
        for prefix, (name, sec) in CRYPT_PREFIXES.items():
            if hash_str.startswith(prefix):
                return name, sec

        # Plain hex hashes by length
        if re.fullmatch(r'[a-fA-F0-9]{32}', hash_str):
            # Could be MD5 or NTLM — both 32-hex
            return 'MD5 / NTLM', 'CRITICAL'
        if re.fullmatch(r'[a-fA-F0-9]{40}', hash_str):
            return 'SHA-1', 'HIGH'
        if re.fullmatch(r'[a-fA-F0-9]{56}', hash_str):
            return 'SHA-224', 'MODERATE'
        if re.fullmatch(r'[a-fA-F0-9]{64}', hash_str):
            return 'SHA-256', 'MODERATE'
        if re.fullmatch(r'[a-fA-F0-9]{96}', hash_str):
            return 'SHA-384', 'STRONG'
        if re.fullmatch(r'[a-fA-F0-9]{128}', hash_str):
            return 'SHA-512', 'STRONG'
        if re.fullmatch(r'[a-fA-F0-9]{8}', hash_str):
            return 'CRC32 / DES', 'CRITICAL'

        return 'Unknown', 'UNKNOWN'

    # ── Parsers ────────────────────────────────────────────────────────────────
    def parse_shadow_content(self, content: str) -> list:
        """Parse /etc/shadow-format text. Returns list of dicts."""
        entries = []
        for line in content.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 2:
                continue
            user = parts[0]
            hash_val = parts[1]
            # Skip locked / empty accounts
            if hash_val in ('!', '*', 'x', '!!', ''):
                entries.append({
                    'user': user,
                    'hash': '[LOCKED / NO PASSWORD]',
                    'algorithm': 'N/A',
                    'security': 'N/A',
                    'locked': True,
                })
                continue
            algo, sec = self.identify_algorithm(hash_val)
            entries.append({
                'user': user,
                'hash': hash_val,
                'algorithm': algo,
                'security': sec,
                'locked': False,
            })
        return entries

    def parse_ntlm_dump(self, content: str) -> list:
        """Parse Windows SAM / secretsdump NTLM format."""
        entries = []
        # Format: user:rid:LM:NTLM:::
        pattern = re.compile(
            r'^(.+?):(\d+):([a-fA-F0-9]{32}|NOPASSWD):([a-fA-F0-9]{32}|[a-fA-F0-9]{0}):::')
        for line in content.strip().splitlines():
            m = pattern.match(line.strip())
            if not m:
                continue
            user, rid, lm, ntlm = m.groups()
            algo, sec = self.identify_algorithm(
                ntlm) if ntlm else ('N/A', 'N/A')
            entries.append({
                'user': user,
                'rid': rid,
                'lm_hash': lm,
                'hash': ntlm,
                'algorithm': 'NTLM',
                'security': 'CRITICAL',
                'locked': False,
            })
        return entries

    def parse_plain_hashes(self, content: str) -> list:
        """Parse a plain list of hashes (one per line)."""
        entries = []
        for i, line in enumerate(content.strip().splitlines(), 1):
            h = line.strip()
            if not h:
                continue
            algo, sec = self.identify_algorithm(h)
            entries.append({
                'user': f'hash_{i:03d}',
                'hash': h,
                'algorithm': algo,
                'security': sec,
                'locked': False,
            })
        return entries

    def parse_file(self, filepath: str) -> list:
        """Auto-detect format and parse a hash file."""
        if not os.path.exists(filepath):
            print(f"  [!] File not found: {filepath}")
            return []
        with open(filepath, encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Detect format
        if ':::' in content:
            return self.parse_ntlm_dump(content)
        elif re.search(r':\$\d\$', content) or re.search(r':\$2[aby]\$', content):
            return self.parse_shadow_content(content)
        else:
            return self.parse_plain_hashes(content)

    # ── Demo ───────────────────────────────────────────────────────────────────
    def generate_real_hashes(self) -> list:
        """Generate actual MD5 / SHA hashes of common words for demo."""
        samples = ['password', 'admin123',
                   'letmein', 'qwerty', 'root', 'test123']
        demo = []
        for word in samples:
            demo.append({
                'word': word,
                'md5': hashlib.md5(word.encode()).hexdigest(),
                'sha1': hashlib.sha1(word.encode()).hexdigest(),
                'sha256': hashlib.sha256(word.encode()).hexdigest(),
                'sha512': hashlib.sha512(word.encode()).hexdigest(),
            })
        return demo

    def run_demo(self) -> list:
        """Run demo mode with sample shadow & NTLM data."""
        print(f"\n  [+] HashExtractor — demo mode")

        # Shadow
        print(f"\n  {' LINUX /etc/shadow ':─^50}")
        shadow_entries = self.parse_shadow_content(DEMO_SHADOW)
        for e in shadow_entries:
            status = '[LOCKED]' if e['locked'] else f"[{e['security']}]"
            print(
                f"    {e['user']:<12} | {e['algorithm']:<16} | {status:<10} | {e['hash'][:40]}")

        # NTLM
        print(f"\n  {' WINDOWS NTLM DUMP ':─^50}")
        ntlm_entries = self.parse_ntlm_dump(DEMO_NTLM)
        for e in ntlm_entries:
            print(
                f"    {e['user']:<12} | NTLM              | [CRITICAL]  | {e['hash']}")

        # Real hash examples
        print(f"\n  {' REAL HASH EXAMPLES ':─^50}")
        real = self.generate_real_hashes()
        for r in real:
            print(f"    Word: {r['word']:<12} | MD5: {r['md5'][:32]}")

        all_entries = shadow_entries + ntlm_entries
        print(f"\n  [+] Total entries extracted: {len(all_entries)}")
        return all_entries
