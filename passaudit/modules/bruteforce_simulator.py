"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Brute-Force Simulator             ║
║   File: modules/bruteforce_simulator.py                 ║
╚══════════════════════════════════════════════════════════╝

Simulates password cracking techniques in a controlled lab:
  - Dictionary attack (wordlist vs hash)
  - Incremental / brute-force (a-z, 0-9, symbols)
  - Hybrid attack (dict + mutations)
  - Crack-time estimation (no actual cracking)

Ethical guards:
  - Max attempt limit (from config)
  - No network activity
  - Demo hashes only by default
"""

import hashlib
import itertools
import string
import time
import os


# ─── GPU speed estimates (hashes / second) ──────────────────────────────────────
GPU_SPEEDS = {
    'md5': 60_000_000_000,   # 60 Gh/s  — RTX 4090 Hashcat
    'sha1': 20_000_000_000,   # 20 Gh/s
    'sha256':  4_000_000_000,  # 4 Gh/s
    'sha512':  1_300_000_000,  # 1.3 Gh/s
    'ntlm': 90_000_000_000,   # 90 Gh/s
    'bcrypt':        184_000,   # 184K h/s  (cost 12)
    'argon2':          5_000,  # 5K h/s
}


class BruteForceSimulator:
    """Simulates password cracking attacks with ethical limits."""

    def __init__(self, config: dict):
        self.max_attempts = config.get('max_attempts', 100_000)
        self.default_algo = config.get('default_hash', 'md5')

    # ── Hash helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def hash_word(word: str, algo: str = 'md5') -> str:
        """Hash a word with the given algorithm."""
        algo = algo.lower().replace('-', '')
        try:
            h = hashlib.new(algo, word.encode('utf-8', errors='replace'))
            return h.hexdigest()
        except ValueError:
            # Fallback if algo not supported by hashlib
            return hashlib.md5(word.encode()).hexdigest()

    # ── Crack-time estimation ──────────────────────────────────────────────────
    def estimate_crack_time(self, password: str, algo: str = 'md5') -> dict:
        """
        Estimate worst-case brute-force crack time.

        Returns a dict with charset info and time estimates.
        """
        charset_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += 32
        if charset_size == 0:
            charset_size = 26

        combinations = charset_size ** len(password)
        speed = GPU_SPEEDS.get(algo.lower().replace('-', ''), 1_000_000_000)

        def fmt(secs):
            if secs < 1:
                return '< 1 second'
            if secs < 60:
                return f'{secs:.1f} seconds'
            if secs < 3_600:
                return f'{secs/60:.1f} minutes'
            if secs < 86_400:
                return f'{secs/3_600:.1f} hours'
            if secs < 31_536_000:
                return f'{secs/86_400:.1f} days'
            if secs < 3.15e10:
                return f'{secs/31_536_000:.1f} years'
            return 'Centuries+'

        worst_secs = combinations / speed
        avg_secs = worst_secs / 2

        return {
            'password': password,
            'length': len(password),
            'charset_size': charset_size,
            'combinations': combinations,
            'algo': algo,
            'gpu_speed': speed,
            'worst_case': fmt(worst_secs),
            'avg_case': fmt(avg_secs),
            'safe': worst_secs > 3.15e10,   # > 1000 years
        }

    def print_estimate(self, password: str, algo: str = 'md5'):
        """Pretty-print crack-time estimate for a password."""
        result = self.estimate_crack_time(password, algo)
        safe_label = '✓ SAFE' if result['safe'] else '✕ CRACKABLE'
        print(f"""
  ╔══ CRACK TIME ESTIMATE ════════════════════╗
  ║  Password   : {'*' * len(result['password'])} ({result['length']} chars)
  ║  Charset    : {result['charset_size']} symbols
  ║  Combos     : {result['combinations']:,}
  ║  Algorithm  : {result['algo'].upper()}
  ║  GPU Speed  : {result['gpu_speed']:,} h/s
  ╠══ RESULTS ════════════════════════════════╣
  ║  Avg case   : {result['avg_case']}
  ║  Worst case : {result['worst_case']}
  ║  Verdict    : {safe_label}
  ╚═══════════════════════════════════════════╝""")

    # ── Dictionary attack ──────────────────────────────────────────────────────
    def dictionary_attack(self, target_hash: str, wordlist: list,
                          algo: str = 'md5') -> str | None:
        """
        Attempt to crack target_hash using a wordlist.

        Args:
            target_hash: hex hash string to crack
            wordlist:    list of candidate passwords
            algo:        hash algorithm name

        Returns:
            Plaintext password if found, else None.
        """
        print(
            f"\n  [*] Dictionary attack | algo={algo} | wordlist={len(wordlist):,} words")
        print(f"  [*] Target : {target_hash}")
        print(f"  [*] Limit  : {self.max_attempts:,} attempts\n")

        start = time.time()
        cap = min(len(wordlist), self.max_attempts)

        for i, word in enumerate(wordlist[:cap]):
            if self.hash_word(word, algo) == target_hash.lower():
                elapsed = time.time() - start
                speed = int((i + 1) / max(elapsed, 0.001))
                print(f"  [CRACKED!]  '{word}'  found after {i+1:,} attempts")
                print(
                    f"  [INFO]      Time elapsed : {elapsed:.3f}s | Speed: {speed:,} h/s")
                return word
            # Progress every 10k
            if i % 10_000 == 0 and i > 0:
                elapsed = time.time() - start
                pct = i / cap * 100
                speed = int(i / max(elapsed, 0.001))
                print(
                    f"  [~] {pct:5.1f}% | {i:,} attempts | {speed:,} h/s", end='\r')

        elapsed = time.time() - start
        print(f"\n  [-] Not found in {cap:,} attempts ({elapsed:.2f}s)")
        return None

    # ── Incremental attack ─────────────────────────────────────────────────────
    def incremental_attack(self, target_hash: str, max_len: int = 4,
                           charset: str = 'lowercase') -> str | None:
        """
        Incremental brute-force up to max_len characters.

        charset options: 'lowercase', 'digits', 'alphanum', 'printable'
        """
        charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'alphanum': string.ascii_lowercase + string.digits,
            'mixedcase': string.ascii_letters,
            'printable': string.ascii_letters + string.digits + '!@#$%',
        }
        chars = charsets.get(charset, string.ascii_lowercase)
        attempts = 0
        algo = self.default_algo

        print(
            f"\n  [*] Incremental attack | charset='{charset}' ({len(chars)} chars) | max_len={max_len}")
        print(f"  [*] Target : {target_hash}\n")

        start = time.time()

        for length in range(1, max_len + 1):
            total_at_len = len(chars) ** length
            print(
                f"  [*] Trying length {length} ({total_at_len:,} combinations)...")

            for combo in itertools.product(chars, repeat=length):
                word = ''.join(combo)
                if self.hash_word(word, algo) == target_hash.lower():
                    elapsed = time.time() - start
                    print(
                        f"  [CRACKED!]  '{word}'  after {attempts:,} attempts ({elapsed:.3f}s)")
                    return word
                attempts += 1
                if attempts >= self.max_attempts:
                    print(
                        f"  [-] Max attempt limit reached ({self.max_attempts:,})")
                    return None
                if attempts % 50_000 == 0:
                    elapsed = time.time() - start
                    speed = int(attempts / max(elapsed, 0.001))
                    print(
                        f"  [~] {attempts:,} attempts | {speed:,} h/s", end='\r')

        elapsed = time.time() - start
        print(
            f"\n  [-] Not found after {attempts:,} attempts ({elapsed:.2f}s)")
        return None

    # ── Hybrid attack ──────────────────────────────────────────────────────────
    def hybrid_attack(self, target_hash: str, wordlist: list,
                      algo: str = 'md5') -> str | None:
        """
        Hybrid attack: dictionary words + common mutations applied on-the-fly.
        """
        print(f"\n  [*] Hybrid attack | base wordlist={len(wordlist):,} words")
        LEET = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        suffixes = ['1', '12', '123', '!', '@', '2024', '#']

        start = time.time()
        attempts = 0
        cap = self.max_attempts

        for word in wordlist:
            candidates = [word, word.upper(), word.capitalize()]
            leet_w = ''.join(LEET.get(c, '') or c for c in word.lower())
            candidates.extend([leet_w, leet_w.capitalize()])
            for base in candidates:
                for suf in [''] + suffixes:
                    candidate = base + suf
                    if self.hash_word(candidate, algo) == target_hash.lower():
                        elapsed = time.time() - start
                        print(
                            f"  [CRACKED!]  '{candidate}'  after {attempts:,} attempts ({elapsed:.3f}s)")
                        return candidate
                    attempts += 1
                    if attempts >= cap:
                        print(f"  [-] Max attempts reached ({cap:,})")
                        return None

        elapsed = time.time() - start
        print(f"  [-] Not found after {attempts:,} attempts ({elapsed:.2f}s)")
        return None

    # ── Simulate (interactive) ─────────────────────────────────────────────────
    def simulate(self, target: str, mode: str = 'dictionary',
                 wordlist: list = None) -> str | None:
        """
        Run simulation based on mode.

        Args:
            target:   hash string, or 'demo' to use a built-in demo hash
            mode:     'dictionary' | 'incremental' | 'hybrid' | 'estimate'
            wordlist: word candidates (used for dictionary/hybrid modes)
        """
        algo = self.default_algo

        if target.lower() == 'demo':
            # MD5 of 'admin' = 21232f297a57a5a743894a0e4a801fc3
            target = hashlib.md5(b'admin').hexdigest()
            demo_word = 'admin'
            print(f"  [*] Demo mode | Target is MD5 of a common word")

        if mode == 'estimate':
            # Can't estimate without knowing the plaintext — show for demo word
            pw = input("  Enter a password to estimate crack time: ").strip()
            self.print_estimate(pw, algo)
            return None

        wl = wordlist or ['password', 'admin', 'letmein',
                          '123456', 'qwerty', 'test', 'root']

        if mode == 'dictionary':
            result = self.dictionary_attack(target, wl, algo)
        elif mode == 'incremental':
            result = self.incremental_attack(
                target, max_len=4, charset='lowercase')
        elif mode == 'hybrid':
            result = self.hybrid_attack(target, wl, algo)
        else:
            result = self.dictionary_attack(target, wl, algo)

        return result

    # ── Bulk simulation (pipeline) ─────────────────────────────────────────────
    def simulate_bulk(self, hash_entries: list, wordlist: list) -> list:
        """
        Run dictionary attack against a list of hash entries.
        Only works on MD5 / NTLM entries (32-hex) for demo safety.
        """
        cracked = []
        algo = 'md5'

        for entry in hash_entries:
            h = entry.get('hash', '')
            if not h or len(h) != 32 or not all(c in '0123456789abcdefABCDEF' for c in h):
                continue  # Skip non-MD5 hashes

            result = self.dictionary_attack(h, wordlist, algo)
            if result:
                cracked.append(
                    {'user': entry['user'], 'plaintext': result, 'hash': h})

        print(
            f"\n  [+] Bulk simulation done | Cracked: {len(cracked)}/{len(hash_entries)}")
        return cracked
