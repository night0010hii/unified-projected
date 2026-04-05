"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Strength Analyzer                 ║
║   File: modules/strength_analyzer.py                    ║
╚══════════════════════════════════════════════════════════╝

Evaluates password strength using:
  - Length scoring
  - Character-set diversity
  - Shannon entropy (bits)
  - Common password dictionary check
  - Pattern detection (keyboard walks, repeated chars, sequences)
  - Severity rating: CRITICAL / WEAK / MODERATE / STRONG / VERY STRONG
  - Actionable improvement recommendations
"""

import math
import string
import re
import os


# ─── Rating thresholds ──────────────────────────────────────────────────────────
RATINGS = [
    (0,  25,  'CRITICAL',    '\033[91m'),   # bright red
    (25, 40,  'WEAK',        '\033[91m'),
    (40, 60,  'MODERATE',    '\033[93m'),   # yellow
    (60, 80,  'STRONG',      '\033[92m'),   # green
    (80, 101, 'VERY STRONG', '\033[96m'),   # cyan
]

# ─── Keyboard walk patterns ─────────────────────────────────────────────────────
KEYBOARD_WALKS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl',
    'zxcvbn', 'zxcvbnm', '1qaz', '2wsx', '3edc',
    'qazwsx', '1q2w3e4r', 'q1w2e3r4t5', '123qwe'
]


class StrengthAnalyzer:
    """Scores and audits password strength."""

    def __init__(self, config: dict):
        self.common_path = config.get(
            'common_passwords', 'data/common_passwords.txt')
        self.common_set = self._load_common()

    # ── Data loading ───────────────────────────────────────────────────────────
    def _load_common(self) -> set:
        """Load common passwords into a set for O(1) lookup."""
        built_in = {
            'password', 'password1', 'password123', '123456', '12345678',
            '1234567890', 'qwerty', 'abc123', 'monkey', 'letmein',
            'dragon', 'master', 'sunshine', 'princess', 'welcome',
            'shadow', 'superman', 'michael', 'football', 'baseball',
            'iloveyou', 'hello', 'charlie', 'donald', 'admin',
            'admin123', 'root', 'toor', 'test', 'guest', 'login',
            'pass', 'changeme', 'default', 'secret', 'god', 'sex',
            'mustang', 'access', 'batman', 'trustno1', '111111',
            'qwerty123', 'iloveyou1', 'password!', 'pass@123',
        }
        if os.path.exists(self.common_path):
            with open(self.common_path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    built_in.add(line.strip().lower())
        return built_in

    # ── Entropy calculation ────────────────────────────────────────────────────
    @staticmethod
    def entropy_bits(password: str) -> float:
        """
        Calculate Shannon entropy bits.
        Uses charset size × length model (pool entropy).
        """
        cs = 0
        if re.search(r'[a-z]', password):
            cs += 26
        if re.search(r'[A-Z]', password):
            cs += 26
        if re.search(r'[0-9]', password):
            cs += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            cs += 32
        return 0.0 if cs == 0 else math.log2(cs) * len(password)

    # ── Pattern detection ──────────────────────────────────────────────────────
    @staticmethod
    def has_keyboard_walk(password: str) -> bool:
        pw_low = password.lower()
        return any(walk in pw_low for walk in KEYBOARD_WALKS)

    @staticmethod
    def has_repeated_chars(password: str, n: int = 3) -> bool:
        """Check for n or more consecutive identical characters (e.g. 'aaa')."""
        return bool(re.search(r'(.)\1{' + str(n - 1) + r',}', password))

    @staticmethod
    def has_sequential(password: str) -> bool:
        """Detect ascending/descending numeric or alpha sequences."""
        for i in range(len(password) - 2):
            a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
            if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
                return True
        return False

    # ── Scoring ────────────────────────────────────────────────────────────────
    def score(self, password: str) -> int:
        """
        Compute a 0–100 strength score.

        Scoring breakdown:
          +40  length  (up to 20 chars)
          +10  lowercase present
          +10  uppercase present
          +10  digits present
          +20  symbols present
          −40  found in common password list
          −20  length < 8
          −10  keyboard walk detected
          −10  repeated characters detected
          −5   sequential pattern detected
        """
        s = 0
        length = len(password)

        # Length bonus: 2 pts per char, capped at 40
        s += min(length * 2, 40)

        # Charset bonuses
        if re.search(r'[a-z]', password):
            s += 10
        if re.search(r'[A-Z]', password):
            s += 10
        if re.search(r'[0-9]', password):
            s += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            s += 20

        # Penalties
        if password.lower() in self.common_set:
            s -= 40
        if length < 8:
            s -= 20
        if length < 6:
            s -= 20   # double penalty
        if self.has_keyboard_walk(password):
            s -= 10
        if self.has_repeated_chars(password):
            s -= 10
        if self.has_sequential(password):
            s -= 5

        return max(0, min(100, s))

    # ── Rating ─────────────────────────────────────────────────────────────────
    @staticmethod
    def get_rating(score: int) -> tuple:
        """Return (rating_label, ansi_color) for a score."""
        for lo, hi, label, color in RATINGS:
            if lo <= score < hi:
                return label, color
        return 'UNKNOWN', ''

    # ── Recommendations ────────────────────────────────────────────────────────
    def recommendations(self, password: str) -> list:
        """Return a list of improvement recommendations."""
        recs = []
        if len(password) < 8:
            recs.append('Use at least 8 characters (12+ recommended)')
        elif len(password) < 12:
            recs.append(
                'Increase length to 12+ characters for stronger security')
        if not re.search(r'[A-Z]', password):
            recs.append('Add at least one uppercase letter (A–Z)')
        if not re.search(r'[a-z]', password):
            recs.append('Add at least one lowercase letter (a–z)')
        if not re.search(r'[0-9]', password):
            recs.append('Include at least one digit (0–9)')
        if not re.search(r'[^a-zA-Z0-9]', password):
            recs.append('Add special characters (!@#$%^&*)')
        if password.lower() in self.common_set:
            recs.append(
                'This password is in known common-password lists — change it immediately!')
        if self.has_keyboard_walk(password):
            recs.append('Avoid keyboard patterns (qwerty, asdf, 1qaz...)')
        if self.has_repeated_chars(password):
            recs.append('Avoid repeating the same character (e.g. aaa, 111)')
        if self.has_sequential(password):
            recs.append('Avoid sequential patterns (abc, 123, xyz)')
        if not recs:
            recs.append('Password meets all strong policy requirements ✓')
        return recs

    # ── Public API ─────────────────────────────────────────────────────────────
    def analyze(self, password: str, show_password: bool = False) -> dict:
        """
        Fully analyze a password.

        Args:
            password:      the password string to assess
            show_password: if False, mask in printed output

        Returns:
            dict with score, entropy, rating, flags, recommendations
        """
        s = self.score(password)
        entropy = self.entropy_bits(password)
        rating, color = self.get_rating(s)
        recs = self.recommendations(password)
        reset = '\033[0m'

        display = password if show_password else '*' * len(password)

        print(f"""
  ╔══ PASSWORD ANALYSIS ════════════════════════╗
  ║  Password  : {display}
  ║  Length    : {len(password)} characters
  ║  Score     : {s}/100
  ║  Entropy   : {entropy:.1f} bits
  ║  Rating    : {color}{rating}{reset}
  ╠══ FLAGS ════════════════════════════════════╣
  ║  Common list   : {'YES — VULNERABLE' if password.lower() in self.common_set else 'No'}
  ║  Keyboard walk : {'YES' if self.has_keyboard_walk(password) else 'No'}
  ║  Repeated chars: {'YES' if self.has_repeated_chars(password) else 'No'}
  ║  Sequential    : {'YES' if self.has_sequential(password) else 'No'}
  ╠══ RECOMMENDATIONS ══════════════════════════╣""")
        for r in recs:
            print(f"  ║  • {r}")
        print(f"  ╚═════════════════════════════════════════════╝")

        return {
            'password': password,
            'length': len(password),
            'score': s,
            'entropy': round(entropy, 2),
            'rating': rating,
            'common': password.lower() in self.common_set,
            'kb_walk': self.has_keyboard_walk(password),
            'repeated': self.has_repeated_chars(password),
            'sequential': self.has_sequential(password),
            'recs': recs,
        }

    def analyze_bulk(self, passwords: list) -> list:
        """Analyze multiple passwords and print a summary table."""
        results = []
        print(f"\n  {'BULK PASSWORD ANALYSIS':═^60}")
        print(
            f"  {'#':<4} {'PASSWORD':<20} {'SCORE':<7} {'ENTROPY':<10} {'RATING':<12}")
        print(f"  {'─'*60}")
        for i, pwd in enumerate(passwords, 1):
            s = self.score(pwd)
            entropy = self.entropy_bits(pwd)
            rating, color = self.get_rating(s)
            reset = '\033[0m'
            display = '*' * min(len(pwd), 12)
            print(
                f"  {i:<4} {display:<20} {s:<7} {entropy:<10.1f} {color}{rating}{reset}")
            results.append({'password': pwd, 'score': s,
                           'entropy': entropy, 'rating': rating})
        print(f"  {'─'*60}")
        weak = sum(1 for r in results if r['score'] < 40)
        print(f"  Weak/Critical: {weak}/{len(results)}")
        return results
