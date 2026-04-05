"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Entropy Calculator                ║
║   File: modules/entropy_calculator.py                   ║
╚══════════════════════════════════════════════════════════╝

Calculates Shannon entropy for password strings:
  - Total entropy in bits
  - Bits per character
  - Effective charset size
  - Character frequency map
  - Entropy rating with security guidance
"""

import math
import re
import collections


class EntropyCalculator:
    """Shannon entropy analysis for password strings."""

    # ── Charset detection ──────────────────────────────────────────────────────
    @staticmethod
    def charset_size(text: str) -> int:
        """Return pool size of character classes present in text."""
        pool = 0
        if re.search(r'[a-z]', text):
            pool += 26
        if re.search(r'[A-Z]', text):
            pool += 26
        if re.search(r'[0-9]', text):
            pool += 10
        if re.search(r'[^a-zA-Z0-9]', text):
            pool += 32
        return pool or 26

    # ── Entropy methods ────────────────────────────────────────────────────────
    def pool_entropy(self, text: str) -> float:
        """Entropy from charset pool size × length (password-cracking model)."""
        cs = self.charset_size(text)
        return math.log2(cs) * len(text)

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """True Shannon entropy from character frequency distribution."""
        if not text:
            return 0.0
        freq = collections.Counter(text)
        total = len(text)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    # ── Frequency map ──────────────────────────────────────────────────────────
    @staticmethod
    def frequency_map(text: str) -> dict:
        """Return character frequency dict sorted by count descending."""
        freq = collections.Counter(text)
        return dict(sorted(freq.items(), key=lambda x: -x[1]))

    # ── Rating ─────────────────────────────────────────────────────────────────
    @staticmethod
    def entropy_rating(bits: float) -> tuple:
        """Return (label, colour) for entropy value."""
        RED, YELLOW, ORANGE, GREEN, CYAN, RESET = (
            '\033[91m', '\033[93m', '\033[33m',
            '\033[92m', '\033[96m', '\033[0m'
        )
        if bits < 28:
            return 'VERY WEAK',    RED
        if bits < 36:
            return 'WEAK',          RED
        if bits < 60:
            return 'MODERATE',      YELLOW
        if bits < 128:
            return 'STRONG',        GREEN
        return 'VERY STRONG (Cryptographic)', CYAN

    # ── Public API ─────────────────────────────────────────────────────────────
    def calculate(self, text: str) -> dict:
        """
        Full entropy analysis of a string.

        Returns:
            dict with pool_entropy, shannon_entropy, charset_size, freq_map, rating
        """
        reset = '\033[0m'
        pool = self.pool_entropy(text)
        sh = self.shannon_entropy(text)
        cs = self.charset_size(text)
        freq = self.frequency_map(text)
        rating, color = self.entropy_rating(pool)

        print(f"""
  ╔══ ENTROPY ANALYSIS ═════════════════════════╗
  ║  Input length    : {len(text)} characters
  ║  Charset pool    : {cs} symbols
  ║  Pool entropy    : {pool:.2f} bits (cracking model)
  ║  Shannon entropy : {sh:.4f} bits/char (info-theory)
  ║  Total bits      : {pool:.1f}
  ║  Rating          : {color}{rating}{reset}
  ╠══ CHARACTER FREQUENCY ══════════════════════╣""")
        for ch, cnt in list(freq.items())[:10]:
            bar = '█' * cnt
            display = 'SPC' if ch == ' ' else ch
            print(f"  ║  '{display}' × {cnt:<3} {bar}")
        if len(freq) > 10:
            print(f"  ║  ... and {len(freq)-10} more unique characters")
        print(f"  ╚═════════════════════════════════════════════╝")

        return {
            'length': len(text),
            'charset_size': cs,
            'pool_entropy': round(pool, 2),
            'shannon_entropy': round(sh, 4),
            'rating': rating,
            'freq_map': freq,
        }
