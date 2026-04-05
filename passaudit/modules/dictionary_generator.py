"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Dictionary Generator              ║
║   File: modules/dictionary_generator.py                 ║
╚══════════════════════════════════════════════════════════╝

Builds targeted wordlists from keywords with mutation rules:
  - Leet-speak substitutions
  - Uppercase / capitalize variants
  - Numeric and symbol suffixes / prefixes
  - Keyword combinations
  - Common password base list
"""

import itertools
import os

# ─── Mutation tables ────────────────────────────────────────────────────────────
LEET_MAP = {
    'a': '4', 'e': '3', 'i': '1', 'o': '0',
    's': '5', 't': '7', 'g': '9', 'b': '8', 'l': '1'
}

NUM_SUFFIXES = [
    '', '1', '12', '123', '1234', '12345',
    '0', '01', '007', '2020', '2021', '2022', '2023', '2024', '2025',
    '99', '100', '111', '000', '69', '786'
]

SYM_SUFFIXES = ['', '!', '@', '#', '$', '!!', '!@#', '_', '.', '*', '?']

PREFIXES = ['', '@', 'the', 'my', 'super', 'best', 'new', 'old']

KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdfgh', 'zxcvbn',
    '1qaz2wsx', 'qazwsx', '1q2w3e4r', 'q1w2e3r4'
]

COMMON_BASE = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
    'letmein', 'dragon', 'master', 'sunshine', 'princess', 'welcome',
    'shadow', 'superman', 'michael', 'football', 'baseball', 'mustang',
    'access', 'batman', 'trustno1', 'admin', 'login', 'pass', 'root',
    'test', 'guest', 'iloveyou', 'hello', 'charlie', 'donald', 'password1',
    'password123', 'admin123', 'root123', 'toor', 'changeme', 'default'
]


class DictionaryGenerator:
    """Generates targeted wordlists with configurable mutation rules."""

    def __init__(self, config: dict):
        self.output_path = os.path.join(config.get(
            'output_dir', 'output'), 'generated_wordlist.txt')
        self.common_path = config.get(
            'common_passwords', 'data/common_passwords.txt')
        self.max_size = config.get('max_wordlist_size', 50000)
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _leet(self, word: str) -> str:
        """Apply full leet-speak substitution."""
        return ''.join(LEET_MAP.get(c.lower(), c.lower()) for c in word)

    def _partial_leet(self, word: str) -> str:
        """Apply leet-speak only to first matching character."""
        result = list(word.lower())
        for i, c in enumerate(result):
            if c in LEET_MAP:
                result[i] = LEET_MAP[c]
                break
        return ''.join(result)

    def _variants(self, word: str) -> set:
        """Return all case / leet variants of a word."""
        w = word.strip()
        if not w:
            return set()
        leet = self._leet(w)
        p_leet = self._partial_leet(w)
        return {
            w,
            w.lower(),
            w.upper(),
            w.capitalize(),
            w.lower().capitalize(),
            leet,
            leet.capitalize(),
            p_leet,
            p_leet.capitalize(),
        }

    def _apply_affixes(self, variants: set) -> set:
        """Attach numeric/symbol suffixes and prefixes to every variant."""
        result = set()
        for v in variants:
            for pre in PREFIXES:
                for suf in NUM_SUFFIXES:
                    result.add(pre + v + suf)
                for suf in SYM_SUFFIXES:
                    result.add(v + suf)
        return result

    def _load_common(self) -> list:
        """Load common passwords from file or fall back to built-in list."""
        if os.path.exists(self.common_path):
            with open(self.common_path, encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        return COMMON_BASE

    # ── Public API ─────────────────────────────────────────────────────────────
    def generate(self, keywords: list) -> list:
        """
        Build a wordlist from keywords.

        Args:
            keywords: list of target strings (names, dates, words)

        Returns:
            list of generated password candidates (up to max_size)
        """
        print(
            f"\n  [+] DictionaryGenerator — {len(keywords)} keyword(s) received")

        all_words = set(self._load_common())
        all_words.update(KEYBOARD_PATTERNS)

        for kw in keywords:
            if not kw:
                continue
            variants = self._variants(kw)
            all_words.update(variants)
            all_words.update(self._apply_affixes(variants))

        # Keyword combinations (permutations of 2)
        for a, b in itertools.permutations(keywords, 2):
            if not a or not b:
                continue
            all_words.add(a + b)
            all_words.add(a.capitalize() + b)
            all_words.add(a + '_' + b)
            all_words.add(a + b + '1')
            all_words.add(a + b + '123')

        # DOB / year hybrids: keyword + every year suffix
        years = [str(y) for y in range(1960, 2026)]
        for kw in keywords:
            if len(kw) < 3:
                continue
            for yr in years:
                all_words.add(kw.lower() + yr)
                all_words.add(kw.capitalize() + yr)

        # Truncate to max size
        wordlist = sorted(all_words)[:self.max_size]

        # Save output
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(wordlist))

        print(f"  [+] Wordlist saved  : {self.output_path}")
        print(f"  [+] Total entries   : {len(wordlist):,}")
        print(f"  [+] Sample entries  : {', '.join(wordlist[:8])}")

        return wordlist
