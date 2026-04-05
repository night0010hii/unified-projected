"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Policy Checker                    ║
║   File: modules/policy_checker.py                       ║
╚══════════════════════════════════════════════════════════╝

Validates passwords against configurable security policies:
  - NIST SP 800-63B
  - OWASP Application Security
  - Custom enterprise policy
  - PCI-DSS requirement 8
  - CIS Controls

Each policy returns a compliance report with pass/fail
per rule, overall score, and recommendations.
"""

import re
import os
import math
import string


# ─── Built-in policy presets ────────────────────────────────────────────────────
POLICIES = {

    'nist': {
        'name': 'NIST SP 800-63B',
        'description': 'NIST guidelines focus on length over complexity.',
        'min_length': 8,
        'max_length': 64,
        'require_upper': False,
        'require_lower': False,
        'require_digit': False,
        'require_symbol': False,
        'block_common': True,
        'block_repeat': False,
        'block_sequential': False,
        'min_unique_chars': 0,
    },

    'owasp': {
        'name': 'OWASP Application Security',
        'description': 'OWASP recommends complexity + length.',
        'min_length': 10,
        'max_length': 128,
        'require_upper': True,
        'require_lower': True,
        'require_digit': True,
        'require_symbol': True,
        'block_common': True,
        'block_repeat': True,
        'block_sequential': True,
        'min_unique_chars': 0,
    },

    'enterprise': {
        'name': 'Enterprise Standard Policy',
        'description': 'Common corporate policy with strong complexity.',
        'min_length': 12,
        'max_length': 128,
        'require_upper': True,
        'require_lower': True,
        'require_digit': True,
        'require_symbol': True,
        'block_common': True,
        'block_repeat': True,
        'block_sequential': True,
        'min_unique_chars': 6,
    },

    'pci_dss': {
        'name': 'PCI-DSS Requirement 8',
        'description': 'Payment Card Industry Data Security Standard.',
        'min_length': 7,
        'max_length': 999,
        'require_upper': True,
        'require_lower': False,
        'require_digit': True,
        'require_symbol': False,
        'block_common': True,
        'block_repeat': False,
        'block_sequential': False,
        'min_unique_chars': 0,
    },

    'custom': {
        'name': 'Custom Policy',
        'description': 'User-defined policy.',
        'min_length': 8,
        'max_length': 128,
        'require_upper': True,
        'require_lower': True,
        'require_digit': True,
        'require_symbol': False,
        'block_common': True,
        'block_repeat': False,
        'block_sequential': False,
        'min_unique_chars': 0,
    },
}

COMMON_PASSWORDS = {
    'password', 'password1', 'password123', '123456', '12345678',
    'qwerty', 'abc123', 'letmein', 'admin', 'admin123',
    'welcome', 'monkey', 'dragon', 'master', 'iloveyou',
    'sunshine', 'princess', 'football', 'baseball', 'login',
    'pass', 'root', 'toor', 'test', 'guest', 'default', 'secret',
}

RED, GREEN, YELLOW, CYAN, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[0m'


class PolicyChecker:
    """Validates passwords against configurable security policies."""

    def __init__(self, config: dict = None):
        self.common_path = (config or {}).get(
            'common_passwords', 'data/common_passwords.txt')
        self.common_set = self._load_common()

    def _load_common(self) -> set:
        base = set(COMMON_PASSWORDS)
        if os.path.exists(self.common_path):
            with open(self.common_path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    base.add(line.strip().lower())
        return base

    # ── Rule checks ────────────────────────────────────────────────────────────
    @staticmethod
    def _check_length(pwd, min_len, max_len):
        if len(pwd) < min_len:
            return False, f'Too short: {len(pwd)} chars (min {min_len})'
        if len(pwd) > max_len:
            return False, f'Too long: {len(pwd)} chars (max {max_len})'
        return True, f'Length OK: {len(pwd)} chars'

    @staticmethod
    def _check_upper(pwd):
        return bool(re.search(r'[A-Z]', pwd)), 'Uppercase letter present' if re.search(r'[A-Z]', pwd) else 'Missing uppercase letter (A-Z)'

    @staticmethod
    def _check_lower(pwd):
        return bool(re.search(r'[a-z]', pwd)), 'Lowercase letter present' if re.search(r'[a-z]', pwd) else 'Missing lowercase letter (a-z)'

    @staticmethod
    def _check_digit(pwd):
        return bool(re.search(r'[0-9]', pwd)), 'Digit present' if re.search(r'[0-9]', pwd) else 'Missing digit (0-9)'

    @staticmethod
    def _check_symbol(pwd):
        has = bool(re.search(r'[^a-zA-Z0-9]', pwd))
        return has, 'Special character present' if has else 'Missing special character (!@#$...)'

    def _check_common(self, pwd):
        bad = pwd.lower() in self.common_set
        return not bad, ('Not in common password list' if not bad else 'FOUND in common password list — CHANGE IMMEDIATELY')

    @staticmethod
    def _check_repeat(pwd):
        bad = bool(re.search(r'(.)\1{2,}', pwd))
        return not bad, ('No excessive repeated chars' if not bad else 'Repeated characters detected (e.g. aaa, 111)')

    @staticmethod
    def _check_sequential(pwd):
        for i in range(len(pwd) - 2):
            a, b, c = ord(pwd[i]), ord(pwd[i+1]), ord(pwd[i+2])
            if (b-a == 1 and c-b == 1) or (a-b == 1 and b-c == 1):
                return False, 'Sequential pattern detected (e.g. abc, 123)'
        return True, 'No sequential patterns found'

    @staticmethod
    def _check_unique(pwd, min_unique):
        u = len(set(pwd))
        return u >= min_unique, f'{u} unique characters (min {min_unique})'

    # ── Core checker ───────────────────────────────────────────────────────────
    def check(self, password: str, policy_name: str = 'enterprise') -> dict:
        """
        Validate a password against a named policy.

        Args:
            password:    password string to validate
            policy_name: one of 'nist', 'owasp', 'enterprise', 'pci_dss', 'custom'

        Returns:
            dict with rules, passed count, compliance %, verdict
        """
        pol = POLICIES.get(policy_name, POLICIES['enterprise'])
        rules = []

        # ── Run all configured checks ──────────────────────────────────────────
        ok, msg = self._check_length(
            password, pol['min_length'], pol['max_length'])
        rules.append(
            {'rule': f"Length ({pol['min_length']}–{pol['max_length']} chars)", 'pass': ok, 'msg': msg, 'required': True})

        if pol['require_upper']:
            ok, msg = self._check_upper(password)
            rules.append({'rule': 'Requires uppercase',
                         'pass': ok, 'msg': msg, 'required': True})

        if pol['require_lower']:
            ok, msg = self._check_lower(password)
            rules.append({'rule': 'Requires lowercase',
                         'pass': ok, 'msg': msg, 'required': True})

        if pol['require_digit']:
            ok, msg = self._check_digit(password)
            rules.append({'rule': 'Requires digit', 'pass': ok,
                         'msg': msg, 'required': True})

        if pol['require_symbol']:
            ok, msg = self._check_symbol(password)
            rules.append({'rule': 'Requires symbol', 'pass': ok,
                         'msg': msg, 'required': True})

        if pol['block_common']:
            ok, msg = self._check_common(password)
            rules.append({'rule': 'Not a common password',
                         'pass': ok, 'msg': msg, 'required': True})

        if pol['block_repeat']:
            ok, msg = self._check_repeat(password)
            rules.append({'rule': 'No repeated chars (aaa)',
                         'pass': ok, 'msg': msg, 'required': False})

        if pol['block_sequential']:
            ok, msg = self._check_sequential(password)
            rules.append({'rule': 'No sequential patterns',
                         'pass': ok, 'msg': msg, 'required': False})

        if pol['min_unique_chars'] > 0:
            ok, msg = self._check_unique(password, pol['min_unique_chars'])
            rules.append(
                {'rule': f"Min {pol['min_unique_chars']} unique chars", 'pass': ok, 'msg': msg, 'required': True})

        # ── Results ────────────────────────────────────────────────────────────
        passed = sum(1 for r in rules if r['pass'])
        total = len(rules)
        req_rules = [r for r in rules if r['required']]
        req_passed = sum(1 for r in req_rules if r['pass'])
        compliant = req_passed == len(req_rules)
        pct = round(passed / total * 100)

        verdict_color = GREEN if compliant else RED
        verdict = 'COMPLIANT' if compliant else 'NON-COMPLIANT'

        print(f"""
  ╔══ POLICY CHECK — {pol['name'].upper()} {'':═<30}╗
  ║  {pol['description']}
  ╠══ RESULTS {'':═<50}╣
  ║  Rules passed  : {passed}/{total}  ({pct}%)
  ║  Verdict       : {verdict_color}{verdict}{RESET}
  ╠══ RULE DETAILS {'':═<46}╣""")

        for r in rules:
            icon = f"{GREEN}✓{RESET}" if r['pass'] else f"{RED}✕{RESET}"
            req = '' if r['required'] else f" {YELLOW}[optional]{RESET}"
            print(f"  ║  {icon} {r['rule']:<32}{req}")
            if not r['pass']:
                print(f"  ║    → {r['msg']}")

        print(f"  ╚{'═'*60}╝")

        return {
            'policy': pol['name'],
            'password': password,
            'rules': rules,
            'passed': passed,
            'total': total,
            'pct': pct,
            'compliant': compliant,
            'verdict': verdict,
        }

    def check_all_policies(self, password: str) -> dict:
        """Run password against all built-in policies and print comparison."""
        print(f"\n  {'ALL POLICY COMPARISON':═^60}")
        all_results = {}
        for name in POLICIES:
            result = self.check(password, name)
            all_results[name] = result

        print(f"\n  {'POLICY':<30} {'VERDICT':<14} {'PASSED':<10}")
        print(f"  {'─'*54}")
        for name, r in all_results.items():
            color = GREEN if r['compliant'] else RED
            print(
                f"  {r['policy']:<30} {color}{r['verdict']:<14}{RESET} {r['passed']}/{r['total']}")
        return all_results
