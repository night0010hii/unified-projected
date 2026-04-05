"""
╔══════════════════════════════════════════════════════════╗
║   PassAudit — Module: Report Generator                  ║
║   File: modules/report_generator.py                     ║
╚══════════════════════════════════════════════════════════╝

Generates comprehensive audit reports:
  - Plain text (.txt) — terminal-friendly
  - JSON (.json) — machine-readable
  - Sections: summary, hashes, cracked, analysis,
    policy compliance, recommendations
"""

import json
import os
from datetime import datetime


# ─── Policy recommendations ──────────────────────────────────────────────────────
RECOMMENDATIONS = [
    ('AUTHENTICATION', [
        'Enforce minimum 12-character password length',
        'Require mixed case, digits, AND special characters',
        'Block all passwords found in common/leaked password lists',
        'Implement account lockout after 5 consecutive failures',
        'Enable Multi-Factor Authentication (MFA) for all accounts',
        'Use adaptive authentication for high-risk logins',
    ]),
    ('STORAGE & HASHING', [
        'Replace MD5 / SHA-1 / NTLM with bcrypt, Argon2id, or scrypt',
        'Use bcrypt cost factor ≥ 12 (or Argon2id with 64MB memory)',
        'Never store plaintext or reversibly-encrypted passwords',
        'Apply unique per-password salts (built-in to bcrypt/Argon2)',
        'Audit hash algorithms in all applications annually',
    ]),
    ('OPERATIONAL', [
        'Enforce 90-day password rotation for privileged accounts',
        'Monitor authentication logs for brute-force patterns',
        'Implement CAPTCHA and rate limiting on login endpoints',
        'Alert users on login from new devices / locations',
        'Disable / lock accounts unused for 30+ days',
        'Audit privileged accounts (root, admin) monthly',
    ]),
    ('COMPLIANCE', [
        'NIST SP 800-63B: Minimum 8 chars, block compromised passwords',
        'OWASP: Use bcrypt/scrypt/Argon2, enforce MFA',
        'PCI-DSS 4.0: Min 12 chars, complexity, 90-day rotation',
        'ISO 27001: Annual credential security audits required',
        'GDPR: Protect credentials as personal data; report breaches',
    ]),
]

# ─── Risk color map (ANSI only for terminal output) ──────────────────────────────
RISK_COLOR = {
    'CRITICAL': '\033[91m\033[1m',
    'HIGH': '\033[91m',
    'MODERATE': '\033[93m',
    'WEAK': '\033[91m',
    'STRONG': '\033[92m',
    'VERY STRONG': '\033[96m',
}
RESET = '\033[0m'


class ReportGenerator:
    """Produces comprehensive security audit reports."""

    def __init__(self, config: dict):
        self.output_dir = config.get('output_dir', 'output')
        self.report_fmt = config.get('report_format', 'both')
        os.makedirs(self.output_dir, exist_ok=True)

    # ── Internal helpers ───────────────────────────────────────────────────────
    @staticmethod
    def _bar(pct: int, width: int = 30, char: str = '█') -> str:
        filled = int(pct / 100 * width)
        return char * filled + '░' * (width - filled)

    @staticmethod
    def _severity(score: int) -> str:
        if score < 25:
            return 'CRITICAL'
        if score < 40:
            return 'WEAK'
        if score < 60:
            return 'MODERATE'
        if score < 80:
            return 'STRONG'
        return 'VERY STRONG'

    # ── Build report text ──────────────────────────────────────────────────────
    def _build_text(self, session: dict, ts: str) -> str:
        hashes = session.get('hashes',   [])
        cracked = session.get('cracked',  [])
        analysis = session.get('analysis', [])
        wordlist = session.get('wordlist', [])

        # Distribution
        dist = {'CRITICAL': 0, 'WEAK': 0, 'MODERATE': 0,
                'STRONG': 0, 'VERY STRONG': 0}
        for a in analysis:
            rating = a.get('rating', self._severity(a.get('score', 0)))
            if rating in dist:
                dist[rating] += 1

        total_analyzed = len(analysis) or 1
        crack_rate = len(cracked) / max(len(hashes), 1) * 100

        # Risk level
        risk_score = dist['CRITICAL'] * 30 + \
            dist['WEAK'] * 15 + len(cracked) * 20
        risk_score = min(100, risk_score)
        if risk_score >= 75:
            risk = 'CRITICAL'
        elif risk_score >= 50:
            risk = 'HIGH'
        elif risk_score >= 25:
            risk = 'MODERATE'
        else:
            risk = 'LOW'

        lines = []

        def h(title, char='═'):
            lines.append(f"\n  {char * 3} {title} {char * (55 - len(title))}")

        lines.append(f"""
╔══════════════════════════════════════════════════════════════════╗
║           PASSAUDIT — COMPREHENSIVE SECURITY AUDIT REPORT       ║
╚══════════════════════════════════════════════════════════════════╝

  Generated    : {ts}
  Tool         : PassAudit v2.0 — Password Security Assessment Toolkit
  Mode         : Ethical Lab Assessment (Simulated Environment)
  Disclaimer   : For authorized security testing only.""")

        h('EXECUTIVE SUMMARY')
        lines.append(f"""
  Overall Risk Level : {risk}
  ──────────────────────────────────────────
  Hashes Extracted   : {len(hashes)}
  Passwords Cracked  : {len(cracked)}  ({crack_rate:.0f}% crack rate)
  Passwords Analyzed : {len(analysis)}
  Wordlist Size      : {len(wordlist):,} entries

  STRENGTH DISTRIBUTION:
  {'CRITICAL':<14} {dist['CRITICAL']:>3}  {self._bar(dist['CRITICAL']/total_analyzed*100, 20)}
  {'WEAK':<14} {dist['WEAK']:>3}  {self._bar(dist['WEAK']/total_analyzed*100, 20)}
  {'MODERATE':<14} {dist['MODERATE']:>3}  {self._bar(dist['MODERATE']/total_analyzed*100, 20)}
  {'STRONG':<14} {dist['STRONG']:>3}  {self._bar(dist['STRONG']/total_analyzed*100, 20)}
  {'VERY STRONG':<14} {dist['VERY STRONG']:>3}  {self._bar(dist['VERY STRONG']/total_analyzed*100, 20)}""")

        h('HASH EXTRACTION RESULTS')
        if hashes:
            lines.append(
                f"\n  {'USER':<14} {'ALGORITHM':<18} {'SECURITY':<12} {'HASH PREVIEW'}")
            lines.append(f"  {'─'*70}")
            for e in hashes:
                algo = e.get('algorithm', 'Unknown')
                sec = e.get('security',  'UNKNOWN')
                h_ = e.get('hash', '')[:40]
                lines.append(
                    f"  {e.get('user', '?'):<14} {algo:<18} {sec:<12} {h_}")
        else:
            lines.append('\n  No hash extraction data in this session.')

        h('CRACKED PASSWORDS')
        if cracked:
            lines.append(
                f"\n  {'#':<4} {'USER':<14} {'PLAINTEXT':<20} {'HASH'}")
            lines.append(f"  {'─'*70}")
            for i, c in enumerate(cracked, 1):
                lines.append(
                    f"  {i:<4} {c.get('user', '?'):<14} {c.get('plaintext', '?'):<20} {c.get('hash', '')[:32]}")
        else:
            lines.append('\n  No passwords cracked in this session.')

        h('PASSWORD STRENGTH ANALYSIS')
        if analysis:
            lines.append(
                f"\n  {'#':<4} {'SCORE':<7} {'ENTROPY':<10} {'RATING':<14} {'COMMON':<8} {'ISSUES'}")
            lines.append(f"  {'─'*70}")
            for i, a in enumerate(analysis, 1):
                score = a.get('score', 0)
                entropy = a.get('entropy', 0.0)
                rating = a.get('rating',  self._severity(score))
                common = 'YES' if a.get('common') else 'No'
                issues = []
                if a.get('common'):
                    issues.append('common')
                if a.get('kb_walk'):
                    issues.append('kb-walk')
                if a.get('repeated'):
                    issues.append('repeat')
                if a.get('sequential'):
                    issues.append('seq')
                lines.append(
                    f"  {i:<4} {score:<7} {entropy:<10.1f} {rating:<14} {common:<8} {', '.join(issues) or '—'}")
        else:
            lines.append('\n  No strength analysis data in this session.')

        h('POLICY RECOMMENDATIONS')
        for category, recs in RECOMMENDATIONS:
            lines.append(f"\n  {category}:")
            for r in recs:
                lines.append(f"    ✓ {r}")

        lines.append(f"""
  {'═'*65}
  COMPLIANCE NOTES:
    NIST SP 800-63B : Min 8 chars; block compromised passwords
    OWASP           : bcrypt/scrypt/Argon2; enforce MFA
    PCI-DSS 4.0     : Min 12 chars; complexity; 90-day rotation
    ISO 27001       : Annual credential security audits required
    GDPR            : Treat credentials as personal data; report breaches

  {'═'*65}
                       END OF REPORT
  {'═'*65}""")

        return '\n'.join(lines)

    # ── JSON output ────────────────────────────────────────────────────────────
    def _build_json(self, session: dict, ts: str) -> dict:
        return {
            'meta': {
                'tool': 'PassAudit v2.0',
                'generated': ts,
                'ethical_mode': True,
            },
            'summary': {
                'hashes_extracted': len(session.get('hashes',   [])),
                'passwords_cracked': len(session.get('cracked',  [])),
                'passwords_analyzed': len(session.get('analysis', [])),
                'wordlist_size': len(session.get('wordlist', [])),
            },
            'hashes': session.get('hashes',   []),
            'cracked': session.get('cracked',  []),
            'analysis': session.get('analysis', []),
            'recommendations': {cat: recs for cat, recs in RECOMMENDATIONS},
        }

    # ── Public API ─────────────────────────────────────────────────────────────
    def generate(self, session: dict) -> dict:
        """
        Generate audit report from session data.

        Args:
            session: dict containing 'hashes', 'cracked', 'analysis', 'wordlist'

        Returns:
            dict with file paths of generated reports
        """
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        txt_path = os.path.join(self.output_dir, f'audit_report_{stamp}.txt')
        json_path = os.path.join(self.output_dir, f'results_{stamp}.json')
        paths = {}

        report_text = self._build_text(session, ts)

        # ── Plain text ─────────────────────────────────────────────────────────
        if self.report_fmt in ('text', 'both'):
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(report_text)
            print(f"\n  [+] Text report saved : {txt_path}")
            paths['txt'] = txt_path

        # ── JSON ───────────────────────────────────────────────────────────────
        if self.report_fmt in ('json', 'both'):
            report_json = self._build_json(session, ts)
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_json, f, indent=2, default=str)
            print(f"  [+] JSON report saved : {json_path}")
            paths['json'] = json_path

        return paths
