#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║        PassAudit — Password Security Toolkit v2.0       ║
║              CLI Entry Point: main.py                   ║
║         ETHICAL USE ONLY — Lab Environments             ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import json
import os

from modules.dictionary_generator import DictionaryGenerator
from modules.hash_extractor import HashExtractor
from modules.bruteforce_simulator import BruteForceSimulator
from modules.strength_analyzer import StrengthAnalyzer
from modules.entropy_calculator import EntropyCalculator
from modules.hash_identifier import HashIdentifier
from modules.policy_checker import PolicyChecker
from modules.report_generator import ReportGenerator

# ─── Colours ───────────────────────────────────────────────────────────────────


class C:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


BANNER = f"""
{C.CYAN}{C.BOLD}
 ██████╗  █████╗ ███████╗███████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██████╔╝███████║███████╗███████╗███████║██║   ██║██║  ██║██║   ██║
 ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══██║██║   ██║██║  ██║██║   ██║
 ██║     ██║  ██║███████║███████║██║  ██║╚██████╔╝██████╔╝██║   ██║
 ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
{C.RESET}{C.YELLOW}  Password Security Assessment Toolkit v2.0  |  ETHICAL USE ONLY
{C.DIM}  Run only in controlled lab environments. Do not test real systems.{C.RESET}
"""

# ─── Load config ───────────────────────────────────────────────────────────────


def load_config(path='config.json'):
    if not os.path.exists(path):
        default = {
            "output_dir":         "output",
            "shadow_file":        "data/sample_shadow.txt",
            "common_passwords":   "data/common_passwords.txt",
            "max_wordlist_size":  50000,
            "max_attempts":       100000,
            "default_hash":       "md5",
            "report_format":      "both",
            "ethical_mode":       True,
            "log_level":          "INFO"
        }
        with open(path, 'w') as f:
            json.dump(default, f, indent=2)
        print(
            f"  {C.YELLOW}[!] config.json not found — created with defaults.{C.RESET}")
    with open(path) as f:
        return json.load(f)

# ─── Interactive menu ───────────────────────────────────────────────────────────


def print_menu():
    print(f"""
{C.CYAN}╔══════════════════════════════════════════════════╗
║              SELECT MODULE                      ║
╠══════════════════════════════════════════════════╣
║  {C.GREEN}[1]{C.CYAN}  Dictionary Generator                      ║
║  {C.GREEN}[2]{C.CYAN}  Hash Extractor & Analyzer                 ║
║  {C.GREEN}[3]{C.CYAN}  Brute-Force Simulator                     ║
║  {C.GREEN}[4]{C.CYAN}  Password Strength Analyzer                ║
║  {C.GREEN}[5]{C.CYAN}  Entropy Calculator                        ║
║  {C.GREEN}[6]{C.CYAN}  Hash Identifier                           ║
║  {C.GREEN}[7]{C.CYAN}  Policy Checker                            ║
║  {C.GREEN}[8]{C.CYAN}  Run Full Audit Pipeline                   ║
║  {C.GREEN}[9]{C.CYAN}  Generate Audit Report                     ║
║  {C.RED}[0]{C.CYAN}  Exit                                      ║
╚══════════════════════════════════════════════════╝{C.RESET}""")


def run_interactive(config):
    session = {}
    while True:
        print_menu()
        choice = input(f"\n{C.YELLOW}passaudit> {C.RESET}").strip()
        if choice == '1':
            gen = DictionaryGenerator(config)
            kw = input("  Enter keywords (comma-separated): ").split(',')
            kw = [k.strip() for k in kw if k.strip()]
            name = input("  Target name (optional): ").strip()
            dob = input("  Date of birth / year (optional): ").strip()
            if name:
                kw.extend(name.split())
            if dob:
                kw.append(dob)
            wordlist = gen.generate(kw)
            session['wordlist'] = wordlist

        elif choice == '2':
            ext = HashExtractor(config)
            src = input("  Source [demo / path to shadow file]: ").strip()
            if src.lower() == 'demo' or src == '':
                hashes = ext.run_demo()
            else:
                hashes = ext.parse_file(src)
            session['hashes'] = hashes

        elif choice == '3':
            bf = BruteForceSimulator(config)
            target = input("  Enter target hash (or 'demo'): ").strip()
            mode = input(
                "  Mode [dictionary / incremental / estimate]: ").strip() or 'dictionary'
            wordlist = session.get('wordlist', [])
            bf.simulate(target, mode, wordlist)

        elif choice == '4':
            analyzer = StrengthAnalyzer(config)
            pwds = []
            print("  Enter passwords to analyze (blank line to finish):")
            while True:
                pwd = input("  > ")
                if not pwd:
                    break
                result = analyzer.analyze(pwd)
                pwds.append(result)
            session['analysis'] = pwds

        elif choice == '5':
            ec = EntropyCalculator()
            pwd = input("  Enter string to calculate entropy: ").strip()
            ec.calculate(pwd)

        elif choice == '6':
            hi = HashIdentifier()
            h = input("  Paste hash string: ").strip()
            hi.identify(h)

        elif choice == '7':
            pc = PolicyChecker(config)
            pwd = input("  Enter password to check against policy: ").strip()
            pc.check(pwd)

        elif choice == '8':
            run_full_pipeline(config, session)

        elif choice == '9':
            reporter = ReportGenerator(config)
            reporter.generate(session)

        elif choice == '0':
            print(f"\n{C.CYAN}  Exiting PassAudit. Stay ethical.{C.RESET}\n")
            sys.exit(0)
        else:
            print(f"  {C.RED}Invalid choice.{C.RESET}")

# ─── Full pipeline ──────────────────────────────────────────────────────────────


def run_full_pipeline(config, session=None):
    if session is None:
        session = {}
    print(f"\n{C.BOLD}{C.CYAN}[*] Running Full Audit Pipeline...{C.RESET}\n")

    gen = DictionaryGenerator(config)
    ext = HashExtractor(config)
    bf = BruteForceSimulator(config)
    analyzer = StrengthAnalyzer(config)
    reporter = ReportGenerator(config)

    print(f"{C.CYAN}[STEP 1/5]{C.RESET} Generating dictionary...")
    wordlist = gen.generate(['admin', 'password', 'user', 'root', 'test'])
    session['wordlist'] = wordlist

    print(f"\n{C.CYAN}[STEP 2/5]{C.RESET} Extracting hashes (demo)...")
    hashes = ext.run_demo()
    session['hashes'] = hashes

    print(f"\n{C.CYAN}[STEP 3/5]{C.RESET} Simulating brute-force attack...")
    cracked = bf.simulate_bulk(hashes, wordlist)
    session['cracked'] = cracked

    print(f"\n{C.CYAN}[STEP 4/5]{C.RESET} Analyzing password strength...")
    analysis = []
    for entry in hashes:
        # Analyze username as a proxy password for demo
        result = analyzer.analyze(entry.get('user', 'unknown'))
        analysis.append(result)
    session['analysis'] = analysis

    print(f"\n{C.CYAN}[STEP 5/5]{C.RESET} Generating audit report...")
    reporter.generate(session)
    print(f"\n{C.GREEN}[✓] Pipeline complete.{C.RESET}")


# ─── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(BANNER)
    config = load_config()

    parser = argparse.ArgumentParser(
        description='PassAudit — Password Security Toolkit')
    parser.add_argument('--mode',     choices=['interactive', 'pipeline'], default='interactive',
                        help='Run mode (default: interactive)')
    parser.add_argument('--config',   default='config.json',
                        help='Path to config file')
    parser.add_argument('--keywords', default='',
                        help='Comma-separated keywords for pipeline mode')
    args = parser.parse_args()

    if args.mode == 'pipeline':
        session = {}
        if args.keywords:
            kws = [k.strip() for k in args.keywords.split(',')]
            gen = DictionaryGenerator(config)
            session['wordlist'] = gen.generate(kws)
        run_full_pipeline(config, session)
    else:
        run_interactive(config)
