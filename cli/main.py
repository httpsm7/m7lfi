#!/usr/bin/env python3
"""
m7lfi - Advanced LFI Testing Framework
Milkyway Intelligence | Author: Sharlix
For authorized lab testing and bug bounty research only.

Usage:
    m7lfi -u https://target.com/page.php?id=1
    m7lfi -l urls.txt --threads 100 --mode smart
    m7lfi -u https://target.com/page.php?file=test --mode stealth --exploit
    m7lfi --manual
"""

import asyncio
import argparse
import os
import sys
import time
import yaml

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner       import Scanner
from core.report_engine import ReportEngine

# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = r"""
    __  __ _____ _     _____ ___ 
   |  \/  |___  | |   |  ___|_ _|
   | |\/| |  / /| |   | |_   | | 
   | |  | | / / | |___|  _|  | | 
   |_|  |_|/_/  |_____|_|   |___|

   ⚡ LFI Testing Framework v1.0
   🛸 Milkyway Intelligence | Sharlix
   ⚠  Authorized Testing Only
"""


def load_config(config_path: str = None) -> dict:
    """Load settings from YAML config file."""
    default_config = {
        "threads":         50,
        "timeout":         10,
        "retry":           2,
        "proxy":           None,
        "mode":            "smart",
        "delay":           0.3,
        "jitter":          0.2,
        "verify_ssl":      False,
        "categories":      "all",
        "exploit":         False,
        "verbose":         False,
        "payloads_dir":    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payloads"),
    }

    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            file_cfg = yaml.safe_load(f) or {}
        default_config.update(file_cfg)

    return default_config


def parse_args():
    parser = argparse.ArgumentParser(
        prog="m7lfi",
        description="m7lfi – Advanced LFI Testing Framework | Milkyway Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  m7lfi -u "https://target.com/page.php?file=test"
  m7lfi -l urls.txt --threads 100 --mode smart
  m7lfi -u "https://target.com/index.php?page=home" --mode stealth --exploit
  m7lfi -u "https://target.com/index.php?file=1" --categories linux,traversal
  m7lfi --manual
        """
    )

    # Target
    target = parser.add_mutually_exclusive_group()
    target.add_argument("-u", "--url",    help="Single target URL (must include vulnerable parameter)")
    target.add_argument("-l", "--list",   help="File containing list of URLs (one per line)")
    target.add_argument("--manual",       action="store_true", help="Enter manual testing mode")

    # Scan options
    parser.add_argument("--threads",      type=int,  default=None,   help="Number of concurrent threads (default: from config)")
    parser.add_argument("--mode",         default=None,               help="Scan mode: fast | smart | stealth (default: smart)")
    parser.add_argument("--timeout",      type=int,  default=None,   help="Request timeout in seconds")
    parser.add_argument("--proxy",        default=None,               help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--categories",   default=None,               help="Payload categories: all | linux,traversal,wrappers ...")
    parser.add_argument("--exploit",      action="store_true",        help="Run exploit chains after confirmed LFI")
    parser.add_argument("--verbose",      action="store_true",        help="Verbose output (show every request result)")

    # Config
    parser.add_argument("--config",       default=None,               help="Path to settings.yaml config file")
    parser.add_argument("--output",       default="output/reports",   help="Output directory for reports")

    return parser.parse_args()


async def run_scan(config: dict, urls: list) -> None:
    """Run the scanner on a list of URLs."""
    scanner = Scanner(config)
    report  = ReportEngine(output_dir=config.get("output", "output/reports"))

    print(f"\n[*] Targets     : {len(urls)}")
    print(f"[*] Mode        : {config.get('mode', 'smart').upper()}")
    print(f"[*] Threads     : {config.get('threads', 50)}")
    print(f"[*] Categories  : {config.get('categories', 'all')}")
    print(f"[*] Exploit     : {'YES' if config.get('exploit') else 'NO'}")
    print("-" * 50)

    start = time.time()
    results = await scanner.scan_list(urls)
    duration = round(time.time() - start, 2)

    # Summary
    vuln_count = sum(1 for r in results if r.vulnerable)
    print("\n" + "=" * 50)
    print(f"  SCAN COMPLETE in {duration}s")
    print(f"  URLs Scanned : {len(results)}")
    print(f"  Vulnerable   : {vuln_count}")
    print("=" * 50)

    if vuln_count > 0:
        print("\n[+] FINDINGS:")
        for r in results:
            if r.vulnerable:
                print(f"  ⚡ {r.url}")
                print(f"     Param   : {r.param}")
                print(f"     Payload : {r.payload}")
                print(f"     Bypass  : {r.bypass_used or 'None'}")
                print(f"     Snippet : {r.snippet[:150]}")
                print(f"     Curl    : {r.curl_cmd}")
                if r.exploit_chains:
                    print(f"     Exploits: {len(r.exploit_chains)} chain(s) successful")
                print()

    # Write reports
    paths = report.generate_all(results, scan_duration=duration)
    print("\n[*] Reports saved:")
    for fmt, path in paths.items():
        print(f"    {fmt.upper()}: {path}")


async def manual_mode(config: dict) -> None:
    """Interactive manual testing mode."""
    from core.request_engine   import RequestEngine
    from core.response_analyzer import ResponseAnalyzer
    from core.payload_engine   import PayloadEngine

    req_eng     = RequestEngine(config)
    payload_eng = PayloadEngine(config.get("payloads_dir", "payloads"))

    print("\n[*] MANUAL TESTING MODE")
    print("    Type 'quit' to exit\n")

    while True:
        url   = input("Target URL (with param): ").strip()
        if url.lower() == "quit":
            break
        param = input("Parameter to test: ").strip()
        if param.lower() == "quit":
            break

        print("\nOptions:")
        print("  1) Enter custom payload")
        print("  2) Test a category (linux/traversal/wrappers)")
        print("  3) Quick test (top 10 payloads)")
        choice = input("Choice [1/2/3]: ").strip()

        payloads_to_test = []

        if choice == "1":
            p = input("Payload: ").strip()
            payloads_to_test = [p]
        elif choice == "2":
            cat = input("Category: ").strip()
            payloads_to_test = payload_eng.load_category(cat)[:20]
        else:
            payloads_to_test = payload_eng.load_all()[:10]

        print(f"\n[*] Testing {len(payloads_to_test)} payload(s)...\n")
        analyzer = ResponseAnalyzer()

        for payload in payloads_to_test:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed  = urlparse(url)
            params  = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            new_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp     = await req_eng.get(new_url)
            analysis = analyzer.analyze(resp)

            status = "🟢 VULN" if analysis.is_vulnerable else ("🔴 BLOCKED" if analysis.waf_detected else "⚪ MISS")
            print(f"  {status} | {payload[:60]}")
            if analysis.is_vulnerable:
                print(f"  └── Snippet: {analysis.snippet[:200]}")
                print(f"  └── Curl: curl -sk \"{new_url}\"")
                print()


def main():
    print(BANNER)

    args   = parse_args()
    config = load_config(args.config)

    # CLI overrides config file
    if args.threads:   config["threads"]    = args.threads
    if args.mode:      config["mode"]       = args.mode
    if args.timeout:   config["timeout"]    = args.timeout
    if args.proxy:     config["proxy"]      = args.proxy
    if args.categories: config["categories"] = args.categories
    if args.exploit:   config["exploit"]    = True
    if args.verbose:   config["verbose"]    = True
    config["output"] = args.output

    # ── Manual mode ───────────────────────────────────────────────────────
    if args.manual:
        asyncio.run(manual_mode(config))
        return

    # ── URL list mode ─────────────────────────────────────────────────────
    if args.list:
        if not os.path.exists(args.list):
            print(f"[!] File not found: {args.list}")
            sys.exit(1)
        with open(args.list) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        asyncio.run(run_scan(config, urls))
        return

    # ── Single URL mode ───────────────────────────────────────────────────
    if args.url:
        asyncio.run(run_scan(config, [args.url]))
        return

    # No target provided
    print("[!] Please provide a target: -u URL or -l urls.txt or --manual")
    sys.exit(1)


if __name__ == "__main__":
    main()
