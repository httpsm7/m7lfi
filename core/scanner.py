"""
m7lfi - Core Scanner
Milkyway Intelligence | Author: Sharlix
Orchestrates the full Send → Analyze → Adapt → Re-send loop.
"""

import asyncio
from typing import List
from urllib.parse import urlparse, parse_qs, urlunparse, quote

from core.request_engine   import RequestEngine
from core.response_analyzer import ResponseAnalyzer
from core.payload_engine   import PayloadEngine
from core.bypass_engine    import BypassEngine
from core.exploit_engine   import ExploitEngine
from core.rate_controller  import RateController


class ScanResult:
    """Holds all findings for a single URL+parameter combination."""
    def __init__(self, url: str, param: str):
        self.url            = url
        self.param          = param
        self.vulnerable     = False
        self.payload        = ""
        self.bypass_used    = ""
        self.snippet        = ""
        self.status_code    = 0
        self.exploit_chains = []
        self.all_findings   = []   # list of intermediate finds
        self.curl_cmd       = ""


class Scanner:
    """
    Main scanner. Iterates URLs → parameters → payloads.
    Implements adaptive: blocked → mutate → retry loop.
    """

    def __init__(self, config: dict):
        self.config = config

        # Sub-engines
        self.rate_ctrl  = RateController(
            mode    = config.get("mode", "smart"),
            threads = config.get("threads", 50),
        )
        # Apply rate-controller settings back to config for RequestEngine
        config["delay"]  = self.rate_ctrl.delay
        config["jitter"] = self.rate_ctrl.jitter

        self.req_engine   = RequestEngine(config)
        self.payload_eng  = PayloadEngine(config.get("payloads_dir", "payloads"))
        self.bypass_eng   = BypassEngine()
        self.exploit_eng  = ExploitEngine(self.req_engine)

        self.results: List[ScanResult] = []
        self._semaphore = self.rate_ctrl.get_semaphore()
        self.verbose    = config.get("verbose", False)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def scan_url(self, url: str) -> List[ScanResult]:
        """Scan a single URL. Returns list of ScanResult objects."""
        params = self._extract_params(url)
        if not params:
            self._log(f"[!] No parameters found in: {url}")
            return []

        categories = self.config.get("categories", "all")
        if categories == "all":
            payloads = self.payload_eng.load_all()
        else:
            payloads = self.payload_eng.load_categories(categories.split(","))

        if not payloads:
            self._log("[!] No payloads loaded. Check payloads/ directory.")
            return []

        self._log(f"[*] Scanning {url} | {len(params)} param(s) | {len(payloads)} payloads")

        tasks = [
            self._scan_param(url, param, payloads)
            for param in params
        ]
        param_results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [r for r in param_results if isinstance(r, ScanResult)]
        self.results.extend(valid)
        return valid

    async def scan_list(self, url_list: List[str]) -> List[ScanResult]:
        """Scan multiple URLs concurrently."""
        all_results = []
        for url in url_list:
            results = await self.scan_url(url.strip())
            all_results.extend(results)
        return all_results

    # ── Parameter scanning ─────────────────────────────────────────────────────

    async def _scan_param(
        self,
        url: str,
        param: str,
        payloads: List[str],
    ) -> ScanResult:
        """
        For a single parameter:
        1. Get baseline response
        2. Try each payload
        3. On block: mutate & retry
        4. On success: run exploit chains
        """
        result = ScanResult(url, param)

        # ── Baseline request ──────────────────────────────────────────────
        # FIX BUG-09: Use the ORIGINAL URL (with its existing param values) as
        # baseline, not the bare URL without params. A bare GET returns a
        # different-length page (e.g. 404 or redirect), making length-diff
        # analysis unreliable. Using the original URL gives a clean reference.
        baseline_resp = await self.req_engine.get(url)
        baseline_len  = len(baseline_resp.content) if baseline_resp else 0
        analyzer      = ResponseAnalyzer(baseline_length=baseline_len)

        self._log(f"  [>] Testing param: {param} | baseline: {baseline_len}b")

        # ── Payload loop ──────────────────────────────────────────────────
        for payload in payloads:
            async with self._semaphore:
                self.rate_ctrl.increment()

                found, scan_result = await self._try_payload(
                    url, param, payload, analyzer
                )

                if found:
                    result = scan_result

                    # ── Run exploit chains ─────────────────────────────
                    if self.config.get("exploit", False):
                        self._log("  [!] Running exploit chains on confirmed LFI...")
                        chains = await self.exploit_eng.run_all(
                            url, param, payload
                        )
                        result.exploit_chains = chains

                    return result  # Stop on first confirmed vulnerability

        return result

    async def _try_payload(
        self,
        url: str,
        param: str,
        payload: str,
        analyzer: ResponseAnalyzer,
        bypass_label: str = "direct",
    ) -> tuple:
        """
        Send a single payload and analyze response.
        If blocked, attempt bypasses.
        Returns (success: bool, ScanResult).
        """
        result = ScanResult(url, param)

        # FIX BUG-08: _inject_param now returns a single URL string (no tuple).
        # Raw payloads (already containing % like ..%2f) are injected without
        # re-encoding so they reach the server exactly as intended.
        injected_url = self._inject_param(url, param, payload)

        # Use stealth headers if WAF mode
        extra_hdrs = {}
        if self.rate_ctrl.mode == "stealth":
            extra_hdrs = self.bypass_eng.random_headers()

        resp     = await self.req_engine.get(injected_url, headers=extra_hdrs)
        analysis = analyzer.analyze(resp)

        if self.verbose:
            status = "VULN" if analysis.is_vulnerable else ("WAF" if analysis.waf_detected else "miss")
            self._log(f"    [{status}] {payload[:60]}")

        # ── WAF detected → adjust rate and try bypass ─────────────────
        if analysis.waf_detected:
            self.rate_ctrl.waf_detected()
            bypass_payloads = self.bypass_eng.apply_bypass(
                payload,
                waf_detected=True,
                blocked_patterns=analysis.blocked_patterns,
            )
            for bp in bypass_payloads[:5]:
                b_url      = self._inject_param(url, param, bp)   # FIX BUG-15: no tuple
                b_resp     = await self.req_engine.get(b_url, headers=self.bypass_eng.random_headers())
                b_analysis = analyzer.analyze(b_resp)
                if b_analysis.is_vulnerable:
                    result.vulnerable  = True
                    result.payload     = bp
                    result.bypass_used = "WAF_BYPASS"
                    result.snippet     = b_analysis.snippet
                    result.status_code = b_analysis.status_code
                    result.curl_cmd    = self._build_curl(b_url)
                    return True, result

        # ── Direct success ─────────────────────────────────────────────
        if analysis.is_vulnerable:
            self.rate_ctrl.success()
            result.vulnerable  = True
            result.payload     = payload
            result.bypass_used = bypass_label
            result.snippet     = analysis.snippet
            result.status_code = analysis.status_code
            result.curl_cmd    = self._build_curl(injected_url)
            return True, result

        return False, result

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL query string."""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """
        Inject payload into a specific parameter, return new URL string.

        FIX BUG-08: urlencode() re-encodes % signs, turning ..%2f into ..%252f.
        Solution: build the query string manually using quote(safe='') only on
        the OTHER params (preserve their values), and append the payload raw so
        already-encoded payloads are not double-encoded.

        FIX BUG-15: removed unused second return value (params dict).
        """
        parsed      = urlparse(url)
        orig_params = parse_qs(parsed.query, keep_blank_values=True)

        # Rebuild query: encode other params normally, inject payload raw
        parts = []
        seen_param = False
        for k, vals in orig_params.items():
            if k == param:
                seen_param = True
                # Use quote only on the key, keep value raw to avoid double-encode
                parts.append(f"{quote(k, safe='')}={value}")
            else:
                for v in vals:
                    parts.append(f"{quote(k, safe='')}={quote(v, safe='')}")

        if not seen_param:
            # Param not in original URL — append it
            parts.append(f"{quote(param, safe='')}={value}")

        new_query = "&".join(parts)
        return urlunparse(parsed._replace(query=new_query))

    def _build_curl(self, url: str) -> str:
        """Build a curl reproduction command."""
        return f'curl -sk "{url}"'

    def _log(self, msg: str):
        """Simple console logger."""
        print(msg)
