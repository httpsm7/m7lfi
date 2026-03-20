"""
m7lfi - Response Analyzer
Milkyway Intelligence | Author: Sharlix
Analyzes HTTP responses to detect LFI success, WAF blocks, and soft-blocks.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
import httpx


# ─── Sensitive file content signatures ────────────────────────────────────────
LFI_SUCCESS_PATTERNS = [
    r"root:x:\d+:\d+:",          # /etc/passwd Unix
    r"daemon:x:\d+:\d+:",
    r"\[boot loader\]",          # boot.ini Windows
    r"\[operating systems\]",
    r"\\windows\\system32",
    r"<?php",                    # PHP source disclosure
    r"DOCUMENT_ROOT",            # environ leak
    r"HTTP_USER_AGENT",
    r"PATH=/usr",
    r"\[global\]",               # smb.conf
    r"mysql.*datadir",           # my.cnf
    r"<\?xml version",           # XXE / config leak
]

# ─── WAF / block signatures ───────────────────────────────────────────────────
WAF_PATTERNS = [
    r"Access Denied",
    r"Forbidden",
    r"Request blocked",
    r"This incident will be reported",   # Cloudflare
    r"cf-ray",                           # Cloudflare header
    r"mod_security",
    r"ModSecurity",
    r"Not Acceptable",
    r"Sucuri WebSite Firewall",
    r"Web Application Firewall",
    r"NAXSI_FMT",                        # Nginx WAF
    r"<title>Security Alert</title>",
]

# ─── Soft-block patterns (filter detected, no WAF page) ──────────────────────
SOFT_BLOCK_PATTERNS = [
    r"Invalid file",
    r"File not found",
    r"No such file",
    r"Permission denied",
    r"Illegal path",
    r"Security violation",
    r"hack",
    r"attack",
]


@dataclass
class AnalysisResult:
    is_vulnerable:      bool         = False
    waf_detected:       bool         = False
    soft_blocked:       bool         = False
    status_code:        int          = 0
    response_length:    int          = 0
    baseline_length:    int          = 0
    matched_patterns:   List[str]    = field(default_factory=list)
    blocked_patterns:   List[str]    = field(default_factory=list)
    waf_signatures:     List[str]    = field(default_factory=list)
    snippet:            str          = ""


class ResponseAnalyzer:
    """
    Analyzes HTTP responses for LFI indicators, WAF blocks, and soft-blocks.
    Returns a structured AnalysisResult.
    """

    def __init__(self, baseline_length: int = 0):
        # Baseline length of the normal (un-injected) response
        self.baseline_length = baseline_length

    def analyze(self, response: Optional[httpx.Response]) -> AnalysisResult:
        """Main entry point. Returns AnalysisResult."""
        result = AnalysisResult(baseline_length=self.baseline_length)

        if response is None:
            return result

        result.status_code     = response.status_code
        result.response_length = len(response.content)

        body = ""
        try:
            body = response.text
        except Exception:
            body = response.content.decode("utf-8", errors="replace")

        # ── 1. Check WAF signatures ────────────────────────────────────────
        for pattern in WAF_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result.waf_detected = True
                result.waf_signatures.append(pattern)

        # Also check response headers for WAF markers
        headers_str = str(dict(response.headers))
        for pattern in WAF_PATTERNS:
            if re.search(pattern, headers_str, re.IGNORECASE):
                result.waf_detected = True
                if pattern not in result.waf_signatures:
                    result.waf_signatures.append(pattern)

        # ── 2. Check soft-block patterns ──────────────────────────────────
        for pattern in SOFT_BLOCK_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result.soft_blocked = True
                result.blocked_patterns.append(pattern)

        # 403 / 406 = explicit block
        if response.status_code in (403, 406, 429):
            result.waf_detected = True

        # ── 3. Check for LFI success signatures ───────────────────────────
        for pattern in LFI_SUCCESS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                result.is_vulnerable = True
                result.matched_patterns.append(pattern)

        # ── 4. Response length anomaly — separate flag, NOT mixed into matched_patterns
        #    FIX BUG-10: previously this was appended to matched_patterns which caused
        #    is_vulnerable to be set True for ANY page with dynamic content (ads, tokens).
        #    Now it is a standalone informational flag only.
        if self.baseline_length > 0:
            diff         = abs(result.response_length - self.baseline_length)
            length_ratio = diff / max(self.baseline_length, 1)
            if length_ratio > 0.25 and result.response_length > self.baseline_length:
                # Only flag as anomaly — does NOT set is_vulnerable by itself
                result.blocked_patterns.append("RESPONSE_LENGTH_ANOMALY_INFO")

        # ── 5. Extract snippet for report ─────────────────────────────────
        result.snippet = self._extract_snippet(body, result.matched_patterns)

        return result

    def _extract_snippet(self, body: str, patterns: List[str]) -> str:
        """Extract a short snippet around the matched pattern."""
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 50)
                end   = min(len(body), m.end() + 200)
                return body[start:end].strip()
        # Fallback: first 300 chars
        return body[:300].strip()
