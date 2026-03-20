"""
m7lfi - Rate Controller
Milkyway Intelligence | Author: Sharlix
Dynamically adjusts scan speed based on WAF detection and response patterns.
"""

import asyncio
import time
from typing import Optional


class RateController:
    """
    Controls request rate and concurrency based on target behavior.

    Modes:
        fast    — No WAF, high concurrency, minimal delay
        smart   — Start fast, slow down if WAF detected
        stealth — Low concurrency, randomized delays, human-like pacing
    """

    MODES = {
        "fast": {
            "threads":      200,
            "delay":        0.0,
            "jitter":       0.0,
            "retry_delay":  1.0,
        },
        "smart": {
            "threads":      50,
            "delay":        0.3,
            "jitter":       0.2,
            "retry_delay":  2.0,
        },
        "stealth": {
            "threads":      10,
            "delay":        1.5,
            "jitter":       1.0,
            "retry_delay":  5.0,
        },
    }

    def __init__(self, mode: str = "smart", threads: Optional[int] = None):
        self.mode = mode.lower()
        cfg = self.MODES.get(self.mode, self.MODES["smart"])

        self.threads     = threads or cfg["threads"]
        self.delay       = cfg["delay"]
        self.jitter      = cfg["jitter"]
        self.retry_delay = cfg["retry_delay"]

        self._waf_hits   = 0      # consecutive WAF detections
        self._total_reqs = 0
        self._start_time = time.time()

    def waf_detected(self):
        """Call this when WAF is detected. Tightens rate limits."""
        self._waf_hits += 1
        if self.mode != "stealth":
            # Progressively slow down
            self.delay   = min(self.delay + 0.5, 3.0)
            self.jitter  = min(self.jitter + 0.3, 2.0)
            self.threads = max(self.threads // 2, 5)
            if self._waf_hits >= 3:
                self._switch_to_stealth()

    def _switch_to_stealth(self):
        """Hard switch to stealth mode after repeated WAF hits."""
        cfg = self.MODES["stealth"]
        self.mode    = "stealth"
        self.delay   = cfg["delay"]
        self.jitter  = cfg["jitter"]
        self.threads = cfg["threads"]

    def success(self):
        """Call on successful (non-blocked) response. Can relax rate limits."""
        if self._waf_hits > 0:
            self._waf_hits -= 1

    def increment(self):
        """Track total request count."""
        self._total_reqs += 1

    def stats(self) -> dict:
        """Return current rate controller stats."""
        elapsed = max(time.time() - self._start_time, 1)
        return {
            "mode":       self.mode,
            "threads":    self.threads,
            "delay":      self.delay,
            "jitter":     self.jitter,
            "total_reqs": self._total_reqs,
            "req_per_sec": round(self._total_reqs / elapsed, 2),
            "waf_hits":   self._waf_hits,
        }

    def get_semaphore(self) -> asyncio.Semaphore:
        """
        Return an asyncio Semaphore for concurrency control.

        FIX BUG-13: asyncio.Semaphore must be created inside a running event
        loop (Python 3.10+ enforces this). Creating it in __init__ (sync context)
        attached it to the wrong loop. get_semaphore() is always called from an
        async context, so creation here is safe.
        """
        return asyncio.Semaphore(self.threads)
