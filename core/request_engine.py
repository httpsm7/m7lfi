"""
m7lfi - Request Engine
Milkyway Intelligence | Author: Sharlix
Async HTTP engine with proxy rotation, retry logic, and rate control.
"""

import asyncio
import random
from typing import Optional
import httpx


# Default browser-like headers to avoid fingerprinting
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


class RequestEngine:
    """
    Async HTTP engine.
    Handles proxies, retries, timeouts, and per-request delay injection.
    """

    def __init__(self, config: dict):
        self.timeout     = config.get("timeout", 10)
        self.retries     = config.get("retry", 2)
        self.proxy       = config.get("proxy", None)        # e.g. "http://127.0.0.1:8080"
        self.delay       = config.get("delay", 0)           # seconds between requests
        self.jitter      = config.get("jitter", 0)          # ± random jitter
        self.verify_ssl  = config.get("verify_ssl", False)
        self.custom_hdrs = config.get("custom_headers", {})

        # FIX BUG-14: Shared AsyncClient with connection pooling — NOT recreated per request
        # NOTE: httpx >= 0.25 uses singular 'proxy' param (not 'proxies' dict)
        self._client = httpx.AsyncClient(
            proxy=self.proxy,           # None = no proxy; "http://..." = proxy URL
            verify=self.verify_ssl,
            timeout=self.timeout,
            http2=True,
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=200,
                max_keepalive_connections=50,
                keepalive_expiry=30,
            ),
        )

    async def close(self):
        """Cleanly close the shared HTTP client and release all connections."""
        await self._client.aclose()

    def _build_headers(self, extra: Optional[dict] = None) -> dict:
        """Merge default + custom + per-request headers."""
        h = {**DEFAULT_HEADERS, **self.custom_hdrs}
        if extra:
            h.update(extra)
        return h

    async def _sleep(self):
        """Inject delay + jitter before next request."""
        total = self.delay + random.uniform(0, self.jitter)
        if total > 0:
            await asyncio.sleep(total)

    async def get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """
        Perform async GET with retry logic.
        Returns httpx.Response or None on failure.
        """
        await self._sleep()
        hdrs = self._build_headers(headers)

        for attempt in range(1, self.retries + 2):
            try:
                resp = await self._client.get(
                    url, params=params, headers=hdrs, cookies=cookies
                )
                return resp

            except (httpx.TimeoutException, httpx.ConnectError):
                # FIX BUG-01: removed unused bare 'e' variable assignment
                if attempt > self.retries:
                    return None
                await asyncio.sleep(1.5 * attempt)

            except Exception:
                return None

        return None

    async def post(
        self,
        url: str,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """Perform async POST."""
        await self._sleep()
        hdrs = self._build_headers(headers)

        for attempt in range(1, self.retries + 2):
            try:
                resp = await self._client.post(url, data=data, headers=hdrs)
                return resp

            except (httpx.TimeoutException, httpx.ConnectError):
                if attempt > self.retries:
                    return None
                await asyncio.sleep(1.5 * attempt)

            except Exception:
                return None

        return None
