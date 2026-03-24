# backend/app/fetcher.py
import asyncio
import logging
import time
from typing import Dict, Optional

import aiohttp
from aiohttp_retry import ExponentialRetry, RetryClient

from .config import MAX_CONCURRENCY

logger = logging.getLogger(__name__)


class Fetcher:
    def __init__(
        self,
        concurrency: int = MAX_CONCURRENCY,
        timeout: int = 10,
        attempts: int = 2,
        user_agent: Optional[str] = None,
        raise_for_status: bool = False,
        polite_delay: float = 0.2,
        auth_token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
    ):
        self.concurrency = max(1, concurrency)
        self.sem = asyncio.Semaphore(self.concurrency)
        retry = ExponentialRetry(attempts=attempts)
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(
            limit=max(8, self.concurrency * 4),
            limit_per_host=max(4, self.concurrency * 2),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        session = aiohttp.ClientSession(connector=connector, timeout=timeout_cfg, raise_for_status=raise_for_status)
        self._client = RetryClient(client_session=session, retry_options=retry)
        self._user_agent = user_agent or "webscanner/1.0"
        self._last_request_time = 0.0
        self._delay = polite_delay
        self._auth_token = auth_token
        self._cookies = cookies or {}

    async def _apply_rate_limit(self):
        if self._delay <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._delay:
            await asyncio.sleep(self._delay - elapsed)
        self._last_request_time = time.monotonic()

    async def _request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        headers: Dict[str, str] = kwargs.pop("headers", {}) or {}
        headers.setdefault("User-Agent", self._user_agent)
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        if "cookies" in kwargs:
            all_cookies = {**self._cookies, **kwargs.pop("cookies")}
        else:
            all_cookies = self._cookies

        async with self.sem:
            await self._apply_rate_limit()
            if method.lower() == "get":
                response = await self._client.get(url, headers=headers, cookies=all_cookies, **kwargs)
            elif method.lower() == "post":
                response = await self._client.post(url, headers=headers, cookies=all_cookies, **kwargs)
            else:
                response = await self._client.request(method, url, headers=headers, cookies=all_cookies, **kwargs)
            return response

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await self._request("get", url, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await self._request("post", url, **kwargs)

    async def close(self):
        try:
            await self._client.close()
        except Exception as e:
            logger.debug("fetcher close error: %s", e)
