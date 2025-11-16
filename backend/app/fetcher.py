# backend/app/fetcher.py
import asyncio
from typing import Any, Optional, Dict
from aiohttp_retry import RetryClient, ExponentialRetry
import aiohttp
from .config import MAX_CONCURRENCY
import logging
import time

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
        self.sem = asyncio.Semaphore(concurrency)
        retry = ExponentialRetry(attempts=attempts)
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        self._client = RetryClient(
            retry_options=retry,
            timeout=timeout_cfg,
            raise_for_status=raise_for_status
        )
        self._user_agent = user_agent or "webscanner/1.0"
        self._last_request_time = 0.0
        self._delay = polite_delay
        self._auth_token = auth_token
        self._cookies = cookies or {}

    async def _apply_rate_limit(self):
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._delay:
            await asyncio.sleep(self._delay - elapsed)
        self._last_request_time = time.time()

    async def _request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        headers: Dict[str, str] = kwargs.pop("headers", {}) or {}
        headers.setdefault("User-Agent", self._user_agent)
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"

        # merge cookies
        if "cookies" in kwargs:
            all_cookies = {**self._cookies, **kwargs.pop("cookies")}
        else:
            all_cookies = self._cookies

        async with self.sem:
            await self._apply_rate_limit()
            if method.lower() == "get":
                resp = await self._client.get(url, headers=headers, cookies=all_cookies, **kwargs)
            elif method.lower() == "post":
                resp = await self._client.post(url, headers=headers, cookies=all_cookies, **kwargs)
            else:
                resp = await self._client.request(method, url, headers=headers, cookies=all_cookies, **kwargs)
            return resp

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await self._request("get", url, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await self._request("post", url, **kwargs)

    async def close(self):
        try:
            await self._client.close()
        except Exception as e:
            logger.debug("fetcher close error: %s", e)