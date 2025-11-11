# backend/app/fetcher.py
import asyncio
from typing import Any, Optional, Dict
from aiohttp_retry import RetryClient, ExponentialRetry
import aiohttp
from .config import MAX_CONCURRENCY
import logging

logger = logging.getLogger(__name__)

class Fetcher:
    def __init__(
        self,
        concurrency: int = MAX_CONCURRENCY,
        timeout: int = 10,
        attempts: int = 2,
        user_agent: Optional[str] = None,
        raise_for_status: bool = False,
    ):
        self.sem = asyncio.Semaphore(concurrency)
        retry = ExponentialRetry(attempts=attempts)
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        self._client = RetryClient(retry_options=retry, timeout=timeout_cfg, raise_for_status=raise_for_status)
        self._user_agent = user_agent or "webscanner/1.0"

    async def _request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        headers: Dict[str, str] = kwargs.pop("headers", {}) or {}
        headers.setdefault("User-Agent", self._user_agent)
        async with self.sem:
            # note: RetryClient.get/post return a response object that should be used as async context manager if streaming,
            # but here we follow existing pattern returning response and letting caller call .text()/status
            if method.lower() == "get":
                resp = await self._client.get(url, headers=headers, **kwargs)
            elif method.lower() == "post":
                resp = await self._client.post(url, headers=headers, **kwargs)
            else:
                resp = await self._client.request(method, url, headers=headers, **kwargs)
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
