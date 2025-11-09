import asyncio
from aiohttp_retry import RetryClient, ExponentialRetry
import aiohttp
from .config import MAX_CONCURRENCY
class Fetcher:
    def __init__(self, concurrency:int=MAX_CONCURRENCY, timeout:int=10):
        self.sem = asyncio.Semaphore(concurrency)
        retry = ExponentialRetry(attempts=2)
        timeout_cfg = aiohttp.ClientTimeout(total=timeout)
        self._client = RetryClient(retry_options=retry, timeout=timeout_cfg, raise_for_status=False)
    async def get(self, url, **kwargs):
        headers = kwargs.pop('headers', {})
        headers.setdefault("User-Agent", "webscanner/1.0")
        async with self.sem:
            resp = await self._client.get(url, headers=headers, **kwargs)
            return resp
    async def close(self):
        await self._client.close()
