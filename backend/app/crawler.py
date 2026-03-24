import asyncio
from contextlib import suppress
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .fetcher import Fetcher
import logging

logger = logging.getLogger(__name__)


class Crawler:
    def __init__(self, base_url, concurrency=3, max_pages=50):
        self.base = base_url.rstrip("/")
        self.parsed = urlparse(self.base)
        self.concurrency = max(1, concurrency)
        self.fetcher = Fetcher(concurrency=concurrency)
        self.max_pages = max_pages
        self.seen = set()
        self.found_forms = []

    def _same_domain(self, url):
        try:
            p = urlparse(url)
            return p.netloc == self.parsed.netloc or p.netloc == ""
        except Exception:
            return False

    def _normalize(self, url):
        if not url:
            return ""
        url = url.strip()
        if url.startswith(("#", "javascript:", "mailto:", "tel:")):
            return ""
        if url.startswith("//"):
            normalized = f"{self.parsed.scheme}:{url}"
        elif url.startswith("/"):
            normalized = urljoin(self.base, url)
        elif not urlparse(url).scheme:
            normalized = urljoin(f"{self.base}/", url)
        else:
            normalized = url

        parsed = urlparse(normalized)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return ""
        return normalized.split("#", 1)[0]

    async def _parse(self, html, current):
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            normalized = self._normalize(a["href"])
            if normalized:
                links.add(normalized)
        for form in soup.find_all("form"):
            action = form.get("action") or current
            normalized_action = self._normalize(action) or current
            method = str(form.get("method") or "get").lower()
            enctype = str(form.get("enctype") or "application/x-www-form-urlencoded").lower()
            inputs = {}
            for i in form.find_all(["input", "textarea", "select"]):
                name = i.get("name")
                if not name:
                    continue
                inputs[name] = i.get("value") or ""
            self.found_forms.append(
                (
                    normalized_action,
                    {"method": method, "inputs": inputs, "enctype": enctype},
                )
            )
        return links

    async def crawl(self):
        q = asyncio.Queue()
        await q.put(self.base)
        workers = []

        async def worker():
            while True:
                try:
                    url = await asyncio.wait_for(q.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    return
                if len(self.seen) >= self.max_pages:
                    q.task_done()
                    continue
                if url in self.seen:
                    q.task_done()
                    continue
                try:
                    resp = await self.fetcher.get(url)
                    text = await resp.text(errors="ignore")
                except Exception as e:
                    logger.debug("fetch error %s %s", url, e)
                    self.seen.add(url)
                    q.task_done()
                    continue
                self.seen.add(url)
                links = await self._parse(text, url)
                for l in links:
                    if self._same_domain(l) and l not in self.seen:
                        await q.put(l)
                q.task_done()

        for _ in range(max(1, min(self.concurrency, self.max_pages))):
            workers.append(asyncio.create_task(worker()))

        await q.join()

        for w in workers:
            w.cancel()
            with suppress(asyncio.CancelledError):
                await w

        await self.fetcher.close()
        return {"urls": list(self.seen), "forms": self.found_forms}
