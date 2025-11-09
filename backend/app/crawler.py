import asyncio
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .fetcher import Fetcher
import logging
logger = logging.getLogger(__name__)

class Crawler:
    def __init__(self, base_url, concurrency=3, max_pages=50):
        self.base = base_url.rstrip('/')
        self.parsed = urlparse(self.base)
        self.fetcher = Fetcher(concurrency=concurrency)
        self.max_pages = max_pages
        self.seen = set()
        self.found_forms = []
    def _same_domain(self, url):
        try:
            p = urlparse(url)
            return p.netloc == self.parsed.netloc or p.netloc == ''
        except:
            return False
        
    def _normalize(self, url):
        if url.startswith('//'):
            return f'{self.parsed.scheme}:{url}'
        if url.startswith('/'):
            return urljoin(self.base, url)
        if not urlparse(url).scheme:
            return urljoin(self.base+'/', url)
        return url
    
    async def _parse(self, html, current):
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            links.add(self._normalize(a['href']))
        for form in soup.find_all("form"):
            action = form.get('action') or current
            method = str(form.get("method") or "get").lower()
            inputs = {}
            for i in form.find_all(['input','textarea','select']):
                name = i.get('name')
                if not name: continue
                inputs[name] = i.get('value') or ''
            self.found_forms.append((self._normalize(action), {'method':method,'inputs':inputs}))
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
                    text = await resp.text(errors='ignore')
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
        for _ in range(min(5, self.max_pages)):
            workers.append(asyncio.create_task(worker()))
        await q.join()
        for w in workers:
            w.cancel()
        await self.fetcher.close()
        return {'urls': list(self.seen), 'forms': self.found_forms}
