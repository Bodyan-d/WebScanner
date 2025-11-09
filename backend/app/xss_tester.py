import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .fetcher import Fetcher
import logging
logger = logging.getLogger(__name__)
MARKER = "__WS__{id}__"
class XSSTester:
    def __init__(self, fetcher: Fetcher):
        self.fetcher = fetcher
    def _marker(self):
        return MARKER.format(id=uuid.uuid4().hex[:8])
    async def test_reflected(self, url, param):
        marker = self._marker()
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [marker]
        new_q = urlencode({k:v[0] for k,v in qs.items()})
        target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
        try:
            resp = await self.fetcher.get(target)
            text = await resp.text(errors='ignore')
            return {'url':target,'param':param,'marker':marker,'reflected': marker in text, 'status':resp.status}
        except Exception as e:
            logger.debug("xss test err %s", e)
            return {'url':url,'param':param,'reflected':False,'error':str(e)}
    async def scan_urls(self, urls):
        results=[]
        for u in urls:
            parsed = urlparse(u)
            if parsed.query:
                from urllib.parse import parse_qs
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for p in qs.keys():
                    results.append(await self.test_reflected(u,p))
        return results
