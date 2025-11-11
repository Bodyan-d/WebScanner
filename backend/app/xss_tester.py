# backend/app/xss_tester.py
import asyncio
import uuid
import json
import re
from typing import List, Dict, Any, Optional, Union, AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
import logging

from .fetcher import Fetcher

logger = logging.getLogger(__name__)

MARKER_TMPL = "__WS__{id}__"


def _normalize_html(text: str) -> str:
    """Remove obviously-dynamic bits to avoid false positives."""
    if not text:
        return ""
    # remove script/style blocks
    text = re.sub(r"<script.*?>.*?</script>", "", text, flags=re.S | re.I)
    text = re.sub(r"<style.*?>.*?</style>", "", text, flags=re.S | re.I)
    # remove timestamps / long numbers / nonce-like tokens
    text = re.sub(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b", "", text)
    text = re.sub(r"\b[0-9]{6,}\b", "", text)
    text = re.sub(r'id="[^"]{8,}"', "", text)
    text = re.sub(r"nonce-[a-z0-9]+", "", text)
    # collapse whitespace
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


class XSSTester:
    """
    Robust XSS tester with streaming helpers.
    - fetcher: instance of your Fetcher (async wrapper around aiohttp).
    Methods:
      - test_reflected_get(url, param)
      - test_reflected_post(form)
      - scan_urls(urls) -> List
      - scan_forms(forms) -> List
      - scan_urls_stream(urls) -> async iterator yielding each result as soon as ready
      - scan_forms_stream(forms) -> async iterator yielding each result as soon as ready
    """

    def __init__(self, fetcher: Fetcher, default_retries: int = 2):
        self.fetcher = fetcher
        self.default_retries = default_retries

    def _marker(self) -> str:
        return MARKER_TMPL.format(id=uuid.uuid4().hex[:8])

    async def _fetch_text(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Wrapper around fetcher.get/post to provide text and status and safe exceptions.
        kwargs may include data, json, headers, timeout, params, etc.
        """
        try:
            if method.lower() == "get":
                resp = await self.fetcher.get(url, **kwargs)
            else:
                resp = await self.fetcher.post(url, **kwargs)
            text = await resp.text(errors="ignore")
            return {"ok": True, "status": getattr(resp, "status", None), "text": text}
        except Exception as e:
            logger.debug("xss fetch err %s %s %s", method, url, e)
            return {"ok": False, "error": str(e)}

    async def test_reflected_get(
        self, url: str, param: str, similarity_threshold: float = 0.98, retries: Optional[int] = None
    ) -> Dict[str, Any]:
        """Test single GET parameter for reflected XSS (marker injection)."""
        if retries is None:
            retries = self.default_retries

        marker = self._marker()
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        # ensure we keep other params
        qs[param] = [marker]
        new_q = urlencode({k: v[0] for k, v in qs.items()})
        target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

        base_try = await self._fetch_text("get", url)
        base_text = base_try.get("text", "") if base_try.get("ok") else ""

        # do retries, keep best (lowest similarity) as evidence
        best_sim = 1.0
        best_text = ""
        last_status = None
        for i in range(retries + 1):
            got = await self._fetch_text("get", target)
            if not got.get("ok"):
                return {
                    "url": target,
                    "param": param,
                    "marker": marker,
                    "reflected": False,
                    "status": got.get("status"),
                    "error": got.get("error"),
                }
            text = got.get("text", "")
            last_status = got.get("status")
            a = _normalize_html(base_text)
            b = _normalize_html(text)
            sim = _similarity(a, b)
            if sim < best_sim:
                best_sim = sim
                best_text = text
            # quick positive if marker literally present (definite)
            if marker in text:
                return {"url": target, "param": param, "marker": marker, "reflected": True, "status": last_status, "similarity": sim}
        # after retries: decide by similarity OR literal occurence
        reflected = (marker in best_text) or (best_sim < similarity_threshold)
        return {"url": target, "param": param, "marker": marker, "reflected": reflected, "status": last_status, "similarity": best_sim}

    async def test_reflected_post(
        self,
        form: Dict[str, Any],
        similarity_threshold: float = 0.98,
        retries: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        form: dict with keys:
          - url (required)
          - method (optional, default 'post')
          - inputs: dict of name->value (values ignored; replaced with 'testmarker')
          - enctype (optional) e.g. application/json or form-urlencoded
        """
        if retries is None:
            retries = self.default_retries

        try:
            url = form.get("url") or form.get("action") or ""
            method = str(form.get("method", "post")).lower()
            if not url:
                return {"error": "no url in form", "form": form}
            inputs = form.get("inputs") or {}
            if not isinstance(inputs, dict):
                try:
                    inputs = dict(inputs)
                except Exception:
                    inputs = {}

            marker = self._marker()
            # create payload
            enctype = str(form.get("enctype", "application/x-www-form-urlencoded")).lower()
            if "json" in enctype:
                payload = {k: marker for k in inputs.keys()}
                fetch_kwargs = {"json": payload}
            else:
                data = "&".join(f"{k}={marker}" for k in inputs.keys())
                fetch_kwargs = {"data": data}
            # baseline fetch (GET)
            base_try = await self._fetch_text("get", url)
            base_text = base_try.get("text", "") if base_try.get("ok") else ""
            # attempt POST
            best_sim = 1.0
            best_text = ""
            last_status = None
            for i in range(retries + 1):
                got = await self._fetch_text(method, url, **fetch_kwargs)
                if not got.get("ok"):
                    return {"url": url, "param": list(inputs.keys()), "marker": marker, "reflected": False, "status": got.get("status"), "error": got.get("error")}
                text = got.get("text", "")
                last_status = got.get("status")
                a = _normalize_html(base_text)
                b = _normalize_html(text)
                sim = _similarity(a, b)
                if sim < best_sim:
                    best_sim = sim
                    best_text = text
                if marker in text:
                    return {"url": url, "param": list(inputs.keys()), "marker": marker, "reflected": True, "status": last_status, "similarity": sim}
            reflected = (marker in best_text) or (best_sim < similarity_threshold)
            return {"url": url, "param": list(inputs.keys()), "marker": marker, "reflected": reflected, "status": last_status, "similarity": best_sim}
        except Exception as e:
            logger.exception("xss post test failed %s", e)
            return {"url": form.get("url"), "error": str(e)}

    # -----------------------
    # Streaming variants (yield results as they are ready)
    # -----------------------
    async def scan_urls_stream(self, urls: List[str], concurrency: int = 10) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator that yields each parameter test result as dict as soon as it's available.
        Useful to stream to frontend via SSE/websocket.
        """
        sem = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        tasks = []

        async def _worker(u: str):
            async with sem:
                parsed = urlparse(u)
                if not parsed.query:
                    return []
                qs = parse_qs(parsed.query, keep_blank_values=True)
                results = []
                for p in qs.keys():
                    try:
                        r = await self.test_reflected_get(u, p)
                        results.append(r)
                    except Exception:
                        logger.exception("xss scan_urls_stream: failed for %s param %s", u, p)
                return results

        for u in urls:
            tasks.append(loop.create_task(_worker(u)))

        # iterate tasks as they complete
        for fut in asyncio.as_completed(tasks):
            try:
                res = await fut
                if isinstance(res, list):
                    for r in res:
                        yield r
                elif isinstance(res, dict):
                    yield res
            except Exception as e:
                logger.debug("xss stream worker error: %s", e)

    async def scan_forms_stream(self, forms: List[Union[Dict[str, Any], List, tuple]], concurrency: int = 5) -> AsyncIterator[Dict[str, Any]]:
        """
        Async generator yields one result dict per test (POST/GET form parameter).
        Accepts list of dicts or (url, dict) tuples like crawler sometimes returns.
        """
        sem = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        tasks = []

        def _normalize(raw) -> Optional[Dict[str, Any]]:
            try:
                if isinstance(raw, dict):
                    return raw
                if isinstance(raw, (list, tuple)) and len(raw) >= 2 and isinstance(raw[1], dict):
                    nf = {"url": str(raw[0])}
                    nf.update(raw[1])
                    return nf
            except Exception:
                logger.exception("xss normalize form failed %r", raw)
            return None

        async def _worker(fr):
            async with sem:
                nf = _normalize(fr)
                if nf is None:
                    return []
                try:
                    method = str(nf.get("method", "post")).lower()
                    if method == "get":
                        parsed = urlparse(nf.get("url"))
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        out = []
                        for p in qs.keys():
                            url_val = nf.get("url")
                            if not isinstance(url_val, str):
                                continue
                            param_name = p.decode() if isinstance(p, bytes) else str(p)
                            out.append(await self.test_reflected_get(url_val, param_name))
                        return out
                    else:
                        return [await self.test_reflected_post(nf)]
                except Exception:
                    logger.exception("xss scan_forms worker failed %r", nf)
                    return []

        for f in forms:
            tasks.append(loop.create_task(_worker(f)))

        for fut in asyncio.as_completed(tasks):
            try:
                res = await fut
                if isinstance(res, list):
                    for r in res:
                        yield r
                elif isinstance(res, dict):
                    yield res
            except Exception as e:
                logger.debug("xss stream worker error: %s", e)
                
    async def scan_urls(self, urls: List[str], concurrency: int = 10) -> List[Dict[str, Any]]:
        results = []
        async for item in self.scan_urls_stream(urls, concurrency=concurrency):
            results.append(item)
        return results
