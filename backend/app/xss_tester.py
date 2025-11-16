# backend/app/xss_tester.py
import asyncio
import uuid
import re
import logging
from typing import List, Dict, Any, Optional, Union, AsyncIterator
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from collections import defaultdict

logger = logging.getLogger(__name__)
MARKER_TMPL = "__WS__{id}__"

DEFAULT_XSS_PAYLOADS = [
    MARKER_TMPL.format(id="{MARK}"),                 # placeholder for marker literal check
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "';alert(1);//",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
]

def _normalize_html(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r"<script.*?>.*?</script>", "", text, flags=re.S | re.I)
    text = re.sub(r"<style.*?>.*?</style>", "", text, flags=re.S | re.I)
    text = re.sub(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b", "", text)
    text = re.sub(r"\b[0-9]{6,}\b", "", text)
    text = re.sub(r'id="[^"]{8,}"', "", text)
    text = re.sub(r"nonce-[a-z0-9]+", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


try:
    from playwright.async_api import async_playwright  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False

FormLike = Union[Dict[str, Any], List[Any], tuple]

class XSSTester:
    """
    Improved XSSTester — backward-compatible interface.

    Key new constructor params:
      - default_retries (int)
      - payloads (list[str]) templates, use "{MARK}" token to insert marker
      - dom (bool) enable Playwright DOM checks (requires Playwright installed)
      - polite_delay (float) seconds to sleep between requests to the same host
      - auth_headers (dict) headers to add to every request (Authorization, etc)
      - basic_auth ((user, pass)) optional basic auth tuple forwarded to fetcher (if supported)
      - max_concurrency (int) global concurrency (used by scanning helpers)
    """

    def __init__(
        self,
        fetcher,
        default_retries: int = 2,
        payloads: Optional[List[str]] = None,
        dom: bool = False,
        polite_delay: float = 0.2,
        auth_headers: Optional[Dict[str, str]] = None,
        basic_auth: Optional[tuple] = None,
        max_concurrency: int = 20,
    ):
        self.fetcher = fetcher
        self.default_retries = default_retries
        self.payloads = payloads or DEFAULT_XSS_PAYLOADS
        self.dom = dom and PLAYWRIGHT_AVAILABLE
        if dom and not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not available — DOM checks disabled")
        # polite rate-limiting
        self.polite_delay = polite_delay
        # headers/auth defaults included in all requests
        self.auth_headers = auth_headers or {}
        self.basic_auth = basic_auth
        # concurrency control
        self.max_concurrency = max_concurrency
        # per-host semaphore to avoid pounding single host
        self._host_locks = defaultdict(lambda: asyncio.Semaphore(4))
        # last-request timestamp per host (to enforce polite_delay)
        self._host_last_ts = defaultdict(lambda: 0.0)

    def _marker(self) -> str:
        return MARKER_TMPL.format(id=uuid.uuid4().hex[:8])

    async def _throttle_for_host(self, host: str):
        # respects polite_delay per host
        sem = self._host_locks[host]
        await sem.acquire()
        try:
            now = asyncio.get_event_loop().time()
            last = self._host_last_ts[host]
            delta = self.polite_delay - (now - last)
            if delta > 0:
                await asyncio.sleep(delta)
            self._host_last_ts[host] = asyncio.get_event_loop().time()
        finally:
            sem.release()

    async def _fetch_text(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """
        Wrapper around fetcher.get/post to provide text and status and safe exceptions.
        Adds auth headers and basic auth if configured.
        kwargs may include data, json, headers, timeout, params, cookies, etc.
        """
        parsed = urlparse(url)
        host = parsed.netloc
        await self._throttle_for_host(host)

        headers = kwargs.pop("headers", {}) or {}
        headers.update(self.auth_headers)
        # pass basic_auth through kwargs if fetcher supports it
        if self.basic_auth:
            kwargs["auth"] = self.basic_auth

        kwargs["headers"] = headers

        try:
            if method.lower() == "get":
                resp = await self.fetcher.get(url, **kwargs)
            else:
                resp = await self.fetcher.post(url, **kwargs)
            text = await resp.text(errors="ignore")
            return {"ok": True, "status": getattr(resp, "status", None), "text": text}
        except Exception as e:
            logger.debug("xss fetch err %s %s %s", method, url, e)
            return {"ok": False, "error": str(e), "status": getattr(e, "status", None)}

    # ------------------------
    # GET param tests (returns list of dicts — one per payload)
    # ------------------------
    async def test_reflected_get(
        self,
        url: str,
        param: str,
        similarity_threshold: float = 0.98,
        retries: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if retries is None:
            retries = self.default_retries

        results: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        if not parsed.query:
            return results

        base_try = await self._fetch_text("get", url)
        base_text = base_try.get("text", "") if base_try.get("ok") else ""

        for payload_template in self.payloads:
            marker = self._marker()
            payload = payload_template.replace("{MARK}", marker)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_q = urlencode(qs, doseq=True)
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

            best_sim = 1.0
            best_text = ""
            last_status = None
            error = None

            for i in range(retries + 1):
                got = await self._fetch_text("get", target)
                if not got.get("ok"):
                    error = got.get("error")
                    last_status = got.get("status")
                    break
                text = got.get("text", "")
                last_status = got.get("status")
                a = _normalize_html(base_text)
                b = _normalize_html(text)
                sim = _similarity(a, b)
                if sim < best_sim:
                    best_sim = sim
                    best_text = text
                if marker in text:
                    r = {
                        "url": target,
                        "param": param,
                        "payload": payload,
                        "marker": marker,
                        "reflected": True,
                        "suspected": False,
                        "status": last_status,
                        "similarity": sim,
                    }
                    # optional DOM check later in scan stream
                    results.append(r)
                    break
            else:
                reflected = (marker in best_text) or (best_sim < similarity_threshold)
                suspected = (not reflected) and (best_sim < (similarity_threshold + 0.05))
                results.append({
                    "url": target,
                    "param": param,
                    "payload": payload,
                    "marker": marker,
                    "reflected": reflected,
                    "suspected": suspected,
                    "status": last_status,
                    "similarity": best_sim,
                })

            if error:
                results.append({
                    "url": target,
                    "param": param,
                    "payload": payload,
                    "marker": marker,
                    "reflected": False,
                    "suspected": False,
                    "status": last_status,
                    "error": error,
                })
        return results

    # ------------------------
    # POST/form tests (list of dicts)
    # ------------------------
    async def test_reflected_post(
        self,
        form: Dict[str, Any],
        similarity_threshold: float = 0.98,
        retries: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if retries is None:
            retries = self.default_retries
        try:
            url = form.get("url") or form.get("action") or ""
            method = str(form.get("method", "post")).lower()
            if not url:
                return [{"error": "no url in form", "form": form}]
            inputs = form.get("inputs") or {}
            if not isinstance(inputs, dict):
                try:
                    inputs = dict(inputs)
                except Exception:
                    inputs = {}

            base_try = await self._fetch_text("get", url)
            base_text = base_try.get("text", "") if base_try.get("ok") else ""
            enctype = str(form.get("enctype", "application/x-www-form-urlencoded")).lower()
            results: List[Dict[str, Any]] = []

            for payload_template in self.payloads:
                marker = self._marker()
                payload = payload_template.replace("{MARK}", marker)
                if "json" in enctype:
                    payload_obj = {k: payload for k in inputs.keys()}
                    fetch_kwargs = {"json": payload_obj}
                else:
                    data_obj = {k: payload for k in inputs.keys()}
                    fetch_kwargs = {"data": data_obj}

                best_sim = 1.0
                best_text = ""
                last_status = None
                error = None

                for i in range(retries + 1):
                    got = await self._fetch_text(method, url, **fetch_kwargs)
                    if not got.get("ok"):
                        error = got.get("error")
                        last_status = got.get("status")
                        break
                    text = got.get("text", "")
                    last_status = got.get("status")
                    a = _normalize_html(base_text)
                    b = _normalize_html(text)
                    sim = _similarity(a, b)
                    if sim < best_sim:
                        best_sim = sim
                        best_text = text
                    if marker in text:
                        results.append({
                            "url": url,
                            "param": list(inputs.keys()),
                            "payload": payload,
                            "marker": marker,
                            "reflected": True,
                            "suspected": False,
                            "status": last_status,
                            "similarity": sim,
                        })
                        break
                else:
                    reflected = (marker in best_text) or (best_sim < similarity_threshold)
                    suspected = (not reflected) and (best_sim < (similarity_threshold + 0.05))
                    results.append({
                        "url": url,
                        "param": list(inputs.keys()),
                        "payload": payload,
                        "marker": marker,
                        "reflected": reflected,
                        "suspected": suspected,
                        "status": last_status,
                        "similarity": best_sim,
                    })

                if error:
                    results.append({
                        "url": url,
                        "param": list(inputs.keys()),
                        "payload": payload,
                        "marker": marker,
                        "reflected": False,
                        "suspected": False,
                        "status": last_status,
                        "error": error,
                    })
            return results
        except Exception as e:
            logger.exception("xss post test failed %s", e)
            return [{"url": form.get("url"), "error": str(e)}]

    # ------------------------
    # Streaming helpers (backward-compatible)
    # ------------------------
    async def scan_urls_stream(self, urls: List[str], concurrency: int = 10) -> AsyncIterator[Dict[str, Any]]:
        sem = asyncio.Semaphore(min(concurrency, self.max_concurrency))
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
                        param_name = p.decode() if isinstance(p, bytes) else str(p)
                        sub = await self.test_reflected_get(u, param_name)
                        for r in sub:
                            # if DOM checks enabled and candidate appears suspicious/positive — try a lightweight DOM check
                            if self.dom and (r.get("reflected") or r.get("suspected")):
                                try:
                                    dom_ok = await self._try_dom_check(u, param_name, r.get("payload"))
                                    r["dom_executed"] = dom_ok
                                except Exception:
                                    r["dom_executed"] = False
                            results.append(r)
                    except Exception:
                        logger.exception("xss scan_urls_stream: failed for %s param %s", u, p)
                return results

        for u in urls:
            tasks.append(loop.create_task(_worker(u)))

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

    async def scan_forms_stream(self, forms: List[FormLike], concurrency: int = 5) -> AsyncIterator[Dict[str, Any]]:
        sem = asyncio.Semaphore(min(concurrency, self.max_concurrency))
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
                            sub = await self.test_reflected_get(url_val, param_name)
                            for r in sub:
                                out.append(r)
                        return out
                    else:
                        sub = await self.test_reflected_post(nf)
                        return sub
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
        results: List[Dict[str, Any]] = []
        async for item in self.scan_urls_stream(urls, concurrency=concurrency):
            results.append(item)
        return results


    async def _try_dom_check(self, url: str, param: str, payload: Optional[str]) -> bool:
        
        logger.info("_try_dom_check started")
        if not self.dom or not PLAYWRIGHT_AVAILABLE:
            return False
        if payload is None:
            return False
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_q = urlencode(qs, doseq=True)
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()

                try:
                    if hasattr(self.fetcher, "get_cookies_for"):
                        try:
                            cookies = await self.fetcher.get_cookies_for(parsed.netloc)
                            if isinstance(cookies, (list, tuple)):
                                await context.add_cookies(cookies)
                        except Exception:
                            pass
                    page = await context.new_page()
                    await page.goto(target, wait_until="load", timeout=5000)
                    try:
                        dialog = await page.wait_for_event("dialog", timeout=2000)
                        logger.info(dialog)
                        await dialog.dismiss()
                        await browser.close()
                        logger.info(f"dialog: {dialog}", )
                        return True
                    except Exception:
                        await browser.close()
                        return False
                except Exception:
                    await browser.close()
                    return False
        except Exception as e:
            logger.debug("DOM check failed %s", e)
            return False
