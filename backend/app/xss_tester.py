# backend/app/xss_tester.py
import asyncio
import html
import logging
import re
import uuid
from collections import defaultdict
from difflib import SequenceMatcher
from typing import Any, AsyncIterator, Dict, List, Optional, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)
MARKER_TMPL = "__WS__{id}__"

DEFAULT_XSS_PAYLOADS = [
    MARKER_TMPL.format(id="{MARK}"),
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "';alert(1);//",
    "<svg/onload=alert(1)>",
    "\"><svg/onload=alert(1)>",
]


def _normalize_html(text):
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


def _find_payload_evidence(text: str, marker: str, payload: str) -> List[str]:
    evidence: List[str] = []
    escaped_marker = html.escape(marker, quote=True)

    if marker in text:
        evidence.append("marker_reflected")
    elif escaped_marker != marker and escaped_marker in text:
        evidence.append("marker_escaped")

    payload_without_marker = payload.replace(marker, "").strip()
    if payload_without_marker:
        escaped_payload = html.escape(payload_without_marker, quote=True)
        if payload_without_marker in text:
            evidence.append("payload_fragment")
        elif escaped_payload != payload_without_marker and escaped_payload in text:
            evidence.append("payload_fragment_escaped")

    return evidence


def _build_candidate_result(
    *,
    url: str,
    param: Union[str, List[str]],
    payload: str,
    marker: str,
    status: Optional[int],
    similarity: float,
    evidence: List[str],
) -> Dict[str, Any]:
    reflected = "marker_reflected" in evidence
    suspected = (not reflected) and bool(evidence)
    if status and status >= 500 and similarity < 0.95:
        suspected = True
        if "server_error" not in evidence:
            evidence.append("server_error")

    return {
        "url": url,
        "param": param,
        "payload": payload,
        "marker": marker,
        "reflected": reflected,
        "suspected": suspected,
        "status": status,
        "similarity": similarity,
        "evidence": evidence,
    }


try:
    from playwright.async_api import async_playwright  # type: ignore

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    PLAYWRIGHT_AVAILABLE = False


FormLike = Union[Dict[str, Any], List[Any], tuple]


class XSSTester:
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
            logger.warning("Playwright not available - DOM checks disabled")
        self.polite_delay = polite_delay
        self.auth_headers = auth_headers or {}
        self.basic_auth = basic_auth
        self.max_concurrency = max_concurrency
        self._host_locks = defaultdict(lambda: asyncio.Semaphore(4))
        self._host_last_ts = defaultdict(lambda: 0.0)

    def _marker(self) -> str:
        return MARKER_TMPL.format(id=uuid.uuid4().hex[:8])

    async def _throttle_for_host(self, host: str):
        sem = self._host_locks[host]
        await sem.acquire()
        try:
            now = asyncio.get_running_loop().time()
            last = self._host_last_ts[host]
            delta = self.polite_delay - (now - last)
            if delta > 0:
                await asyncio.sleep(delta)
            self._host_last_ts[host] = asyncio.get_running_loop().time()
        finally:
            sem.release()

    async def _fetch_text(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)
        host = parsed.netloc
        await self._throttle_for_host(host)

        headers = kwargs.pop("headers", {}) or {}
        headers.update(self.auth_headers)
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

    async def test_reflected_get(
        self,
        url: str,
        param: str,
        similarity_threshold: float = 0.98,
        retries: Optional[int] = None,
        base_text: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if retries is None:
            retries = self.default_retries

        results: List[Dict[str, Any]] = []
        parsed = urlparse(url)
        if not parsed.query:
            return results

        if base_text is None:
            base_try = await self._fetch_text("get", url)
            base_text = base_try.get("text", "") if base_try.get("ok") else ""

        for payload_template in self.payloads:
            marker = self._marker()
            payload = payload_template.replace("{MARK}", marker)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_q = urlencode(qs, doseq=True)
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

            error = None
            last_status = None
            best_similarity = 1.0

            for _ in range(retries + 1):
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
                best_similarity = min(best_similarity, sim)
                evidence = _find_payload_evidence(text, marker, payload)
                candidate = _build_candidate_result(
                    url=target,
                    param=param,
                    payload=payload,
                    marker=marker,
                    status=last_status,
                    similarity=sim,
                    evidence=evidence,
                )
                if candidate["reflected"] or candidate["suspected"] or sim < (similarity_threshold - 0.25):
                    if sim < (similarity_threshold - 0.25) and not candidate["evidence"]:
                        candidate["evidence"].append("significant_markup_change")
                        candidate["suspected"] = True
                    results.append(candidate)
                    break

            if error:
                results.append(
                    {
                        "url": target,
                        "param": param,
                        "payload": payload,
                        "marker": marker,
                        "reflected": False,
                        "suspected": False,
                        "status": last_status,
                        "similarity": best_similarity,
                        "error": error,
                    }
                )
        return results

    async def test_reflected_post(
        self,
        form: Dict[str, Any],
        similarity_threshold: float = 0.98,
        retries: Optional[int] = None,
        base_text: Optional[str] = None,
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

            if base_text is None:
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

                error = None
                last_status = None
                best_similarity = 1.0

                for _ in range(retries + 1):
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
                    best_similarity = min(best_similarity, sim)
                    evidence = _find_payload_evidence(text, marker, payload)
                    candidate = _build_candidate_result(
                        url=url,
                        param=list(inputs.keys()),
                        payload=payload,
                        marker=marker,
                        status=last_status,
                        similarity=sim,
                        evidence=evidence,
                    )
                    if candidate["reflected"] or candidate["suspected"] or sim < (similarity_threshold - 0.25):
                        if sim < (similarity_threshold - 0.25) and not candidate["evidence"]:
                            candidate["evidence"].append("significant_markup_change")
                            candidate["suspected"] = True
                        results.append(candidate)
                        break

                if error:
                    results.append(
                        {
                            "url": url,
                            "param": list(inputs.keys()),
                            "payload": payload,
                            "marker": marker,
                            "reflected": False,
                            "suspected": False,
                            "status": last_status,
                            "similarity": best_similarity,
                            "error": error,
                        }
                    )
            return results
        except Exception as e:
            logger.exception("xss post test failed %s", e)
            return [{"url": form.get("url"), "error": str(e)}]

    async def scan_urls_stream(self, urls: List[str], concurrency: int = 10) -> AsyncIterator[Dict[str, Any]]:
        sem = asyncio.Semaphore(min(concurrency, self.max_concurrency))
        loop = asyncio.get_running_loop()
        tasks = []

        async def _worker(u: str):
            async with sem:
                parsed = urlparse(u)
                if not parsed.query:
                    return []
                base_try = await self._fetch_text("get", u)
                base_text = base_try.get("text", "") if base_try.get("ok") else ""
                qs = parse_qs(parsed.query, keep_blank_values=True)
                results = []
                for p in qs.keys():
                    try:
                        param_name = p.decode() if isinstance(p, bytes) else str(p)
                        sub = await self.test_reflected_get(u, param_name, base_text=base_text)
                        for r in sub:
                            if self.dom and r.get("reflected") and not r.get("error"):
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
            if not urlparse(u).query:
                continue
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

        def _normalize(raw: FormLike):
            try:
                if isinstance(raw, dict):
                    return raw
                if isinstance(raw, (list, tuple)) and len(raw) >= 2 and isinstance(raw[1], dict):
                    normalized = {"url": str(raw[0])}
                    normalized.update(raw[1])
                    return normalized
            except Exception:
                logger.exception("xss normalize form failed %r", raw)
            return None

        async def _worker(form_like: FormLike):
            async with sem:
                normalized = _normalize(form_like)
                if normalized is None:
                    return []
                try:
                    method = str(normalized.get("method", "post")).lower()
                    if method == "get":
                        out = []
                        url_value = normalized.get("url")
                        if not isinstance(url_value, str):
                            return out
                        inputs = normalized.get("inputs") or {}
                        parsed = urlparse(url_value)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        for name in inputs.keys():
                            qs.setdefault(str(name), [""])
                        if not qs:
                            return out
                        target = urlunparse(
                            (
                                parsed.scheme,
                                parsed.netloc,
                                parsed.path,
                                parsed.params,
                                urlencode(qs, doseq=True),
                                parsed.fragment,
                            )
                        )
                        base_try = await self._fetch_text("get", target)
                        base_text = base_try.get("text", "") if base_try.get("ok") else ""
                        for name in qs.keys():
                            sub = await self.test_reflected_get(target, str(name), base_text=base_text)
                            out.extend(sub)
                        return out

                    base_try = await self._fetch_text("get", normalized.get("url"))
                    base_text = base_try.get("text", "") if base_try.get("ok") else ""
                    return await self.test_reflected_post(normalized, base_text=base_text)
                except Exception:
                    logger.exception("xss scan_forms worker failed %r", normalized)
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

    async def scan_forms(self, forms: List[FormLike], concurrency: int = 5) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        async for item in self.scan_forms_stream(forms, concurrency=concurrency):
            results.append(item)
        return results

    async def _try_dom_check(self, url: str, param: str, payload: Optional[str]) -> bool:
        if not self.dom or not PLAYWRIGHT_AVAILABLE or payload is None:
            return False

        browser = None
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            new_q = urlencode(qs, doseq=True)
            target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                await page.goto(target, wait_until="load", timeout=5000)

                try:
                    dialog = await page.wait_for_event("dialog", timeout=2000)
                    await dialog.dismiss()
                    return True
                except Exception:
                    return False
        except Exception as e:
            logger.debug("DOM check failed %s", e)
            return False
        finally:
            if browser is not None:
                await browser.close()
