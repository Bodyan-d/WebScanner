import asyncio
import json
import re
import time
import uuid
from collections import defaultdict, deque
from contextlib import suppress
from typing import Any, Deque, Dict, List, Optional, Union, cast
from urllib.parse import urlparse

import aiohttp
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

from .config import (
    API_KEY,
    CORS_ALLOW_ORIGINS,
    ENABLE_DOM_XSS,
    MAX_CONCURRENCY,
    MAX_PAGES_LIMIT,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    SCAN_CACHE_TTL_SECONDS,
    SQLMAP_MAX_URLS,
    USE_SQLMAP,
)
from .crawler import Crawler
from .db import database
from .fetcher import Fetcher
from .headers_checker import check_headers
from .models import scans
from .port_scanner import nmap_scan, tcp_scan
from .reporter import build_report
from .sqli_tester import SQLiTester
from .xss_tester import XSSTester

app = FastAPI(title="WebScanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: HttpUrl
    max_pages: int = Field(MAX_PAGES_LIMIT, ge=1, le=MAX_PAGES_LIMIT)
    concurrency: int = Field(MAX_CONCURRENCY, ge=1, le=MAX_CONCURRENCY)
    run_sqlmap: bool = False
    sqlmap_args: Optional[List[str]] = None
    scan_id: Optional[str] = None


SCAN_CACHE: Dict[str, Dict[str, Any]] = {}
SQLMAP_JOBS: Dict[str, Dict[str, Any]] = {}
SQLMAP_TASKS: Dict[str, asyncio.Task[Any]] = {}
RATE_LIMITS: Dict[str, Deque[float]] = defaultdict(deque)


def sanitize_sqlmap_args(args):
    if not args:
        return None

    safe: List[str] = []
    tamper_re = re.compile(r"^[A-Za-z0-9_,.-]{1,80}$")
    for raw_arg in args:
        if not isinstance(raw_arg, str):
            continue
        arg = raw_arg.strip()
        if not arg or len(arg) > 160:
            continue
        if arg in {"--random-agent", "--batch"}:
            safe.append(arg)
        elif re.fullmatch(r"--level=[1-5]", arg):
            safe.append(arg)
        elif re.fullmatch(r"--risk=[1-3]", arg):
            safe.append(arg)
        elif re.fullmatch(r"--threads=([1-9]|10)", arg):
            safe.append(arg)
        elif re.fullmatch(r"--crawl=([0-9]|10)", arg):
            safe.append(arg)
        elif arg.startswith("--tamper="):
            tamper_value = arg.split("=", 1)[1]
            if tamper_re.fullmatch(tamper_value):
                safe.append(arg)
        if len(safe) >= 10:
            break
    return safe or None


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    for task in SQLMAP_TASKS.values():
        task.cancel()
    for task in SQLMAP_TASKS.values():
        with suppress(asyncio.CancelledError):
            await task
    await database.disconnect()


@app.get("/api/health")
async def healthcheck():
    return {
        "ok": True,
        "sqlmap_enabled": USE_SQLMAP,
        "cache_items": len(SCAN_CACHE),
        "sqlmap_jobs": len(SQLMAP_JOBS),
    }


def _ensure_list_of_str(raw: Any) -> List[str]:
    out: List[str] = []
    if raw is None:
        return out
    if isinstance(raw, (list, set, tuple)):
        for item in raw:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                url_value = item.get("url") or item.get("action")
                if isinstance(url_value, str):
                    out.append(url_value)
    elif isinstance(raw, dict):
        urls = raw.get("urls")
        if isinstance(urls, (list, set, tuple)):
            for item in urls:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    url_value = item.get("url")
                    if isinstance(url_value, str):
                        out.append(url_value)
    elif isinstance(raw, str):
        out.append(raw)
    return list(dict.fromkeys(out))


def _ensure_forms(raw: Any) -> List[Union[Dict[str, Any], list, tuple]]:
    out: List[Union[Dict[str, Any], list, tuple]] = []
    if not raw:
        return out
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict) or isinstance(item, (list, tuple)):
                out.append(item)
    elif isinstance(raw, dict):
        forms = raw.get("forms")
        if isinstance(forms, list):
            for item in forms:
                if isinstance(item, dict) or isinstance(item, (list, tuple)):
                    out.append(item)
    return out


def _extract_forms_from_crawl(crawl_res: Any) -> List[Any]:
    forms_raw: List[Any] = []
    if isinstance(crawl_res, dict):
        maybe = crawl_res.get("forms")
        if isinstance(maybe, list):
            forms_raw = maybe
        else:
            nested = crawl_res.get("crawl")
            if isinstance(nested, dict):
                nested_forms = nested.get("forms")
                if isinstance(nested_forms, list):
                    forms_raw = nested_forms
    elif isinstance(crawl_res, list):
        for item in cast(List[Any], crawl_res):
            if not isinstance(item, dict):
                continue
            forms = item.get("forms")
            if isinstance(forms, list):
                forms_raw.extend(forms)
            else:
                nested = item.get("crawl")
                if isinstance(nested, dict):
                    nested_forms = nested.get("forms")
                    if isinstance(nested_forms, list):
                        forms_raw.extend(nested_forms)
    return forms_raw


def _normalize_form(raw: Any) -> Optional[Dict[str, Any]]:
    try:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, (list, tuple)) and len(raw) >= 2 and isinstance(raw[1], dict):
            normalized = {"url": str(raw[0])}
            normalized.update(raw[1])
            return normalized
    except Exception:
        return None
    return None


def _normalize_forms(forms: List[Any]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for raw in forms:
        item = _normalize_form(raw)
        if item:
            normalized.append(item)
    return normalized


def _dedupe_forms(forms: List[Any]) -> List[Any]:
    seen = set()
    deduped: List[Any] = []
    for form in forms:
        try:
            if isinstance(form, dict):
                key = (
                    form.get("url") or form.get("action"),
                    json.dumps(form.get("inputs", {}), sort_keys=True),
                    form.get("method", "get"),
                )
            elif isinstance(form, (list, tuple)) and len(form) >= 2 and isinstance(form[1], dict):
                key = (
                    str(form[0]),
                    json.dumps(form[1].get("inputs", {}), sort_keys=True),
                    form[1].get("method", "get"),
                )
            else:
                key = (str(form), "", "unknown")
        except Exception:
            key = (str(form), "", "unknown")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(form)
    return deduped


def _dedupe_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for item in items:
        key = json.dumps(
            {
                "url": item.get("url"),
                "param": item.get("param"),
                "payload": item.get("payload"),
                "status": item.get("status"),
                "error": item.get("error"),
                "evidence": item.get("evidence"),
            },
            sort_keys=True,
            default=str,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _count_open_ports(parts: Dict[str, Any]) -> List[int]:
    ports = parts.get("ports") or {}
    if not isinstance(ports, dict):
        return []

    tcp_ports = ports.get("tcp")
    if isinstance(tcp_ports, dict):
        open_ports = []
        for port, is_open in tcp_ports.items():
            if is_open:
                try:
                    open_ports.append(int(port))
                except (TypeError, ValueError):
                    continue
        return sorted(open_ports)

    nmap = ports.get("nmap")
    if isinstance(nmap, dict):
        output = nmap.get("output", "")
        if isinstance(output, str):
            return sorted(int(match) for match in re.findall(r"(?m)^(\d+)/tcp\s+open", output))
    return []


def _build_summary(parts: Dict[str, Any]) -> Dict[str, Any]:
    crawl = parts.get("crawl") or {}
    urls = _ensure_list_of_str(crawl.get("urls", []) if isinstance(crawl, dict) else crawl)
    forms = _ensure_forms(crawl.get("forms", []) if isinstance(crawl, dict) else None)
    open_ports = _count_open_ports(parts)
    sqlmap = parts.get("sqlmap") or {}
    sqlmap_findings = sqlmap.get("findings", []) if isinstance(sqlmap, dict) else []
    return {
        "open_ports": open_ports,
        "open_port_count": len(open_ports),
        "url_count": len(urls),
        "form_count": len(forms),
        "xss_count": len(parts.get("xss", []) or []),
        "sqli_count": len(parts.get("sqli", []) or []),
        "sqlmap_count": len(sqlmap_findings) if isinstance(sqlmap_findings, list) else 0,
    }


def _serialize_job(job: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not job:
        return None
    return {
        "job_id": job["job_id"],
        "scan_id": job["scan_id"],
        "status": job["status"],
        "error": job.get("error"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "scanned_urls": job.get("scanned_urls", []),
    }


def _build_sqlmap_state(
    *,
    status: str,
    job_id: Optional[str],
    ok: Optional[bool],
    error: Optional[str],
    scanned_urls: List[str],
    findings: Optional[List[Dict[str, Any]]] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "status": status,
        "job_id": job_id,
        "ok": ok,
        "error": error,
        "message": message,
        "scanned_urls": scanned_urls,
        "findings": findings or [],
    }


def _build_scan_response(scan_id: str, scan_entry: Dict[str, Any], job: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "scan_id": scan_id,
        "target": scan_entry["target"],
        "report": scan_entry["report_path"],
        "parts": scan_entry["parts"],
        "job": _serialize_job(job),
    }


async def _persist_scan(scan_entry: Dict[str, Any]):
    try:
        db_id = scan_entry.get("db_id")
        summary = _build_summary(scan_entry["parts"])
        if db_id is None:
            query = scans.insert().values(
                target=scan_entry["target"],
                report_path=scan_entry["report_path"],
                summary=summary,
                details=scan_entry["parts"],
            )
            scan_entry["db_id"] = await database.execute(query)
        else:
            query = (
                scans.update()
                .where(scans.c.id == db_id)
                .values(report_path=scan_entry["report_path"], summary=summary, details=scan_entry["parts"])
            )
            await database.execute(query)
    except Exception:
        pass


def _cleanup_runtime_state():
    now = time.monotonic()
    active_scan_ids = {
        job["scan_id"]
        for job in SQLMAP_JOBS.values()
        if job.get("status") in {"queued", "running"}
    }

    expired_scans = [
        scan_id
        for scan_id, entry in SCAN_CACHE.items()
        if scan_id not in active_scan_ids and now - entry.get("created_at", now) > SCAN_CACHE_TTL_SECONDS
    ]
    for scan_id in expired_scans:
        SCAN_CACHE.pop(scan_id, None)

    expired_jobs = [
        job_id
        for job_id, job in SQLMAP_JOBS.items()
        if job.get("status") not in {"queued", "running"}
        and now - job.get("updated_at", now) > SCAN_CACHE_TTL_SECONDS
    ]
    for job_id in expired_jobs:
        SQLMAP_JOBS.pop(job_id, None)
        SQLMAP_TASKS.pop(job_id, None)


def _enforce_request_access(request: Request):
    if API_KEY and request.headers.get("x-api-key", "").strip() != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid API key.")

    client_host = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    if not client_host and request.client:
        client_host = request.client.host
    client_host = client_host or "unknown"

    now = time.monotonic()
    bucket = RATE_LIMITS[client_host]
    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in about {RATE_LIMIT_WINDOW_SECONDS} seconds.",
        )
    bucket.append(now)


def _filter_query_urls(urls: List[str]) -> List[str]:
    return [url for url in urls if urlparse(url).query]


def _form_has_inputs(form: Any) -> bool:
    normalized = _normalize_form(form)
    if not normalized:
        return False
    inputs = normalized.get("inputs") or {}
    return isinstance(inputs, dict) and bool(inputs)


def _select_sqlmap_targets(target: str, crawl_res: Any, forms: List[Any]) -> List[str]:
    candidates: List[str] = []
    urls = _ensure_list_of_str(crawl_res.get("urls", []) if isinstance(crawl_res, dict) else crawl_res)
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.query:
            candidates.append(url)

    for form in _normalize_forms(forms):
        inputs = form.get("inputs") or {}
        form_url = form.get("url") or form.get("action")
        if isinstance(form_url, str) and inputs:
            parsed = urlparse(form_url)
            if parsed.scheme in {"http", "https"}:
                candidates.append(form_url)

    target_parsed = urlparse(target)
    if target_parsed.query:
        candidates.append(target)

    deduped = list(dict.fromkeys(candidates))
    return deduped[:SQLMAP_MAX_URLS]


async def _scan_ports(host) :
    try:
        nmap = await asyncio.to_thread(nmap_scan, host)
        if isinstance(nmap, dict) and nmap.get("ok"):
            return {"nmap": nmap}
        tcp = await tcp_scan(host)
        return {"tcp": tcp}
    except Exception as e:
        return {"error": str(e)}


async def _scan_headers(target) :
    async with aiohttp.ClientSession() as session:
        return await check_headers(session, target)


async def _scan_xss(urls: List[str], forms: List[Any], concurrency: int) -> List[Dict[str, Any]]:
    url_candidates = _filter_query_urls(urls)
    form_candidates = [form for form in forms if _form_has_inputs(form)]
    if not url_candidates and not form_candidates:
        return []

    fetcher = Fetcher(concurrency=concurrency, polite_delay=0.15)
    tester = XSSTester(fetcher, dom=ENABLE_DOM_XSS, polite_delay=0.15)
    try:
        url_task = asyncio.create_task(tester.scan_urls(url_candidates, concurrency=min(20, concurrency * 2))) if url_candidates else None
        form_task = asyncio.create_task(tester.scan_forms(form_candidates, concurrency=max(1, concurrency))) if form_candidates else None

        url_results = await url_task if url_task else []
        form_results = await form_task if form_task else []
        return _dedupe_findings(url_results + form_results)
    finally:
        await fetcher.close()


async def _scan_basic_sqli(urls: List[str], concurrency: int) -> List[Dict[str, Any]]:
    candidates = _filter_query_urls(urls)
    if not candidates:
        return []

    fetcher = Fetcher(concurrency=max(1, concurrency), polite_delay=0.1)
    tester = SQLiTester(fetcher)
    sem = asyncio.Semaphore(max(1, min(concurrency, 6)))

    async def _worker(url: str) -> List[Dict[str, Any]]:
        async with sem:
            try:
                return await tester.basic_diff(url)
            except Exception:
                return []

    try:
        tasks = [asyncio.create_task(_worker(url)) for url in candidates]
        subsets = await asyncio.gather(*tasks)
    finally:
        await fetcher.close()

    findings: List[Dict[str, Any]] = []
    for subset in subsets:
        findings.extend(subset)
    return _dedupe_findings(findings)


async def _run_base_scan(req: ScanRequest) -> Dict[str, Any]:
    target = str(req.url)
    host = req.url.host

    crawler = Crawler(base_url=target, concurrency=req.concurrency, max_pages=req.max_pages)
    ports_task = asyncio.create_task(_scan_ports(host))
    headers_task = asyncio.create_task(_scan_headers(target))
    crawl_task = asyncio.create_task(crawler.crawl())

    ports, header_res, crawl_res = await asyncio.gather(ports_task, headers_task, crawl_task)

    urls = _ensure_list_of_str(crawl_res.get("urls", []) if isinstance(crawl_res, dict) else crawl_res)
    forms = _ensure_forms(crawl_res.get("forms", []) if isinstance(crawl_res, dict) else None)

    xss_task = asyncio.create_task(_scan_xss(urls, forms, req.concurrency))
    sqli_task = asyncio.create_task(_scan_basic_sqli(urls, req.concurrency))
    xss_results, sqli_results = await asyncio.gather(xss_task, sqli_task)

    parts = {
        "ports": ports,
        "crawl": crawl_res,
        "headers": header_res,
        "xss": xss_results,
        "sqli": sqli_results,
        "sqlmap": None,
    }

    report_path = build_report(target, parts)
    scan_id = str(uuid.uuid4())
    scan_entry = {
        "scan_id": scan_id,
        "created_at": time.monotonic(),
        "db_id": None,
        "target": target,
        "parts": parts,
        "report_path": report_path,
    }
    SCAN_CACHE[scan_id] = scan_entry
    await _persist_scan(scan_entry)
    return _build_scan_response(scan_id, scan_entry)


def _find_active_sqlmap_job(scan_id: str) -> Optional[Dict[str, Any]]:
    for job in SQLMAP_JOBS.values():
        if job.get("scan_id") == scan_id and job.get("status") in {"queued", "running"}:
            return job
    return None


async def _run_sqlmap_job(job_id: str):
    job = SQLMAP_JOBS.get(job_id)
    if not job:
        return

    scan_id = job["scan_id"]
    scan_entry = SCAN_CACHE.get(scan_id)
    if not scan_entry:
        job["status"] = "failed"
        job["error"] = "scan_id expired before sqlmap job started"
        job["updated_at"] = time.monotonic()
        return

    try:
        job["status"] = "running"
        job["updated_at"] = time.monotonic()
        scan_entry["created_at"] = time.monotonic()
        scan_entry["parts"]["sqlmap"] = _build_sqlmap_state(
            status="running",
            job_id=job_id,
            ok=None,
            error=None,
            scanned_urls=job["scanned_urls"],
            message="sqlmap is running.",
        )

        tester = SQLiTester()
        findings = await tester.run_sqlmap_for_urls(
            job["scanned_urls"],
            forms=job["forms"],
            extra_args=job["extra_args"],
            timeout=job["timeout"],
            concurrency=job["concurrency"],
        )

        sqlmap_state = _build_sqlmap_state(
            status="completed",
            job_id=job_id,
            ok=True,
            error=None,
            scanned_urls=job["scanned_urls"],
            findings=findings,
            message="sqlmap finished successfully.",
        )
        scan_entry["parts"]["sqlmap"] = sqlmap_state
        scan_entry["report_path"] = build_report(scan_entry["target"], scan_entry["parts"])
        scan_entry["created_at"] = time.monotonic()
        await _persist_scan(scan_entry)

        job["status"] = "completed"
        job["error"] = None
        job["updated_at"] = time.monotonic()
    except Exception as e:
        sqlmap_state = _build_sqlmap_state(
            status="failed",
            job_id=job_id,
            ok=False,
            error=str(e),
            scanned_urls=job["scanned_urls"],
            findings=[],
        )
        scan_entry["parts"]["sqlmap"] = sqlmap_state
        scan_entry["report_path"] = build_report(scan_entry["target"], scan_entry["parts"])
        scan_entry["created_at"] = time.monotonic()
        await _persist_scan(scan_entry)

        job["status"] = "failed"
        job["error"] = str(e)
        job["updated_at"] = time.monotonic()
    finally:
        SQLMAP_TASKS.pop(job_id, None)


async def _enqueue_sqlmap_job(req: ScanRequest) -> Dict[str, Any]:
    if not req.scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required to run sqlmap on existing crawl results.")

    scan_entry = SCAN_CACHE.get(req.scan_id)
    if not scan_entry:
        raise HTTPException(status_code=404, detail="scan_id not found or expired.")

    if not req.run_sqlmap:
        return _build_scan_response(req.scan_id, scan_entry)

    if not USE_SQLMAP:
        scan_entry["parts"]["sqlmap"] = _build_sqlmap_state(
            status="failed",
            job_id=None,
            ok=False,
            error="sqlmap disabled by configuration",
            scanned_urls=[],
            findings=[],
        )
        scan_entry["report_path"] = build_report(scan_entry["target"], scan_entry["parts"])
        scan_entry["created_at"] = time.monotonic()
        await _persist_scan(scan_entry)
        return _build_scan_response(req.scan_id, scan_entry)

    existing_job = _find_active_sqlmap_job(req.scan_id)
    if existing_job:
        scan_entry["parts"]["sqlmap"] = _build_sqlmap_state(
            status=existing_job["status"],
            job_id=existing_job["job_id"],
            ok=None,
            error=existing_job.get("error"),
            scanned_urls=existing_job.get("scanned_urls", []),
            findings=[],
            message="sqlmap job already exists for this scan.",
        )
        return _build_scan_response(req.scan_id, scan_entry, existing_job)

    crawl_res = scan_entry["parts"].get("crawl", {})
    forms = _dedupe_forms(_ensure_forms(_extract_forms_from_crawl(crawl_res)))
    targets = _select_sqlmap_targets(scan_entry["target"], crawl_res, forms)

    if not targets:
        scan_entry["parts"]["sqlmap"] = _build_sqlmap_state(
            status="completed",
            job_id=None,
            ok=True,
            error=None,
            scanned_urls=[],
            findings=[],
            message="No suitable sqlmap targets were found in the crawl results.",
        )
        scan_entry["report_path"] = build_report(scan_entry["target"], scan_entry["parts"])
        scan_entry["created_at"] = time.monotonic()
        await _persist_scan(scan_entry)
        return _build_scan_response(req.scan_id, scan_entry)

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "scan_id": req.scan_id,
        "status": "queued",
        "error": None,
        "created_at": time.monotonic(),
        "updated_at": time.monotonic(),
        "scanned_urls": targets,
        "forms": _normalize_forms(forms),
        "extra_args": sanitize_sqlmap_args(req.sqlmap_args or []),
        "timeout": 600,
        "concurrency": min(3, max(1, req.concurrency)),
    }
    SQLMAP_JOBS[job_id] = job

    scan_entry["parts"]["sqlmap"] = _build_sqlmap_state(
        status="queued",
        job_id=job_id,
        ok=None,
        error=None,
        scanned_urls=targets,
        findings=[],
        message="sqlmap job is queued.",
    )
    scan_entry["report_path"] = build_report(scan_entry["target"], scan_entry["parts"])
    scan_entry["created_at"] = time.monotonic()
    await _persist_scan(scan_entry)

    SQLMAP_TASKS[job_id] = asyncio.create_task(_run_sqlmap_job(job_id))
    return _build_scan_response(req.scan_id, scan_entry, job)


@app.post("/api/scan_no_sqlmap")
async def api_scan_no_sqlmap(request: Request, req: ScanRequest):
    _cleanup_runtime_state()
    _enforce_request_access(request)
    return await _run_base_scan(req)


@app.post("/api/scan_sqlmap")
async def api_scan_sqlmap(request: Request, req: ScanRequest = Body(...)):
    _cleanup_runtime_state()
    _enforce_request_access(request)
    return await _enqueue_sqlmap_job(req)


@app.get("/api/scan_sqlmap/{job_id}")
async def api_scan_sqlmap_status(request: Request, job_id: str):
    _cleanup_runtime_state()
    _enforce_request_access(request)

    job = SQLMAP_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="sqlmap job not found or expired.")

    scan_entry = SCAN_CACHE.get(job["scan_id"])
    if not scan_entry:
        raise HTTPException(status_code=404, detail="Associated scan not found or expired.")

    return _build_scan_response(job["scan_id"], scan_entry, job)


@app.post("/api/scan")
async def api_scan(request: Request, req: ScanRequest):
    _cleanup_runtime_state()
    _enforce_request_access(request)

    base_result = await _run_base_scan(req)
    if not req.run_sqlmap:
        return base_result

    sqlmap_req = ScanRequest(
        url=req.url,
        max_pages=req.max_pages,
        concurrency=req.concurrency,
        run_sqlmap=True,
        sqlmap_args=req.sqlmap_args,
        scan_id=base_result["scan_id"],
    )
    return await _enqueue_sqlmap_job(sqlmap_req)
