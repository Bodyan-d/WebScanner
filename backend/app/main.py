import json
import uuid
from typing import Optional, List, Dict, Any, Union, Sequence, cast

from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field, HttpUrl
from fastapi.middleware.cors import CORSMiddleware
import aiohttp

from .crawler import Crawler
from .fetcher import Fetcher
from .port_scanner import tcp_scan, nmap_scan
from .xss_tester import XSSTester
from .sqli_tester import SQLiTester
from .headers_checker import check_headers
from .reporter import build_report
from .db import database
from .models import scans
from .config import MAX_PAGES_LIMIT, MAX_CONCURRENCY
from sqlalchemy import insert

MAX_PAGES_LIMIT = 50
MAX_CONCURRENCY = 5

app = FastAPI(title="WebScanner API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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


ALLOWED_SQLMAP_PREFIXES = (
    "--level=",
    "--risk=",
    "--threads=",
    "--crawl=",
    "--tamper=",
    "--random-agent",
    "--batch",
)


def sanitize_sqlmap_args(args: Optional[List[str]]) -> Optional[List[str]]:
    if not args:
        return None
    safe: List[str] = []
    for a in args:
        if not isinstance(a, str):
            continue
        a = a.strip()
        if not a or len(a) > 160:
            continue
        if a in ("--random-agent", "--batch") or any(a.startswith(pref) for pref in ALLOWED_SQLMAP_PREFIXES):
            safe.append(a)
        if len(safe) >= 20:
            break
    return safe or None


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


def _ensure_list_of_str(raw: Any) -> List[str]:
    """
    Convert various crawler outputs into list[str].
    - Accepts list[str], list[dict] (with 'url'), set, etc.
    - Filters out non-str results.
    """
    out: List[str] = []
    if raw is None:
        return out
    if isinstance(raw, (list, set, tuple)):
        for item in raw:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                u = item.get("url") or item.get("action")
                if isinstance(u, str):
                    out.append(u)
    elif isinstance(raw, dict):
        # maybe crawl_res is dict with 'urls' key
        u = raw.get("urls")
        if isinstance(u, (list, set, tuple)):
            for item in u:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    uu = item.get("url")
                    if isinstance(uu, str):
                        out.append(uu)
    elif isinstance(raw, str):
        out.append(raw)
    return out


def _ensure_forms(raw: Any) -> List[Union[Dict[str, Any], list, tuple]]:
    """
    Normalize forms into list of dicts/tuples acceptable by XSSTester/SQLiTester.
    The crawler stores forms as tuples (url, {method, inputs}), so we accept that.
    """
    out: List[Union[Dict[str, Any], list, tuple]] = []
    if not raw:
        return out
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                out.append(item)
            elif isinstance(item, (list, tuple)):
                out.append(item)
    elif isinstance(raw, dict):
        # if forms in a dict
        forms = raw.get("forms")
        if isinstance(forms, list):
            for item in forms:
                if isinstance(item, dict) or isinstance(item, (list, tuple)):
                    out.append(item)
    return out

# -------------------------
# 1) Базовий ендпойнт — без sqlmap
# -------------------------
@app.post("/api/scan_no_sqlmap")
async def api_scan_no_sqlmap(req: ScanRequest):
    target = str(req.url)
    host = req.url.host

    # --- Ports (nmap or tcp) ---
    try:
        nmap = nmap_scan(host)
        if isinstance(nmap, dict) and nmap.get("ok"):
            ports = {"nmap": nmap}
        else:
            tcp = await tcp_scan(host)
            ports = {"tcp": tcp}
    except Exception as e:
        ports = {"error": str(e)}

    # --- Crawl ---
    crawler = Crawler(base_url=target, concurrency=req.concurrency, max_pages=req.max_pages)
    crawl_res = await crawler.crawl()

    # --- Headers ---
    async with aiohttp.ClientSession() as session:
        header_res = await check_headers(session, target)

    # --- XSS ---
    urls_raw = None
    if isinstance(crawl_res, dict):
        urls_raw = crawl_res.get("urls", [])
    else:
        urls_raw = crawl_res or []

    urls: List[str] = _ensure_list_of_str(urls_raw)

    fetcher = Fetcher(concurrency=req.concurrency)
    xss_tester = XSSTester(fetcher, dom=True, polite_delay=0.3, auth_headers={"Authorization": "Bearer MYTOKEN"})
    xss_results = []
    try:
        if urls:
            xss_results = await xss_tester.scan_urls(urls, concurrency=min(20, req.concurrency * 2))
    finally:
        await fetcher.close()

    # --- SQLi basic ---
    fetcher2 = Fetcher(concurrency=1)
    tester = SQLiTester(fetcher2)

    sqli_basic: List[Dict[str, Any]] = []
    for u in urls:
        try:
            sqli_basic.extend(await tester.basic_diff(u))
        except Exception:
            continue
    await fetcher2.close()

    # --- parts (no sqlmap) ---
    parts = {
        "ports": ports,
        "crawl": crawl_res,
        "headers": header_res,
        "xss": xss_results,
        "sqli": sqli_basic,
        "sqlmap": None,
    }

    report_path = build_report(target, parts)

    scan_id = str(uuid.uuid4())
    SCAN_CACHE[scan_id] = {
        "target": target,
        "parts": parts,
        "report_path": report_path,
    }


    try:
        summary = {"open_ports": len(parts.get("ports", {}) if isinstance(parts.get("ports"), dict) else [])}
        query = scans.insert().values(target=target, report_path=report_path, summary=summary, details=parts)
        await database.execute(query)
    except Exception:
        pass

    return {"scan_id": scan_id, "report": report_path, "parts": parts}


@app.post("/api/scan_sqlmap")
async def api_scan_sqlmap(req: ScanRequest = Body(...)):

    if not req.scan_id:
        raise HTTPException(status_code=400, detail="scan_id is required to run sqlmap on existing crawl results.")

    scan_entry = SCAN_CACHE.get(req.scan_id)
    if not scan_entry:
        raise HTTPException(status_code=404, detail="scan_id not found or expired.")

    target = scan_entry["target"]
    parts: Dict[str, Any] = scan_entry["parts"]


    crawl_res = parts.get("crawl", {})


    forms_raw: List[Any] = []
    if isinstance(crawl_res, dict):
        maybe = crawl_res.get("forms")
        if isinstance(maybe, list):
            forms_raw = maybe
        else:
            nested = crawl_res.get("crawl")
            if isinstance(nested, dict):
                maybe2 = nested.get("forms")
                if isinstance(maybe2, list):
                    forms_raw = maybe2
    elif isinstance(crawl_res, list):
        for item in cast(List[Any], crawl_res):
            if not isinstance(item, dict):
                continue
            f = item.get("forms")
            if isinstance(f, list):
                forms_raw.extend(f)
            else:
                nested = item.get("crawl")
                if isinstance(nested, dict):
                    nf = nested.get("forms")
                    if isinstance(nf, list):
                        forms_raw.extend(nf)

    if not isinstance(forms_raw, list):
        forms_raw = []

    forms = _ensure_forms(forms_raw)


    seen = set()
    dedup_forms: List[Any] = []
    for fm in forms:
        try:
            if isinstance(fm, dict):
                key = (fm.get("url") or fm.get("action"), json.dumps(fm.get("inputs", {}), sort_keys=True))
            elif isinstance(fm, (list, tuple)) and len(fm) >= 2 and isinstance(fm[1], dict):
                key = (str(fm[0]), json.dumps(fm[1].get("inputs", {}), sort_keys=True))
            else:
                key = (str(fm), "")
        except Exception:
            key = (str(fm), "")
        if key in seen:
            continue
        seen.add(key)
        dedup_forms.append(fm)


    sqlmap_parsed = None
    if req.run_sqlmap:

        raw_args: List[str] = req.sqlmap_args or []
        extra_args = sanitize_sqlmap_args(raw_args)  
        fetcher2 = Fetcher(concurrency=1)
        tester = SQLiTester(fetcher2)
        try:
            # збираємо urls
            urls = []
            crawl_obj = parts.get("crawl")
            if isinstance(crawl_obj, dict):
                urls_raw = crawl_obj.get("urls", [])
            elif isinstance(crawl_obj, list):
                urls_raw = crawl_obj
            else:
                urls_raw = []

            urls = _ensure_list_of_str(urls_raw)
            if target not in urls:
                urls.append(target)

            sqlmap_res = await tester.run_sqlmap_for_urls(urls, forms=dedup_forms, extra_args=extra_args, timeout=600)

            if isinstance(sqlmap_res, dict) and sqlmap_res.get("ok"):
                sqlmap_parsed = tester._parse_sqlmap_output(sqlmap_res.get("output", ""))
            else:
                sqlmap_parsed = {"ok": False, "raw": sqlmap_res}
        except Exception as e:
            sqlmap_parsed = {"ok": False, "error": str(e)}
        finally:
            await fetcher2.close()
    else:
        sqlmap_parsed = None


    parts["sqlmap"] = sqlmap_parsed
    report_path = build_report(target, parts)
    scan_entry["parts"] = parts
    scan_entry["report_path"] = report_path


    try:

        # query = scans.update().where(scans.c.target == target).values(report_path=report_path, details=parts)
        # await database.execute(query)
        pass
    except Exception:
        pass

    return {"scan_id": req.scan_id, "report": report_path, "parts": parts}