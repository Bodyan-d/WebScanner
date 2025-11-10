import asyncio, os
import json
from fastapi import FastAPI, HTTPException
from typing import Optional, List
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

app = FastAPI(title='WebScanner API')
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)

class ScanRequest(BaseModel):
    url: HttpUrl

    max_pages: int = Field(MAX_PAGES_LIMIT, ge=1, le=MAX_PAGES_LIMIT)
    concurrency: int = Field(MAX_CONCURRENCY, ge=1, le=MAX_CONCURRENCY)
    run_sqlmap: bool = False
    sqlmap_args: Optional[List[str]] = None
    
ALLOWED_SQLMAP_PREFIXES = (
    "--level=", "--risk=", "--threads=", "--crawl=",
    "--tamper=", "--random-agent", "--batch", "--risk=", "--level="
)

def sanitize_sqlmap_args(args: Optional[List[str]]) -> Optional[List[str]]:
    if not args:
        return None
    safe: List[str] = []
    for a in args:
        if not isinstance(a, str):
            continue
        a = a.strip()
        if len(a) == 0 or len(a) > 120:  
            continue
        
        if a in ("--random-agent", "--batch") or any(a.startswith(pref) for pref in ALLOWED_SQLMAP_PREFIXES):
            safe.append(a)
        
        if len(safe) >= 20: 
            break
    return safe or None

@app.on_event('startup')
async def startup():
    await database.connect()

@app.on_event('shutdown')
async def shutdown():
    await database.disconnect()

@app.post('/api/scan')
async def api_scan(req: ScanRequest):
    target = str(req.url)
    parsed = req.url
    host = parsed.host

    # --- Ports scan ---
    try:
        nmap = nmap_scan(host)
        if nmap.get('ok'):
            ports = {'nmap': nmap}
        else:
            tcp = await tcp_scan(host)
            ports = {'tcp': tcp}
    except Exception as e:
        ports = {'error': str(e)}

    # --- Crawl ---
    crawler = Crawler(base_url=target, concurrency=req.concurrency, max_pages=req.max_pages)
    crawl_res: dict | list | None = await crawler.crawl()

    # --- Headers ---
    async with aiohttp.ClientSession() as session:
        header_res = await check_headers(session, target)

    # --- XSS ---
    fetcher = Fetcher(concurrency=req.concurrency)
    xss = await XSSTester(fetcher).scan_urls(crawl_res.get('urls', []))
    await fetcher.close()

    # --- SQLi (basic + optional sqlmap) ---
    fetcher2 = Fetcher(concurrency=1)
    tester = SQLiTester(fetcher2)

    # simple param-based SQLi tests
    sqli = []
    for u in crawl_res.get('urls', []):
        sqli.extend(await tester.basic_diff(u))

        # advanced sqlmap scan
    sqlmap_res = None
    if req.run_sqlmap:
        
        forms = []

        # case A: crawl_res is dict with top-level 'forms'
        if isinstance(crawl_res, dict):
            maybe = crawl_res.get("forms")
            if isinstance(maybe, list):
                forms = maybe
            else:
                # nested under 'crawl' key
                nested = crawl_res.get("crawl")
                if isinstance(nested, dict):
                    maybe2 = nested.get("forms")
                    if isinstance(maybe2, list):
                        forms = maybe2

        # case B: crawl_res is a list of page dicts -> collect 'forms' from items
        elif isinstance(crawl_res, list):
            for item in crawl_res:
                if not isinstance(item, dict):
                    continue
                f = item.get("forms")
                if isinstance(f, list):
                    forms.extend(f)
                    continue
                nested = item.get("crawl")
                if isinstance(nested, dict):
                    nf = nested.get("forms")
                    if isinstance(nf, list):
                        forms.extend(nf)

        # ensure we have a list
        if not isinstance(forms, list):
            forms = []

        # optional: deduplicate forms by (url, inputs) to avoid repeats
        seen = set()
        deduped = []
        for fm in forms:
            try:
                key = (fm.get("url"), json.dumps(fm.get("inputs", {}), sort_keys=True))
            except Exception:
                key = str(fm)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(fm)
        forms = deduped
        
        extra_args = sanitize_sqlmap_args(req.sqlmap_args)
        

        # run sqlmap with discovered forms (or empty list)
        sqlmap_res = await tester.run_sqlmap_async(
            url=target,
            forms=forms,
            extra_args=extra_args,
        )

    await fetcher2.close()

    # --- Combine all results ---
    parts = {
        'ports': ports,
        'crawl': crawl_res,
        'headers': header_res,
        'xss': xss,
        'sqli': sqli,
        'sqlmap': sqlmap_res,
    }

    # --- Report ---
    report_path = build_report(target, parts)

    # --- Save in DB ---
    try:
        summary = {'open_ports': len(parts.get('ports', {}))}
        query = scans.insert().values(
            target=target,
            report_path=report_path,
            summary=summary,
            details=parts
        )
        await database.execute(query)
    except Exception:
        pass

    return {'report': report_path, 'parts': parts}

