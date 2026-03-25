import asyncio
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import aiohttp

from .config import (
    ENABLE_PORT_VULN_LOOKUP,
    NVD_API_BASE,
    NVD_API_KEY,
    PORT_VULN_CACHE_TTL_SECONDS,
    PORT_VULN_LOOKUP_CONCURRENCY,
    PORT_VULN_MAX_RESULTS,
    PORT_VULN_REQUEST_TIMEOUT_SECONDS,
    VULNERABILITY_LOOKUP_API_BASE,
)

_LOOKUP_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}


def cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _clean_token(value: Optional[str]) -> str:
    cleaned = re.sub(r"[^a-z0-9.+_-]+", " ", str(value or "").lower()).strip()
    return re.sub(r"\s+", " ", cleaned)


def _tokenize(values: Iterable[Optional[str]]) -> List[str]:
    tokens = []
    for value in values:
        cleaned = _clean_token(value)
        if not cleaned:
            continue
        for token in cleaned.split():
            if len(token) >= 3:
                tokens.append(token)
    return list(dict.fromkeys(tokens))


def _derive_vendor(service: Dict[str, Any]) -> Optional[str]:
    vendor = _clean_token(service.get("vendor"))
    if vendor:
        return vendor.replace(" ", "_")

    product = _clean_token(service.get("product"))
    if product:
        return product.split()[0].replace(" ", "_")

    name = _clean_token(service.get("name"))
    if name:
        return name.split()[0].replace(" ", "_")
    return None


def _derive_product(service: Dict[str, Any]) -> Optional[str]:
    product = _clean_token(service.get("product"))
    if product:
        return product.replace(" ", "_")
    name = _clean_token(service.get("name"))
    if name:
        return name.replace(" ", "_")
    return None


def _build_query(service: Dict[str, Any]) -> Dict[str, Optional[str]]:
    product = _derive_product(service)
    version = str(service.get("version") or "").strip() or None
    vendor = _derive_vendor(service)

    keyword_parts = []
    if vendor and vendor != product:
        keyword_parts.append(vendor.replace("_", " "))
    if product:
        keyword_parts.append(product.replace("_", " "))
    if version:
        keyword_parts.append(version)

    if not keyword_parts and service.get("name"):
        keyword_parts.append(str(service["name"]))

    keyword = " ".join(part for part in keyword_parts if part).strip() or None
    return {
        "vendor": vendor,
        "product": product,
        "version": version,
        "keyword": keyword,
    }


def _stringify(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (int, float, bool)):
        return str(obj)
    if isinstance(obj, list):
        return " ".join(_stringify(item) for item in obj)
    if isinstance(obj, dict):
        return " ".join(_stringify(value) for value in obj.values())
    return str(obj)


def _find_first_value(node: Any, keys: List[str]) -> Optional[Any]:
    lowered = {key.lower() for key in keys}

    def _walk(value: Any) -> Optional[Any]:
        if isinstance(value, dict):
            for dict_key, dict_value in value.items():
                if dict_key.lower() in lowered and dict_value not in (None, "", [], {}):
                    return dict_value
            for dict_value in value.values():
                found = _walk(dict_value)
                if found not in (None, "", [], {}):
                    return found
        elif isinstance(value, list):
            for item in value:
                found = _walk(item)
                if found not in (None, "", [], {}):
                    return found
        return None

    return _walk(node)


def _extract_score_from_any(node: Any) -> Optional[float]:
    for keys in (
        ["baseScore"],
        ["score"],
        ["cvss"],
        ["cvss3"],
        ["cvss3_base_score"],
        ["cvss_base_score"],
    ):
        raw = _find_first_value(node, keys)
        if raw is None:
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            continue
    return None


def _extract_description_nvd(cve: Dict[str, Any]) -> str:
    for entry in cve.get("descriptions", []) or []:
        if isinstance(entry, dict) and entry.get("lang") == "en":
            return str(entry.get("value") or "").strip()
    return ""


def _extract_nvd_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, Optional[str]]:
    metric_sets = [
        ("cvssMetricV40", "cvssData", "vectorString"),
        ("cvssMetricV31", "cvssData", "vectorString"),
        ("cvssMetricV30", "cvssData", "vectorString"),
        ("cvssMetricV2", "cvssData", "vectorString"),
    ]
    for metric_key, data_key, vector_key in metric_sets:
        values = metrics.get(metric_key)
        if not isinstance(values, list):
            continue
        for entry in values:
            if not isinstance(entry, dict):
                continue
            data = entry.get(data_key) or {}
            try:
                score = float(data.get("baseScore"))
            except (TypeError, ValueError):
                score = None
            severity = entry.get("baseSeverity") or data.get("baseSeverity") or cvss_to_severity(score)
            vector = data.get(vector_key)
            return score, str(severity), str(vector) if vector else None
    return None, "Unknown", None


def _match_service_tokens(service: Dict[str, Any], haystack: str) -> bool:
    tokens = _tokenize(
        [
            service.get("vendor"),
            service.get("product"),
            service.get("name"),
            service.get("version"),
        ]
    )
    if not tokens:
        return True
    lowered = haystack.lower()
    matched = sum(1 for token in tokens if token in lowered)
    if service.get("version"):
        version = str(service["version"]).lower()
        if version and version in lowered:
            return True
    return matched >= min(2, len(tokens))


def _normalize_vulnerability(raw: Dict[str, Any], source: str, service: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    vuln_id = _find_first_value(raw, ["id", "cveId", "vulnerability_id", "CVE", "cve"])
    if not vuln_id:
        return None
    vuln_id = str(vuln_id).upper()

    description = (
        str(_find_first_value(raw, ["summary", "title", "description", "shortDescription"]) or "").strip()
        or None
    )
    score = _extract_score_from_any(raw)
    severity = str(_find_first_value(raw, ["severity", "baseSeverity"]) or cvss_to_severity(score))
    published = str(_find_first_value(raw, ["published", "published_at", "datePublished", "dateReported"]) or "").strip() or None
    modified = str(_find_first_value(raw, ["lastModified", "updated", "modified", "updated_at"]) or "").strip() or None
    vector = _find_first_value(raw, ["vectorString", "vector"])

    link = None
    if source == "nvd" and vuln_id.startswith("CVE-"):
        link = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    elif VULNERABILITY_LOOKUP_API_BASE:
        link = f"{VULNERABILITY_LOOKUP_API_BASE.rstrip('/')}/vulnerability/{quote(vuln_id.lower())}"

    evidence = _stringify(raw)
    if description:
        evidence = f"{description} {evidence}"
    if not _match_service_tokens(service, evidence):
        return None

    return {
        "id": vuln_id,
        "source": source,
        "sources": [source],
        "summary": description,
        "cvss": score,
        "severity": cvss_to_severity(score) if severity.lower() == "unknown" else severity.title(),
        "published": published,
        "last_modified": modified,
        "vector": str(vector) if vector else None,
        "link": link,
    }


def _merge_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for item in items:
        key = item["id"]
        existing = merged.get(key)
        if not existing:
            merged[key] = item
            continue
        existing["sources"] = sorted(set(existing.get("sources", [])) | set(item.get("sources", [])))
        if (item.get("cvss") or -1) > (existing.get("cvss") or -1):
            existing["cvss"] = item.get("cvss")
            existing["severity"] = item.get("severity")
            existing["vector"] = item.get("vector")
        if not existing.get("summary") and item.get("summary"):
            existing["summary"] = item["summary"]
        if not existing.get("link") and item.get("link"):
            existing["link"] = item["link"]
        if not existing.get("published") and item.get("published"):
            existing["published"] = item["published"]
        if not existing.get("last_modified") and item.get("last_modified"):
            existing["last_modified"] = item["last_modified"]

    return sorted(
        merged.values(),
        key=lambda item: (item.get("cvss") is not None, item.get("cvss") or -1, item.get("id") or ""),
        reverse=True,
    )[:PORT_VULN_MAX_RESULTS]


def build_risk_summary(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not vulnerabilities:
        return {
            "cve_count": 0,
            "highest_cvss": None,
            "severity": "None",
        }

    highest = max((item.get("cvss") for item in vulnerabilities if item.get("cvss") is not None), default=None)
    severity = cvss_to_severity(highest)
    return {
        "cve_count": len(vulnerabilities),
        "highest_cvss": highest,
        "severity": severity,
    }


async def _fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
) -> Any:
    async with session.get(url, params=params, headers=headers or {}) as response:
        if response.status >= 400:
            text = await response.text(errors="ignore")
            raise RuntimeError(f"{response.status} {text[:200]}")
        return await response.json(content_type=None)


async def _lookup_nvd(session: aiohttp.ClientSession, service: Dict[str, Any], query: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    if not NVD_API_BASE or not query.get("keyword"):
        return []

    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    payload = await _fetch_json(
        session,
        NVD_API_BASE,
        params={
            "keywordSearch": query["keyword"],
            "resultsPerPage": str(min(max(1, PORT_VULN_MAX_RESULTS), 10)),
        },
        headers=headers,
    )

    findings: List[Dict[str, Any]] = []
    for entry in payload.get("vulnerabilities", []) or []:
        cve = entry.get("cve")
        if not isinstance(cve, dict):
            continue
        score, severity, vector = _extract_nvd_cvss(cve.get("metrics") or {})
        normalized = _normalize_vulnerability(
            {
                "id": cve.get("id"),
                "summary": _extract_description_nvd(cve),
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "severity": severity,
                "vector": vector,
                "baseScore": score,
                "configurations": cve.get("configurations"),
                "references": cve.get("references"),
            },
            "nvd",
            service,
        )
        if normalized:
            findings.append(normalized)
    return findings


async def _lookup_vulnerability_lookup(
    session: aiohttp.ClientSession,
    service: Dict[str, Any],
    query: Dict[str, Optional[str]],
) -> List[Dict[str, Any]]:
    if not VULNERABILITY_LOOKUP_API_BASE:
        return []

    base = VULNERABILITY_LOOKUP_API_BASE.rstrip("/")
    params = {"per_page": str(min(max(1, PORT_VULN_MAX_RESULTS), 10))}
    if query.get("vendor") and query.get("product"):
        url = f"{base}/vulnerability/search/{quote(query['vendor'])}/{quote(query['product'])}"
    elif query.get("product"):
        url = f"{base}/vulnerability/"
        params["product"] = query["product"]
    else:
        return []

    payload = await _fetch_json(session, url, params=params)
    findings: List[Dict[str, Any]] = []
    for entry in payload.get("data", []) or []:
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_vulnerability(entry, "vulnerability-lookup", service)
        if normalized:
            findings.append(normalized)
    return findings


async def lookup_service_vulnerabilities(session: aiohttp.ClientSession, service: Dict[str, Any]) -> Dict[str, Any]:
    query = _build_query(service)
    cache_key = "|".join(
        [
            str(query.get("vendor") or ""),
            str(query.get("product") or ""),
            str(query.get("version") or ""),
            str(query.get("keyword") or ""),
        ]
    )
    now = time.monotonic()
    cached = _LOOKUP_CACHE.get(cache_key)
    if cached and now - cached[0] <= PORT_VULN_CACHE_TTL_SECONDS:
        return cached[1]

    errors: List[str] = []
    findings: List[Dict[str, Any]] = []

    if ENABLE_PORT_VULN_LOOKUP:
        for fn in (_lookup_nvd, _lookup_vulnerability_lookup):
            try:
                findings.extend(await fn(session, service, query))
            except Exception as exc:
                errors.append(str(exc))

    merged = _merge_findings(findings)
    result = {
        "vulnerabilities": merged,
        "risk": build_risk_summary(merged),
        "lookup_error": "; ".join(errors) if errors else None,
    }
    _LOOKUP_CACHE[cache_key] = (now, result)
    return result


async def enrich_port_report(report: Dict[str, Any]) -> Dict[str, Any]:
    items = report.get("items")
    if not isinstance(items, list) or not items:
        report["summary"] = {
            "open_port_count": 0,
            "highest_cvss": None,
            "highest_severity": "None",
            "ports_with_vulnerabilities": 0,
        }
        return report

    timeout = aiohttp.ClientTimeout(total=max(3, PORT_VULN_REQUEST_TIMEOUT_SECONDS))
    connector = aiohttp.TCPConnector(limit=max(2, PORT_VULN_LOOKUP_CONCURRENCY), ttl_dns_cache=300)
    sem = asyncio.Semaphore(max(1, PORT_VULN_LOOKUP_CONCURRENCY))

    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        async def _enrich(item: Dict[str, Any]) -> Dict[str, Any]:
            service = item.get("service") or {}
            if not isinstance(service, dict) or not any(service.get(key) for key in ("name", "product", "version")):
                item["vulnerabilities"] = []
                item["risk"] = build_risk_summary([])
                item["lookup_error"] = None
                return item
            async with sem:
                enriched = await lookup_service_vulnerabilities(session, service)
            item["vulnerabilities"] = enriched["vulnerabilities"]
            item["risk"] = enriched["risk"]
            item["lookup_error"] = enriched["lookup_error"]
            return item

        report["items"] = await asyncio.gather(*[_enrich(dict(item)) for item in items])

    highest = max(
        (item.get("risk", {}).get("highest_cvss") for item in report["items"] if item.get("risk", {}).get("highest_cvss") is not None),
        default=None,
    )
    ports_with_vulns = sum(1 for item in report["items"] if item.get("risk", {}).get("cve_count", 0) > 0)
    report["summary"] = {
        "open_port_count": len(report["items"]),
        "highest_cvss": highest,
        "highest_severity": cvss_to_severity(highest),
        "ports_with_vulnerabilities": ports_with_vulns,
    }
    return report
