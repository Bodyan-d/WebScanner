import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .config import OUTPUT_DIR


def ensure_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _safe_target_slug(target):
    parsed = urlparse(target)
    candidate = f"{parsed.scheme}_{parsed.netloc}{parsed.path}" if parsed.scheme else target
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._")
    return (slug or "scan")[:120]


def build_report(target, parts):
    ensure_dir()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = os.path.join(OUTPUT_DIR, f"report_{_safe_target_slug(target)}_{ts}.json")
    data = {"target": target, "generated": ts, "results": parts}
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return fname
