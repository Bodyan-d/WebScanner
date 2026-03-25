import os
from pathlib import Path

from dotenv import load_dotenv


BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"

load_dotenv(dotenv_path=BACKEND_DIR / ".env", verbose=False)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_csv(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return [part.strip() for part in raw.split(",") if part.strip()]


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{(DATA_DIR / 'scans.db').as_posix()}",
)
SQLMAP_CONTAINER_NAME = os.getenv("SQLMAP_CONTAINER_NAME", "sqlmap")
SQLMAP_IMAGE = os.getenv("SQLMAP_IMAGE", "spsproject-sqlmap:latest")
USE_SQLMAP = _env_bool("USE_SQLMAP", False)

MAX_PAGES_LIMIT = max(1, _env_int("MAX_PAGES_LIMIT", 50))
MAX_CONCURRENCY = max(1, _env_int("MAX_CONCURRENCY", 5))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", str(DATA_DIR / "reports"))

CORS_ALLOW_ORIGINS = _env_csv(
    "CORS_ALLOW_ORIGINS",
    ["http://localhost:5173", "http://127.0.0.1:5173"],
)
API_KEY = os.getenv("API_KEY", "").strip()
RATE_LIMIT_WINDOW_SECONDS = max(1, _env_int("RATE_LIMIT_WINDOW_SECONDS", 60))
RATE_LIMIT_MAX_REQUESTS = max(1, _env_int("RATE_LIMIT_MAX_REQUESTS", 20))
STATUS_POLL_RATE_LIMIT_MAX_REQUESTS = max(1, _env_int("STATUS_POLL_RATE_LIMIT_MAX_REQUESTS", 180))
SCAN_CACHE_TTL_SECONDS = max(60, _env_int("SCAN_CACHE_TTL_SECONDS", 1800))
SQLMAP_MAX_URLS = max(0, _env_int("SQLMAP_MAX_URLS", 0))
ENABLE_DOM_XSS = _env_bool("ENABLE_DOM_XSS", False)
PORT_SCAN_TIMEOUT_SECONDS = max(1, _env_int("PORT_SCAN_TIMEOUT_SECONDS", 2))
SERVICE_DETECTION_ENABLED = _env_bool("SERVICE_DETECTION_ENABLED", True)
ENABLE_PORT_VULN_LOOKUP = _env_bool("ENABLE_PORT_VULN_LOOKUP", True)
PORT_VULN_MAX_RESULTS = max(1, _env_int("PORT_VULN_MAX_RESULTS", 5))
PORT_VULN_REQUEST_TIMEOUT_SECONDS = max(3, _env_int("PORT_VULN_REQUEST_TIMEOUT_SECONDS", 12))
PORT_VULN_LOOKUP_CONCURRENCY = max(1, _env_int("PORT_VULN_LOOKUP_CONCURRENCY", 2))
PORT_VULN_CACHE_TTL_SECONDS = max(60, _env_int("PORT_VULN_CACHE_TTL_SECONDS", 43200))
NVD_API_BASE = os.getenv("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0").strip()
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
VULNERABILITY_LOOKUP_API_BASE = os.getenv("VULNERABILITY_LOOKUP_API_BASE", "https://vulnerability.circl.lu/api").strip()
