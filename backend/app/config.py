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
SCAN_CACHE_TTL_SECONDS = max(60, _env_int("SCAN_CACHE_TTL_SECONDS", 1800))
SQLMAP_MAX_URLS = max(1, _env_int("SQLMAP_MAX_URLS", 10))
ENABLE_DOM_XSS = _env_bool("ENABLE_DOM_XSS", False)
