import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(dotenv_path=Path('.') / '.env', verbose=False)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./scan_results.db")
SQLMAP_CONTAINER_NAME = os.getenv("SQLMAP_CONTAINER_NAME", "sqlmap")
USE_SQLMAP = os.getenv("USE_SQLMAP", "false").lower() in ("1","true","yes")
MAX_PAGES_LIMIT = int(os.getenv("MAX_PAGES_LIMIT", "50"))
MAX_CONCURRENCY = int(os.getenv("MAX_CONCURRENCY", "5"))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/tmp/scan_reports")

USE_SQLMAP = True

SQLMAP_IMAGE = os.getenv("SQLMAP_IMAGE", "spsproject-sqlmap:latest")

