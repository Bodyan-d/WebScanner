# WebScanner

Asynchronous web security scanner with a FastAPI backend, React frontend, optional `sqlmap` integration, JSON reports, and SQLite history.

## What The Project Does

WebScanner is meant for quick, controlled audits of web applications. It can:

- crawl pages within the same domain,
- collect forms and basic metadata,
- scan common TCP ports,
- inspect HTTP security headers,
- run reflected XSS heuristics,
- run lightweight SQLi differential checks,
- optionally launch deeper SQLi checks with `sqlmap`,
- save reports to disk and summaries to SQLite.

This is still a practical scanner for development and demo environments, not a replacement for a full penetration testing workflow.

## Main Improvements In `some_updates`

The branch now includes:

- safer backend defaults for DB, CORS, cache TTL, and report paths,
- request throttling and optional API key protection,
- fixed `sqlmap` timeout handling and DB update after the `sqlmap` stage,
- background `sqlmap` jobs with polling instead of one long blocking HTTP request,
- faster scan orchestration: ports, headers, crawl, XSS, and basic SQLi now do less serial waiting,
- better XSS and SQLi heuristics with fewer false positives,
- a new `GET /api/health` endpoint,
- a backward-compatible `POST /api/scan` endpoint,
- frontend fixes for loading states, API base URL, result rendering, and keeping existing results visible during follow-up work,
- cleanup of generated DB/report files from git,
- a refreshed `README.md` and basic backend tests.

## Project Structure

```text
.
├─ backend/
│  ├─ app/
│  │  ├─ config.py
│  │  ├─ crawler.py
│  │  ├─ db.py
│  │  ├─ fetcher.py
│  │  ├─ headers_checker.py
│  │  ├─ main.py
│  │  ├─ models.py
│  │  ├─ port_scanner.py
│  │  ├─ reporter.py
│  │  ├─ sqli_tester.py
│  │  └─ xss_tester.py
│  ├─ data/
│  ├─ tests/
│  ├─ db_init.sql
│  ├─ Dockerfile
│  ├─ init_db.sh
│  └─ requirements.txt
├─ frontend/
│  ├─ src/
│  │  ├─ App.jsx
│  │  ├─ index.css
│  │  ├─ main.jsx
│  │  └─ components/
│  ├─ Dockerfile
│  ├─ nginx.conf
│  ├─ package.json
│  └─ vite.config.js
├─ img/
├─ sqlmap/
│  └─ Dockerfile
└─ docker-compose.yml
```

## Configuration

Important backend environment variables:

- `DATABASE_URL`
  Default: SQLite database in `backend/data/scans.db`
- `OUTPUT_DIR`
  Local default: `backend/data/reports`
  Docker compose default: `/tmp/scan_reports`
- `USE_SQLMAP`
  `true` or `false`
- `SQLMAP_IMAGE`
  Docker image used for `sqlmap`
- `SQLMAP_CONTAINER_NAME`
  Prefix for transient `sqlmap` containers
- `MAX_PAGES_LIMIT`
  Maximum crawl depth in pages
- `MAX_CONCURRENCY`
  Maximum API-accepted scan concurrency
- `CORS_ALLOW_ORIGINS`
  Comma-separated allowed origins
- `API_KEY`
  Optional shared key expected in `X-API-Key`
- `RATE_LIMIT_WINDOW_SECONDS`
  API rate-limit window
- `RATE_LIMIT_MAX_REQUESTS`
  API requests allowed per window per client
- `SCAN_CACHE_TTL_SECONDS`
  How long base scan results stay available for follow-up `sqlmap`
- `SQLMAP_MAX_URLS`
  How many URLs from the crawl can be passed to `sqlmap`
- `ENABLE_DOM_XSS`
  Enables Playwright-based DOM confirmation checks

Frontend environment variables:

- `VITE_API_URL`
  Default: `/api`
- `VITE_API_KEY`
  Optional, forwarded as `X-API-Key`

## Running Locally

### Backend

```bash
cd backend
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Generated data:

- SQLite DB: `backend/data/scans.db`
- Reports: `backend/data/reports/`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

By default Vite runs on `http://localhost:5173` and proxies `/api` to `http://localhost:8000`.

## Running With Docker Compose

```bash
docker compose build
docker compose up
```

Services:

- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

In Docker mode, nginx serves the frontend and proxies `/api` to the backend container. Reports are written to `./scan_results` through the mounted `/tmp/scan_reports` directory.

## API Endpoints

### `GET /api/health`

Health check:

```json
{
  "ok": true,
  "sqlmap_enabled": true,
  "cache_items": 0,
  "sqlmap_jobs": 0
}
```

### `POST /api/scan_no_sqlmap`

Runs the base scan only.

```json
{
  "url": "https://example.com",
  "max_pages": 25,
  "concurrency": 3,
  "run_sqlmap": false
}
```

### `POST /api/scan_sqlmap`

Queues a background `sqlmap` job using an existing `scan_id`.

```json
{
  "url": "https://example.com",
  "scan_id": "previous-scan-id",
  "run_sqlmap": true,
  "sqlmap_args": ["--level=3", "--risk=2", "--threads=5", "--batch", "--random-agent"]
}
```

The response returns immediately with a `job` object and `parts.sqlmap.status` set to `queued` or `running`.

### `GET /api/scan_sqlmap/{job_id}`

Polls background `sqlmap` status until it becomes `completed` or `failed`.

Possible states:

- `queued`
- `running`
- `completed`
- `failed`

### `POST /api/scan`

Convenience endpoint that performs the base scan and, if requested, queues the follow-up `sqlmap` stage in the same request.

```json
{
  "url": "https://example.com",
  "max_pages": 25,
  "concurrency": 3,
  "run_sqlmap": true,
  "sqlmap_args": ["--level=3", "--risk=2", "--threads=5"]
}
```

### Optional API Key Header

If `API_KEY` is configured on the backend, send:

```text
X-API-Key: your-shared-key
```

## Example Response Shape

```json
{
  "scan_id": "0eab4f5d-...",
  "target": "https://example.com",
  "report": "/tmp/scan_reports/report_https_example.com_20260324T120000Z.json",
  "job": {
    "job_id": "4b43f2b7-...",
    "scan_id": "0eab4f5d-...",
    "status": "running",
    "error": null,
    "created_at": 12345.0,
    "updated_at": 12350.0,
    "scanned_urls": ["https://example.com/login?id=1"]
  },
  "parts": {
    "ports": {
      "tcp": {
        "80": true,
        "443": true
      }
    },
    "crawl": {
      "urls": ["https://example.com", "https://example.com/login"],
      "forms": [
        [
          "https://example.com/login",
          {
            "method": "post",
            "inputs": {
              "username": "",
              "password": ""
            },
            "enctype": "application/x-www-form-urlencoded"
          }
        ]
      ]
    },
    "headers": {
      "present": {},
      "missing": ["Content-Security-Policy"]
    },
    "xss": [],
    "sqli": [],
    "sqlmap": {
      "status": "running",
      "job_id": "4b43f2b7-...",
      "ok": null,
      "error": null,
      "message": "sqlmap is running.",
      "findings": [],
      "scanned_urls": ["https://example.com/login?id=1"]
    }
  }
}
```

## Tests

Basic backend tests were added for:

- SQLMap argument sanitization,
- summary counting,
- SQLMap output parsing.

Run them with:

```bash
cd backend
python -m pytest
```

## Notes

- The frontend now expects `/api` by default, which works both with Vite proxy and nginx proxy.
- The frontend keeps the already loaded report visible while a follow-up `sqlmap` job is queued or running; only the `sqlmap` tab changes state.
- Long `sqlmap` runs no longer rely on a single long-lived nginx request. The backend returns a job id immediately, and the frontend polls status updates.
- If you want stricter protection, set `API_KEY` in the backend and `VITE_API_KEY` in the frontend.
- `sqlmap` runs are intentionally capped and sanitized to keep the app safer and more predictable.

![Image alt](./img/Screenshot%202026-01-07%20154022.png)
![Image alt](./img/Screenshot%202026-01-07%20154739.png)
![Image alt](./img/Screenshot%202026-01-07%20154746.png)
![Image alt](./img/Screenshot%202026-01-07%20154751.png)
![Image alt](./img/Screenshot%202026-01-07%20154800.png)
![Image alt](./img/Screenshot%202026-01-07%20154805.png)
![Image alt](./img/Screenshot%202026-01-07%20160118.png)
![Image alt](./img/Screenshot%202026-01-07%20154814.png)
![Image alt](./img/Screenshot%202026-01-07%20155342.png)
