# WebScanner — README (Polski)

> Asynchroniczny skaner sieciowy do szybkiego audytu stron WWW
> (crawling, nagłówki bezpieczeństwa, podstawowy XSS i SQLi, integracja z `sqlmap`)

---

## Spis treści

1. [Opis projektu](#opis-projektu)
2. [Funkcje](#funkcje)
3. [Technologie](#technologie)
4. [Struktura katalogów](#struktura-katalog%C3%B3w)
5. [Szybkie uruchomienie — lokalnie](#szybkie-uruchomienie--lokalnie)
6. [Uruchomienie z Docker / docker-compose](#uruchomienie-z-docker--docker-compose)
7. [Konfiguracja / zmienne środowiskowe](#konfiguracja--zmienne-%C5%9Brodowiskowe)
8. [API — przykłady](#api--przyk%C5%82ady)
9. [Format odpowiedzi — przykładowy wynik](#format-odpowiedzi--przyk%C5%82adowy-wynik)



---

## Opis projektu

**WebScanner** to asynchroniczna aplikacja (backend + frontend), która wykonuje audyt wybranej witryny [WWW](http://WWW). Główne zadania:

* crawluje witrynę (zbiera linki i formularze),
* skanuje porty (nmap lub proste skany TCP),
* sprawdza nagłówki bezpieczeństwa (CSP, HSTS, Referrer-Policy itp.),
* testuje podatności XSS (reflected) i wykonuje podstawowe testy SQLi,
* opcjonalnie uruchamia `sqlmap` w kontenerze Docker dla głębszej analizy,
* generuje raport i zapisuje wyniki w bazie danych.

Projekt jest przeznaczony jako narzędzie do audytu i prototypowania — nie zastępuje pełnych testów penetracyjnych.

---

## Funkcje

* Asynchroniczny crawler oparty na `BeautifulSoup` (limit stron, ograniczenie do domeny).
* Skan portów (nmap lub TCP scan fallback).
* Kontrola nagłówków HTTP i lista brakujących nagłówków bezpieczeństwa.
* XSS tester (reflected) z normalizacją HTML by zmniejszyć false-positives.
* Prosty differential SQLi tester (porównuje odpowiedzi przy payloadach).
* Integracja z `sqlmap` uruchamianym w kontenerze Docker (opcjonalnie, konfigurowalne argumenty).
* Generacja raportu (plik + zapis w DB).
* Frontend (React) z widokiem wyników podzielonych na zakładki.

---

## Technologie

* **Backend:** Python 3.11, FastAPI, aiohttp, asyncio, pathlib, urllib
* **Parser HTML:** BeautifulSoup (lxml)
* **Baza / ORM:** SQLAlchemy, databases
* **Narzędzia zewnętrzne:** sqlmap (Docker)
* **Frontend:** React (Vite)
* **Orkiestracja:** Docker / docker-compose

---

## Struktura katalogów (przykład)

```
.
├─ backend/
│  ├─ app/
|  |  ├─ __init__.py
|  |  ├─ config.py
│  │  ├─ main.py
│  │  ├─ crawler.py
│  │  ├─ fetcher.py
│  │  ├─ xss_tester.py
│  │  ├─ sqli_tester.py
│  │  ├─ port_scanner.py
│  │  ├─ headers_checker.py
│  │  ├─ reporter.py
│  │  ├─ db.py
│  │  └─ models.py
|  ├─ data/
|  |  ├─ scans.db
|  ├─ Dockerfile
|  ├─ init_db.sh
|  ├─ db_init.sql
│  └─ requirements.txt
├─ frontend/
│  ├─ src/
│  │  ├─ App.jsx
│  │  ├─ index.css
│  │  ├─ main.jsx
│  │  └─ components/
│  |  │  ├─ Results.jsx
│  |  │  ├─ ScanForm.jsx
│  |  │  └─ Tabs.jsx
│  ├─ package.json
│  ├─ tailwind.config.js
│  ├─ vite.config.js
│  ├─ nginx.conf
│  ├─ index.html
│  └─ Dockerfile
├─ scan_results/
│  └─ report_[url]__[time/id].json
├─ sqlmap/
│  └─ Dockerfile
└─ docker-compose.yml
```

---

## Szybkie uruchomienie — lokalnie (dev)

### Backend

```bash
cd backend
python -m venv .venv
# mac/linux
source .venv/bin/activate
# windows (powershell)
# .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend (dev)

```bash
cd frontend
npm install
npm run dev
# budowa produkcyjna
npm run build
```

---

## Uruchomienie z Docker / docker-compose

1. Zbuduj obrazy (w katalogu z `docker-compose.yml`):

```bash
docker compose build
```

2. Uruchom kontenery:

```bash
docker compose up
```

Dostęp:

* Frontend (nginx): `http://localhost:5173` (domyślnie mapowane `5173:80`)
* Backend: `http://localhost:8000`

**Uwaga**: jeśli frontend po buildzie wydaje się „stary”, upewnij się, że nie masz zamontowanego wolumenu, który nadpisuje `/usr/share/nginx/html` oraz wykonaj `docker compose up --build`.

---

## Konfiguracja / zmienne środowiskowe

Najważniejsze zmienne (można przekazać przez `docker-compose` lub `.env`):

* `USE_SQLMAP` — `true` / `false` — czy uruchamiać sqlmap
* `SQLMAP_IMAGE` — obraz sqlmap (np. `spsproject-sqlmap:latest`)
* `SQLMAP_CONTAINER_NAME` — (opcjonalnie) nazwa kontenera sqlmap
* `MAX_PAGES_LIMIT`, `MAX_CONCURRENCY` — limity dla crawlera (ustaw w kodzie lub pliku konfiguracyjnym)

---

## API — przykłady

**Endpoint:** `POST /api/scan`

**Body (JSON):**

```json
{
  "url": "https://example.com",
  "max_pages": 30,
  "concurrency": 5,
  "run_sqlmap": true,
  "sqlmap_args": ["--level=1","--risk=1","--threads=5","--crawl=1"]
}
```

**curl:**

```bash
curl -X POST "http://localhost:8000/api/scan" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","max_pages":20,"concurrency":3,"run_sqlmap":false}'
```

---

## Format odpowiedzi — przykładowy wynik 

```json
{
  "report": "/tmp/scan_reports/report_http_example.com__20251109T....json",
  "parts": {
    "ports": { "tcp": { "80": true, "443": true } },
    "crawl": { "urls": ["https://example.com/","https://example.com/search?..."], "forms": [["https://example.com/login", {"method":"post","inputs":{"user":"","pwd":""}}]] },
    "headers": { "present": {...}, "missing": ["Content-Security-Policy","Strict-Transport-Security"] },
    "xss": [ { "url":"...","param":"q","reflected":true,"similarity":0.89 } ],
    "sqli": [ { "url":"...","param":"id","payload":"'","suspected":true } ],
    "sqlmap": [ { "level":"CRITICAL","message":"...","detail":"..." } ]
  }
}
```

## Sugestie rozwoju / roadmapa

* Streaming wyników do frontendu (SSE / WebSocket) — przydatne jeśli sqlmap działa długo.
* Lepszy parser sqlmap (CSV/JSON) i agregacja wykryć.
* UI z historią skanów, eksportem (PDF/HTML) i filtrowaniem wyników.
* Obsługa ciasteczek/sesji i formularzy logowania w crawlerze.
* Testy jednostkowe (pytest) i CI.