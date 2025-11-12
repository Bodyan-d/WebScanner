import logging
import asyncio
import json
import sys
import urllib.parse
import re
from typing import Any, Dict, List, Optional, cast
from urllib.parse import urlparse, urlunparse
import itertools
from concurrent.futures import ThreadPoolExecutor

from .fetcher import Fetcher
from .config import USE_SQLMAP, SQLMAP_IMAGE, SQLMAP_CONTAINER_NAME

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


BASIC_PAYLOADS = ["'", "\"", " OR 1=1 -- "]


try:
    import docker
    from docker.errors import ContainerError, ImageNotFound, APIError
except Exception:
    docker = None  # type: ignore
    ContainerError = Exception  # type: ignore
    ImageNotFound = Exception  # type: ignore
    APIError = Exception  # type: ignore


def _rewrite_localhost_for_container(url: str) -> str:
    """
    If url points to localhost/127.0.0.1, rewrite host to host.docker.internal
    (works for Docker Desktop on Windows/Mac). Keep port if present.
    Returns original url if no rewrite needed.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname in ("localhost", "127.0.0.1"):
            new_host = "host.docker.internal"
            if parsed.port:
                new_netloc = f"{new_host}:{parsed.port}"
            else:
                new_netloc = new_host
            return urlunparse((parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        logger.exception("rewrite_localhost failed for url %s", url)
    return url


class SQLiTester:
    def __init__(self, fetcher: Optional[Fetcher] = None):
        """
        fetcher can be None if only running sqlmap container commands.
        For basic_diff you should pass a valid Fetcher instance.
        """
        self.fetcher = fetcher
        self._docker_client = None

    # -----------------------
    # Basic differential tester (async)
    # -----------------------
    async def basic_diff(self, url: str) -> List[Dict[str, Any]]:
        if self.fetcher is None:
            raise RuntimeError("basic_diff requires a Fetcher instance")

        parsed = urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        results: List[Dict[str, Any]] = []
        if not qs:
            return results

        try:
            base_resp = await self.fetcher.get(url)
            base_text = await base_resp.text(errors="ignore")
        except Exception as e:
            logger.debug("basic_diff: failed to fetch base url %s: %s", url, e)
            base_text = ""

        for p in qs.keys():
            for payload in BASIC_PAYLOADS:
                mod = {k: v[0] for k, v in qs.items()}
                mod[p] = mod.get(p, "") + payload
                new_q = urllib.parse.urlencode(mod)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                try:
                    resp = await self.fetcher.get(target)
                    text = await resp.text(errors="ignore")
                    if resp.status >= 500 or len(text) != len(base_text):
                        results.append({
                            "param": p,
                            "payload": payload,
                            "url": target,
                            "suspected": True,
                            "status": resp.status
                        })
                        break
                except Exception as e:
                    logger.debug("basic_diff: request failed %s -> %s", target, e)
        return results

    # -----------------------
    # Docker helper
    # -----------------------
    def _get_docker_client(self):
        if self._docker_client is not None:
            return self._docker_client
        if docker is None:
            raise RuntimeError("docker SDK is not installed in this environment")
        self._docker_client = docker.from_env()
        return self._docker_client

    def _ensure_image_ready(self, image: str) -> Optional[str]:
        """
        Ensure image is available locally (pull once). Returns image name or None on error.
        This is synchronous (Docker SDK).
        """
        if docker is None:
            logger.warning("Docker SDK not available for pre-pull")
            return None
        try:
            client = self._get_docker_client()
            try:
                client.images.get(image)
                logger.info("sqlmap image already present: %s", image)
            except Exception:
                logger.info("Pulling sqlmap image (first time): %s", image)
                client.images.pull(image)
            return image
        except Exception as e:
            logger.exception("Failed to ensure image: %s", e)
            return None

    # -----------------------
    # Run sqlmap in temporary container (async wrapper)
    # -----------------------
    async def run_sqlmap_async(
        self,
        url: str,
        extra_args: Optional[List[str]] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Start sqlmap inside a container (Docker SDK). Returns:
            {'ok': bool, 'output': str, 'error': str|None, ...}
        - extra_args: list of additional sqlmap args (overrides defaults).
        - forms: optional list of forms discovered by crawler (to test POST bodies / JSON).
        """

        logger.info("sqli_tester: EXTRA ARGS: %r", extra_args)
        if not USE_SQLMAP:
            return {"ok": False, "error": "sqlmap disabled (USE_SQLMAP=False)"}

        safe_url = _rewrite_localhost_for_container(url)

        defaults = [
            "--batch",
            "--random-agent",
            "--smart",
            "--flush-session",
            "--level=3",
            "--risk=2",
            "--threads=5",
        ]

        # Use extra_args if given, otherwise defaults
        args: List[str] = list(extra_args) if extra_args else list(defaults)
        logger.info("sqli_tester: ARGS: %r", args)

        # --- Helper: normalize a single raw form element into a dict ---
        def _normalize_one(raw: Any) -> Optional[Dict[str, Any]]:
            try:
                if isinstance(raw, dict):
                    return cast(Dict[str, Any], raw)

                if isinstance(raw, (tuple, list)):
                    # case: (url, dict)
                    if len(raw) == 2 and isinstance(raw[1], dict):
                        url_part = raw[0]
                        if not isinstance(url_part, str):
                            url_part = str(url_part)
                        nf: Dict[str, Any] = {"url": url_part}
                        nf.update(raw[1])
                        return nf

                    # case: (url, method_or_dict, ...)
                    if len(raw) >= 2 and isinstance(raw[0], str):
                        second = raw[1]
                        if isinstance(second, dict):
                            nf = {"url": raw[0]}
                            nf.update(second)
                            return nf

                # unknown shape
                logger.debug("sqli_tester: skipping unknown form shape: %r", raw)
                return None
            except Exception:
                logger.exception("sqli_tester: failed to normalize form: %r", raw)
                return None

        # --- Helper: prepare args for a POST form dict (first suitable) ---
        def _prepare_post_args_from_form(form: Dict[str, Any]) -> List[str]:
            added: List[str] = []
            try:
                method = str(form.get("method", "get")).lower()
                if method != "post":
                    return []

                inputs = form.get("inputs") or {}
                if not isinstance(inputs, dict):
                    try:
                        inputs = dict(inputs)
                    except Exception:
                        inputs = {}

                enctype = str(form.get("enctype", "application/x-www-form-urlencoded")).lower()

                if "json" in enctype:
                    try:
                        data_obj = {k: "test" for k in inputs.keys()}
                        added += ["--data", json.dumps(data_obj)]
                        added += ["--headers", "Content-Type: application/json"]
                    except Exception:
                        # fallback to urlencoded
                        data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                        added += ["--data", data]
                else:
                    data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                    added += ["--data", data]

                return added
            except Exception:
                logger.exception("sqli_tester: failed to prepare data for form %r", form)
                return []

        # If forms provided, normalize and try to attach the first suitable POST
        if forms:
            normalized: List[Dict[str, Any]] = []
            for raw in forms:
                nf = _normalize_one(raw)
                if nf:
                    normalized.append(nf)

            for form in normalized:
                post_args = _prepare_post_args_from_form(form)
                if post_args:
                    args += post_args
                    break  # attach only the first suitable POST form

        # Ensure '-u' is at the start (sqlmap image ENTRYPOINT expects args only)
        final_args = ["-u", safe_url] + args
        logger.info("sqli_tester: FINAL sqlmap args: %r", final_args)

        # run blocking in thread
        return await asyncio.to_thread(self._run_sqlmap_container, final_args, timeout)


    def _run_sqlmap_container(self, cmd_args: List[str], timeout: int) -> Dict[str, Any]:
        """
        Blocking: runs the sqlmap image/container via Docker SDK.
        Returns dict with ok/output/error.
        """
        if docker is None:
            return {"ok": False, "error": "docker SDK not available"}

        try:
            client = self._get_docker_client()
        except RuntimeError as e:
            logger.exception("Docker SDK not available")
            return {"ok": False, "error": str(e)}

        # image: prefer configured image then fallback to spsproject-sqlmap:latest
        raw_image = (SQLMAP_IMAGE or "").strip() or "spsproject-sqlmap:latest"
        image = raw_image.lstrip("/")

        try:
            # ensure image present (pull if name is remote)
            try:
                client.images.get(image)
            except Exception:
                logger.info("Pulling sqlmap image: %s", image)
                client.images.pull(image)

            # Use containers.run with detach=False -> returns logs (blocking)
            try:
                output_bytes = client.containers.run(
                    image=image,
                    command=cmd_args,
                    detach=False,
                    stdout=True,
                    stderr=True,
                    remove=True
                )
                output = output_bytes.decode(errors="replace") if isinstance(output_bytes, (bytes, bytearray)) else str(output_bytes)
                return {"ok": True, "output": output}
            except ContainerError as e:
                stdout = getattr(e, "stdout", None)
                stderr = getattr(e, "stderr", None)
                return {
                    "ok": False,
                    "error": f"container error exit {getattr(e, 'exit_status', 'unknown')}",
                    "stdout": (stdout.decode(errors="replace") if stdout else ""),
                    "stderr": (stderr.decode(errors="replace") if stderr else "")
                }

        except ImageNotFound as e:
            return {"ok": False, "error": f"image not found: {e}"}
        except APIError as e:
            return {"ok": False, "error": f"docker api error: {e}"}
        except Exception as exc:
            logger.exception("Unexpected error when running sqlmap container")
            return {"ok": False, "error": str(exc)}
        
    def _parse_sqlmap_output(self, raw: str) -> List[Dict[str, Any]]:
        """
        Парсить stdout sqlmap і повертає лише реальні знахідки про вразливості.
        Фільтрує службові INFO/WARNING повідомлення.
        """
        if not raw:
            return []

        findings: List[Dict[str, Any]] = []
        seen = set()

        # ключові фрази, які в sqlmap зазвичай означають *справжню уразливість*
        confirmed_keywords = (
            "is vulnerable",
            "is injectable",
            "sql injection vulnerability",
            "identified the following injection point",
            "back-end dbms",
            "parameter",
            "payload:",
            "type: boolean-based blind",
            "type: error-based",
            "type: time-based",
            "the back-end dbms",
        )

        # фрази, які хочемо проігнорувати (тести, мережеві попередження і т.п.)
        ignore_keywords = (
            "testing",
            "trying",
            "could not",
            "connection",
            "resuming",
            "parameter(s) not found",
            "all tested parameters",
            "fetched data logged",
            "starting",
            "ending",
            "check",
            "info",
            "enumerating",
            "payload value used",
            "http error",
            "unknown",
            "possible",
        )

        line_re = re.compile(
            r'^(?:\[\d{2}:\d{2}:\d{2}\]\s*)?\[(?P<level>[A-Z]+)\]\s*(?P<msg>.*)$'
        )

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            m = line_re.match(line)
            if m:
                lvl = m.group("level")
                msg = m.group("msg").strip()
            else:
                lvl = "OTHER"
                msg = line

            low = msg.lower()

            # ігноруємо службові або нецікаві повідомлення
            if any(k in low for k in ignore_keywords):
                continue

            # беремо лише ті, де є ознаки справжніх вразливостей
            if any(k in low for k in confirmed_keywords) or lvl in ("CRITICAL", "ERROR"):
                key = (lvl, msg)
                if key in seen:
                    continue
                seen.add(key)
                short = msg.split(".", 1)[0].strip()
                findings.append({
                    "level": lvl,
                    "message": short,
                    "detail": msg,
                    "line": line
                })

        return findings
    
    async def run_sqlmap_for_urls(
        self,
        urls: List[str],
        extra_args: Optional[List[str]] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 600,
        concurrency: int = 6
    ) -> List[Dict[str, Any]]:
        """
        Паралельно проганяє sqlmap по списку URL'ів з обмеженням concurrency.
        Повертає список знайдених уразливостей (як раніше).

        Параметри:
            - urls: список url для перевірки
            - extra_args: додаткові аргументи sqlmap (список рядків)
            - forms: список форм (для POST/JSON)
            - timeout: таймаут на кожен виклик (секунди)
            - concurrency: скільки контейнерів запускати одночасно
        """
        results: List[Dict[str, Any]] = []
        if not urls:
            return results

        # підготувати образ заздалегідь, щоб уникнути pull в кожному виклику
        raw_image = (SQLMAP_IMAGE or "").strip() or "spsproject-sqlmap:latest"
        image = raw_image.lstrip("/")
        # це виконуємо в потоці (synchronous docker ops)
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._ensure_image_ready, image)
        except Exception:
            # якщо не вдалось підвантажити образ — продовжимо, бо _run_sqlmap_container теж спробує
            logger.debug("Image pre-pull failed or skipped; continuing and letting runner handle it.")

        sem = asyncio.Semaphore(concurrency)

        async def _worker(url: str):
            async with sem:
                try:
                    logger.info("Running sqlmap on %s", url)
                    # Передати extra_args але додати --crawl=0 за замовчуванням, якщо користувач не задав
                    local_extra = list(extra_args) if extra_args else []
                    if not any(a.startswith("--crawl") for a in local_extra):
                        local_extra.append("--crawl=0")
                    # Якщо користувач не задав threads — запропонуємо більше (але не обов'язково)
                    if not any(a.startswith("--threads") for a in local_extra):
                        local_extra.append("--threads=10")

                    res = await self.run_sqlmap_async(url, extra_args=local_extra, forms=forms, timeout=timeout)
                    if not res.get("ok"):
                        logger.warning("sqlmap failed on %s: %s", url, res.get("error"))
                        return []
                    output = res.get("output", "")
                    parsed = self._parse_sqlmap_output(output)
                    if parsed:
                        for f in parsed:
                            f["url"] = url
                    return parsed
                except Exception as e:
                    logger.exception("Failed to scan %s: %s", url, e)
                    return []

        # Запускаємо worker'и (контролюємо concurrency через семафор)
        tasks = [asyncio.create_task(_worker(u)) for u in urls]
        all_found = await asyncio.gather(*tasks, return_exceptions=False)

        for sub in all_found:
            if isinstance(sub, list):
                results.extend(sub)
        return results


# convenience synchronous helper
def run_sqlmap_sync_direct(url: str, extra_args: Optional[List[str]] = None, forms: Optional[List[Dict[str, Any]]] = None, timeout: int = 600) -> Dict[str, Any]:
    """
    Synchronous helper to run sqlmap using Docker SDK directly.
    """
    result: Dict[str, Any] = {"ok": False, "error": "unknown"}

    if docker is None:
        return {"ok": False, "error": "docker SDK not available"}

    try:
        tester = SQLiTester(fetcher=None)
        # adapt same logic as run_sqlmap_async (rewrite localhost, prepare args)
        safe_url = _rewrite_localhost_for_container(url)
        defaults = [
            "--batch",
            "--random-agent",
            "--level=3",
            "--risk=2",
            "--threads=5",
        ]
        args = list(extra_args) if extra_args else defaults

        # attach form data if provided
        if forms:
            for form in forms:
                method = form.get("method", "get").lower()
                if method != "post":
                    continue
                inputs = form.get("inputs", {}) or {}
                enctype = form.get("enctype", "application/x-www-form-urlencoded").lower()
                if "json" in enctype:
                    try:
                        data_obj = {k: "test" for k in inputs.keys()}
                        args += ["--data", json.dumps(data_obj)]
                        args += ["--headers", "Content-Type: application/json"]
                    except Exception:
                        data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                        args += ["--data", data]
                else:
                    data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                    args += ["--data", data]
                break

        cmd_args = ["-u", safe_url] + args
        result = tester._run_sqlmap_container(cmd_args, timeout)
    except Exception as exc:
        logger.exception("run_sqlmap_sync_direct failed")
        result = {"ok": False, "error": str(exc)}

    return result
