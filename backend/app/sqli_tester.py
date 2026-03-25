import asyncio
import json
import logging
import re
import sys
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, cast
from urllib.parse import urlparse, urlunparse

from .config import SQLMAP_CONTAINER_NAME, SQLMAP_IMAGE, USE_SQLMAP
from .fetcher import Fetcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

BASIC_PAYLOADS = ["'", '"', " OR 1=1 -- "]
OVERRIDABLE_SQLMAP_PREFIXES = ("--level=", "--risk=", "--threads=", "--crawl=", "--tamper=")

try:
    import docker
    from docker.errors import APIError, ImageNotFound
except Exception:
    docker = None  # type: ignore
    APIError = Exception  # type: ignore
    ImageNotFound = Exception  # type: ignore


def _rewrite_localhost_for_container(url: str) -> str:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname in ("localhost", "127.0.0.1"):
            new_host = "host.docker.internal"
            new_netloc = f"{new_host}:{parsed.port}" if parsed.port else new_host
            return urlunparse((parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
    except Exception:
        logger.exception("rewrite_localhost failed for url %s", url)
    return url


def _merge_sqlmap_args(defaults: List[str], extra_args: Optional[List[str]]) -> List[str]:
    merged = list(defaults)
    for extra in extra_args or []:
        prefix = next((item for item in OVERRIDABLE_SQLMAP_PREFIXES if extra.startswith(item)), None)
        if prefix:
            merged = [arg for arg in merged if not arg.startswith(prefix)]
        if extra not in merged:
            merged.append(extra)
    return merged


class SQLiTester:
    def __init__(self, fetcher: Optional[Fetcher] = None):
        self.fetcher = fetcher
        self._docker_client = None

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
            base_status = base_resp.status
        except Exception as e:
            logger.debug("basic_diff: failed to fetch base url %s: %s", url, e)
            base_text = ""
            base_status = None

        for p in qs.keys():
            for payload in BASIC_PAYLOADS:
                mod = {k: v[0] for k, v in qs.items()}
                mod[p] = mod.get(p, "") + payload
                new_q = urllib.parse.urlencode(mod)
                target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                try:
                    resp = await self.fetcher.get(target)
                    text = await resp.text(errors="ignore")
                    status_changed = base_status is not None and resp.status != base_status
                    significant_length_delta = abs(len(text) - len(base_text)) > max(40, int(len(base_text) * 0.3))
                    if resp.status >= 500 or (status_changed and resp.status >= 400) or significant_length_delta:
                        results.append(
                            {
                                "param": p,
                                "payload": payload,
                                "url": target,
                                "suspected": True,
                                "status": resp.status,
                                "evidence": [
                                    item
                                    for item, enabled in (
                                        ("server_error", resp.status >= 500),
                                        ("status_change", status_changed and resp.status >= 400),
                                        ("response_length_shift", significant_length_delta),
                                    )
                                    if enabled
                                ],
                            }
                        )
                        break
                except Exception as e:
                    logger.debug("basic_diff: request failed %s -> %s", target, e)
        return results

    def _get_docker_client(self):
        if self._docker_client is not None:
            return self._docker_client
        if docker is None:
            raise RuntimeError("docker SDK is not installed in this environment")
        self._docker_client = docker.from_env()
        return self._docker_client

    def _ensure_image_ready(self, image: str) -> Optional[str]:
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

    async def run_sqlmap_async(
        self,
        url: str,
        extra_args: Optional[List[str]] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 600,
    ) -> Dict[str, Any]:
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
        args = _merge_sqlmap_args(defaults, extra_args)
        logger.info("sqli_tester: ARGS: %r", args)

        def _normalize_one(raw: Any) -> Optional[Dict[str, Any]]:
            try:
                if isinstance(raw, dict):
                    return cast(Dict[str, Any], raw)
                if isinstance(raw, (tuple, list)) and len(raw) >= 2 and isinstance(raw[1], dict):
                    normalized: Dict[str, Any] = {"url": str(raw[0])}
                    normalized.update(raw[1])
                    return normalized
                logger.debug("sqli_tester: skipping unknown form shape: %r", raw)
                return None
            except Exception:
                logger.exception("sqli_tester: failed to normalize form: %r", raw)
                return None

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
                if not inputs:
                    return []

                enctype = str(form.get("enctype", "application/x-www-form-urlencoded")).lower()
                if "json" in enctype:
                    try:
                        data_obj = {k: "test" for k in inputs.keys()}
                        added += ["--data", json.dumps(data_obj)]
                        added += ["--headers", "Content-Type: application/json"]
                    except Exception:
                        data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                        added += ["--data", data]
                else:
                    data = "&".join(f"{k}={urllib.parse.quote_plus('test')}" for k in inputs.keys())
                    added += ["--data", data]
                return added
            except Exception:
                logger.exception("sqli_tester: failed to prepare data for form %r", form)
                return []

        if forms:
            normalized_forms: List[Dict[str, Any]] = []
            for raw in forms:
                normalized = _normalize_one(raw)
                if normalized:
                    normalized_forms.append(normalized)

            for form in normalized_forms:
                post_args = _prepare_post_args_from_form(form)
                if post_args:
                    args.extend(post_args)
                    break

        final_args = ["-u", safe_url] + args
        logger.info("sqli_tester: FINAL sqlmap args: %r", final_args)
        return await asyncio.to_thread(self._run_sqlmap_container, final_args, timeout)

    def _run_sqlmap_container(self, cmd_args: List[str], timeout: int) -> Dict[str, Any]:
        if docker is None:
            return {"ok": False, "error": "docker SDK not available"}

        try:
            client = self._get_docker_client()
        except RuntimeError as e:
            logger.exception("Docker SDK not available")
            return {"ok": False, "error": str(e)}

        raw_image = (SQLMAP_IMAGE or "").strip() or "spsproject-sqlmap:latest"
        image = raw_image.lstrip("/")
        container = None

        try:
            try:
                client.images.get(image)
            except Exception:
                logger.info("Pulling sqlmap image: %s", image)
                client.images.pull(image)

            container_name = f"{SQLMAP_CONTAINER_NAME}-{uuid.uuid4().hex[:8]}" if SQLMAP_CONTAINER_NAME else None
            container = client.containers.run(
                image=image,
                command=cmd_args,
                detach=True,
                stdout=True,
                stderr=True,
                remove=False,
                name=container_name,
                labels={"app": "webscanner", "component": "sqlmap"},
            )

            deadline = time.monotonic() + max(1, timeout)
            timed_out = False
            while time.monotonic() < deadline:
                container.reload()
                if container.status in {"exited", "dead"}:
                    break
                time.sleep(1.0)
            else:
                timed_out = True
                try:
                    container.kill()
                except Exception:
                    logger.exception("Failed to kill timed out sqlmap container")

            try:
                wait_result = container.wait(timeout=5)
                exit_status = int(wait_result.get("StatusCode", 1))
            except Exception:
                exit_status = 124 if timed_out else 1

            output_bytes = container.logs(stdout=True, stderr=True)
            output = output_bytes.decode(errors="replace") if isinstance(output_bytes, (bytes, bytearray)) else str(output_bytes)

            if timed_out:
                return {"ok": False, "error": f"sqlmap timed out after {timeout}s", "output": output}
            if exit_status == 0:
                return {"ok": True, "output": output}
            return {"ok": False, "error": f"container error exit {exit_status}", "output": output}

        except ImageNotFound as e:
            return {"ok": False, "error": f"image not found: {e}"}
        except APIError as e:
            return {"ok": False, "error": f"docker api error: {e}"}
        except Exception as exc:
            logger.exception("Unexpected error when running sqlmap container")
            return {"ok": False, "error": str(exc)}
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Could not remove sqlmap container %s", getattr(container, "name", "<unknown>"))

    def _parse_sqlmap_output(self, raw: str) -> List[Dict[str, Any]]:
        if not raw:
            return []

        findings: List[Dict[str, Any]] = []
        seen = set()

        confirmed_patterns = [
            r"is vulnerable",
            r"is injectable",
            r"sql injection vulnerability",
            r"identified the following injection point",
            r"back-end dbms",
            r"parameter",
            r"payload:",
            r"type: boolean-based blind",
            r"type: error-based",
            r"type: time-based",
            r"possible",
        ]

        ignore_patterns = [
            r"testing",
            r"trying",
            r"could not",
            r"connection",
            r"resuming",
            r"parameter\(s\) not found",
            r"all tested parameters",
            r"fetched data logged",
            r"starting",
            r"ending",
            r"check",
            r"info",
            r"enumerating",
            r"payload value used",
            r"http error",
            r"unknown",
        ]

        line_re = re.compile(r"^(?:\[\d{2}:\d{2}:\d{2}\]\s*)?\[(?P<level>[A-Z]+)\]\s*(?P<msg>.*)$")
        current_block = {"level": "OTHER", "lines": []}

        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            match = line_re.match(line)
            if match:
                if current_block["lines"]:
                    full_msg = "\n".join(current_block["lines"]).strip()
                    low_msg = full_msg.lower()
                    if not any(re.search(pat, low_msg) for pat in ignore_patterns):
                        if any(re.search(pat, low_msg) for pat in confirmed_patterns) or current_block["level"] in ("CRITICAL", "ERROR"):
                            key = (current_block["level"], full_msg)
                            if key not in seen:
                                seen.add(key)
                                short_msg = full_msg.split(".", 1)[0][:100].strip()
                                findings.append(
                                    {
                                        "level": current_block["level"],
                                        "message": short_msg,
                                        "detail": full_msg,
                                        "lines": current_block["lines"],
                                    }
                                )
                current_block = {"level": match.group("level"), "lines": [match.group("msg").strip()]}
            else:
                current_block["lines"].append(line)

        if current_block["lines"]:
            full_msg = "\n".join(current_block["lines"]).strip()
            low_msg = full_msg.lower()
            if not any(re.search(pat, low_msg) for pat in ignore_patterns):
                if any(re.search(pat, low_msg) for pat in confirmed_patterns) or current_block["level"] in ("CRITICAL", "ERROR"):
                    key = (current_block["level"], full_msg)
                    if key not in seen:
                        seen.add(key)
                        short_msg = full_msg.split(".", 1)[0][:100].strip()
                        findings.append(
                            {
                                "level": current_block["level"],
                                "message": short_msg,
                                "detail": full_msg,
                                "lines": current_block["lines"],
                            }
                        )

        return findings

    async def run_sqlmap_for_urls(
        self,
        urls: List[str],
        extra_args: Optional[List[str]] = None,
        forms: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 600,
        concurrency: int = 3,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        if not urls:
            return results

        normalized_forms: List[Dict[str, Any]] = []
        for raw in forms or []:
            if isinstance(raw, dict):
                normalized_forms.append(cast(Dict[str, Any], raw))

        ordered_urls = list(dict.fromkeys(urls))
        ordered_urls.sort(key=lambda item: (not bool(urlparse(item).query), item))

        raw_image = (SQLMAP_IMAGE or "").strip() or "spsproject-sqlmap:latest"
        image = raw_image.lstrip("/")

        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, self._ensure_image_ready, image)
        except Exception:
            logger.debug("Image pre-pull failed or skipped; continuing and letting runner handle it.")

        sem = asyncio.Semaphore(max(1, concurrency))

        async def _worker(url: str):
            async with sem:
                try:
                    logger.info("Running sqlmap on %s", url)
                    local_extra = list(extra_args) if extra_args else []
                    matching_forms = [
                        form
                        for form in normalized_forms
                        if str(form.get("url") or form.get("action") or "").strip() == url
                    ]
                    if not any(a.startswith("--crawl") for a in local_extra):
                        local_extra.append("--crawl=0" if urlparse(url).query or matching_forms else "--crawl=1")
                    if not any(a.startswith("--threads") for a in local_extra):
                        local_extra.append("--threads=10")

                    res = await self.run_sqlmap_async(
                        url,
                        extra_args=local_extra,
                        forms=matching_forms or None,
                        timeout=timeout,
                    )
                    if not res.get("ok"):
                        logger.warning("sqlmap failed on %s: %s", url, res.get("error"))
                        return []
                    output = res.get("output", "")
                    parsed = self._parse_sqlmap_output(output)
                    for finding in parsed:
                        finding["url"] = url
                    return parsed
                except Exception as e:
                    logger.exception("Failed to scan %s: %s", url, e)
                    return []

        tasks = [asyncio.create_task(_worker(u)) for u in ordered_urls]
        all_found = await asyncio.gather(*tasks, return_exceptions=False)
        for subset in all_found:
            if isinstance(subset, list):
                results.extend(subset)
        return results


def run_sqlmap_sync_direct(
    url: str,
    extra_args: Optional[List[str]] = None,
    forms: Optional[List[Dict[str, Any]]] = None,
    timeout: int = 600,
) -> Dict[str, Any]:
    if docker is None:
        return {"ok": False, "error": "docker SDK not available"}

    try:
        tester = SQLiTester(fetcher=None)
        safe_url = _rewrite_localhost_for_container(url)
        defaults = [
            "--batch",
            "--random-agent",
            "--level=3",
            "--risk=2",
            "--threads=5",
        ]
        args = _merge_sqlmap_args(defaults, extra_args)

        if forms:
            for form in forms:
                method = str(form.get("method", "get")).lower()
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
        return tester._run_sqlmap_container(cmd_args, timeout)
    except Exception as exc:
        logger.exception("run_sqlmap_sync_direct failed")
        return {"ok": False, "error": str(exc)}
