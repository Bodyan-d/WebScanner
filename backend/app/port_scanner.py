import asyncio
import re
import shutil
import socket
import ssl
import subprocess
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

from .config import PORT_SCAN_TIMEOUT_SECONDS, SERVICE_DETECTION_ENABLED
from .vuln_lookup import enrich_port_report

TOP_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 3306, 5432, 8000, 8080, 8443]
KNOWN_PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
}


def _apply_port_summary(report: Dict[str, Any]) -> Dict[str, Any]:
    items = report.get("items") or []
    report["summary"] = {
        "open_port_count": len(items),
        "highest_cvss": None,
        "highest_severity": "None",
        "ports_with_vulnerabilities": 0,
    }
    report["lookup_status"] = "pending"
    return report


async def _tcp_check(host, port, timeout=PORT_SCAN_TIMEOUT_SECONDS):
    loop = asyncio.get_running_loop()

    def _sync():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    return await loop.run_in_executor(None, _sync)


async def tcp_scan(host, ports=TOP_PORTS):
    tasks = [_tcp_check(host, p) for p in ports]
    res = await asyncio.gather(*tasks)
    return {p: bool(ok) for p, ok in zip(ports, res)}


def _parse_nmap_xml_output(output: str, ports: List[int]) -> Dict[str, Any]:
    parsed_ports = {int(port): False for port in ports}
    items: List[Dict[str, Any]] = []
    root = ElementTree.fromstring(output)

    for port_node in root.findall(".//port"):
        protocol = port_node.attrib.get("protocol", "tcp")
        if protocol != "tcp":
            continue
        try:
            port = int(port_node.attrib.get("portid", "0"))
        except ValueError:
            continue

        state_node = port_node.find("state")
        state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
        is_open = state == "open"
        parsed_ports[port] = is_open
        if not is_open:
            continue

        service_node = port_node.find("service")
        service = None
        if service_node is not None:
            service = {
                "name": service_node.attrib.get("name"),
                "product": service_node.attrib.get("product"),
                "version": service_node.attrib.get("version"),
                "vendor": service_node.attrib.get("vendorproductname"),
                "extrainfo": service_node.attrib.get("extrainfo"),
                "ostype": service_node.attrib.get("ostype"),
                "method": service_node.attrib.get("method"),
                "conf": service_node.attrib.get("conf"),
                "tunnel": service_node.attrib.get("tunnel"),
                "detection": "nmap-sV",
            }

        items.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "open": True,
                "service": service,
                "vulnerabilities": [],
                "risk": None,
                "lookup_error": None,
            }
        )

    return {
        "ok": True,
        "source": "nmap",
        "ports": parsed_ports,
        "items": sorted(items, key=lambda item: item["port"]),
        "raw_output": output,
    }


def nmap_scan(host, ports=TOP_PORTS):
    if not shutil.which("nmap"):
        return {"ok": False, "error": "nmap not installed"}

    args = ["nmap", "-Pn", "-oX", "-", "-p", ",".join(str(x) for x in ports), host]
    if SERVICE_DETECTION_ENABLED:
        args[2:2] = ["-sV", "--version-light"]

    try:
        out = subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=75)
        return _parse_nmap_xml_output(out, ports)
    except Exception as e:
        return {"ok": False, "error": str(e)}


async def _open_stream(host: str, port: int, use_ssl: bool = False):
    ssl_context = None
    server_hostname = None
    if use_ssl:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        server_hostname = host
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=server_hostname),
        timeout=PORT_SCAN_TIMEOUT_SECONDS,
    )


def _service_from_server_header(server_header: str) -> Dict[str, Any]:
    raw = server_header.strip()
    product = raw
    version = None
    if "/" in raw:
        product, version = raw.split("/", 1)
    return {
        "name": "http",
        "product": product.strip() or None,
        "version": version.strip() or None,
        "banner": raw,
        "detection": "banner-http",
    }


async def _probe_http(host: str, port: int, use_ssl: bool) -> Optional[Dict[str, Any]]:
    reader, writer = await _open_stream(host, port, use_ssl=use_ssl)
    try:
        request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii", errors="ignore"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=PORT_SCAN_TIMEOUT_SECONDS)
        text = data.decode("latin-1", errors="ignore")
        match = re.search(r"(?im)^Server:\s*(.+)$", text)
        service = _service_from_server_header(match.group(1) if match else "http")
        service["name"] = "https" if use_ssl else "http"
        return service
    finally:
        writer.close()
        await writer.wait_closed()


async def _probe_banner(host: str, port: int, name: str) -> Optional[Dict[str, Any]]:
    reader, writer = await _open_stream(host, port, use_ssl=False)
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=PORT_SCAN_TIMEOUT_SECONDS)
        banner = data.decode("latin-1", errors="ignore").strip()
        if not banner:
            return {"name": name, "detection": "banner"}
        version = None
        if name == "ssh":
            match = re.search(r"^SSH-\d+\.\d+-([^\s]+)", banner)
            if match:
                version = match.group(1)
        return {
            "name": name,
            "product": banner.split(" ", 1)[0][:80],
            "version": version,
            "banner": banner[:200],
            "detection": "banner",
        }
    finally:
        writer.close()
        await writer.wait_closed()


async def _probe_mysql(host: str, port: int) -> Optional[Dict[str, Any]]:
    reader, writer = await _open_stream(host, port, use_ssl=False)
    try:
        data = await asyncio.wait_for(reader.read(128), timeout=PORT_SCAN_TIMEOUT_SECONDS)
        if len(data) < 6:
            return {"name": "mysql", "detection": "banner"}
        try:
            version_end = data.index(b"\x00", 5)
            version = data[5:version_end].decode("latin-1", errors="ignore").strip()
        except ValueError:
            version = None
        return {
            "name": "mysql",
            "product": "MySQL",
            "version": version,
            "banner": data[:40].hex(),
            "detection": "banner",
        }
    finally:
        writer.close()
        await writer.wait_closed()


async def _probe_postgresql(host: str, port: int) -> Optional[Dict[str, Any]]:
    reader, writer = await _open_stream(host, port, use_ssl=False)
    try:
        writer.write(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8), timeout=PORT_SCAN_TIMEOUT_SECONDS)
        if data[:1] in {b"S", b"N"}:
            return {
                "name": "postgresql",
                "product": "PostgreSQL",
                "banner": data[:8].hex(),
                "detection": "protocol-probe",
            }
        return {"name": "postgresql", "detection": "protocol-probe"}
    finally:
        writer.close()
        await writer.wait_closed()


async def detect_service(host: str, port: int) -> Optional[Dict[str, Any]]:
    try:
        if port in {80, 8000, 8080}:
            return await _probe_http(host, port, use_ssl=False)
        if port in {443, 8443}:
            return await _probe_http(host, port, use_ssl=True)
        if port == 3306:
            return await _probe_mysql(host, port)
        if port == 5432:
            return await _probe_postgresql(host, port)
        if port in {21, 22, 25, 110, 143}:
            return await _probe_banner(host, port, KNOWN_PORT_NAMES.get(port, "unknown"))
    except Exception:
        pass

    name = KNOWN_PORT_NAMES.get(port)
    if name:
        return {"name": name, "detection": "known-port"}
    return None


async def scan_ports(host: str, ports=TOP_PORTS, include_vulnerabilities: bool = True) -> Dict[str, Any]:
    nmap = await asyncio.to_thread(nmap_scan, host, ports)
    if isinstance(nmap, dict) and nmap.get("ok"):
        report = nmap
        return await enrich_port_report(report) if include_vulnerabilities else _apply_port_summary(report)

    tcp = await tcp_scan(host, ports)
    items = []
    for port, is_open in sorted(tcp.items()):
        if not is_open:
            continue
        service = await detect_service(host, port)
        items.append(
            {
                "port": int(port),
                "protocol": "tcp",
                "state": "open",
                "open": True,
                "service": service,
                "vulnerabilities": [],
                "risk": None,
                "lookup_error": None,
            }
        )

    report = {
        "ok": True,
        "source": "tcp",
        "ports": {int(port): bool(is_open) for port, is_open in tcp.items()},
        "items": items,
        "fallback_reason": nmap.get("error") if isinstance(nmap, dict) else None,
    }
    return await enrich_port_report(report) if include_vulnerabilities else _apply_port_summary(report)
