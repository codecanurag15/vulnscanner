"""
core.scanner
------------
Lightweight, dependency-free TCP connect scanner with banner grabbing and
basic product/version fingerprinting. Used by both the CLI and the GUI.

Only uses the standard library (socket, ssl, threading) so it runs anywhere
Python 3.8+ runs, with no install step.
"""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Sequence


@dataclass
class PortResult:
    port: int
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    product: Optional[str] = None
    version: Optional[str] = None


# A broad set of commonly-exposed ports: standard services, databases,
# remote access, and common web/alt-web ports.
COMMON_PORTS: List[int] = sorted({
    21, 22, 23, 25, 53, 69, 80, 110, 111, 123, 135, 139, 143, 161, 389,
    443, 445, 465, 514, 587, 631, 636, 873, 902, 993, 995,
    1099, 1433, 1521, 1723, 2049, 2181, 2375, 2379, 3000, 3268, 3306,
    3389, 3690, 4000, 4443, 4567, 5000, 5432, 5601, 5672, 5900, 5901,
    5984, 6000, 6379, 6443, 7001, 7199, 8000, 8008, 8009, 8080, 8081,
    8086, 8161, 8443, 8500, 8888, 8983, 9000, 9042, 9092, 9100, 9200,
    9300, 9418, 9999, 11211, 15672, 25565, 27017, 27018, 28017, 50000,
})

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    631: "IPP", 636: "LDAPS", 873: "rsync", 902: "VMware-Auth",
    993: "IMAPS", 995: "POP3S", 1099: "RMI", 1433: "MSSQL", 1521: "Oracle-DB",
    1723: "PPTP", 2049: "NFS", 2181: "ZooKeeper", 2375: "Docker",
    2379: "etcd", 3000: "HTTP-Dev", 3268: "Global-Catalog", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4000: "HTTP-Alt", 4443: "HTTPS-Alt",
    4567: "HTTP-Alt", 5000: "HTTP-Alt", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "AMQP", 5900: "VNC", 5901: "VNC", 5984: "CouchDB", 6000: "X11",
    6379: "Redis", 6443: "Kubernetes-API", 7001: "WebLogic",
    7199: "Cassandra-JMX", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8009: "AJP", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8086: "InfluxDB",
    8161: "ActiveMQ", 8443: "HTTPS-Alt", 8500: "Consul", 8888: "HTTP-Alt",
    8983: "Solr", 9000: "HTTP-Alt", 9042: "Cassandra", 9092: "Kafka",
    9100: "Printer/JetDirect", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 9999: "HTTP-Alt", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    25565: "Minecraft", 27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web",
    50000: "SAP",
}

_TLS_PORTS = {443, 465, 636, 993, 995, 2096, 4443, 6443, 8443, 8161}


def resolve_target(target: str) -> str:
    """Resolve a hostname/URL-ish string or IP to an IPv4/IPv6 address."""
    cleaned = target.strip()
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", cleaned)  # strip scheme
    cleaned = cleaned.split("/")[0].split(":")[0]  # strip path and port
    return socket.gethostbyname(cleaned)


def _http_probe(sock: socket.socket, host: str) -> bytes:
    req = (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vulnscanner/1.0\r\n"
        f"Connection: close\r\n\r\n"
    )
    sock.sendall(req.encode())
    return sock.recv(4096)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Connect to a port and try to pull back an identifying banner."""
    is_tls = port in _TLS_PORTS

    def _connect():
        raw = socket.create_connection((ip, port), timeout=timeout)
        if not is_tls:
            return raw
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=ip)

    # Attempt 1: passive read — many services (SSH, FTP, SMTP, Redis...)
    # announce themselves unprompted right after the handshake.
    try:
        with _connect() as sock:
            sock.settimeout(min(timeout, 1.2))
            data = sock.recv(2048)
            if data:
                return data.decode(errors="ignore")
    except Exception:
        pass

    # Attempt 2: HTTP HEAD probe. Web services on arbitrary/non-standard
    # ports are extremely common, so this isn't limited to known web ports.
    try:
        with _connect() as sock:
            sock.settimeout(timeout)
            data = _http_probe(sock, ip)
            if data:
                return data.decode(errors="ignore")
    except Exception:
        pass

    # Attempt 3: bare newline nudge, for protocols that wait to be spoken to.
    try:
        with _connect() as sock:
            sock.settimeout(timeout)
            sock.sendall(b"\r\n")
            data = sock.recv(2048)
            return data.decode(errors="ignore")
    except Exception:
        return ""


# (regex, product_name_template, version_group) — order matters, first match wins.
_FINGERPRINTS = [
    (re.compile(r"Server:\s*Apache/?([\d.]+)?", re.I), "Apache"),
    (re.compile(r"Server:\s*nginx/?([\d.]+)?", re.I), "nginx"),
    (re.compile(r"Server:\s*Microsoft-IIS/?([\d.]+)?", re.I), "IIS"),
    (re.compile(r"Server:\s*lighttpd/?([\d.]+)?", re.I), "lighttpd"),
    (re.compile(r"Server:\s*cloudflare", re.I), "Cloudflare"),
    (re.compile(r"X-Powered-By:\s*PHP/?([\d.]+)?", re.I), "PHP"),
    (re.compile(r"X-Powered-By:\s*Express", re.I), "Express"),
    (re.compile(r"SSH-\d\.\d-OpenSSH[_-]([\d.p]+)", re.I), "OpenSSH"),
    (re.compile(r"SSH-\d\.\d-([\w.]+)", re.I), "SSH"),
    (re.compile(r"220.*ProFTPD\s+([\d.]+)", re.I), "ProFTPD"),
    (re.compile(r"220.*vsFTPd\s+([\d.]+)", re.I), "vsFTPd"),
    (re.compile(r"220.*FileZilla Server\s*([\d.]+)?", re.I), "FileZilla-Server"),
    (re.compile(r"220.*Postfix", re.I), "Postfix"),
    (re.compile(r"220.*Exim\s+([\d.]+)", re.I), "Exim"),
    (re.compile(r"\+OK.*Dovecot", re.I), "Dovecot"),
    (re.compile(r"mysql_native_password|([\d.]+)-MariaDB", re.I), "MariaDB/MySQL"),
    (re.compile(r"Redis version[:\s]+([\d.]+)", re.I), "Redis"),
    (re.compile(r"MongoDB", re.I), "MongoDB"),
    (re.compile(r"RFB 00(\d)\.00(\d)", re.I), "VNC"),
]


def parse_product_version(banner: str):
    """Best-effort extraction of (product, version) from a raw banner/response."""
    if not banner:
        return None, None
    for pattern, product in _FINGERPRINTS:
        m = pattern.search(banner)
        if m:
            version = None
            if m.groups():
                groups = [g for g in m.groups() if g]
                if groups:
                    version = groups[0] if len(groups) == 1 else ".".join(groups)
            return product, version
    # Generic "Server: X/Y" fallback
    m = re.search(r"Server:\s*([A-Za-z][\w.\-]*)/?([\d][\w.\-]*)?", banner, re.I)
    if m:
        return m.group(1), m.group(2)
    return None, None


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[PortResult]:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except Exception:
        return None
    banner = grab_banner(ip, port, timeout=max(timeout, 1.5))
    product, version = parse_product_version(banner)
    return PortResult(
        port=port,
        state="open",
        service=SERVICE_NAMES.get(port, "unknown"),
        banner=banner.strip()[:500],
        product=product,
        version=version,
    )


def scan_target(
    ip: str,
    ports: Optional[Sequence[int]] = None,
    max_workers: int = 100,
    timeout: float = 1.0,
    progress_cb: Optional[Callable[[int, int, int], None]] = None,
) -> List[PortResult]:
    """Scan `ports` (defaults to COMMON_PORTS) on `ip`, threaded.

    progress_cb(done, total, port) is called after every port finishes,
    regardless of whether it was open, so callers can drive a progress bar.
    """
    ports = list(ports or COMMON_PORTS)
    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        done = 0
        for fut in as_completed(futures):
            done += 1
            port = futures[fut]
            try:
                r = fut.result()
            except Exception:
                r = None
            if r:
                results.append(r)
            if progress_cb:
                progress_cb(done, len(ports), port)
    results.sort(key=lambda r: r.port)
    return results
