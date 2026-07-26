"""Core scanning engine: target/port parsing and threaded TCP connect scans."""
from __future__ import annotations

import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable

from scanner.banner import grab_banner
from scanner.common_ports import TOP_1000_PORTS

logger = logging.getLogger(__name__)

MIN_PORT = 1
MAX_PORT = 65535
_TOP_KEYWORDS = frozenset({"top-1000", "top1000", "top"})


@dataclass
class PortResult:
    """The outcome of probing a single host/port pair."""

    host: str
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """Parse a port specification into a sorted list of unique ports.

    Accepts a single port (``"80"``), a comma-separated list (``"22,80,443"``),
    an inclusive range (``"20-25"``), the keyword ``"top-1000"``, or any
    comma-separated combination of these. Raises ``ValueError`` on malformed
    input or out-of-range ports.
    """
    normalized = spec.strip().lower()
    if not normalized:
        raise ValueError("empty port specification")

    ports: set[int] = set()
    for token in normalized.split(","):
        token = token.strip()
        if not token:
            continue
        if token in _TOP_KEYWORDS:
            ports.update(TOP_1000_PORTS)
        elif "-" in token:
            start_s, _, end_s = token.partition("-")
            start, end = _validate_port(start_s), _validate_port(end_s)
            if start > end:
                raise ValueError(f"invalid range '{token}': start exceeds end")
            ports.update(range(start, end + 1))
        else:
            ports.add(_validate_port(token))

    if not ports:
        raise ValueError(f"no valid ports in '{spec}'")
    return sorted(ports)


def _validate_port(value: str) -> int:
    """Convert a string to a valid TCP port number or raise ``ValueError``."""
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid port '{value}'") from exc
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"port {port} out of range {MIN_PORT}-{MAX_PORT}")
    return port


def expand_targets(target: str) -> list[str]:
    """Expand a target into a list of host addresses to scan.

    Accepts a single IPv4/IPv6 address, a CIDR range such as
    ``"192.168.1.0/30"``, or a hostname (returned unchanged so that DNS
    resolution happens at connect time). For CIDR blocks wider than a single
    address the network and broadcast addresses are excluded.
    """
    target = target.strip()
    if not target:
        raise ValueError("empty target")

    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        addresses = hosts if hosts else list(network)
        return [str(ip) for ip in addresses]

    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        return [target]


def scan_port(
    host: str,
    port: int,
    timeout: float,
    grab_banners: bool = False,
) -> PortResult:
    """Attempt a TCP connect to ``host:port`` and report whether it is open."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, TimeoutError, ConnectionRefusedError):
        return PortResult(host, port, is_open=False)
    except socket.gaierror:
        logger.debug("cannot resolve host %s", host)
        return PortResult(host, port, is_open=False)
    except OSError as exc:
        logger.debug("error scanning %s:%d - %s", host, port, exc)
        return PortResult(host, port, is_open=False)

    with sock:
        service = _service_name(port)
        banner = grab_banner(sock, port, timeout) if grab_banners else ""
    return PortResult(host, port, is_open=True, service=service, banner=banner)


def _service_name(port: int) -> str:
    """Return the IANA service name for a TCP port, or an empty string."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def scan(
    targets: Iterable[str],
    ports: Iterable[int],
    *,
    timeout: float = 1.0,
    threads: int = 100,
    grab_banners: bool = False,
) -> list[PortResult]:
    """Scan every host/port combination concurrently and return open ports.

    Results are sorted by host then port. A ``KeyboardInterrupt`` cancels any
    pending work and is re-raised so the caller can exit cleanly.
    """
    tasks = [(host, port) for host in targets for port in ports]
    if not tasks:
        return []

    open_ports: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout, grab_banners): (host, port)
            for host, port in tasks
        }
        try:
            for future in as_completed(futures):
                result = future.result()
                if result.is_open:
                    open_ports.append(result)
        except KeyboardInterrupt:
            logger.warning("scan interrupted; cancelling pending probes")
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    open_ports.sort(key=lambda r: (r.host, r.port))
    return open_ports
