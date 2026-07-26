"""netscan command-line entry point.

Exit codes:
    0   scan completed successfully
    1   runtime error (no resolvable targets, network failure)
    2   invalid command-line arguments or specification
    130 interrupted by the user (Ctrl-C)
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
from typing import Optional

from scanner import __version__
from scanner.core import expand_targets, parse_ports, scan
from scanner.output import render

logger = logging.getLogger("netscan")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_INTERRUPT = 130


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the netscan CLI."""
    parser = argparse.ArgumentParser(
        prog="netscan",
        description="A multi-threaded TCP port scanner.",
        epilog="Only scan hosts you own or are explicitly authorized to test.",
    )
    parser.add_argument("target", help="single IP, hostname, or CIDR range (e.g. 10.0.0.0/24)")
    parser.add_argument(
        "-p", "--ports", default="top-1000",
        help="port(s): single (80), list (22,80,443), range (20-25), or top-1000 (default)",
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="number of worker threads (default: 100)",
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="per-connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--banner", action="store_true",
        help="grab service banners on open ports",
    )
    parser.add_argument(
        "-o", "--output", choices=("table", "json", "csv"), default="table",
        help="output format (default: table)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="enable debug logging on stderr",
    )
    parser.add_argument("--version", action="version", version=f"netscan {__version__}")
    return parser


def _resolvable_targets(targets: list[str]) -> list[str]:
    """Filter out hosts that cannot be resolved, logging each failure."""
    scannable = []
    for host in targets:
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            logger.error("cannot resolve host: %s", host)
            continue
        scannable.append(host)
    return scannable


def main(argv: Optional[list[str]] = None) -> int:
    """Parse arguments, run the scan, and print formatted results."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    try:
        ports = parse_ports(args.ports)
        targets = expand_targets(args.target)
    except ValueError as exc:
        logger.error("%s", exc)
        return EXIT_USAGE

    targets = _resolvable_targets(targets)
    if not targets:
        logger.error("no resolvable targets to scan")
        return EXIT_ERROR

    logger.info(
        "scanning %d host(s) across %d port(s) using %d threads",
        len(targets), len(ports), args.threads,
    )

    try:
        results = scan(
            targets, ports,
            timeout=args.timeout, threads=args.threads, grab_banners=args.banner,
        )
    except KeyboardInterrupt:
        logger.warning("interrupted by user")
        return EXIT_INTERRUPT

    print(render(results, args.output, show_banner=args.banner))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
