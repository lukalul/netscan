"""Result formatting: human-readable table (default), JSON, and CSV."""
from __future__ import annotations

import csv
import io
import json
from typing import Sequence

from scanner.core import PortResult


def render(results: Sequence[PortResult], output_format: str, show_banner: bool) -> str:
    """Render scan results in the requested format (``table``, ``json``, ``csv``)."""
    if output_format == "json":
        return _format_json(results)
    if output_format == "csv":
        return _format_csv(results)
    return _format_table(results, show_banner)


def _rows(results: Sequence[PortResult]) -> list[dict[str, object]]:
    return [
        {
            "host": r.host,
            "port": r.port,
            "state": "open",
            "service": r.service,
            "banner": r.banner,
        }
        for r in results
    ]


def _format_json(results: Sequence[PortResult]) -> str:
    return json.dumps(_rows(results), indent=2)


def _format_csv(results: Sequence[PortResult]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["host", "port", "state", "service", "banner"]
    )
    writer.writeheader()
    writer.writerows(_rows(results))
    return buffer.getvalue().rstrip("\r\n")


def _format_table(results: Sequence[PortResult], show_banner: bool) -> str:
    if not results:
        return "No open ports found."

    headers = ["HOST", "PORT", "STATE", "SERVICE"]
    if show_banner:
        headers.append("BANNER")

    rows = []
    for r in results:
        row = [r.host, str(r.port), "open", r.service or "-"]
        if show_banner:
            row.append(r.banner or "-")
        rows.append(row)

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def line(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells))

    out = [line(headers), line(["-" * w for w in widths])]
    out.extend(line(row) for row in rows)
    out.append(f"\n{len(results)} open port(s) found.")
    return "\n".join(out)
