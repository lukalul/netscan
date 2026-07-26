"""Banner grabbing for common services over an already-open socket.

Services such as SSH, FTP and SMTP announce themselves on connect, so their
banners are read passively. HTTP servers stay quiet until spoken to, so a
minimal ``HEAD`` request is sent to elicit the response header.
"""
from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)

HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8081, 8088, 8888})
MAX_BANNER_BYTES = 1024


def grab_banner(sock: socket.socket, port: int, timeout: float) -> str:
    """Read a short service banner from an open socket.

    Returns the cleaned banner text, or an empty string if the service does
    not offer one within ``timeout`` seconds.
    """
    sock.settimeout(timeout)
    try:
        if port in HTTP_PORTS:
            return _http_banner(sock)
        return _passive_banner(sock)
    except (socket.timeout, TimeoutError):
        return ""
    except OSError as exc:
        logger.debug("banner read failed on port %d: %s", port, exc)
        return ""


def _passive_banner(sock: socket.socket) -> str:
    """Read a banner that the service sends unprompted (SSH, FTP, SMTP, ...)."""
    return _clean(sock.recv(MAX_BANNER_BYTES))


def _http_banner(sock: socket.socket) -> str:
    """Send a HEAD request and return the reported ``Server`` header."""
    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n")
    text = _clean(sock.recv(MAX_BANNER_BYTES))
    for line in text.split(" | "):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip()
    status = text.split(" | ", 1)[0]
    return status


def _clean(data: bytes) -> str:
    """Decode banner bytes and collapse line breaks into a single line."""
    text = data.decode("latin-1", errors="replace").strip()
    return text.replace("\r\n", " | ").replace("\n", " | ").replace("\r", " | ")
