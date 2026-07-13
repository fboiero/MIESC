"""
JSON-RPC 2.0 message framing for the MIESC Language Server.

The Language Server Protocol frames each JSON-RPC payload with HTTP-style
``Content-Length`` headers over a raw byte stream (stdio). This module keeps
that framing self-contained — no ``pygls`` or other LSP dependency — so the
server stays a thin, dependency-free surface.

Wire format (per the LSP base protocol)::

    Content-Length: <N>\\r\\n
    \\r\\n
    <N bytes of UTF-8 JSON>

Only ``Content-Length`` is required; any other header (e.g. the optional
``Content-Type``) is tolerated and ignored.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
from typing import Any, BinaryIO, Dict, Optional

__all__ = ["encode_message", "read_message"]


def encode_message(payload: Dict[str, Any]) -> bytes:
    """Serialize a JSON-RPC ``payload`` into a Content-Length-framed byte string.

    The body is UTF-8 JSON; the header advertises its exact byte length so the
    peer knows how much to read. Returns the full frame (header + blank line +
    body) ready to write to a binary stream.
    """
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    return header + body


def read_message(stream: BinaryIO) -> Optional[Dict[str, Any]]:
    """Read and decode one Content-Length-framed JSON-RPC message from ``stream``.

    Parses the header block line-by-line until the blank separator, reads exactly
    ``Content-Length`` body bytes, and returns the decoded JSON object. Returns
    ``None`` at end-of-stream or when no readable ``Content-Length`` header is
    present (the signal for the server loop to stop).
    """
    headers: Dict[str, str] = {}
    while True:
        raw = stream.readline()
        if not raw:
            return None  # EOF
        line = raw.decode("ascii") if isinstance(raw, bytes) else raw
        line = line.rstrip("\r\n")
        if line == "":
            break  # end of header block
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    try:
        content_length = int(headers.get("content-length", "0"))
    except ValueError:
        return None
    if content_length <= 0:
        return None

    body = stream.read(content_length)
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return json.loads(body)
