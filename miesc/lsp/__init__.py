"""
MIESC Language Server package.

A thin, dependency-free LSP (over stdio) that surfaces MIESC scan diagnostics
and T2.1 deterministic quick-fixes to any editor. The JSON-RPC framing and
message dispatch are implemented in-house (no ``pygls``), keeping the editor
surface a single small core.

Public entry points:

* :class:`~miesc.lsp.server.LspServer` — the server (handlers + stdio loop).
* :func:`~miesc.lsp.diagnostics.finding_to_diagnostic` — MIESC finding → LSP Diagnostic.
* :func:`~miesc.lsp.protocol.encode_message` / :func:`~miesc.lsp.protocol.read_message`
  — Content-Length JSON-RPC framing.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from miesc.lsp.diagnostics import (
    SEVERITY_MAP,
    finding_to_diagnostic,
    severity_to_lsp,
)
from miesc.lsp.protocol import encode_message, read_message
from miesc.lsp.server import LspServer, scan_file_for_diagnostics, server_capabilities

__all__ = [
    "LspServer",
    "scan_file_for_diagnostics",
    "server_capabilities",
    "finding_to_diagnostic",
    "severity_to_lsp",
    "SEVERITY_MAP",
    "encode_message",
    "read_message",
]
