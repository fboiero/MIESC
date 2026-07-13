"""
Minimal MIESC Language Server (LSP over stdio).

Exposes MIESC's scan + deterministic-fix surface to *any* editor through the
Language Server Protocol, so a single core powers inline diagnostics and
quick-fixes in VS Code, JetBrains, Neovim, etc. The transport is self-contained
JSON-RPC framing (``miesc.lsp.protocol``) — no ``pygls`` or new runtime
dependency.

Scope (minimal-viable, T2.2): the lifecycle (``initialize`` / ``initialized`` /
``shutdown`` / ``exit``) plus two features:

* ``textDocument/didOpen`` and ``textDocument/didSave`` → run a quick scan on the
  ``.sol`` file and push ``textDocument/publishDiagnostics``.
* ``textDocument/codeAction`` → reuse the T2.1 ``build_code_actions`` deterministic
  fixes and return them as LSP quick-fix ``CodeAction`` objects.

Save/change scans are debounced with the same guard ``miesc watch`` uses so a
burst of rapid saves triggers at most one scan per debounce window.

The message handlers are pure functions of ``(params) -> messages`` and are
driven directly by the test-suite; the stdio loop is a thin wrapper over them.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, BinaryIO, Callable, DefaultDict, Dict, List, Optional
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from miesc import __version__ as VERSION
from miesc.cli.constants import QUICK_TOOLS
from miesc.lsp.diagnostics import finding_to_diagnostic, findings_in_range
from miesc.lsp.protocol import encode_message, read_message

__all__ = [
    "LspServer",
    "scan_file_for_diagnostics",
    "uri_to_path",
    "server_capabilities",
]

# LSP TextDocumentSyncKind.Full — the client re-sends the whole document on
# change. Full sync keeps the server stateless about incremental edits.
_SYNC_FULL = 1

ScanFn = Callable[[str], List[Dict[str, Any]]]


def uri_to_path(uri: str) -> str:
    """Convert a ``file://`` URI to a local filesystem path.

    Falls back to returning the input unchanged for non-file URIs or bare paths,
    so callers that already hold a path are unaffected.
    """
    parsed = urlparse(uri)
    if parsed.scheme and parsed.scheme != "file":
        return uri
    if not parsed.scheme:
        return uri
    return url2pathname(unquote(parsed.path))


def server_capabilities() -> Dict[str, Any]:
    """Capabilities advertised in the ``initialize`` response.

    Declares full-document sync (open/close + save carrying text), a diagnostic
    provider, and a quick-fix code-action provider — the minimal surface needed
    for inline findings and one-click fixes.
    """
    return {
        "textDocumentSync": {
            "openClose": True,
            "change": _SYNC_FULL,
            "save": {"includeText": True},
        },
        "diagnosticProvider": {
            "interFileDependencies": False,
            "workspaceDiagnostics": False,
        },
        "codeActionProvider": {"codeActionKinds": ["quickfix"]},
    }


def scan_file_for_diagnostics(
    path: str, tools: Optional[List[str]] = None, timeout: int = 30
) -> List[Dict[str, Any]]:
    """Run a quick MIESC scan on ``path`` and return a flat list of findings.

    Mirrors ``miesc watch``: runs the QUICK_TOOLS adapters, then applies the
    intelligence engine (cross-tool scoring + FP suppression) when available.
    Every finding is tagged with its source ``file``. Designed to be cheap enough
    for interactive editor feedback; heavy LLM passes are intentionally excluded.
    """
    from miesc.cli.utils import run_tool

    scan_tools = tools or list(QUICK_TOOLS)
    findings: List[Dict[str, Any]] = []
    for tool in scan_tools:
        result = run_tool(tool, path, timeout=timeout)
        if result.get("status") == "success":
            findings.extend(result.get("findings", []))

    try:
        from miesc.core.intelligence import enhance_findings

        if findings:
            try:
                code_text = Path(path).read_text(encoding="utf-8")
            except OSError:
                code_text = ""
            enhanced = enhance_findings(findings, source_code=code_text, file_path=path)
            findings = [f for f in enhanced if not f.get("fp_suppressed")]
    except Exception:  # noqa: BLE001 — intelligence is best-effort, never fatal
        pass

    for finding in findings:
        finding.setdefault("file", path)
    return findings


class LspServer:
    """A minimal, dependency-free LSP server for MIESC diagnostics + quick-fixes.

    Handlers are plain methods returning the JSON-RPC messages to send back; the
    :meth:`serve` loop only reads frames, dispatches, and writes responses. This
    keeps every feature unit-testable without spawning a real stdio process.
    """

    def __init__(self, scan_fn: Optional[ScanFn] = None, debounce: float = 1.0) -> None:
        self._scan_fn: ScanFn = scan_fn or scan_file_for_diagnostics
        self._debounce = debounce
        self._last_scan: DefaultDict[str, float] = defaultdict(float)
        self._documents: Dict[str, str] = {}
        self._findings: Dict[str, List[Dict[str, Any]]] = {}
        self._initialized = False
        self._shutdown_requested = False
        self.running = True

    # ------------------------------------------------------------------
    # JSON-RPC envelope helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _response(msg_id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _notification(method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "method": method, "params": params}

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def dispatch(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Route one incoming JSON-RPC ``message`` to its handler.

        Returns the list of outgoing messages (a request's response plus any
        server-initiated notifications such as ``publishDiagnostics``). Unknown
        requests get a ``null`` result; unknown notifications are ignored.
        """
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method == "initialize":
            return [self._response(msg_id, self.handle_initialize(params))]
        if method == "initialized":
            self._initialized = True
            return []
        if method == "shutdown":
            self._shutdown_requested = True
            return [self._response(msg_id, None)]
        if method == "exit":
            self.running = False
            return []
        if method == "textDocument/didOpen":
            return self.handle_did_open(params)
        if method == "textDocument/didSave":
            return self.handle_did_save(params)
        if method == "textDocument/didChange":
            return self.handle_did_change(params)
        if method == "textDocument/codeAction":
            return [self._response(msg_id, self.handle_code_action(params))]

        # Unknown request → benign null result; unknown notification → drop.
        if msg_id is not None:
            return [self._response(msg_id, None)]
        return []

    # ------------------------------------------------------------------
    # Lifecycle handlers
    # ------------------------------------------------------------------

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return server capabilities + identity for the ``initialize`` request."""
        self._initialized = False
        return {
            "capabilities": server_capabilities(),
            "serverInfo": {"name": "miesc-lsp", "version": VERSION},
        }

    # ------------------------------------------------------------------
    # Document sync handlers
    # ------------------------------------------------------------------

    def handle_did_open(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``didOpen``: cache the document text and scan immediately (no debounce)."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        if not uri:
            return []
        self._documents[uri] = td.get("text", "")
        return self._scan_and_publish(uri, force=True)

    def handle_did_save(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``didSave``: refresh text if provided, then debounced re-scan."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        if not uri:
            return []
        if "text" in params:
            self._documents[uri] = params["text"] or ""
        return self._scan_and_publish(uri, force=False)

    def handle_did_change(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``didChange`` (Full sync): replace cached text, debounced re-scan."""
        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        if not uri:
            return []
        changes = params.get("contentChanges") or []
        if changes:
            # Full-sync client: the last change carries the whole document.
            self._documents[uri] = changes[-1].get("text", "")
        return self._scan_and_publish(uri, force=False)

    # ------------------------------------------------------------------
    # Feature handler: code actions (reuses T2.1 build_code_actions)
    # ------------------------------------------------------------------

    def handle_code_action(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """``codeAction``: return T2.1 deterministic fixes as LSP quick-fixes.

        Filters the last scan's findings to the requested range, feeds them to
        the shared :func:`build_code_actions` builder, and wraps each resulting
        edit set in an LSP ``CodeAction`` (kind ``quickfix``, ``edit.changes``
        keyed by document URI). The T2.1 ``edits`` are already 0-based
        ``{range,newText}`` LSP ``TextEdit`` dicts, so no coordinate remapping
        is needed.
        """
        from miesc.cli.commands.fix import build_code_actions

        td = params.get("textDocument", {})
        uri = td.get("uri", "")
        if not uri:
            return []

        rng = params.get("range")
        findings = findings_in_range(self._findings.get(uri, []), rng)
        if not findings:
            return []

        source = self._documents.get(uri)
        if source is None:
            try:
                source = Path(uri_to_path(uri)).read_text(encoding="utf-8")
            except OSError:
                return []

        label = uri_to_path(uri)
        t21_actions = build_code_actions(source, findings, label)
        return [self._to_lsp_code_action(action, uri) for action in t21_actions]

    @staticmethod
    def _to_lsp_code_action(action: Dict[str, Any], uri: str) -> Dict[str, Any]:
        """Wrap a T2.1 CodeAction dict as an LSP ``CodeAction`` with a workspace edit."""
        return {
            "title": action["title"],
            "kind": action.get("kind", "quickfix"),
            "edit": {"changes": {uri: action["edits"]}},
        }

    # ------------------------------------------------------------------
    # Scan + publish (with watch-style debounce)
    # ------------------------------------------------------------------

    def _should_scan(self, uri: str) -> bool:
        """Debounce guard (same shape as ``miesc watch``): at most one scan per window."""
        now = time.monotonic()
        if now - self._last_scan[uri] < self._debounce:
            return False
        self._last_scan[uri] = now
        return True

    def _scan_and_publish(self, uri: str, *, force: bool) -> List[Dict[str, Any]]:
        """Scan the file behind ``uri`` and produce a ``publishDiagnostics`` message.

        ``force`` bypasses the debounce (used for ``didOpen`` — the user just
        opened the file and expects immediate feedback). Save/change go through
        the debounce and yield no message when skipped.
        """
        if force:
            self._last_scan[uri] = time.monotonic()
        elif not self._should_scan(uri):
            return []

        path = uri_to_path(uri)
        findings = self._scan_fn(path)
        self._findings[uri] = findings

        doc_text = self._documents.get(uri)
        diagnostics = [finding_to_diagnostic(f, doc_text) for f in findings]
        return [
            self._notification(
                "textDocument/publishDiagnostics",
                {"uri": uri, "diagnostics": diagnostics},
            )
        ]

    # ------------------------------------------------------------------
    # stdio serve loop
    # ------------------------------------------------------------------

    def serve(
        self, stdin: Optional[BinaryIO] = None, stdout: Optional[BinaryIO] = None
    ) -> None:
        """Run the blocking read → dispatch → write loop over binary streams.

        Reads Content-Length-framed requests from ``stdin``, dispatches each, and
        writes framed responses/notifications to ``stdout``. Exits on EOF or after
        an ``exit`` notification.
        """
        in_stream = stdin or sys.stdin.buffer
        out_stream = stdout or sys.stdout.buffer

        while self.running:
            message = read_message(in_stream)
            if message is None:
                break
            for outgoing in self.dispatch(message):
                out_stream.write(encode_message(outgoing))
                out_stream.flush()
