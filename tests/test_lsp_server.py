"""
Tests for the minimal MIESC Language Server (T2.2).

Covers:
  - JSON-RPC Content-Length framing round-trips (encode → read).
  - initialize → capabilities advertise diagnostic + codeAction providers.
  - didOpen on a vulnerable .sol → publishDiagnostics with correct
    range / severity / source / code (scan mocked to a known finding).
  - didSave debounce reuses the watch-style guard (second save skipped).
  - codeAction → T2.1-shaped quickfix edits wrapped as an LSP CodeAction.
  - severity mapping table (MIESC label → LSP 1..4).
  - lifecycle: shutdown / exit stop the loop.
"""

from __future__ import annotations

import io

from miesc.lsp.diagnostics import (
    LSP_SEVERITY_ERROR,
    LSP_SEVERITY_HINT,
    LSP_SEVERITY_INFORMATION,
    LSP_SEVERITY_WARNING,
    finding_to_diagnostic,
    severity_to_lsp,
)
from miesc.lsp.protocol import encode_message, read_message
from miesc.lsp.server import LspServer, server_capabilities

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REENTRANCY_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Victim {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
}
"""

# A MIESC finding as produced by the scan pipeline: reentrancy on withdraw,
# 1-based line 7, HIGH severity. Carries the fields the diagnostic + code-action
# builders read (type / function / line / severity / message).
REENTRANCY_FINDING = {
    "type": "reentrancy",
    "function": "withdraw",
    "line": 7,
    "severity": "High",
    "message": "Reentrancy in withdraw()",
    "rule_id": "reentrancy-eth",
    "fix_code": "x",
}

FILE_URI = "file:///tmp/Victim.sol"


def _mock_scan(_findings):
    """Build a scan_fn that ignores the path and returns the given findings."""

    def _scan(path):  # noqa: ARG001 — path intentionally unused in the mock
        return [dict(f) for f in _findings]

    return _scan


# ---------------------------------------------------------------------------
# JSON-RPC framing
# ---------------------------------------------------------------------------


class TestProtocolFraming:
    def test_encode_has_content_length_header(self):
        frame = encode_message({"jsonrpc": "2.0", "id": 1, "result": {}})
        assert frame.startswith(b"Content-Length: ")
        assert b"\r\n\r\n" in frame

    def test_round_trip(self):
        payload = {"jsonrpc": "2.0", "id": 7, "method": "x", "params": {"a": [1, 2]}}
        stream = io.BytesIO(encode_message(payload))
        assert read_message(stream) == payload

    def test_content_length_matches_body_bytes(self):
        frame = encode_message({"k": "áéí"})  # multi-byte UTF-8
        header, body = frame.split(b"\r\n\r\n", 1)
        declared = int(header.split(b"Content-Length:")[1].strip())
        assert declared == len(body)

    def test_read_at_eof_returns_none(self):
        assert read_message(io.BytesIO(b"")) is None


# ---------------------------------------------------------------------------
# initialize / capabilities
# ---------------------------------------------------------------------------


class TestInitialize:
    def test_capabilities_include_diagnostic_and_code_action_providers(self):
        caps = server_capabilities()
        assert "diagnosticProvider" in caps
        assert "codeActionProvider" in caps
        assert caps["codeActionProvider"]["codeActionKinds"] == ["quickfix"]
        assert caps["textDocumentSync"]["openClose"] is True

    def test_initialize_response_shape(self):
        server = LspServer(scan_fn=_mock_scan([]))
        out = server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert len(out) == 1
        result = out[0]["result"]
        assert "diagnosticProvider" in result["capabilities"]
        assert "codeActionProvider" in result["capabilities"]
        assert result["serverInfo"]["name"] == "miesc-lsp"


# ---------------------------------------------------------------------------
# didOpen → publishDiagnostics
# ---------------------------------------------------------------------------


class TestDidOpenDiagnostics:
    def _open(self):
        server = LspServer(scan_fn=_mock_scan([REENTRANCY_FINDING]), debounce=0.0)
        out = server.dispatch(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {
                    "textDocument": {
                        "uri": FILE_URI,
                        "languageId": "solidity",
                        "version": 1,
                        "text": REENTRANCY_CONTRACT,
                    }
                },
            }
        )
        return server, out

    def test_publishes_diagnostics_notification(self):
        _server, out = self._open()
        assert len(out) == 1
        msg = out[0]
        assert msg["method"] == "textDocument/publishDiagnostics"
        assert msg["params"]["uri"] == FILE_URI
        assert len(msg["params"]["diagnostics"]) == 1

    def test_diagnostic_range_severity_source_code(self):
        _server, out = self._open()
        diag = out[0]["params"]["diagnostics"][0]
        # 1-based finding line 7 → 0-based line 6.
        assert diag["range"]["start"]["line"] == 6
        assert diag["range"]["start"]["character"] == 0
        # end char extends to the real length of the open document's line.
        assert diag["range"]["end"]["line"] == 6
        assert diag["range"]["end"]["character"] > 0
        assert diag["severity"] == LSP_SEVERITY_ERROR  # High → Error
        assert diag["source"] == "miesc"
        assert diag["code"] == "reentrancy-eth"
        assert "Reentrancy" in diag["message"]

    def test_no_findings_publishes_empty_list(self):
        server = LspServer(scan_fn=_mock_scan([]), debounce=0.0)
        out = server.dispatch(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": FILE_URI, "text": REENTRANCY_CONTRACT}},
            }
        )
        assert out[0]["params"]["diagnostics"] == []


# ---------------------------------------------------------------------------
# didSave debounce
# ---------------------------------------------------------------------------


class TestDidSaveDebounce:
    def test_second_rapid_save_is_debounced(self):
        server = LspServer(scan_fn=_mock_scan([REENTRANCY_FINDING]), debounce=60.0)
        save = {
            "jsonrpc": "2.0",
            "method": "textDocument/didSave",
            "params": {"textDocument": {"uri": FILE_URI}, "text": REENTRANCY_CONTRACT},
        }
        first = server.dispatch(save)
        second = server.dispatch(save)
        assert len(first) == 1  # first save scans + publishes
        assert second == []  # second within window → skipped

    def test_save_scans_when_debounce_zero(self):
        server = LspServer(scan_fn=_mock_scan([REENTRANCY_FINDING]), debounce=0.0)
        out = server.dispatch(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didSave",
                "params": {"textDocument": {"uri": FILE_URI}, "text": REENTRANCY_CONTRACT},
            }
        )
        assert out[0]["method"] == "textDocument/publishDiagnostics"


# ---------------------------------------------------------------------------
# codeAction → T2.1 quickfix
# ---------------------------------------------------------------------------


class TestCodeAction:
    def _server_with_findings(self):
        server = LspServer(scan_fn=_mock_scan([REENTRANCY_FINDING]), debounce=0.0)
        # Prime the finding + document cache via didOpen.
        server.dispatch(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": FILE_URI, "text": REENTRANCY_CONTRACT}},
            }
        )
        return server

    def test_code_action_returns_lsp_quickfix(self):
        server = self._server_with_findings()
        out = server.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "textDocument/codeAction",
                "params": {
                    "textDocument": {"uri": FILE_URI},
                    "range": {
                        "start": {"line": 6, "character": 0},
                        "end": {"line": 6, "character": 0},
                    },
                    "context": {"diagnostics": []},
                },
            }
        )
        actions = out[0]["result"]
        assert len(actions) == 1
        action = actions[0]
        assert action["kind"] == "quickfix"
        assert "nonReentrant" in action["title"]
        # edit.changes keyed by URI, carrying T2.1 {range,newText} TextEdits.
        edits = action["edit"]["changes"][FILE_URI]
        assert edits
        joined = "".join(e["newText"] for e in edits)
        assert "nonReentrant" in joined
        for edit in edits:
            assert "range" in edit and "newText" in edit

    def test_code_action_filters_by_range(self):
        server = self._server_with_findings()
        # Range far from the finding (line 6) → no actions.
        out = server.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 43,
                "method": "textDocument/codeAction",
                "params": {
                    "textDocument": {"uri": FILE_URI},
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 1, "character": 0},
                    },
                    "context": {"diagnostics": []},
                },
            }
        )
        assert out[0]["result"] == []


# ---------------------------------------------------------------------------
# Severity mapping table
# ---------------------------------------------------------------------------


class TestSeverityMapping:
    def test_mapping_table(self):
        assert severity_to_lsp("Critical") == LSP_SEVERITY_ERROR
        assert severity_to_lsp("High") == LSP_SEVERITY_ERROR
        assert severity_to_lsp("Medium") == LSP_SEVERITY_WARNING
        assert severity_to_lsp("Low") == LSP_SEVERITY_INFORMATION
        assert severity_to_lsp("Info") == LSP_SEVERITY_HINT

    def test_mapping_is_case_insensitive(self):
        assert severity_to_lsp("critical") == LSP_SEVERITY_ERROR
        assert severity_to_lsp("HIGH") == LSP_SEVERITY_ERROR

    def test_unknown_severity_defaults_to_hint(self):
        assert severity_to_lsp("banana") == LSP_SEVERITY_HINT
        assert severity_to_lsp(None) == LSP_SEVERITY_HINT

    def test_finding_to_diagnostic_without_doc_text(self):
        diag = finding_to_diagnostic({"line": 3, "severity": "Medium", "type": "x"})
        assert diag["range"]["start"]["line"] == 2
        assert diag["range"]["end"]["character"] == 0  # no doc text → collapsed end
        assert diag["severity"] == LSP_SEVERITY_WARNING


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_shutdown_then_exit(self):
        server = LspServer(scan_fn=_mock_scan([]))
        shutdown = server.dispatch({"jsonrpc": "2.0", "id": 9, "method": "shutdown"})
        assert shutdown[0]["result"] is None
        assert server.running is True
        server.dispatch({"jsonrpc": "2.0", "method": "exit"})
        assert server.running is False

    def test_initialized_notification_is_noop(self):
        server = LspServer(scan_fn=_mock_scan([]))
        assert server.dispatch({"jsonrpc": "2.0", "method": "initialized", "params": {}}) == []

    def test_serve_loop_processes_and_stops_on_exit(self):
        server = LspServer(scan_fn=_mock_scan([]))
        instream = io.BytesIO(
            encode_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            + encode_message({"jsonrpc": "2.0", "method": "exit"})
        )
        outstream = io.BytesIO()
        server.serve(stdin=instream, stdout=outstream)
        outstream.seek(0)
        reply = read_message(outstream)
        assert "capabilities" in reply["result"]
        assert server.running is False
