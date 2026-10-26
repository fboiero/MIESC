"""Coverage for the MCP server helpers and tool functions.

The `mcp` SDK is optional; when absent the module's `_MissingMCP` shim makes
`@mcp.tool()` a passthrough, so the tool coroutines are plain callables. Tool
execution is mocked at the module boundary (`_run_layer_internal`,
`_run_tool_internal`) so nothing runs a real adapter.
"""

import asyncio
import json

import pytest

import miesc.mcp_server as mcp_server


def _run(coro):
    return asyncio.run(coro)


def _sol(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text("contract C {}", encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------
class TestHelpers:
    def test_validate_contract_path_ok(self, tmp_path):
        p = _sol(tmp_path)
        assert mcp_server._validate_contract_path(p).endswith("C.sol")

    def test_validate_contract_path_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            mcp_server._validate_contract_path(str(tmp_path / "nope.sol"))

    def test_validate_contract_path_bad_suffix(self, tmp_path):
        bad = tmp_path / "C.txt"
        bad.write_text("x", encoding="utf-8")
        with pytest.raises(ValueError):
            mcp_server._validate_contract_path(str(bad))

    def test_summarize_results_counts(self):
        results = [
            {
                "status": "success",
                "findings": [{"severity": "Critical"}, {"severity": "high"}, {"severity": "Med"}],
            },
            {"status": "error", "findings": [{"severity": "weird"}]},
        ]
        s = mcp_server._summarize_results(results)
        assert s["total_findings"] == 4
        assert s["severity_counts"]["Critical"] == 1
        assert s["severity_counts"]["High"] == 1
        assert s["severity_counts"]["Medium"] == 1
        assert s["severity_counts"]["Info"] == 1  # unknown -> Info
        assert s["tools_run"] == 2
        assert s["tools_succeeded"] == 1

    def test_resolve_profile_layers_legacy_alias(self):
        # "quick" is a legacy alias for "fast".
        profile, available = mcp_server._resolve_profile_layers("quick")
        assert isinstance(available, list)
        assert "quick" in available

    def test_get_layers_and_adapter_map(self):
        assert isinstance(mcp_server._get_layers(), dict)
        assert isinstance(mcp_server._get_adapter_map(), dict)
        assert mcp_server._get_adapter_loader() is not None


# --------------------------------------------------------------------------
# Tool coroutines (execution mocked)
# --------------------------------------------------------------------------
class TestTools:
    def test_quick_scan(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            mcp_server,
            "_run_layer_internal",
            lambda *a, **k: [{"status": "success", "findings": [{"severity": "High"}]}],
        )
        out = json.loads(_run(mcp_server.miesc_quick_scan(_sol(tmp_path))))
        assert out["scan_type"] == "quick"
        assert out["summary"]["total_findings"] == 1

    def test_deep_scan(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            mcp_server,
            "_run_layer_internal",
            lambda *a, **k: [{"status": "success", "findings": []}],
        )
        out = json.loads(_run(mcp_server.miesc_deep_scan(_sol(tmp_path))))
        assert out["scan_type"] == "deep"
        assert out["layers_scanned"] >= 1

    def test_run_tool_unknown(self, tmp_path):
        out = json.loads(_run(mcp_server.miesc_run_tool("no_such_tool", _sol(tmp_path))))
        assert "error" in out
        assert "available_tools" in out

    def test_run_tool_known(self, tmp_path, monkeypatch):
        amap = mcp_server._get_adapter_map()
        a_tool = sorted(amap.keys())[0]
        monkeypatch.setattr(
            mcp_server,
            "_run_tool_internal",
            lambda *a, **k: {"status": "success", "findings": []},
        )
        out = json.loads(_run(mcp_server.miesc_run_tool(a_tool, _sol(tmp_path))))
        assert out["status"] == "success"

    def test_run_layer_invalid(self, tmp_path):
        out = json.loads(_run(mcp_server.miesc_run_layer(99, _sol(tmp_path))))
        assert "error" in out

    def test_run_layer_valid(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            mcp_server,
            "_run_layer_internal",
            lambda *a, **k: [{"status": "success", "findings": []}],
        )
        out = json.loads(_run(mcp_server.miesc_run_layer(1, _sol(tmp_path))))
        assert out["layer"] == 1
        assert "layer_name" in out

    def test_analyze_defi(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            mcp_server,
            "_run_tool_internal",
            lambda *a, **k: {"status": "success", "findings": []},
        )
        out = json.loads(_run(mcp_server.miesc_analyze_defi(_sol(tmp_path), protocol_type="dex")))
        assert "summary" in out
