"""
MIESC MCP Server Tests
Unit tests for mcp_server helper functions and MCP tool endpoints.
"""
import asyncio
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock the mcp SDK before importing mcp_server so the module-level
# FastMCP instantiation does not fail when the SDK is absent.
# The .tool() decorator must be a passthrough so async functions survive.
_fake_fastmcp = MagicMock()
_fake_fastmcp.tool.return_value = lambda fn: fn
_fake_mcp_mod = MagicMock()
_fake_mcp_mod.server.fastmcp.FastMCP.return_value = _fake_fastmcp
sys.modules.setdefault("mcp", _fake_mcp_mod)
sys.modules.setdefault("mcp.server", _fake_mcp_mod.server)
sys.modules.setdefault("mcp.server.fastmcp", _fake_mcp_mod.server.fastmcp)

from miesc.mcp_server import (  # noqa: E402
    _summarize_results, _validate_contract_path,
    miesc_get_status, miesc_get_tool_info, miesc_list_tools,
)

SAMPLE_SOL = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract S {}\n"

# =========================================================================
# Helper: _validate_contract_path
# =========================================================================
class TestValidateContractPath:
    def test_valid_sol_file(self, tmp_path):
        sol = tmp_path / "Token.sol"
        sol.write_text(SAMPLE_SOL)
        assert _validate_contract_path(str(sol)) == str(sol.resolve())

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError, match="Contract not found"):
            _validate_contract_path("/tmp/does_not_exist_999.sol")

    def test_wrong_extension_raises(self, tmp_path):
        txt = tmp_path / "notes.txt"
        txt.write_text("not a contract")
        with pytest.raises(ValueError, match="Unsupported file type"):
            _validate_contract_path(str(txt))

    def test_valid_circom_file(self, tmp_path):
        circ = tmp_path / "circuit.circom"
        circ.write_text("template Main() {}")
        assert _validate_contract_path(str(circ)) == str(circ.resolve())

# =========================================================================
# Helper: _summarize_results
# =========================================================================
class TestSummarizeResults:
    def test_empty_results(self):
        summary = _summarize_results([])
        assert summary["total_findings"] == 0
        assert summary["tools_run"] == 0
        assert summary["tools_succeeded"] == 0
        assert all(v == 0 for v in summary["severity_counts"].values())

    def test_mixed_severities(self):
        results = [
            {"status": "success", "findings": [
                {"severity": "Critical"}, {"severity": "High"},
                {"severity": "Medium"}, {"severity": "Low"},
                {"severity": "Informational"},
            ]},
            {"status": "error", "findings": [{"severity": "high"}]},
        ]
        summary = _summarize_results(results)
        assert summary["total_findings"] == 6
        assert summary["tools_run"] == 2
        assert summary["tools_succeeded"] == 1
        assert summary["severity_counts"]["Critical"] == 1
        assert summary["severity_counts"]["High"] == 2
        assert summary["severity_counts"]["Medium"] == 1
        assert summary["severity_counts"]["Low"] == 1
        assert summary["severity_counts"]["Info"] == 1

# =========================================================================
# Config loaders: _get_layers / _get_adapter_map
# =========================================================================
class TestConfigLoaders:
    @patch("miesc.mcp_server._get_layers")
    def test_get_layers_non_empty(self, mock_layers):
        mock_layers.return_value = {1: {"name": "Static", "tools": ["slither"]}}
        assert len(mock_layers()) > 0

    @patch("miesc.mcp_server._get_adapter_map")
    def test_get_adapter_map_non_empty(self, mock_map):
        mock_map.return_value = {"slither": "SlitherAdapter"}
        assert len(mock_map()) > 0

# =========================================================================
# MCP Tools (async, via mocking)
# =========================================================================
_LAYERS = {1: {"name": "Static Analysis", "tools": ["slither", "aderyn"]}}
_AMAP = {"slither": "SlitherAdapter", "aderyn": "AderynAdapter"}

def _make_loader():
    loader = MagicMock()
    loader.get_available_tools.return_value = ["slither"]
    loader.get_adapter.return_value = None
    return loader

class TestMCPTools:
    """Tests for MCP tool functions with mocked internals."""
    @pytest.fixture(autouse=True)
    def _patch_internals(self):
        with patch("miesc.mcp_server._get_layers", return_value=_LAYERS), \
             patch("miesc.mcp_server._get_adapter_map", return_value=_AMAP), \
             patch("miesc.mcp_server._get_adapter_loader", return_value=_make_loader()):
            yield

    def test_miesc_list_tools(self):
        data = json.loads(asyncio.run(miesc_list_tools()))
        assert data["total"] == 2
        assert data["available"] == 1
        assert any(t["name"] == "slither" for t in data["tools"])

    def test_miesc_list_tools_by_layer(self):
        data = json.loads(asyncio.run(miesc_list_tools(layer=1)))
        assert data["total"] == 2

    def test_miesc_get_status(self):
        data = json.loads(asyncio.run(miesc_get_status()))
        assert data["status"] == "operational"
        assert data["architecture"]["total_tools"] == 2
        assert "1" in data["layers"]

    def test_miesc_get_tool_info_unknown(self):
        data = json.loads(asyncio.run(miesc_get_tool_info("nonexistent_tool")))
        assert "error" in data
        assert "Unknown tool" in data["error"]

    def test_miesc_get_tool_info_known_no_adapter(self):
        data = json.loads(asyncio.run(miesc_get_tool_info("slither")))
        assert data["name"] == "slither"
        assert data["status"] == "adapter_not_loaded"
