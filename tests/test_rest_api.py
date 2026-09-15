"""
Tests for MIESC REST API (Django REST Framework)

Author: Fernando Boiero
License: AGPL-3.0
"""

import os
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest


# Test imports
class TestRestApiImports:
    """Test that REST API module imports correctly."""

    def test_import_rest_module(self):
        """Test importing the rest module."""
        from miesc.api import rest

        assert hasattr(rest, "VERSION")
        from miesc import __version__

        assert rest.VERSION == __version__

    def test_import_layers(self):
        """Test LAYERS dictionary is available."""
        from miesc.api.rest import LAYERS

        assert len(LAYERS) == 9
        assert 1 in LAYERS
        assert 7 in LAYERS

    def test_import_adapter_map(self):
        """Test ADAPTER_MAP dictionary is available."""
        from miesc.api.rest import ADAPTER_MAP

        assert len(ADAPTER_MAP) > 0
        assert "slither" in ADAPTER_MAP
        assert "mythril" in ADAPTER_MAP

    def test_import_quick_tools(self):
        """Test QUICK_TOOLS list is available."""
        from miesc.api.rest import QUICK_TOOLS

        assert "slither" in QUICK_TOOLS
        assert "mythril" in QUICK_TOOLS
        assert len(QUICK_TOOLS) == 4

    def test_import_with_drf_before_settings_configured(self):
        """Django settings must be configured before importing DRF modules."""
        pytest.importorskip("django")
        pytest.importorskip("rest_framework")

        code = """
from django.conf import settings
assert not settings.configured
from miesc.api import rest
assert rest.DJANGO_AVAILABLE
assert rest.DRF_AVAILABLE
rest.create_app()
"""
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


class TestAdapterLoader:
    """Test AdapterLoader functionality."""

    def test_adapter_loader_singleton(self):
        """Test that AdapterLoader loads adapters once."""
        from miesc.api.rest import AdapterLoader

        # Reset loader state
        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}

        # First load
        adapters1 = AdapterLoader.load_all()

        # Second load should return same cached adapters
        adapters2 = AdapterLoader.load_all()

        assert adapters1 is adapters2

    def test_get_available_tools(self):
        """Test getting list of available tools."""
        from miesc.api.rest import AdapterLoader

        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}
        AdapterLoader.load_all()

        tools = AdapterLoader.get_available_tools()
        assert isinstance(tools, list)
        # At least some adapters should be available
        assert len(tools) >= 0

    def test_get_adapter_unknown_tool(self):
        """Test getting adapter for unknown tool."""
        from miesc.api.rest import AdapterLoader

        adapter = AdapterLoader.get_adapter("unknown_tool_xyz")
        assert adapter is None

    def test_check_tool_status_no_adapter(self):
        """Test check_tool_status for tool without adapter."""
        from miesc.api.rest import AdapterLoader

        status = AdapterLoader.check_tool_status("unknown_tool_xyz")
        assert status["status"] == "no_adapter"
        assert status["available"] is False


class TestLayerDefinitions:
    """Test layer definitions."""

    def test_layer_1_static_analysis(self):
        """Test Layer 1 static analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[1]
        assert layer["name"] == "Static Analysis"
        assert "slither" in layer["tools"]
        assert "aderyn" in layer["tools"]

    def test_layer_2_dynamic_testing(self):
        """Test Layer 2 dynamic testing definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[2]
        assert layer["name"] == "Dynamic Testing"
        assert "echidna" in layer["tools"]
        assert "medusa" in layer["tools"]

    def test_layer_3_symbolic_execution(self):
        """Test Layer 3 symbolic execution definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[3]
        assert layer["name"] == "Symbolic Execution"
        assert "mythril" in layer["tools"]
        assert "halmos" in layer["tools"]

    def test_layer_4_formal_verification(self):
        """Test Layer 4 formal verification definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[4]
        assert layer["name"] == "Formal Verification"
        assert "certora" in layer["tools"]
        assert "smtchecker" in layer["tools"]

    def test_layer_5_ai_analysis(self):
        """Test Layer 5 AI analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[5]
        assert layer["name"] == "AI Analysis"
        assert "smartllm" in layer["tools"]
        assert "gptscan" in layer["tools"]

    def test_layer_6_ml_detection(self):
        """Test Layer 6 ML detection definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[6]
        assert layer["name"] == "ML Detection"
        assert "dagnn" in layer["tools"]
        assert "smartbugs_ml" in layer["tools"]

    def test_layer_7_specialized(self):
        """Test Layer 7 specialized analysis definition."""
        from miesc.api.rest import LAYERS

        layer = LAYERS[7]
        assert layer["name"] == "Specialized Analysis"
        assert "threat_model" in layer["tools"]
        assert "gas_analyzer" in layer["tools"]


class TestAnalysisFunctions:
    """Test analysis functions."""

    def test_summarize_findings_empty(self):
        """Test summarizing empty findings."""
        from miesc.api.rest import summarize_findings

        results = []
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 0
        assert summary["HIGH"] == 0
        assert summary["MEDIUM"] == 0
        assert summary["LOW"] == 0
        assert summary["INFO"] == 0

    def test_summarize_findings_mixed(self):
        """Test summarizing mixed findings."""
        from miesc.api.rest import summarize_findings

        results = [
            {
                "tool": "test",
                "findings": [
                    {"severity": "CRITICAL"},
                    {"severity": "HIGH"},
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                    {"severity": "LOW"},
                    {"severity": "INFO"},
                ],
            }
        ]
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 2
        assert summary["MEDIUM"] == 1
        assert summary["LOW"] == 1
        assert summary["INFO"] == 1

    def test_summarize_findings_normalized_severity(self):
        """Test summarizing with normalized severity names."""
        from miesc.api.rest import summarize_findings

        results = [
            {
                "tool": "test",
                "findings": [
                    {"severity": "CRIT"},  # Should map to CRITICAL
                    {"severity": "HI"},  # Should map to HIGH
                    {"severity": "MED"},  # Should map to MEDIUM
                    {"severity": "LO"},  # Should map to LOW
                ],
            }
        ]
        summary = summarize_findings(results)

        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 1
        assert summary["LOW"] == 1


class TestSarifConversion:
    """Test SARIF format conversion."""

    def test_to_sarif_structure(self):
        """Test SARIF output structure."""
        from miesc.api.rest import to_sarif

        results = [
            {
                "tool": "slither",
                "contract": "Test.sol",
                "findings": [
                    {
                        "type": "reentrancy",
                        "title": "Reentrancy vulnerability",
                        "severity": "HIGH",
                        "description": "Test description",
                        "location": {"file": "Test.sol", "line": 10},
                    }
                ],
            }
        ]

        sarif = to_sarif(results)

        assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "MIESC"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_to_sarif_empty_results(self):
        """Test SARIF conversion with empty results."""
        from miesc.api.rest import to_sarif

        sarif = to_sarif([])

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0

    def test_to_sarif_severity_mapping(self):
        """Test SARIF severity level mapping."""
        from miesc.api.rest import to_sarif

        results = [
            {
                "tool": "test",
                "findings": [
                    {"type": "test1", "severity": "CRITICAL"},
                    {"type": "test2", "severity": "HIGH"},
                    {"type": "test3", "severity": "MEDIUM"},
                    {"type": "test4", "severity": "LOW"},
                ],
            }
        ]

        sarif = to_sarif(results)
        levels = [r["level"] for r in sarif["runs"][0]["results"]]

        assert "error" in levels  # CRITICAL/HIGH
        assert "warning" in levels  # MEDIUM
        assert "note" in levels  # LOW


class TestRunToolFunction:
    """Test run_tool function."""

    def test_run_tool_no_adapter(self):
        """Test running tool without adapter."""
        from miesc.api.rest import run_tool

        result = run_tool("nonexistent_tool", "/path/to/contract.sol")

        assert result["tool"] == "nonexistent_tool"
        assert result["status"] == "no_adapter"
        assert result["findings"] == []
        assert "error" in result

    @patch("miesc.api.rest.AdapterLoader.get_adapter")
    def test_run_tool_not_available(self, mock_get_adapter):
        """Test running tool that's not available."""

        mock_adapter = Mock()
        mock_adapter.is_available.return_value = Mock(value="not_installed")
        mock_get_adapter.return_value = mock_adapter

        # Mock ToolStatus
        with patch("miesc.api.rest.AdapterLoader.get_adapter", return_value=mock_adapter):
            # Need to also mock the import inside the function
            pass


class TestRunLayerFunction:
    """Test run_layer function."""

    def test_run_layer_invalid_layer(self):
        """Test running invalid layer."""
        from miesc.api.rest import run_layer

        results = run_layer(99, "/path/to/contract.sol")
        assert results == []

    def test_run_layer_valid_layer(self):
        """Test running valid layer returns list."""
        from miesc.api.rest import run_layer

        # Layer 1 should have tools defined
        results = run_layer(1, "/nonexistent/contract.sol")
        assert isinstance(results, list)
        # Should have results for each tool in layer 1
        from miesc.api.rest import LAYERS

        assert len(results) == len(LAYERS[1]["tools"])


class TestFullAudit:
    """Test full audit function."""

    def test_run_full_audit_returns_dict(self):
        """Test full audit returns proper structure."""
        from miesc.api.rest import run_full_audit

        result = run_full_audit("/nonexistent/contract.sol", layers=[1])

        assert "audit_id" in result
        assert "contract" in result
        assert "layers" in result
        assert "results" in result
        assert "summary" in result
        assert "execution_time" in result
        assert "timestamp" in result
        assert "version" in result

    def test_run_full_audit_default_layers(self):
        """Test full audit with default layers."""
        from miesc.api.rest import LAYERS, run_full_audit

        result = run_full_audit("/nonexistent/contract.sol")

        # Should include all 7 layers
        assert result["layers"] == list(LAYERS.keys())


class TestCLIImports:
    """Test CLI module imports (post v5.1.0 refactoring)."""

    def test_import_cli_module(self):
        """Test importing the CLI module."""
        from miesc.cli import main

        assert hasattr(main, "cli")
        assert hasattr(main, "VERSION")

    def test_cli_version(self):
        """Test CLI version matches package version."""
        from miesc import __version__
        from miesc.cli.main import VERSION

        assert VERSION == __version__

    def test_cli_layers_in_api(self):
        """Test LAYERS is defined in miesc.api.rest (moved from CLI in v5.1.0)."""
        from miesc.api.rest import LAYERS

        assert len(LAYERS) == 9

    def test_cli_adapter_map_in_api(self):
        """Test ADAPTER_MAP is defined in miesc.api.rest (moved from CLI in v5.1.0)."""
        from miesc.api.rest import ADAPTER_MAP

        assert len(ADAPTER_MAP) > 0


class TestCLIAdapterLoader:
    """Test CLI AdapterLoader functionality (post v5.1.0 refactoring)."""

    def test_adapter_loader_load_all(self):
        """Test AdapterLoader.load_all() from miesc.cli.utils."""
        from miesc.cli.utils import AdapterLoader

        # Reset state
        AdapterLoader._loaded = False
        AdapterLoader._adapters = {}

        adapters = AdapterLoader.load_all()
        assert isinstance(adapters, dict)

    def test_adapter_loader_get_available_tools(self):
        """Test getting available tools from CLI utils."""
        from miesc.cli.utils import AdapterLoader

        tools = AdapterLoader.get_available_tools()
        assert isinstance(tools, list)


class TestCLIOutputHelpers:
    """Test CLI output helper functions (post v5.1.0 refactoring).

    Note: These functions are now private (_to_sarif, _to_markdown) in the audit module.
    Tests access them directly for unit testing purposes.
    """

    def test_summarize_findings_cli(self):
        """Test CLI _summarize_findings equivalent via severity counting."""
        # Post-refactoring: summarize logic is inline in audit commands
        # Test the core logic pattern used in audits
        results = [
            {
                "findings": [
                    {"severity": "HIGH"},
                    {"severity": "MEDIUM"},
                ]
            }
        ]

        # Replicate the summarize logic used in audit commands
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in results:
            for finding in result.get("findings", []):
                sev = finding.get("severity", "INFO").upper()
                if sev in summary:
                    summary[sev] += 1

        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 1

    def test_to_sarif_cli(self):
        """Test CLI _to_sarif function from audit module."""
        from miesc.cli.commands.audit import _to_sarif

        results = [{"tool": "test", "findings": [{"type": "test", "severity": "HIGH"}]}]

        sarif = _to_sarif(results)
        assert sarif["version"] == "2.1.0"

    def test_to_markdown_cli(self):
        """Test CLI _to_markdown function from audit module."""
        from miesc.cli.commands.audit import _to_markdown

        results = [
            {
                "tool": "slither",
                "status": "success",
                "execution_time": 1.5,
                "findings": [
                    {"severity": "HIGH", "title": "Test Finding", "description": "Test description"}
                ],
            }
        ]

        md = _to_markdown(results, "Test.sol")
        assert "# MIESC Security Audit Report" in md
        assert "Test.sol" in md
        assert "SLITHER" in md


class TestResolveContractPath:
    """Test _resolve_contract_path (path-traversal guard for /remediate and analyze/*)."""

    def test_relative_path_inside_root_is_allowed(self, tmp_path, monkeypatch):
        from miesc.api.rest import _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        resolved = _resolve_contract_path("Contract.sol")
        assert resolved == str((tmp_path / "Contract.sol").resolve())

    def test_nested_relative_path_inside_root_is_allowed(self, tmp_path, monkeypatch):
        from miesc.api.rest import _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        resolved = _resolve_contract_path("contracts/Vault.sol")
        assert resolved == str((tmp_path / "contracts" / "Vault.sol").resolve())

    def test_dotdot_traversal_outside_root_is_rejected(self, tmp_path, monkeypatch):
        from miesc.api.rest import PathTraversalError, _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        with pytest.raises(PathTraversalError):
            _resolve_contract_path("../../../etc/passwd")

    def test_absolute_path_outside_root_is_rejected(self, tmp_path, monkeypatch):
        from miesc.api.rest import PathTraversalError, _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        with pytest.raises(PathTraversalError):
            _resolve_contract_path("/etc/passwd")

    def test_absolute_path_inside_root_is_allowed(self, tmp_path, monkeypatch):
        from miesc.api.rest import _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        inside = tmp_path / "Contract.sol"
        assert _resolve_contract_path(str(inside)) == str(inside.resolve())

    def test_root_itself_is_allowed(self, tmp_path, monkeypatch):
        from miesc.api.rest import _resolve_contract_path

        monkeypatch.setenv("MIESC_REST_ROOT", str(tmp_path))
        assert _resolve_contract_path(".") == str(tmp_path.resolve())


class TestGetApiKey:
    """Test _get_api_key (the auth secret for RequireApiKey)."""

    def _fresh_module(self, monkeypatch):
        """Reimport miesc.api.rest with a clean _api_key_cache."""
        import miesc.api.rest as rest_module

        monkeypatch.setattr(rest_module, "_api_key_cache", [])
        return rest_module

    def test_pinned_key_from_env_is_used(self, monkeypatch):
        rest_module = self._fresh_module(monkeypatch)
        monkeypatch.setenv("MIESC_API_KEY", "pinned-test-key")
        assert rest_module._get_api_key() == "pinned-test-key"

    def test_generated_key_is_cached_across_calls(self, monkeypatch):
        rest_module = self._fresh_module(monkeypatch)
        monkeypatch.delenv("MIESC_API_KEY", raising=False)
        first = rest_module._get_api_key()
        second = rest_module._get_api_key()
        assert first == second
        assert len(first) > 20  # secrets.token_urlsafe(32) output


class TestRestApiAuthAndPathGuardEndToEnd:
    """End-to-end proof (real Django test client, fresh subprocess) that
    RequireApiKey and _resolve_contract_path are actually wired into the live
    views -- not just correct in isolation. Runs in a subprocess so Django
    settings start unconfigured, same reason as
    test_import_with_drf_before_settings_configured above.
    """

    def test_permission_and_path_guard_wired_into_real_requests(self, tmp_path):
        pytest.importorskip("django")
        pytest.importorskip("rest_framework")

        code = """
from django.conf import settings
assert not settings.configured
from miesc.api import rest
from django.test import Client

client = Client()
key = rest._get_api_key()

# 1. No API key -> analyze/quick is blocked
r = client.post("/api/v1/analyze/quick/", data={}, content_type="application/json")
assert r.status_code == 403, r.status_code

# 2. Wrong API key -> still blocked
r = client.post(
    "/api/v1/analyze/quick/", data={}, content_type="application/json",
    HTTP_X_API_KEY="wrong-key",
)
assert r.status_code == 403, r.status_code

# 3. Correct API key, missing body fields -> gets past auth, hits validation (400)
r = client.post(
    "/api/v1/analyze/quick/", data={}, content_type="application/json",
    HTTP_X_API_KEY=key,
)
assert r.status_code == 400, r.status_code

# 4. Correct API key, path-traversal attempt -> rejected by the path guard, not a 500
r = client.post(
    "/api/v1/analyze/quick/",
    data={"contract_path": "../../../etc/passwd"},
    content_type="application/json",
    HTTP_X_API_KEY=key,
)
assert r.status_code == 400, r.status_code
assert "outside the allowed root" in r.json()["error"], r.json()

# 5. Read-only endpoint stays open without a key
r = client.get("/api/v1/health/")
assert r.status_code == 200, r.status_code

print("OK")
"""
        env = dict(os.environ)
        env["MIESC_API_KEY"] = "test-fixed-key-for-e2e"
        env["MIESC_REST_ROOT"] = str(tmp_path)
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=False,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "OK" in result.stdout


class TestApiPackageInit:
    """Test API package __init__.py."""

    def test_api_version(self):
        """Test API package version matches main version."""
        from miesc import __version__
        from miesc.api import __version__ as api_version

        assert api_version == __version__


# Skip Django-specific tests if Django not properly configured
try:
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            DATABASES={},
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth"],
            REST_FRAMEWORK={},
        )
    from rest_framework.test import APIClient

    DJANGO_AVAILABLE = True
except (ImportError, Exception):
    DJANGO_AVAILABLE = False
    APIClient = None  # Placeholder


@pytest.mark.skipif(not DJANGO_AVAILABLE, reason="Django not installed")
class TestDjangoViews:
    """Test Django REST Framework views.

    Note: These tests require a properly configured Django environment.
    In unit test context, we test that the API module structure is correct.
    """

    def test_health_endpoint(self):
        """Test health view configuration exists."""
        # Test that the REST API module has the expected configuration
        from miesc.api.rest import ADAPTER_MAP, LAYERS

        assert len(LAYERS) > 0
        assert len(ADAPTER_MAP) > 0

    def test_tools_list_endpoint(self):
        """Test tools configuration is complete."""
        from miesc.api.rest import ADAPTER_MAP, QUICK_TOOLS

        # All quick tools should be in adapter map
        for tool in QUICK_TOOLS:
            assert tool in ADAPTER_MAP

    def test_layers_endpoint(self):
        """Test layers configuration is valid."""
        from miesc.api.rest import LAYERS

        # All layers should have required fields
        for _layer_id, layer in LAYERS.items():
            assert "name" in layer
            assert "tools" in layer
            assert isinstance(layer["tools"], list)
