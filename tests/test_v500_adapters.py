"""
MIESC v5.0.0 Adapter Tests
Unit tests for the 17 new adapters introduced in v5.0.0.

Tests cover:
  - Import verification
  - Metadata validation (name, category, capabilities, is_optional)
  - Graceful handling of missing/nonexistent files

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import importlib

import pytest

# ---------------------------------------------------------------------------
# Adapter registry: (module_name, class_name)
# ---------------------------------------------------------------------------
ADAPTERS = [
    ("fouranalyzer_adapter", "FourAnalyzerAdapter"),
    ("oyente_adapter", "OyenteAdapter"),
    ("pakala_adapter", "PakalaAdapter"),
    ("scribble_adapter", "ScribbleAdapter"),
    ("solcmc_adapter", "SolCMCAdapter"),
    ("gptlens_adapter", "GPTLensAdapter"),
    ("llamaaudit_adapter", "LlamaAuditAdapter"),
    ("iaudit_adapter", "IAuditAdapter"),
    ("peculiar_adapter", "PeculiarAdapter"),
    ("upgradability_checker_adapter", "UpgradabilityCheckerAdapter"),
    ("bridge_monitor_adapter", "BridgeMonitorAdapter"),
    ("l2_validator_adapter", "L2ValidatorAdapter"),
    ("circom_analyzer_adapter", "CircomAnalyzerAdapter"),
    ("audit_consensus_adapter", "AuditConsensusAdapter"),
    ("exploit_synthesizer_adapter", "ExploitSynthesizerAdapter"),
    ("vuln_verifier_adapter", "VulnVerifierAdapter"),
    ("remediation_validator_adapter", "RemediationValidatorAdapter"),
]

# Adapters whose analyze() needs findings-related kwargs to exercise
# their main code paths; they still accept contract_path as first arg.
META_ADAPTERS = {
    "audit_consensus_adapter",
    "exploit_synthesizer_adapter",
    "vuln_verifier_adapter",
    "remediation_validator_adapter",
}

NONEXISTENT_PATH = "/tmp/nonexistent_contract_v500_test.sol"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _import_adapter_class(module_name: str, class_name: str):
    """Dynamically import and return the adapter class."""
    mod = importlib.import_module(f"src.adapters.{module_name}")
    return getattr(mod, class_name)


def _make_instance(module_name: str, class_name: str):
    """Instantiate an adapter with its default constructor."""
    cls = _import_adapter_class(module_name, class_name)
    return cls()


# ---------------------------------------------------------------------------
# Parametrized fixture
# ---------------------------------------------------------------------------
@pytest.fixture(params=ADAPTERS, ids=[a[0] for a in ADAPTERS])
def adapter_info(request):
    """Yield (module_name, class_name) for each v5.0.0 adapter."""
    return request.param


# ---------------------------------------------------------------------------
# Test suite: Import
# ---------------------------------------------------------------------------
class TestV500AdapterImport:
    """Verify that every v5.0.0 adapter class can be imported."""

    def test_import(self, adapter_info):
        module_name, class_name = adapter_info
        cls = _import_adapter_class(module_name, class_name)
        assert cls is not None, f"Failed to import {class_name} from src.adapters.{module_name}"


# ---------------------------------------------------------------------------
# Test suite: Metadata
# ---------------------------------------------------------------------------
class TestV500AdapterMetadata:
    """Verify get_metadata() returns valid ToolMetadata for each adapter."""

    def test_metadata(self, adapter_info):
        module_name, class_name = adapter_info
        adapter = _make_instance(module_name, class_name)
        metadata = adapter.get_metadata()

        # name must be a non-empty string
        assert (
            isinstance(metadata.name, str) and len(metadata.name) > 0
        ), f"{class_name}.get_metadata().name is empty or not a string"

        # category must be set
        assert metadata.category is not None, f"{class_name}.get_metadata().category is None"

        # at least one capability
        assert len(metadata.capabilities) >= 1, f"{class_name}.get_metadata().capabilities is empty"

        # all v5.0.0 adapters are optional (no vendor lock-in)
        assert (
            metadata.is_optional is True
        ), f"{class_name}.get_metadata().is_optional should be True"


# ---------------------------------------------------------------------------
# Test suite: analyze() with nonexistent path
# ---------------------------------------------------------------------------
class TestV500AdapterAnalyze:
    """Verify analyze() handles missing files gracefully."""

    def test_analyze_missing_file(self, adapter_info):
        module_name, class_name = adapter_info
        adapter = _make_instance(module_name, class_name)

        # Build kwargs depending on adapter type
        kwargs: dict = {"timeout": 10}
        if module_name in META_ADAPTERS:
            # Meta/verification adapters expect findings in kwargs
            kwargs["findings"] = []
            kwargs["findings_map"] = {}
            kwargs["original_findings"] = []

        result = adapter.analyze(NONEXISTENT_PATH, **kwargs)

        # Must return a dict
        assert isinstance(result, dict), f"{class_name}.analyze() did not return a dict"

        # Must contain a "status" key (success, error, skipped, etc.)
        assert "status" in result, (
            f"{class_name}.analyze() result missing 'status' key. "
            f"Got keys: {list(result.keys())}"
        )
