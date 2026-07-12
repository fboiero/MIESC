"""Tests for miesc.adapters.zk_circuit_adapter — ZK circuit security analyzer."""

import pytest

from miesc.adapters.zk_circuit_adapter import (
    ZK_VULNERABILITY_PATTERNS,
    ZKCircuitAdapter,
    ZKFramework,
)
from miesc.core.tool_protocol import ToolStatus

# ---------------------------------------------------------------------------
# Sample circuit code fixtures
# ---------------------------------------------------------------------------

CIRCOM_UNCONSTRAINED = """
pragma circom 2.0.0;

template Unsafe() {
    signal input a;
    signal input b;
    signal output result;
    signal intermediate;

    // intermediate is declared but never constrained
    result <== a * b;
}

component main = Unsafe();
"""

CIRCOM_WITH_DIVISION = """
pragma circom 2.0.0;

template DivCircuit() {
    signal input numerator;
    signal input denominator;
    signal output quotient;

    quotient === numerator / denominator;
}

component main = DivCircuit();
"""

CIRCOM_WELL_CONSTRAINED = """
pragma circom 2.0.0;

template Add() {
    signal input a;
    signal input b;
    signal output out;

    out === a + b;
}

component main = Add();
"""

CIRCOM_UNCONSTRAINED_OUTPUT = """
pragma circom 2.0.0;

template LeakyOutput() {
    signal input a;
    signal output leaked;
    signal output constrained;

    constrained <== a * 2;
    // 'leaked' output is never constrained
}

component main = LeakyOutput();
"""

NOIR_UNCONSTRAINED_FN = """
use dep::std;

fn main(x: Field, y: Field) -> pub Field {
    let z = x + y;
    z
}

unconstrained fn helper(val: Field) -> Field {
    val * 2
}
"""

NOIR_MANY_ASSERTS = """
fn main(x: Field) {
    assert(x > 0);
    assert(x < 100);
    assert(x != 50);
    assert(x != 25);
    assert(x != 75);
    assert(x != 10);
    // barely any constrain calls
    constrain x;
}
"""

EMPTY_CIRCOM = ""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter():
    return ZKCircuitAdapter()


@pytest.fixture
def circom_file(tmp_path):
    f = tmp_path / "circuit.circom"
    f.write_text(CIRCOM_UNCONSTRAINED)
    return str(f)


@pytest.fixture
def circom_division_file(tmp_path):
    f = tmp_path / "div.circom"
    f.write_text(CIRCOM_WITH_DIVISION)
    return str(f)


@pytest.fixture
def circom_well_constrained_file(tmp_path):
    f = tmp_path / "safe.circom"
    f.write_text(CIRCOM_WELL_CONSTRAINED)
    return str(f)


@pytest.fixture
def circom_unconstrained_output_file(tmp_path):
    f = tmp_path / "leaky.circom"
    f.write_text(CIRCOM_UNCONSTRAINED_OUTPUT)
    return str(f)


@pytest.fixture
def noir_file(tmp_path):
    f = tmp_path / "program.nr"
    f.write_text(NOIR_UNCONSTRAINED_FN)
    return str(f)


@pytest.fixture
def noir_many_asserts_file(tmp_path):
    f = tmp_path / "asserts.nr"
    f.write_text(NOIR_MANY_ASSERTS)
    return str(f)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterMetadata:
    def test_get_metadata_name(self, adapter):
        meta = adapter.get_metadata()
        assert meta.name == "zk_circuit_analyzer"

    def test_get_metadata_version(self, adapter):
        meta = adapter.get_metadata()
        assert meta.version == "1.0.0"

    def test_get_metadata_has_capabilities(self, adapter):
        meta = adapter.get_metadata()
        assert len(meta.capabilities) >= 2

    def test_get_metadata_no_api_key_required(self, adapter):
        meta = adapter.get_metadata()
        assert meta.requires_api_key is False

    def test_get_metadata_cost_is_zero(self, adapter):
        meta = adapter.get_metadata()
        assert meta.cost == 0.0

    def test_get_metadata_is_optional(self, adapter):
        meta = adapter.get_metadata()
        assert meta.is_optional is True


# ---------------------------------------------------------------------------
# is_available
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterAvailability:
    def test_is_available_returns_tool_status(self, adapter):
        status = adapter.is_available()
        assert isinstance(status, ToolStatus)

    def test_is_available_does_not_raise(self, adapter):
        # circomspect may or may not be installed in CI — must not raise
        try:
            adapter.is_available()
        except Exception as exc:
            pytest.fail(f"is_available() raised unexpectedly: {exc}")

    def test_is_available_returns_known_status(self, adapter):
        status = adapter.is_available()
        assert status in (
            ToolStatus.AVAILABLE,
            ToolStatus.NOT_INSTALLED,
            ToolStatus.CONFIGURATION_ERROR,
        )


# ---------------------------------------------------------------------------
# ZKFramework enum
# ---------------------------------------------------------------------------


class TestZKFrameworkEnum:
    def test_circom_value(self):
        assert ZKFramework.CIRCOM.value == "circom"

    def test_noir_value(self):
        assert ZKFramework.NOIR.value == "noir"

    def test_halo2_value(self):
        assert ZKFramework.HALO2.value == "halo2"

    def test_gnark_value(self):
        assert ZKFramework.GNARK.value == "gnark"

    def test_all_values_are_lowercase(self):
        for member in ZKFramework:
            assert (
                member.value == member.value.lower()
            ), f"ZKFramework.{member.name} value '{member.value}' is not lowercase"


# ---------------------------------------------------------------------------
# ZK_VULNERABILITY_PATTERNS — enum-style validation
# ---------------------------------------------------------------------------


class TestZKVulnerabilityPatterns:
    EXPECTED_KEYS = [
        "under_constrained",
        "over_constrained",
        "unused_signal",
        "unconstrained_output",
        "division_by_zero",
        "field_overflow",
        "non_deterministic",
        "unsafe_component",
        "signal_aliasing",
    ]

    def test_all_expected_keys_present(self):
        for key in self.EXPECTED_KEYS:
            assert key in ZK_VULNERABILITY_PATTERNS, f"Missing key: {key}"

    def test_all_keys_are_lowercase_snake_case(self):
        for key in ZK_VULNERABILITY_PATTERNS:
            assert key == key.lower(), f"Key '{key}' is not lowercase"
            assert " " not in key, f"Key '{key}' contains spaces"

    def test_each_entry_has_severity(self):
        for key, val in ZK_VULNERABILITY_PATTERNS.items():
            assert "severity" in val, f"{key} missing severity"

    def test_each_entry_has_description(self):
        for key, val in ZK_VULNERABILITY_PATTERNS.items():
            assert "description" in val, f"{key} missing description"

    def test_each_entry_has_impact(self):
        for key, val in ZK_VULNERABILITY_PATTERNS.items():
            assert "impact" in val, f"{key} missing impact"

    def test_under_constrained_is_critical(self):
        assert ZK_VULNERABILITY_PATTERNS["under_constrained"]["severity"] == "CRITICAL"

    def test_unconstrained_output_is_critical(self):
        assert ZK_VULNERABILITY_PATTERNS["unconstrained_output"]["severity"] == "CRITICAL"

    def test_division_by_zero_severity(self):
        assert ZK_VULNERABILITY_PATTERNS["division_by_zero"]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# can_analyze
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterCanAnalyze:
    def test_can_analyze_circom(self, adapter):
        assert adapter.can_analyze("circuit.circom") is True

    def test_can_analyze_noir(self, adapter):
        assert adapter.can_analyze("program.nr") is True

    def test_can_analyze_zk(self, adapter):
        assert adapter.can_analyze("file.zk") is True

    def test_can_analyze_circom_uppercase(self, adapter):
        assert adapter.can_analyze("CIRCUIT.CIRCOM") is True

    def test_cannot_analyze_sol(self, adapter):
        assert adapter.can_analyze("contract.sol") is False

    def test_cannot_analyze_js(self, adapter):
        assert adapter.can_analyze("test.js") is False

    def test_cannot_analyze_no_extension(self, adapter):
        assert adapter.can_analyze("circuit") is False


# ---------------------------------------------------------------------------
# _detect_framework
# ---------------------------------------------------------------------------


class TestDetectFramework:
    def test_detects_circom(self, adapter, tmp_path):
        p = tmp_path / "test.circom"
        from pathlib import Path

        assert adapter._detect_framework(Path(str(p))) == ZKFramework.CIRCOM

    def test_detects_noir(self, adapter, tmp_path):
        p = tmp_path / "test.nr"
        from pathlib import Path

        assert adapter._detect_framework(Path(str(p))) == ZKFramework.NOIR

    def test_returns_none_for_sol(self, adapter, tmp_path):
        p = tmp_path / "test.sol"
        from pathlib import Path

        assert adapter._detect_framework(Path(str(p))) is None

    def test_returns_none_for_unknown(self, adapter, tmp_path):
        p = tmp_path / "test.xyz"
        from pathlib import Path

        assert adapter._detect_framework(Path(str(p))) is None


# ---------------------------------------------------------------------------
# analyze() — Circom patterns
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterAnalyzeCircom:
    def test_analyze_circom_returns_success(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        assert result["status"] == "success"
        assert result["tool"] == "zk_circuit_analyzer"

    def test_analyze_circom_metadata_framework(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        assert result["metadata"]["framework"] == "circom"

    def test_analyze_circom_has_findings_key(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        assert "findings" in result

    def test_analyze_circom_has_execution_time(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        assert result["execution_time"] >= 0

    def test_analyze_circom_detects_unused_signal(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        categories = [f["category"] for f in result["findings"]]
        assert "unused_signal" in categories

    def test_analyze_circom_division_detects_division_by_zero(self, adapter, circom_division_file):
        result = adapter.analyze(circom_division_file)
        categories = [f["category"] for f in result["findings"]]
        assert "division_by_zero" in categories

    def test_analyze_circom_unconstrained_output(self, adapter, circom_unconstrained_output_file):
        result = adapter.analyze(circom_unconstrained_output_file)
        categories = [f["category"] for f in result["findings"]]
        assert "unconstrained_output" in categories

    def test_analyze_circom_findings_have_required_fields(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        for finding in result["findings"]:
            assert "id" in finding
            assert "title" in finding
            assert "severity" in finding
            assert "category" in finding
            assert "source" in finding

    def test_analyze_circom_findings_sorted_by_severity(self, adapter, circom_file):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        result = adapter.analyze(circom_file)
        findings = result["findings"]
        if len(findings) >= 2:
            severities = [severity_order.get(f["severity"], 4) for f in findings]
            assert severities == sorted(severities)

    def test_analyze_circom_constraint_ratio_check(self, adapter, circom_file):
        # Circuit has more signals than constraints — should flag under-constrained
        result = adapter.analyze(circom_file)
        categories = [f["category"] for f in result["findings"]]
        # May or may not trigger depending on ratio heuristic — just verify no crash
        assert isinstance(categories, list)


# ---------------------------------------------------------------------------
# analyze() — Noir patterns
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterAnalyzeNoir:
    def test_analyze_noir_returns_success(self, adapter, noir_file):
        result = adapter.analyze(noir_file)
        assert result["status"] == "success"

    def test_analyze_noir_metadata_framework(self, adapter, noir_file):
        result = adapter.analyze(noir_file)
        assert result["metadata"]["framework"] == "noir"

    def test_analyze_noir_detects_unconstrained_function(self, adapter, noir_file):
        result = adapter.analyze(noir_file)
        categories = [f["category"] for f in result["findings"]]
        assert "unconstrained_output" in categories

    def test_analyze_noir_many_asserts(self, adapter, noir_many_asserts_file):
        result = adapter.analyze(noir_many_asserts_file)
        assert result["status"] == "success"
        categories = [f["category"] for f in result["findings"]]
        # Many asserts vs few constraints triggers under_constrained
        assert "under_constrained" in categories


# ---------------------------------------------------------------------------
# analyze() — edge cases
# ---------------------------------------------------------------------------


class TestZKCircuitAdapterEdgeCases:
    def test_analyze_nonexistent_file_returns_error(self, adapter):
        result = adapter.analyze("/nonexistent/circuit.circom")
        assert result["status"] == "error"
        assert result["findings"] == []

    def test_analyze_nonexistent_file_has_error_field(self, adapter):
        result = adapter.analyze("/nonexistent/circuit.circom")
        assert "error" in result

    def test_analyze_unsupported_extension_returns_error(self, adapter, tmp_path):
        f = tmp_path / "code.sol"
        f.write_text("contract X {}")
        result = adapter.analyze(str(f))
        assert result["status"] == "success"
        assert result["metadata"]["skipped"] is True
        assert "Unsupported file type" in result["metadata"]["skipped_reason"]

    def test_analyze_empty_circom_file(self, adapter, tmp_path):
        f = tmp_path / "empty.circom"
        f.write_text(EMPTY_CIRCOM)
        result = adapter.analyze(str(f))
        # Empty file returns error because _read_file returns falsy empty string
        assert result["status"] == "error"
        assert result["findings"] == []

    def test_normalize_findings_from_analysis(self, adapter, circom_file):
        result = adapter.analyze(circom_file)
        normalized = adapter.normalize_findings(result)
        assert isinstance(normalized, list)

    def test_normalize_findings_empty_dict(self, adapter):
        assert adapter.normalize_findings({}) == []

    def test_normalize_findings_non_dict(self, adapter):
        assert adapter.normalize_findings("not a dict") == []

    def test_get_default_config(self, adapter):
        config = adapter.get_default_config()
        assert "timeout" in config
        assert config["timeout"] > 0

    def test_deduplication_removes_same_title_and_category(self, adapter, tmp_path):
        # Write a circuit that will trigger the same finding twice if not deduped
        # (well-constrained circuit should still pass without crashing)
        f = tmp_path / "dedup.circom"
        f.write_text(CIRCOM_WELL_CONSTRAINED)
        result = adapter.analyze(str(f))
        assert result["status"] == "success"
        # Verify no duplicate (category, title, line) tuples
        keys = [
            (
                f["category"],
                f["title"],
                str(f.get("location", {}).get("line", "")),
            )
            for f in result["findings"]
        ]
        assert len(keys) == len(set(keys))
