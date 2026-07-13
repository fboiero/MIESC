"""
Tests for PolicyAgent (src/agents/policy_agent.py).

Pure compliance-scoring agent: maps an aggregated findings list to ISO27001 /
NIST-SSDF / OWASP / SWC / DASP / ConsenSys / SCSVS / CCSS / DeFi / MiCA / DORA
results. Every _check_* method is pure (findings -> dict). Driving analyze() with
a diverse findings list exercises the bulk; targeted calls cover the branches.
The module was at ~8% (only import/init were tested).
"""

from unittest.mock import MagicMock, patch

import pytest


def _agent():
    from miesc.agents.policy_agent import PolicyAgent

    with patch("miesc.agents.base_agent.get_context_bus") as mock_bus:
        mock_bus.return_value = MagicMock()
        return PolicyAgent()


# Diverse findings touching many types/severities to exercise scoring branches.
RICH = [
    {"severity": "Critical", "type": "reentrancy", "category": "reentrancy", "swc_id": "SWC-107"},
    {
        "severity": "High",
        "type": "access-control",
        "category": "access_control",
        "swc_id": "SWC-105",
    },
    {"severity": "High", "type": "arithmetic", "swc_id": "SWC-101"},
    {"severity": "Medium", "type": "timestamp", "swc_id": "SWC-116"},
    {"severity": "Low", "type": "unchecked-call", "swc_id": "SWC-104"},
    {"severity": "Critical", "type": "delegatecall", "swc_id": "SWC-112"},
    {"severity": "High", "type": "front-running", "swc_id": "SWC-114"},
    {"severity": "Medium", "type": "denial-of-service", "swc_id": "SWC-113"},
    {"severity": "High", "type": "bad-randomness", "swc_id": "SWC-120"},
    {"severity": "Critical", "type": "oracle-manipulation"},
    {"severity": "High", "type": "flash-loan"},
]

CHECK_METHODS = [
    "_check_iso27001",
    "_check_nist_ssdf",
    "_check_owasp_coverage",
    "_map_to_swc_registry",
    "_check_dasp_top10",
    "_check_consensys_practices",
    "_check_scsvs_compliance",
    "_audit_checklist_score",
    "_assess_defi_risks",
    "_check_mica_compliance",
    "_check_dora_resilience",
]


# --------------------------------------------------------------------------- #
# init / metadata
# --------------------------------------------------------------------------- #
def test_init():
    a = _agent()
    assert a.agent_name == "PolicyAgent"
    assert a.get_context_types()


# --------------------------------------------------------------------------- #
# analyze() — full orchestration over rich + empty findings
# --------------------------------------------------------------------------- #
def test_analyze_full_flow_rich(monkeypatch):
    a = _agent()
    monkeypatch.setattr(a, "_aggregate_all_findings", lambda: RICH)
    results = a.analyze("/tmp/contracts/C.sol")
    for key in (
        "iso27001_status",
        "nist_ssdf_status",
        "owasp_coverage",
        "swc_classification",
        "dasp_coverage",
        "scsvs_status",
        "ccss_status",
        "defi_risk_assessment",
        "mica_compliance",
        "dora_resilience",
        "compliance_report",
    ):
        assert key in results
    assert "audit_readiness" in results  # analyzers-unavailable branch


def test_analyze_empty_findings(monkeypatch):
    a = _agent()
    monkeypatch.setattr(a, "_aggregate_all_findings", lambda: [])
    results = a.analyze("/tmp/C.sol")
    assert results["compliance_report"]


# --------------------------------------------------------------------------- #
# each _check_* method directly, with rich + empty inputs (branch coverage)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method", CHECK_METHODS)
def test_check_methods_return_dicts(method):
    a = _agent()
    fn = getattr(a, method)
    assert isinstance(fn(RICH), dict)
    assert isinstance(fn([]), dict)


def test_check_ccss_compliance():
    a = _agent()
    out = a._check_ccss_compliance(RICH)
    assert isinstance(out, dict)


# --------------------------------------------------------------------------- #
# recommendation / scoring helpers
# --------------------------------------------------------------------------- #
def test_scsvs_recommendation_levels():
    a = _agent()
    for level in ("L1", "L2", "L3", "none"):
        assert isinstance(a._scsvs_recommendation(level), str)


def test_defi_risk_recommendation_levels():
    a = _agent()
    for level in ("critical", "high", "medium", "low", "minimal"):
        assert isinstance(a._defi_risk_recommendation(level), str)


def test_assess_audit_readiness():
    a = _agent()
    assert isinstance(a._assess_audit_readiness(RICH), str)
    assert isinstance(a._assess_audit_readiness([]), str)


def test_calculate_overall_compliance():
    a = _agent()
    sample = {
        "iso27001_status": {"compliance_score": 0.9},
        "nist_ssdf_status": {"compliance_score": 0.8},
    }
    score = a._calculate_overall_compliance(sample)
    assert isinstance(score, (int, float))


def _mock_analyzers(agent, *, raises=False):
    from unittest.mock import MagicMock

    if raises:

        def _boom(*a, **k):
            raise RuntimeError("analyzer failed")

        for attr in (
            "documentation_analyzer",
            "testing_analyzer",
            "maturity_analyzer",
            "security_practices_analyzer",
        ):
            m = MagicMock()
            m.analyze_all.side_effect = _boom
            setattr(agent, attr, m)
        return
    doc = MagicMock()
    doc.analyze_all.return_value = {
        "passes_audit_readiness": False,
        "natspec": {"coverage_percentage": 50},
        "readme": {"passes_threshold": False, "sections_missing": ["Install", "Usage"]},
    }
    testing = MagicMock()
    testing.analyze_all.return_value = {
        "passes_audit_readiness": False,
        "coverage": {"line_coverage": 60},
        "property_tests": {"passes_threshold": False},
    }
    maturity = MagicMock()
    maturity.analyze_all.return_value = {
        "passes_audit_readiness": False,
        "maturity": {"maturity_score": 0.3, "maturity_level": "early"},
    }
    security = MagicMock()
    security.analyze_all.return_value = {
        "passes_audit_readiness": False,
        "practices": {"recommendations": ["Use ReentrancyGuard"]},
    }
    agent.documentation_analyzer = doc
    agent.testing_analyzer = testing
    agent.maturity_analyzer = maturity
    agent.security_practices_analyzer = security


def test_comprehensive_audit_readiness_with_recommendations():
    a = _agent()
    _mock_analyzers(a)
    res = a._comprehensive_audit_readiness_assessment(RICH, "/tmp/C.sol", "/tmp/proj")
    assert "overall_score" in res
    assert "readiness_status" in res
    assert res["findings_severity"]["total"] == len(RICH)
    assert res["recommendations"]  # recommendation branches fired


def test_comprehensive_audit_readiness_handles_analyzer_errors():
    a = _agent()
    _mock_analyzers(a, raises=True)
    res = a._comprehensive_audit_readiness_assessment(RICH, "/tmp/C.sol", "/tmp/proj")
    # each analyzer error is captured, assessment still completes
    assert res["documentation"]["passes_audit_readiness"] is False


def test_analyze_runs_comprehensive_when_analyzers_present(monkeypatch):
    a = _agent()
    _mock_analyzers(a)
    monkeypatch.setattr(a, "_aggregate_all_findings", lambda: RICH)
    results = a.analyze("/tmp/proj/C.sol")
    assert "audit_readiness" in results
