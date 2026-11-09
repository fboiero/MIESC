"""Rule classes: lint / informational rules are capped at Low / Info everywhere.

Acceptance (plan B.1): a severity-class table in ``miesc/data/config`` with a
test that no Info/Low-class rule reaches Medium.
"""

from unittest.mock import patch

import pytest

from miesc.cli import utils
from miesc.core import rule_classes as rc
from miesc.core.intelligence import calibrate_severity, enhance_findings
from miesc.core.tool_protocol import ToolStatus

MEDIUM_OR_ABOVE = {"Medium", "High", "Critical"}


def _all_rules():
    table = rc.load_rule_classes()
    for tool, rules in table["rules"].items():
        for rule, cls in rules.items():
            yield tool, rule, cls


class TestTable:
    def test_table_ships_with_package_and_parses(self):
        assert rc.RULE_CLASSES_PATH.is_file()
        table = rc.load_rule_classes()
        assert {"lint", "informational"} <= set(table["classes"])
        assert {"aderyn", "slither", "solhint"} <= set(table["rules"])

    def test_every_class_has_a_ceiling_at_or_below_low(self):
        for cls in rc.load_rule_classes()["classes"]:
            ceiling = rc.class_max_severity(cls)
            assert ceiling in {"Low", "Info"}, (cls, ceiling)

    def test_every_rule_points_at_a_declared_class(self):
        classes = set(rc.load_rule_classes()["classes"])
        for tool, rule, cls in _all_rules():
            assert cls in classes, (tool, rule, cls)

    def test_the_plan_examples_are_lint(self):
        assert rc.rule_class("aderyn", "useless-public-function") == "lint"
        assert rc.rule_class("aderyn", "unspecific-solidity-pragma") == "lint"

    def test_security_rules_have_no_class(self):
        assert rc.rule_class("aderyn", "send-ether-no-checks") is None
        assert rc.rule_class("slither", "reentrancy-eth") is None
        assert rc.rule_class("unknown-tool", "anything") is None


class TestCapSeverity:
    @pytest.mark.parametrize("tool,rule,cls", list(_all_rules()))
    def test_no_lint_or_info_rule_reaches_medium(self, tool, rule, cls):
        for raw in ("Critical", "High", "Medium", "critical", "HIGH"):
            capped = rc.cap_severity(tool, rule, raw)
            assert capped not in MEDIUM_OR_ABOVE and rc.severity_rank(capped) <= 1, (
                tool,
                rule,
                raw,
                capped,
            )
            # The intelligence engine's calibration honours the same ceiling.
            finding = {"tool": tool, "type": rule, "severity": raw}
            assert calibrate_severity(finding) == rc.class_max_severity(cls)

    def test_unknown_rule_passes_through_same_object(self):
        sev = "High"
        assert rc.cap_severity("aderyn", "send-ether-no-checks", sev) is sev

    def test_already_below_ceiling_is_unchanged(self):
        assert rc.cap_severity("aderyn", "useless-public-function", "Info") == "Info"

    def test_finding_cap_records_original_and_class(self):
        f = {"tool": "aderyn", "type": "useless-public-function", "severity": "Medium"}
        assert rc.cap_finding_severity(f) is True
        assert f["severity"] == "Low"
        assert f["severity_before_class_cap"] == "Medium"
        assert f["rule_class"] == "lint"

    def test_solhint_rule_id_is_read_from_rule_key(self):
        f = {
            "tool": "solhint",
            "type": "style_violation",
            "rule": "max-line-length",
            "severity": "medium",
        }
        assert rc.finding_rule_class(f) == "informational"  # "rule" wins over "type"
        g = {"tool": "solhint", "rule": "max-line-length", "severity": "medium"}
        assert rc.finding_rule_class(g) == "informational"
        assert rc.cap_finding_severity(g) and g["severity"] == "Info"

    def test_apply_counts_only_lowered(self):
        fs = [
            {"tool": "aderyn", "type": "useless-public-function", "severity": "Medium"},
            {"tool": "aderyn", "type": "useless-public-function", "severity": "Low"},
            {"tool": "slither", "type": "reentrancy-eth", "severity": "High"},
            "not-a-finding",
        ]
        assert rc.apply_rule_class_caps(fs) == 1


class TestPipelines:
    def test_enhance_findings_caps_aderyn_lint_despite_low_to_medium_calibration(self):
        # Aderyn 0.1.9 only has high/low buckets and the per-tool calibration
        # lifts aderyn Low to Medium. A lint rule must still come out Low.
        findings = [
            {
                "type": "useless-public-function",
                "severity": "Low",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 17, "function": "deposit"},
            },
            {
                "type": "unspecific-solidity-pragma",
                "severity": "Low",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 2, "function": "unknown"},
            },
            {
                "type": "send-ether-no-checks",
                "severity": "High",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 27, "function": "withdraw"},
            },
        ]
        out = {f["type"]: f for f in enhance_findings(findings)}
        assert out["useless-public-function"]["severity"] == "Low"
        assert out["useless-public-function"]["rule_class"] == "lint"
        assert out["unspecific-solidity-pragma"]["severity"] == "Low"
        assert out["send-ether-no-checks"]["severity"] == "High"
        assert "rule_class" not in out["send-ether-no-checks"]

    def test_run_tool_caps_at_the_source(self, tmp_path):
        class _Adapter:
            def is_available(self):
                return ToolStatus.AVAILABLE

            def analyze(self, contract, timeout=0, **kw):
                return {
                    "status": "success",
                    "findings": [
                        {"type": "useless-public-function", "severity": "Critical"},
                        {"type": "reentrancy-eth", "severity": "High"},
                    ],
                }

        utils.AdapterLoader.reset_availability()
        with patch.object(utils.AdapterLoader, "get_adapter", return_value=_Adapter()):
            result = utils.run_tool("aderyn", str(tmp_path / "C.sol"), timeout=5)
        sev = {f["type"]: f["severity"] for f in result["findings"]}
        assert sev == {"useless-public-function": "Low", "reentrancy-eth": "High"}
        assert all(f["tool"] == "aderyn" for f in result["findings"])

    def test_ml_orchestrator_cap_helper_is_wired(self):
        import inspect

        from miesc.core import ml_orchestrator

        assert "apply_rule_class_caps" in inspect.getsource(ml_orchestrator)
