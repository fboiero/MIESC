"""Identical rule hits within one file are grouped with a count (plan B.1)."""

from miesc.cli.commands.audit import _to_sarif
from miesc.core.intelligence import enhance_findings, group_identical_rule_hits


def _hit(rule, line, function, tool="aderyn", severity="Low", **extra):
    return {
        "type": rule,
        "tool": tool,
        "severity": severity,
        "confidence": 0.5,
        "location": {"file": "Bank.sol", "line": line, "function": function},
        **extra,
    }


class TestGroupIdenticalRuleHits:
    def test_same_rule_same_file_becomes_one_finding_with_locations(self):
        hits = [
            _hit("useless-public-function", 59, "deposit"),
            _hit("useless-public-function", 17, "deposit", confidence=0.7),
            _hit("useless-public-function", 44, "getContractBalance", severity="Medium"),
        ]
        out = group_identical_rule_hits(hits)
        assert len(out) == 1
        g = out[0]
        assert g["occurrences"] == 3
        assert g["location"]["line"] == 17  # lowest line is the survivor
        assert [loc["line"] for loc in g["locations"]] == [17, 44, 59]
        assert g["locations"][1]["function"] == "getContractBalance"
        assert g["severity"] == "Medium" and g["confidence"] == 0.7

    def test_single_hit_is_untouched(self):
        out = group_identical_rule_hits([_hit("send-ether-no-checks", 27, "withdraw")])
        assert "occurrences" not in out[0] and "locations" not in out[0]

    def test_different_file_tool_or_suppression_state_do_not_group(self):
        a = _hit("x", 1, "f")
        b = _hit("x", 2, "g")
        b["location"]["file"] = "Other.sol"
        c = _hit("x", 3, "h", tool="slither")
        d = _hit("x", 4, "i", fp_suppressed=True)
        assert len(group_identical_rule_hits([a, b, c, d])) == 4

    def test_findings_without_file_or_line_pass_through(self):
        a = {"type": "x", "tool": "t", "location": {"file": "", "line": 3}}
        b = {"type": "x", "tool": "t", "location": {"file": "F.sol", "line": 0}}
        c = {"type": "x", "tool": "t", "location": "F.sol:1"}
        assert group_identical_rule_hits([a, b, c]) == [a, b, c]

    def test_enhance_findings_groups_in_the_report(self):
        findings = [
            _hit("useless-public-function", line, fn)
            for line, fn in ((17, "deposit"), (44, "getContractBalance"), (59, "deposit"))
        ] + [_hit("send-ether-no-checks", 27, "withdraw", severity="High")]
        out = enhance_findings(findings)
        by_type = {f["type"]: f for f in out}
        assert len(out) == 2
        assert by_type["useless-public-function"]["occurrences"] == 3
        assert by_type["useless-public-function"]["severity"] == "Low"
        assert "occurrences" not in by_type["send-ether-no-checks"]


def test_sarif_emits_every_grouped_location():
    grouped = enhance_findings(
        [_hit("useless-public-function", line, "f") for line in (17, 44, 59)]
    )
    sarif = _to_sarif([{"tool": "aderyn", "status": "success", "findings": grouped}])
    result = sarif["runs"][0]["results"][0]
    starts = [loc["physicalLocation"]["region"]["startLine"] for loc in result["locations"]]
    assert starts == [17, 44, 59]
