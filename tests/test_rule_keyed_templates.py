"""Fix / exploit / recommendation templates are keyed by detector rule.

Plan B.1: Aderyn `send-ether-no-checks` on a public `withdraw()` used to get
"Add onlyOwner modifier" because templates were keyed by canonical category
(SWC-105 -> access_control). A fix is tied to the rule, or omitted.
"""

from pathlib import Path

from miesc.core.intelligence import (
    enhance_findings,
    generate_exploit_scenario,
    generate_fix_code,
)

VULNERABLE_BANK = Path(__file__).resolve().parent.parent / "examples/contracts/VulnerableBank.sol"


def _aderyn(rule, line, function="unknown", severity="High"):
    security = rule == "send-ether-no-checks"
    return {
        "type": rule,
        "severity": severity,
        "tool": "aderyn",
        "message": (
            "Sending native Eth is not protected from these functions."
            if security
            else "`public` functions not used internally could be marked `external`"
        ),
        "recommendation": "Review and fix the issue according to best practices",
        "swc_id": "SWC-105" if security else None,
        "location": {"file": "VulnerableBank.sol", "line": line, "function": function},
        "_aderyn_detector": rule,
    }


class TestRuleKeyedResolution:
    def test_send_ether_no_checks_gets_rule_text_not_only_owner(self):
        f = _aderyn("send-ether-no-checks", 27, "withdraw")
        fix = generate_fix_code(f)
        assert fix is not None and "onlyOwner" in fix  # mentioned as the WRONG fix for a user withdraw
        assert "Do NOT add onlyOwner" in fix
        assert "Checks-Effects-Interactions" in fix or "CHECKS" in fix
        assert generate_exploit_scenario(f) is None  # no honest generic attack story

    def test_rule_resolved_only_through_swc_gets_no_category_fallback(self):
        f = {"type": "some-new-detector", "tool": "aderyn", "swc_id": "SWC-105", "severity": "High"}
        assert generate_fix_code(f) is None
        assert generate_exploit_scenario(f) is None

    def test_strong_rules_keep_the_category_template(self):
        slither = {"type": "reentrancy-eth", "tool": "slither", "severity": "High"}
        assert "nonReentrant" in generate_fix_code(slither)
        assert generate_exploit_scenario(slither)[0].startswith("1. Attacker deploys")
        pattern = {"type": "unchecked_return_value", "tool": "miesc-intelligence", "swc_id": "SWC-104"}
        assert "require(success" in generate_fix_code(pattern)

    def test_type_that_is_a_category_name_still_resolves(self):
        llm = {"type": "access-control", "tool": "smartllm", "severity": "High"}
        assert "onlyOwner" in generate_fix_code(llm)
        assert generate_exploit_scenario(llm) is not None

    def test_legacy_callers_with_only_canonical_category(self):
        assert "ReentrancyGuard" in generate_fix_code({"canonical_category": "reentrancy"})
        assert generate_exploit_scenario({"canonical_category": "oracle_manipulation"})

    def test_tx_origin_has_its_own_fix_and_scenario(self):
        f = {"type": "tx-origin", "tool": "slither", "severity": "Medium"}
        assert "msg.sender == owner" in generate_fix_code(f)
        assert "tx.origin is the EOA" in " ".join(generate_exploit_scenario(f))

    def test_lint_rule_gets_nothing(self):
        f = {"type": "useless-public-function", "tool": "aderyn", "severity": "Low"}
        assert generate_fix_code(f) is None
        assert generate_exploit_scenario(f) is None


class TestVulnerableBankReadsCorrectly:
    """Acceptance (plan B.1): the VulnerableBank scan shows no onlyOwner advice on withdraw()."""

    def test_no_only_owner_advice_on_public_withdraw(self):
        source = VULNERABLE_BANK.read_text(encoding="utf-8")
        findings = [
            _aderyn("send-ether-no-checks", 27),
            _aderyn("send-ether-no-checks", 68),
            _aderyn("useless-public-function", 27, severity="Low"),
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": str(VULNERABLE_BANK), "line": 27, "function": "withdraw"},
            },
        ]
        out = enhance_findings(findings, source_code=source, file_path=str(VULNERABLE_BANK))
        withdraw_hits = [f for f in out if f["location"]["function"] == "withdraw"]
        assert withdraw_hits
        for f in withdraw_hits:
            text = " ".join(
                [
                    str(f.get("recommendation", "")),
                    " ".join(f.get("exploit_scenario") or []),
                ]
            )
            assert "onlyOwner" not in text, f["type"]
            assert "Add access control modifier" not in text, f["type"]
            if f["type"] == "send-ether-no-checks":
                assert "Do NOT add onlyOwner" in f["fix_code"]
                assert "exploit_scenario" not in f
                assert "user withdrawal needs no caller restriction" in f["recommendation"]
        lint = next(f for f in out if f["type"] == "useless-public-function")
        assert lint["severity"] == "Low"
        assert "fix_code" not in lint and "exploit_scenario" not in lint
        # The lint rule's own title is its advice.
        assert lint["recommendation"] == lint["message"]
