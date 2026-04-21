"""
Tests for src.core.intelligence — the 6-improvement intelligence engine.

1. Cross-tool confirmation scoring
2. Semantic deduplication
3. Patterns for 0%-recall categories
4. Context-aware FP suppression
5. LLM↔static cross-validation
6. Severity calibration
"""

from __future__ import annotations

import pytest

from src.core.intelligence import (
    MergedFinding,
    calibrate_severity,
    compute_cross_tool_confidence,
    context_aware_fp_check,
    detect_zero_recall_categories,
    enhance_findings,
    semantic_dedup,
    tag_cross_validation,
)


# ---------------------------------------------------------------------------
# 1. Cross-tool confirmation scoring
# ---------------------------------------------------------------------------


class TestCrossToolConfidence:
    def test_single_tool(self):
        conf = compute_cross_tool_confidence(["slither"])
        assert 0.5 < conf < 0.95

    def test_two_tools_higher(self):
        single = compute_cross_tool_confidence(["slither"])
        double = compute_cross_tool_confidence(["slither", "aderyn"])
        assert double > single

    def test_three_tools_near_max(self):
        triple = compute_cross_tool_confidence(["slither", "aderyn", "mythril"])
        assert triple > 0.90

    def test_empty_tools(self):
        assert compute_cross_tool_confidence([]) == 0.5

    def test_unknown_tool_uses_default_weight(self):
        conf = compute_cross_tool_confidence(["unknown_tool_xyz"])
        assert 0.3 < conf < 0.7

    def test_capped_at_099(self):
        many = ["slither", "aderyn", "mythril", "halmos", "echidna"]
        assert compute_cross_tool_confidence(many) <= 0.99


# ---------------------------------------------------------------------------
# 2. Semantic deduplication
# ---------------------------------------------------------------------------


class TestSemanticDedup:
    def test_same_type_same_function_merged(self):
        findings = [
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 27, "function": "withdraw"}},
            {"type": "reentrancy", "severity": "High", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 25, "function": "withdraw"}},
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 1
        assert len(merged[0].confirming_tools) == 2

    def test_different_types_not_merged(self):
        findings = [
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 10, "function": "withdraw"}},
            {"type": "access-control", "severity": "High", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 50, "function": "setOwner"}},
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 2

    def test_same_type_distant_lines_not_merged(self):
        findings = [
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 10, "function": "foo"}},
            {"type": "reentrancy-eth", "severity": "High", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 200, "function": "bar"}},
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 2

    def test_empty_findings(self):
        assert semantic_dedup([]) == []

    def test_representative_takes_highest_severity(self):
        findings = [
            {"type": "reentrancy", "severity": "Medium", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 10, "function": "f"}},
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 10, "function": "f"}},
        ]
        merged = semantic_dedup(findings)
        assert merged[0].representative["severity"] == "High"


# ---------------------------------------------------------------------------
# 3. Zero-recall category patterns
# ---------------------------------------------------------------------------


class TestZeroRecallPatterns:
    def test_detects_block_timestamp(self):
        code = "function f() { require(block.timestamp > deadline); }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "time_manipulation" in types

    def test_detects_blockhash_randomness(self):
        code = "uint random = uint(keccak256(abi.encodePacked(blockhash(block.number - 1))));"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness" in types

    def test_detects_pre_08_arithmetic(self):
        code = "pragma solidity ^0.7.0;\ncontract C { uint x = a + b; }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" in types

    def test_no_arithmetic_on_08_plus(self):
        code = "pragma solidity ^0.8.0;\ncontract C { uint x = a + b; }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" not in types

    def test_detects_approve_front_running(self):
        code = "function approve(address spender, uint256 amount) external { allowances[msg.sender][spender] = amount; }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "front_running" in types

    def test_no_front_running_with_safe_approve(self):
        code = "function increaseAllowance() external { }\nfunction approve() external { }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "front_running" not in types

    def test_safemath_suppresses_arithmetic(self):
        code = "pragma solidity ^0.6.0;\nusing SafeMath for uint256;"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" not in types

    def test_empty_code(self):
        assert detect_zero_recall_categories("") == []


# ---------------------------------------------------------------------------
# 4. Context-aware FP suppression
# ---------------------------------------------------------------------------


class TestContextAwareFP:
    def test_admin_function_suppresses_access_control(self):
        code = """
        function setOwner(address newOwner) external onlyOwner {
            owner = newOwner;
        }
        """
        finding = {"type": "access-control", "severity": "High",
                   "location": {"function": "setOwner"}}
        is_fp, reason = context_aware_fp_check(finding, code)
        assert is_fp is True
        assert "admin modifier" in reason

    def test_non_admin_function_not_suppressed(self):
        code = """
        function withdraw(uint amount) external {
            payable(msg.sender).transfer(amount);
        }
        """
        finding = {"type": "access-control", "severity": "High",
                   "location": {"function": "withdraw"}}
        is_fp, _ = context_aware_fp_check(finding, code)
        assert is_fp is False

    def test_test_file_suppressed(self):
        finding = {"type": "reentrancy", "severity": "High", "location": {}}
        is_fp, reason = context_aware_fp_check(finding, "", "tests/test_Vault.t.sol")
        assert is_fp is True
        assert "test" in reason.lower()

    def test_arithmetic_on_08_suppressed(self):
        code = "pragma solidity ^0.8.20;"
        finding = {"type": "integer-overflow", "severity": "High", "location": {}}
        is_fp, reason = context_aware_fp_check(finding, code)
        assert is_fp is True
        assert "0.8" in reason

    def test_reentrancy_with_guard_and_oz_suppressed(self):
        code = """
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        function withdraw() external nonReentrant {
            msg.sender.call{value: amount}("");
        }
        """
        finding = {"type": "reentrancy-eth", "severity": "High",
                   "location": {"function": "withdraw"}}
        is_fp, reason = context_aware_fp_check(finding, code)
        assert is_fp is True
        assert "nonReentrant" in reason


# ---------------------------------------------------------------------------
# 5. Cross-validation tagging
# ---------------------------------------------------------------------------


class TestCrossValidation:
    def test_static_and_llm_boosts(self):
        m = MergedFinding(
            canonical_category="reentrancy",
            representative={},
            confirming_tools=["slither", "smartllm"],
            confidence=0.70,
        )
        tag_cross_validation(m)
        assert m.cross_validated_by_static is True
        assert m.cross_validated_by_llm is True
        assert m.confidence > 0.70

    def test_static_only_no_boost(self):
        m = MergedFinding(
            canonical_category="reentrancy",
            representative={},
            confirming_tools=["slither", "aderyn"],
            confidence=0.70,
        )
        tag_cross_validation(m)
        assert m.cross_validated_by_static is True
        assert m.cross_validated_by_llm is False
        assert m.confidence == 0.70

    def test_llm_only(self):
        m = MergedFinding(
            canonical_category="access_control",
            representative={},
            confirming_tools=["gptscan"],
            confidence=0.60,
        )
        tag_cross_validation(m)
        assert m.cross_validated_by_static is False
        assert m.cross_validated_by_llm is True


# ---------------------------------------------------------------------------
# 6. Severity calibration
# ---------------------------------------------------------------------------


class TestSeverityCalibration:
    def test_aderyn_low_becomes_medium(self):
        f = {"tool": "aderyn", "severity": "Low"}
        assert calibrate_severity(f) == "Medium"

    def test_slither_informational_becomes_info(self):
        f = {"tool": "slither", "severity": "Informational"}
        assert calibrate_severity(f) == "Info"

    def test_unknown_tool_passthrough(self):
        f = {"tool": "custom", "severity": "High"}
        assert calibrate_severity(f) == "High"

    def test_case_insensitive(self):
        f = {"tool": "custom", "severity": "CRITICAL"}
        assert calibrate_severity(f) == "Critical"


# ---------------------------------------------------------------------------
# enhance_findings — full pipeline
# ---------------------------------------------------------------------------


class TestEnhanceFindings:
    def test_basic_enhancement(self):
        findings = [
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 10, "function": "withdraw"}},
            {"type": "reentrancy", "severity": "Low", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 10, "function": "withdraw"}},
        ]
        result = enhance_findings(findings, source_code="pragma solidity ^0.8.0;")
        # Should merge into 1 finding (same function, same category)
        assert len(result) < len(findings)
        # Merged finding should have tool_count >= 2
        assert result[0]["tool_count"] >= 2
        assert result[0]["confidence"] > 0.5

    def test_adds_zero_recall_patterns(self):
        code = "pragma solidity ^0.7.0;\nfunction f() { require(block.timestamp > x); }"
        result = enhance_findings([], source_code=code)
        types = [f["type"] for f in result]
        assert "time_manipulation" in types
        assert "arithmetic_pre08" in types

    def test_suppressed_findings_last(self):
        code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        function withdraw() external nonReentrant { msg.sender.call{value: x}(""); }
        function setOwner(address a) external onlyOwner { owner = a; }
        """
        findings = [
            {"type": "reentrancy-eth", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 4, "function": "withdraw"}},
            {"type": "access-control", "severity": "High", "tool": "slither",
             "location": {"file": "C.sol", "line": 5, "function": "setOwner"}},
        ]
        result = enhance_findings(findings, source_code=code)
        # Suppressed findings should sort to the end
        suppressed = [f for f in result if f.get("fp_suppressed")]
        not_suppressed = [f for f in result if not f.get("fp_suppressed")]
        if suppressed and not_suppressed:
            # Verify ordering
            last_not_sup = result.index(not_suppressed[-1])
            first_sup = result.index(suppressed[0])
            assert last_not_sup < first_sup

    def test_empty_findings_returns_empty(self):
        assert enhance_findings([]) == []

    def test_severity_calibrated(self):
        findings = [
            {"type": "reentrancy", "severity": "Low", "tool": "aderyn",
             "location": {"file": "C.sol", "line": 10, "function": "f"}},
        ]
        result = enhance_findings(findings)
        assert result[0]["severity"] == "Medium"  # Aderyn Low → Medium
