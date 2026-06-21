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

from src.core.intelligence import (
    MergedFinding,
    _passes_zero_recall_context_filter,
    calibrate_severity,
    compute_cross_tool_confidence,
    context_aware_fp_check,
    detect_zero_recall_categories,
    enhance_findings,
    generate_exploit_scenario,
    generate_fix_code,
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
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 27, "function": "withdraw"},
            },
            {
                "type": "reentrancy",
                "severity": "High",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 25, "function": "withdraw"},
            },
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 1
        assert len(merged[0].confirming_tools) == 2

    def test_different_types_not_merged(self):
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
            },
            {
                "type": "access-control",
                "severity": "High",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 50, "function": "setOwner"},
            },
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 2

    def test_same_type_distant_lines_not_merged(self):
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "foo"},
            },
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 200, "function": "bar"},
            },
        ]
        merged = semantic_dedup(findings)
        assert len(merged) == 2

    def test_empty_findings(self):
        assert semantic_dedup([]) == []

    def test_representative_takes_highest_severity(self):
        findings = [
            {
                "type": "reentrancy",
                "severity": "Medium",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 10, "function": "f"},
            },
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "f"},
            },
        ]
        merged = semantic_dedup(findings)
        assert merged[0].representative["severity"] == "High"


# ---------------------------------------------------------------------------
# 3. Zero-recall category patterns
# ---------------------------------------------------------------------------


class TestZeroRecallPatterns:
    def test_timelock_require_not_flagged(self):
        """Pure timelock require(block.timestamp > deadline) is NOT a vulnerability."""
        code = "function f() { require(block.timestamp > deadline); }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "time_manipulation" not in types

    def test_detects_timestamp_in_assignment(self):
        """block.timestamp used in assignment IS a vulnerability."""
        code = "uint seed = block.timestamp;"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "time_manipulation" in types

    def test_detects_timestamp_in_arithmetic(self):
        """block.timestamp used in arithmetic IS a vulnerability."""
        code = "uint lockEnd = block.timestamp + lockDuration;\nrequire(block.timestamp > lockEnd);"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "time_manipulation" in types

    def test_detects_blockhash_randomness(self):
        code = "uint random = uint(keccak256(abi.encodePacked(blockhash(block.number - 1))));"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness" in types

    def test_blockhash_without_randomness_context_not_flagged(self):
        """blockhash used for replay protection, not randomness — should not flag bad_randomness_blockhash."""
        code = "require(blockhash(blockNumber) == expectedHash);"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness_blockhash" not in types

    def test_block_timestamp_simple_gating_not_flagged_as_randomness(self):
        """block.timestamp used in require() for time gating — not randomness."""
        code = "require(block.timestamp > lastUpdate + cooldown);"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness_block_vars" not in types

    def test_block_vars_modulo_is_randomness(self):
        """block.timestamp % N is clearly used for pseudo-randomness."""
        code = "uint winner = block.timestamp % participants.length;"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness_block_vars" in types

    def test_pre_08_arithmetic_not_flagged_by_zero_recall(self):
        # arithmetic was removed from the zero-recall patterns: slither/aderyn
        # already detect it, so the blanket "pre-0.8 has arithmetic" pattern only
        # added false positives (+32 FP / 0 TP measured on SmartBugs).
        code = "pragma solidity ^0.7.0;\ncontract C { uint x = a + b; }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" not in types

    def test_pre_08_without_arithmetic_not_flagged_as_overflow(self):
        code = "pragma solidity ^0.7.0;\ncontract C { address owner; }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" not in types

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

    def test_detects_claimable_reward_front_running(self):
        # SmartBugs eth_tx_order_dependence_minimal: reward paid from mutable state
        # (transfer(reward)) is order-dependent (setReward/claimReward front-run).
        code = (
            "pragma solidity ^0.4.16;\ncontract C { uint public reward;\n"
            "function claimReward(uint256 s) { require(s < 10); msg.sender.transfer(reward); } }"
        )
        types = [f["type"] for f in detect_zero_recall_categories(code)]
        assert "front_running" in types

    def test_detects_ordering_game_without_explicit_public(self):
        # SmartBugs odds_and_evens: a play(uint) game touching `players`, but with
        # implicit/payable visibility (pre-0.5) — the pattern no longer requires a
        # literal `public`. Was a false negative; recall 2/4 -> 3/4, 0 new FPs.
        code = (
            "pragma solidity ^0.4.2;\ncontract C { Player[2] public players;\n"
            "function play(uint number) payable{ players[tot] = Player(msg.sender, number); } }"
        )
        types = [f["type"] for f in detect_zero_recall_categories(code)]
        assert "front_running" in types

    def test_safemath_suppresses_arithmetic(self):
        code = "pragma solidity ^0.6.0;\nusing SafeMath for uint256;"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "arithmetic_pre08" not in types

    def test_empty_code(self):
        assert detect_zero_recall_categories("") == []

    def test_blockhash_without_randomness_context_not_flagged(self):
        code = "function previous() external view returns (bytes32) { return blockhash(block.number - 1); }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "bad_randomness" not in types

    def test_comment_only_timestamp_not_flagged(self):
        code = "// block.timestamp is mentioned in documentation"
        assert detect_zero_recall_categories(code) == []

    def test_detects_multiline_incorrect_constructor_name(self):
        code = """
        pragma solidity ^0.4.21;
        contract Wallet {
            address public owner;
            function Walet()
                public
            {
                owner = msg.sender;
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "incorrect_constructor_name" in types

    def test_detects_multiline_unprotected_delegatecall(self):
        code = """
        contract Proxy {
            function execute(address target, bytes data)
                public
            {
                target.delegatecall(data);
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "delegatecall_unprotected" in types

    def test_detects_multiline_arbitrary_mapping_write(self):
        code = """
        contract C {
            uint256[] public map;
            function write(uint256 key)
                public
            {
                map.length = key;
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "mapping_write_arbitrary" in types

    def test_detects_constructor_mismatch_creator_assignment(self):
        code = """
        pragma solidity ^0.4.21;
        contract DynamicPyramid {
            address public creator;
            function DynamicPyramids() public {
                creator = msg.sender;
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "constructor_mismatch" in types

    def test_detects_withdraw_without_balance_reset(self):
        code = """
        contract Vault {
            mapping(address => uint256) public balances;
            function withdraw() public {
                msg.sender.transfer(balances[msg.sender]);
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "withdraw_no_balance_update" in types

    def test_balance_reset_suppresses_withdraw_no_balance_update(self):
        code = """
        contract Vault {
            mapping(address => uint256) public balances;
            function withdraw() public {
                msg.sender.transfer(balances[msg.sender]);
                balances[msg.sender] = 0;
            }
        }
        """
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "withdraw_no_balance_update" not in types

    def test_detects_confused_balance_comparison(self):
        code = "function withdraw(uint amount) public { require(amount >= balances[msg.sender]); }"
        findings = detect_zero_recall_categories(code)
        types = [f["type"] for f in findings]
        assert "confused_comparison" in types


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
        finding = {
            "type": "access-control",
            "severity": "High",
            "location": {"function": "setOwner"},
        }
        is_fp, reason = context_aware_fp_check(finding, code)
        assert is_fp is True
        assert "admin modifier" in reason

    def test_non_admin_function_not_suppressed(self):
        code = """
        function withdraw(uint amount) external {
            payable(msg.sender).transfer(amount);
        }
        """
        finding = {
            "type": "access-control",
            "severity": "High",
            "location": {"function": "withdraw"},
        }
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
        finding = {
            "type": "reentrancy-eth",
            "severity": "High",
            "location": {"function": "withdraw"},
        }
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
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
            },
            {
                "type": "reentrancy",
                "severity": "Low",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
            },
        ]
        result = enhance_findings(findings, source_code="pragma solidity ^0.8.0;")
        # Should merge into 1 finding (same function, same category)
        assert len(result) < len(findings)
        # Merged finding should have tool_count >= 2
        assert result[0]["tool_count"] >= 2
        assert result[0]["confidence"] > 0.5

    def test_adds_zero_recall_patterns(self):
        code = (
            "pragma solidity ^0.7.0;\n"
            "function f(uint a, uint b) { uint c = a + b; uint t = block.timestamp; }"
        )
        result = enhance_findings([], source_code=code)
        types = [f["type"] for f in result]
        assert "time_manipulation" in types
        # arithmetic_pre08 removed — no longer added by zero-recall patterns
        assert "arithmetic_pre08" not in types

    def test_timelock_not_flagged_in_enhance(self):
        """Timelock require() with timestamp does not produce time_manipulation."""
        code = (
            "pragma solidity ^0.7.0;\n"
            "function f(uint a, uint b) { uint c = a + b; require(block.timestamp > x); }"
        )
        result = enhance_findings([], source_code=code)
        types = [f["type"] for f in result]
        # time_manipulation does NOT fire (pure timelock require)
        assert "time_manipulation" not in types

    def test_suppressed_findings_last(self):
        code = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        function withdraw() external nonReentrant { msg.sender.call{value: x}(""); }
        function setOwner(address a) external onlyOwner { owner = a; }
        """
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 4, "function": "withdraw"},
            },
            {
                "type": "access-control",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 5, "function": "setOwner"},
            },
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
            {
                "type": "reentrancy",
                "severity": "Low",
                "tool": "aderyn",
                "location": {"file": "C.sol", "line": 10, "function": "f"},
            },
        ]
        result = enhance_findings(findings)
        assert result[0]["severity"] == "Medium"  # Aderyn Low → Medium


# ---------------------------------------------------------------------------
# 8. Fix-code generation
# ---------------------------------------------------------------------------


class TestGenerateFixCode:
    def test_reentrancy_returns_solidity_snippet(self):
        finding = {"canonical_category": "reentrancy"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "nonReentrant" in code
        assert "ReentrancyGuard" in code

    def test_access_control_contains_onlyowner(self):
        finding = {"canonical_category": "access_control"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "onlyOwner" in code

    def test_oracle_manipulation_has_staleness_check(self):
        finding = {"canonical_category": "oracle_manipulation"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "latestRoundData" in code
        assert "STALENESS_THRESHOLD" in code

    def test_arithmetic_has_safemath(self):
        finding = {"canonical_category": "arithmetic"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "SafeMath" in code
        assert "unchecked" in code

    def test_unchecked_call_has_safeerc20(self):
        finding = {"canonical_category": "unchecked_call"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "SafeERC20" in code
        assert "safeTransfer" in code

    def test_bad_randomness_has_vrf(self):
        finding = {"canonical_category": "bad_randomness"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "VRF" in code
        assert "requestRandomWords" in code

    def test_time_manipulation_uses_block_number(self):
        finding = {"canonical_category": "time_manipulation"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "block.number" in code

    def test_front_running_has_increase_allowance(self):
        finding = {"canonical_category": "front_running"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "increaseAllowance" in code or "safeIncreaseAllowance" in code

    def test_proxy_upgrade_has_authorize_upgrade(self):
        finding = {"canonical_category": "proxy_upgrade"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "_authorizeUpgrade" in code
        assert "UUPSUpgradeable" in code

    def test_initialization_has_initializer_modifier(self):
        finding = {"canonical_category": "initialization"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "initializer" in code
        assert "Initializable" in code

    def test_other_category_returns_none(self):
        finding = {"canonical_category": "other"}
        assert generate_fix_code(finding) is None

    def test_unknown_canonical_returns_none(self):
        finding = {"canonical_category": "does_not_exist"}
        assert generate_fix_code(finding) is None

    def test_missing_canonical_falls_back_to_normalize(self):
        # No canonical_category key — should resolve via normalize_finding_type
        finding = {"type": "reentrancy-eth", "severity": "High", "tool": "slither"}
        code = generate_fix_code(finding)
        assert code is not None
        assert "nonReentrant" in code

    def test_fix_code_is_valid_solidity_string(self):
        # Basic sanity: all templates should contain the contract keyword or import
        for cat in [
            "reentrancy",
            "access_control",
            "oracle_manipulation",
            "arithmetic",
            "unchecked_call",
            "bad_randomness",
            "time_manipulation",
            "front_running",
            "proxy_upgrade",
            "initialization",
        ]:
            finding = {"canonical_category": cat}
            code = generate_fix_code(finding)
            assert code is not None, f"Missing template for {cat}"
            assert len(code) >= 100, f"Template too short for {cat}"
            assert "contract " in code or "import " in code, f"Not a Solidity snippet for {cat}"


# ---------------------------------------------------------------------------
# 9. Exploit scenario generation
# ---------------------------------------------------------------------------


class TestGenerateExploitScenario:
    def test_reentrancy_has_enough_steps(self):
        finding = {"canonical_category": "reentrancy"}
        steps = generate_exploit_scenario(finding)
        assert steps is not None
        assert len(steps) >= 3

    def test_access_control_steps(self):
        finding = {"canonical_category": "access_control"}
        steps = generate_exploit_scenario(finding)
        assert steps is not None
        assert len(steps) >= 3

    def test_oracle_manipulation_steps(self):
        finding = {"canonical_category": "oracle_manipulation"}
        steps = generate_exploit_scenario(finding)
        assert steps is not None
        assert len(steps) >= 4  # oracle attacks typically have 4+ steps

    def test_all_known_categories_have_scenario(self):
        categories = [
            "reentrancy",
            "access_control",
            "oracle_manipulation",
            "arithmetic",
            "unchecked_call",
            "bad_randomness",
            "time_manipulation",
            "front_running",
            "proxy_upgrade",
            "initialization",
        ]
        for cat in categories:
            finding = {"canonical_category": cat}
            steps = generate_exploit_scenario(finding)
            assert steps is not None, f"Missing scenario for {cat}"
            assert len(steps) >= 3, f"Too few steps for {cat}"

    def test_other_category_returns_none(self):
        finding = {"canonical_category": "other"}
        assert generate_exploit_scenario(finding) is None

    def test_unknown_canonical_returns_none(self):
        finding = {"canonical_category": "nonexistent_category"}
        assert generate_exploit_scenario(finding) is None

    def test_steps_are_strings(self):
        finding = {"canonical_category": "reentrancy"}
        steps = generate_exploit_scenario(finding)
        assert all(isinstance(s, str) for s in steps)

    def test_fallback_to_normalize_without_canonical(self):
        finding = {"type": "bad-randomness", "severity": "High", "tool": "slither"}
        steps = generate_exploit_scenario(finding)
        assert steps is not None
        assert len(steps) >= 3

    def test_returns_copy_not_reference(self):
        # Modifying the returned list should not affect subsequent calls
        finding = {"canonical_category": "reentrancy"}
        steps1 = generate_exploit_scenario(finding)
        steps1.append("extra step")
        steps2 = generate_exploit_scenario(finding)
        assert "extra step" not in steps2


# ---------------------------------------------------------------------------
# enhance_findings — fix_code and exploit_scenario integration
# ---------------------------------------------------------------------------


class TestEnhanceFindingsFixAndExploit:
    def test_fix_code_populated_for_reentrancy(self):
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
            },
        ]
        result = enhance_findings(findings)
        reentrancy = next((f for f in result if f.get("canonical_category") == "reentrancy"), None)
        assert reentrancy is not None
        assert "fix_code" in reentrancy
        assert "nonReentrant" in reentrancy["fix_code"]

    def test_exploit_scenario_populated_for_access_control(self):
        findings = [
            {
                "type": "access-control",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 5, "function": "setOwner"},
            },
        ]
        result = enhance_findings(findings)
        ac = next((f for f in result if f.get("canonical_category") == "access_control"), None)
        assert ac is not None
        assert "exploit_scenario" in ac
        assert len(ac["exploit_scenario"]) >= 3

    def test_other_category_has_no_fix_code(self):
        # A finding that maps to "other" should not have fix_code
        findings = [
            {
                "type": "totally-unknown-detector-xyz",
                "severity": "Low",
                "tool": "custom",
                "location": {"file": "X.sol", "line": 1, "function": "f"},
            },
        ]
        result = enhance_findings(findings)
        # Find the finding that ended up as "other"
        other = next((f for f in result if f.get("canonical_category") == "other"), None)
        if other is not None:
            assert "fix_code" not in other

    def test_multiple_findings_each_get_fix_and_scenario(self):
        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "tool": "slither",
                "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
            },
            {
                "type": "integer-overflow",
                "severity": "High",
                "tool": "mythril",
                "location": {"file": "C.sol", "line": 50, "function": "add"},
            },
        ]
        result = enhance_findings(findings)
        for f in result:
            cat = f.get("canonical_category", "other")
            if cat != "other":
                assert "fix_code" in f, f"Missing fix_code for category={cat}"
                assert "exploit_scenario" in f, f"Missing exploit_scenario for category={cat}"


class TestZeroRecallContextFilter:
    """Tests for _passes_zero_recall_context_filter — precision filters that gate
    recall-boost findings. Returns True = fire (vulnerable), False = suppress."""

    def test_no_filter_fires(self):
        assert _passes_zero_recall_context_filter(None, "anything", "anything") is True

    def test_commented_match_is_suppressed(self):
        assert _passes_zero_recall_context_filter(
            "randomness_context", "// uint x = blockhash(1);", "// uint x = blockhash(1);"
        ) is False

    def test_unknown_filter_fires(self):
        assert _passes_zero_recall_context_filter(
            "some_unknown_filter", "code", "code"
        ) is True

    # --- non_timelock_timestamp ---
    def test_pure_timelock_is_suppressed(self):
        src = "function f() { require(block.timestamp > deadline); }"
        assert _passes_zero_recall_context_filter(
            "non_timelock_timestamp", src, "require(block.timestamp > deadline)"
        ) is False

    def test_non_timelock_timestamp_fires(self):
        src = "function f() { uint t = block.timestamp; bet(t); }"
        assert _passes_zero_recall_context_filter(
            "non_timelock_timestamp", src, "uint t = block.timestamp;"
        ) is True

    # --- randomness_context ---
    def test_randomness_keccak_fires(self):
        src = "uint r = keccak256(blockhash(block.number));"
        assert _passes_zero_recall_context_filter("randomness_context", src, src) is True

    def test_randomness_modulo_fires(self):
        src = "uint r = block.timestamp % 10;"
        assert _passes_zero_recall_context_filter("randomness_context", src, src) is True

    def test_randomness_entropy_assignment_fires(self):
        src = "uint seed = uint(blockhash(block.number - 1));"
        assert _passes_zero_recall_context_filter("randomness_context", src, src) is True

    def test_randomness_keyword_near_block_var_fires(self):
        src = "function lottery() { pickWinner(blockhash(block.number)); }"
        assert _passes_zero_recall_context_filter("randomness_context", src, src) is True

    def test_benign_block_var_suppressed(self):
        src = "uint lastUpdate = block.number;"
        assert _passes_zero_recall_context_filter("randomness_context", src, src) is False

    # --- has_unchecked_arithmetic ---
    def test_financial_arithmetic_fires(self):
        src = "function f() { balances[msg.sender] += amount; }"
        assert _passes_zero_recall_context_filter("has_unchecked_arithmetic", src, src) is True

    def test_pragma_only_arithmetic_suppressed(self):
        src = "pragma solidity 0.4.24;\n// no arithmetic here\ncontract C {}"
        assert _passes_zero_recall_context_filter("has_unchecked_arithmetic", src, src) is False

    def test_non_timelock_skips_commented_timestamp_line(self):
        src = "// legacy: block.timestamp check\nuint t = block.timestamp; bet(t);"
        assert _passes_zero_recall_context_filter(
            "non_timelock_timestamp", src, "uint t = block.timestamp;"
        ) is True


class TestContextAwareFpCheckExtra:
    """Extra context_aware_fp_check rules: guarded selfdestruct, proxy, SafeERC20."""

    def test_guarded_selfdestruct_suppressed(self):
        src = "function destroy() public onlyOwner { selfdestruct(owner); }"
        finding = {"type": "suicidal", "severity": "High", "location": {}}
        is_fp, reason = context_aware_fp_check(finding, src)
        assert is_fp is True
        assert "selfdestruct guarded" in reason

    def test_unguarded_selfdestruct_not_suppressed(self):
        src = "function destroy() public { selfdestruct(msg.sender); }"
        finding = {"type": "suicidal", "severity": "High", "location": {}}
        is_fp, _ = context_aware_fp_check(finding, src)
        assert is_fp is False

    def test_proxy_with_oz_upgrade_infra_suppressed(self):
        src = "contract C is Initializable { function init() public initializer {} }"
        finding = {"type": "proxy_upgrade", "severity": "High", "location": {}}
        is_fp, reason = context_aware_fp_check(finding, src)
        assert is_fp is True
        assert "OpenZeppelin upgrade" in reason

    def test_unchecked_call_with_safeerc20_suppressed(self):
        src = (
            'import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";\n'
            "contract C { using SafeERC20 for IERC20; function f() { t.safeTransfer(a, x); } }"
        )
        finding = {"type": "unchecked-call", "severity": "Medium", "location": {}}
        is_fp, reason = context_aware_fp_check(finding, src)
        assert is_fp is True
        assert "SafeERC20" in reason
