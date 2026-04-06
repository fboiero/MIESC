"""
End-to-end pipeline integration tests.

Tests the full flow: contract → analysis → findings → report
using only Slither + Aderyn (fast, always available).
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest


REENTRANCY_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}
"""

SAFE_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SafeCounter {
    uint256 private _count;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function increment() public onlyOwner {
        _count += 1;
    }

    function count() public view returns (uint256) {
        return _count;
    }
}
"""


@pytest.fixture
def vulnerable_contract(tmp_path):
    path = tmp_path / "VulnerableBank.sol"
    path.write_text(REENTRANCY_CONTRACT)
    return str(path)


@pytest.fixture
def safe_contract(tmp_path):
    path = tmp_path / "SafeCounter.sol"
    path.write_text(SAFE_CONTRACT)
    return str(path)


class TestMIESCCoreAnalyze:
    """Test MIESCCore.analyze() end-to-end."""

    def test_analyze_returns_findings(self, vulnerable_contract):
        """Vulnerable contract should produce findings."""
        from src.miesc_core import MIESCCore
        core = MIESCCore()
        result = core.analyze(vulnerable_contract, tools=["slither", "aderyn"])

        assert result["success"] is True
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) > 0
        assert "metadata" in result

    def test_analyze_finds_reentrancy_pattern(self, vulnerable_contract):
        """Should detect the reentrancy pattern (call before state update)."""
        from src.miesc_core import MIESCCore
        core = MIESCCore()
        result = core.analyze(vulnerable_contract, tools=["slither", "aderyn"])

        # At least one finding should relate to the external call pattern
        checks = [f.get("check", f.get("type", "")).lower() for f in result["findings"]]
        has_call_related = any(
            kw in c for c in checks
            for kw in ["send-ether", "arbitrary-send", "reentrancy", "call", "ether"]
        )
        assert has_call_related, f"Expected call-related finding, got checks: {checks}"

    def test_analyze_safe_contract(self, safe_contract):
        """Safe contract should have fewer/no high-severity findings."""
        from src.miesc_core import MIESCCore
        core = MIESCCore()
        result = core.analyze(safe_contract, tools=["slither", "aderyn"])

        assert result["success"] is True
        high_findings = [
            f for f in result["findings"]
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        # Safe contract should have fewer high findings than vulnerable one
        assert len(high_findings) <= 5  # Aderyn may flag some patterns

    def test_analyze_with_nonexistent_tools(self, vulnerable_contract):
        """Non-existent tools should fail gracefully."""
        from src.miesc_core import MIESCCore
        core = MIESCCore()
        result = core.analyze(vulnerable_contract, tools=["nonexistent_tool"])

        assert result["success"] is True
        # Should return empty or minimal findings
        assert isinstance(result["findings"], list)

    def test_analyze_scan_alias(self, vulnerable_contract):
        """scan() should work as alias for analyze()."""
        from src.miesc_core import MIESCCore
        core = MIESCCore()
        result = core.scan(vulnerable_contract, tools=["slither", "aderyn"])

        assert result["success"] is True
        assert isinstance(result["findings"], list)


class TestFPFilter:
    """Test false positive filter on real findings."""

    def test_filter_produces_results(self):
        """FP filter should process findings without errors."""
        try:
            from src.ml.fp_filter import FalsePositiveFilter
            fp = FalsePositiveFilter()
            finding = {"type": "reentrancy", "severity": "high", "check": "reentrancy-eth", "confidence": 0.8}
            fr = fp.filter_finding(finding, code_context="pragma solidity ^0.8.0;\ncontract T {}")
            assert hasattr(fr, "is_likely_fp")
            assert 0.0 <= fr.fp_probability <= 1.0
        except (ImportError, Exception) as e:
            if "sentence-transformers" in str(e) or "chromadb" in str(e):
                pytest.skip(f"FP filter deps not available: {e}")
            raise

    def test_solidity_version_detection(self):
        """Should detect Solidity version from code."""
        from src.ml.fp_filter import FalsePositiveFilter
        fp = FalsePositiveFilter()

        v = fp._detect_solidity_version("pragma solidity ^0.8.20;\ncontract T {}")
        assert v is not None
        assert v >= (0, 8, 0)

        v2 = fp._detect_solidity_version("pragma solidity ^0.4.24;\ncontract T {}")
        assert v2 is not None
        assert v2 < (0, 8, 0)

        v3 = fp._detect_solidity_version("no pragma here")
        assert v3 is None


class TestClassicPatterns:
    """Test classic pattern detection on real code."""

    def test_detects_reentrancy(self):
        """Should detect reentrancy pattern in vulnerable code."""
        from src.ml.classic_patterns import ClassicPatternDetector, ClassicVulnType

        detector = ClassicPatternDetector()
        matches = detector.detect(REENTRANCY_CONTRACT, categories=[ClassicVulnType.REENTRANCY])

        # The contract has .call{value:} which matches reentrancy patterns
        assert len(matches) > 0, "Should detect reentrancy in vulnerable contract"

    def test_oracle_patterns_exist(self):
        """Oracle manipulation patterns should be defined."""
        from src.ml.classic_patterns import ClassicVulnType, CLASSIC_PATTERNS

        assert ClassicVulnType.ORACLE_MANIPULATION in CLASSIC_PATTERNS
        config = CLASSIC_PATTERNS[ClassicVulnType.ORACLE_MANIPULATION]
        assert len(config.patterns) >= 5
        assert len(config.anti_patterns) >= 3

    def test_flash_loan_patterns_exist(self):
        """Flash loan patterns should be defined."""
        from src.ml.classic_patterns import ClassicVulnType, CLASSIC_PATTERNS

        assert ClassicVulnType.FLASH_LOAN in CLASSIC_PATTERNS
        config = CLASSIC_PATTERNS[ClassicVulnType.FLASH_LOAN]
        assert len(config.patterns) >= 4
