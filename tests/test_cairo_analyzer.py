"""Tests for src.adapters.cairo_adapter — Cairo/Starknet analyzer."""

import pytest

from src.adapters.cairo_adapter import (
    CAIRO_PATTERNS,
    CairoAnalyzer,
    CairoFinding,
    CairoVulnType,
    analyze_cairo_contract,
)


CAIRO_VULNERABLE = """
#[starknet::contract]
mod VulnVault {
    use starknet::{ContractAddress, get_caller_address};
    use starknet::syscalls::replace_class_syscall;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        balances: LegacyMap<ContractAddress, felt252>,
    }

    #[external]
    fn mint(ref self: ContractState, amount: felt252, to: ContractAddress) {
        let current = self.balances.read(to);
        self.balances.write(to, current + amount);
    }

    #[l1_handler]
    fn on_receive_from_l1(ref self: ContractState, from_address: felt252) {
    }

    #[external]
    fn upgrade(ref self: ContractState, new_class_hash: starknet::ClassHash) {
        replace_class_syscall(new_class_hash);
    }
}
"""


@pytest.fixture
def analyzer():
    return CairoAnalyzer()


class TestCairoAnalyzer:
    def test_is_available(self, analyzer):
        assert analyzer.is_available() is True

    def test_metadata(self, analyzer):
        assert analyzer.name == "miesc-cairo"
        assert "1.0" in analyzer.version
        assert analyzer.description

    def test_analyze_source_detects_vulnerabilities(self, analyzer):
        result = analyzer.analyze_source(CAIRO_VULNERABLE)
        assert result["success"] is True
        assert result["chain"] == "starknet"
        assert len(result["findings"]) >= 3

    def test_detects_felt_overflow(self, analyzer):
        result = analyzer.analyze_source(CAIRO_VULNERABLE)
        types = [f["type"] for f in result["findings"]]
        assert "felt_overflow" in types

    def test_detects_l1_handler(self, analyzer):
        result = analyzer.analyze_source(CAIRO_VULNERABLE)
        types = [f["type"] for f in result["findings"]]
        assert "l1_l2_message" in types

    def test_detects_proxy_upgrade(self, analyzer):
        result = analyzer.analyze_source(CAIRO_VULNERABLE)
        types = [f["type"] for f in result["findings"]]
        assert "proxy_upgrade" in types

    def test_analyze_missing_file(self, analyzer):
        result = analyzer.analyze("/nonexistent/file.cairo")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_analyze_real_file(self, analyzer, tmp_path):
        f = tmp_path / "test.cairo"
        f.write_text(CAIRO_VULNERABLE)
        result = analyzer.analyze(str(f))
        assert result["success"] is True
        assert len(result["findings"]) > 0

    def test_summary_counts(self, analyzer):
        result = analyzer.analyze_source(CAIRO_VULNERABLE)
        summary = result["summary"]
        total = sum(summary.values())
        assert total == len(result["findings"])

    def test_empty_source(self, analyzer):
        result = analyzer.analyze_source("")
        assert result["success"] is True
        assert len(result["findings"]) == 0

    def test_finding_to_dict(self):
        f = CairoFinding(
            vuln_type=CairoVulnType.REENTRANCY,
            severity="High",
            title="Test",
            description="Test desc",
            line=10,
            function="withdraw",
        )
        d = f.to_dict()
        assert d["tool"] == "miesc-cairo"
        assert d["type"] == "reentrancy"
        assert d["chain"] == "starknet"
        assert d["location"]["line"] == 10
        assert d["location"]["function"] == "withdraw"


class TestConvenienceFunction:
    def test_analyze_cairo_contract(self, tmp_path):
        f = tmp_path / "t.cairo"
        f.write_text(CAIRO_VULNERABLE)
        result = analyze_cairo_contract(str(f))
        assert result["success"] is True
        assert len(result["findings"]) > 0


class TestCairoPatterns:
    def test_all_vuln_types_have_patterns(self):
        # Every enum value with a template should have regex patterns
        for vuln_type in [
            CairoVulnType.FELT_OVERFLOW,
            CairoVulnType.L1_L2_MESSAGE,
            CairoVulnType.CALLER_SPOOFING,
            CairoVulnType.REENTRANCY,
            CairoVulnType.ACCESS_CONTROL,
            CairoVulnType.PROXY_UPGRADE,
        ]:
            assert vuln_type in CAIRO_PATTERNS, f"Missing pattern for {vuln_type}"
            cfg = CAIRO_PATTERNS[vuln_type]
            assert len(cfg["patterns"]) >= 1
            assert cfg["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert cfg["title"]
            assert cfg["description"]
            assert cfg["recommendation"]
