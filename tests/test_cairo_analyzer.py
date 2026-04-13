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
            CairoVulnType.UNCHECKED_U256,
            CairoVulnType.PRAGMA_ORACLE_STALE,
            CairoVulnType.UPGRADE_NO_INIT_GUARD,
            CairoVulnType.UNCHECKED_SYSCALL_RESULT,
            CairoVulnType.SIGNATURE_REPLAY,
        ]:
            assert vuln_type in CAIRO_PATTERNS, f"Missing pattern for {vuln_type}"
            cfg = CAIRO_PATTERNS[vuln_type]
            assert len(cfg["patterns"]) >= 1
            assert cfg["severity"] in ("Critical", "High", "Medium", "Low", "Info")
            assert cfg["title"]
            assert cfg["description"]
            assert cfg["recommendation"]


# ---------------------------------------------------------------------------
# Patterns informed by 2024-2026 real-world exploits
# ---------------------------------------------------------------------------


PRAGMA_ORACLE_VULNERABLE = """
#[starknet::contract]
mod LendingPool {
    use pragma_lib::abi::{IPragmaOracleDispatcher, IPragmaOracleDispatcherTrait};
    use pragma_lib::types::{DataType, PragmaPricesResponse};

    #[external]
    fn get_asset_price(self: @ContractState) -> u128 {
        let oracle = IPragmaOracleDispatcher { contract_address: self.oracle.read() };
        let response = oracle.get_data_median(DataType::SpotEntry('ETH/USD'));
        response.price
    }
}
"""


INITIALIZER_NO_GUARD = """
#[starknet::contract]
mod MyAccount {
    #[external]
    fn initializer(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    fn __validate_deploy__(
        self: @ContractState, class_hash: felt252, salt: felt252, pubkey: felt252
    ) -> felt252 {
        starknet::VALIDATED
    }
}
"""


UNCHECKED_U256_CODE = """
#[starknet::contract]
mod Vault {
    #[external]
    fn credit(ref self: ContractState, amount: u256) {
        let prev: u256 = self.balance.read();
        let total: u256 = prev + amount;
        self.balance.write(total);
    }
}
"""


UNCHECKED_SYSCALL_CODE = """
use starknet::syscalls::call_contract_syscall;

#[starknet::contract]
mod Router {
    #[external]
    fn hit(ref self: ContractState, target: ContractAddress, selector: felt252) {
        call_contract_syscall(target, selector, array![].span());
    }
}
"""


SIGNATURE_REPLAY_CODE = """
#[starknet::contract]
mod AccountLike {
    #[external]
    fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> felt252 {
        starknet::VALIDATED
    }

    #[external]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        array![]
    }
}
"""


class TestRealWorldExploitPatterns:
    @pytest.fixture
    def analyzer(self):
        return CairoAnalyzer()

    def test_detects_pragma_oracle_stale(self, analyzer):
        result = analyzer.analyze_source(PRAGMA_ORACLE_VULNERABLE)
        types = [f["type"] for f in result["findings"]]
        assert "pragma_oracle_stale" in types

    def test_detects_initializer_no_guard(self, analyzer):
        result = analyzer.analyze_source(INITIALIZER_NO_GUARD)
        types = [f["type"] for f in result["findings"]]
        assert "upgrade_no_init_guard" in types

    def test_detects_unchecked_u256(self, analyzer):
        result = analyzer.analyze_source(UNCHECKED_U256_CODE)
        types = [f["type"] for f in result["findings"]]
        assert "unchecked_u256" in types

    def test_detects_unchecked_syscall(self, analyzer):
        result = analyzer.analyze_source(UNCHECKED_SYSCALL_CODE)
        types = [f["type"] for f in result["findings"]]
        assert "unchecked_syscall_result" in types

    def test_detects_signature_replay(self, analyzer):
        result = analyzer.analyze_source(SIGNATURE_REPLAY_CODE)
        types = [f["type"] for f in result["findings"]]
        assert "signature_replay" in types

    def test_analyzer_version_bumped(self, analyzer):
        assert analyzer.version == "1.1.0"


# ---------------------------------------------------------------------------
# Block-level scanning (v5.1.7 multi-line fix)
# ---------------------------------------------------------------------------


class TestMultiLineScanning:
    """Regression tests for the line-by-line -> block-level scan refactor.

    The previous implementation missed patterns that spanned multiple lines,
    e.g. `#[external]` on one line followed by `fn foo(...)` on the next.
    """

    @pytest.fixture
    def analyzer(self):
        return CairoAnalyzer()

    def test_external_fn_access_control_matches_across_lines(self, analyzer):
        code = """
#[starknet::contract]
mod T {
    #[external]
    fn setOwner(ref self: ContractState, new_owner: ContractAddress) {
        self.owner.write(new_owner);
    }
}
"""
        result = analyzer.analyze_source(code)
        types = [f["type"] for f in result["findings"]]
        assert "access_control" in types, (
            "Pattern #[external]\\n fn ... should match across the newline "
            "(regression — this silently failed in 1.1.0 line-by-line scanner)"
        )

    def test_line_number_reports_pattern_start(self, analyzer):
        code = "// padding\n// padding\n// padding\nfn withdraw() { let a: u256 = b + c; }\n"
        result = analyzer.analyze_source(code)
        # The u256 arithmetic lives on line 4 of this snippet
        u256_matches = [f for f in result["findings"] if f["type"] == "unchecked_u256"]
        assert u256_matches, "unchecked_u256 should be detected in block scan"
        assert u256_matches[0]["location"]["line"] >= 4

    def test_malformed_pattern_does_not_abort_scan(self, analyzer, monkeypatch):
        """A malformed regex in the registry must NOT break the whole scan."""
        from src.adapters import cairo_adapter as mod
        # Inject a broken pattern temporarily
        original = mod.CAIRO_PATTERNS[CairoVulnType.FELT_OVERFLOW]["patterns"][0]
        mod.CAIRO_PATTERNS[CairoVulnType.FELT_OVERFLOW]["patterns"][0] = "(unbalanced"
        try:
            result = analyzer.analyze_source("fn f() { selfdestruct(); replace_class_syscall(); }")
            assert result["success"] is True  # did not crash
        finally:
            mod.CAIRO_PATTERNS[CairoVulnType.FELT_OVERFLOW]["patterns"][0] = original
