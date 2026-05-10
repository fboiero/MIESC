"""
Multi-chain vulnerability type coverage tests.

Verifies that each chain adapter's enum + pattern registry is internally
consistent, all vuln types have string values, and the v5.1.9 additions
(Soroban, Solana Anchor, Move Sui/Aptos) are present.
"""

from __future__ import annotations

import pytest

from src.adapters.move_adapter import MoveAnalyzer, MoveVulnerability
from src.adapters.solana_adapter import SolanaAnalyzer, SolanaVulnerability
from src.adapters.stellar_adapter import StellarAnalyzer, StellarVulnerability

# ---------------------------------------------------------------------------
# Stellar / Soroban
# ---------------------------------------------------------------------------


class TestStellarVulnTypes:
    def test_enum_count(self):
        assert len(StellarVulnerability) >= 22

    def test_all_values_are_lowercase_snake(self):
        for v in StellarVulnerability:
            assert v.value == v.value.lower()
            assert " " not in v.value

    @pytest.mark.parametrize(
        "vuln",
        [
            "flash_loan_soroban",
            "uninitialized_storage",
            "admin_key_no_rotation",
            "approve_race_condition",
            "i128_conversion_overflow",
            "missing_invoke_result_check",
            "unbounded_loop",
        ],
    )
    def test_soroban_2024_types_present(self, vuln):
        values = {v.value for v in StellarVulnerability}
        assert vuln in values, f"v5.1.9 Soroban type '{vuln}' missing"

    def test_analyzer_instantiates(self):
        analyzer = StellarAnalyzer()
        assert analyzer.chain_type is not None

    def test_pattern_detector_has_soroban_2024_patterns(self):
        from src.adapters.stellar_adapter import StellarPatternDetector

        assert hasattr(StellarPatternDetector, "SOROBAN_2024_PATTERNS")
        patterns = StellarPatternDetector.SOROBAN_2024_PATTERNS
        assert len(patterns) >= 7
        assert "flash_loan_pattern" in patterns
        assert "i128_narrow" in patterns
        assert "unbounded_iter" in patterns


# ---------------------------------------------------------------------------
# Solana / Anchor
# ---------------------------------------------------------------------------


class TestSolanaVulnTypes:
    def test_enum_count(self):
        assert len(SolanaVulnerability) >= 22

    def test_all_values_are_lowercase_snake(self):
        for v in SolanaVulnerability:
            assert v.value == v.value.lower()

    @pytest.mark.parametrize(
        "vuln",
        [
            "account_closure_reentrancy",
            "missing_discriminator",
            "token_authority_mismatch",
            "program_upgrade_exposure",
            "unchecked_cpi_return",
            "freeze_authority_missing",
            "remaining_accounts_unvalidated",
        ],
    )
    def test_anchor_2024_types_present(self, vuln):
        values = {v.value for v in SolanaVulnerability}
        assert vuln in values, f"v5.1.9 Anchor type '{vuln}' missing"

    def test_analyzer_instantiates(self):
        analyzer = SolanaAnalyzer()
        assert analyzer.chain_type is not None


# ---------------------------------------------------------------------------
# Move / Sui / Aptos
# ---------------------------------------------------------------------------


class TestMoveVulnTypes:
    def test_enum_count(self):
        assert len(MoveVulnerability) >= 19

    def test_all_values_are_lowercase_snake(self):
        for v in MoveVulnerability:
            assert v.value == v.value.lower()

    @pytest.mark.parametrize(
        "vuln",
        [
            "shared_object_race",
            "dynamic_field_manipulation",
            "package_upgrade_attack",
            "capability_delegation_chain",
            "coin_split_precision",
            "clock_manipulation",
            "transfer_policy_bypass",
        ],
    )
    def test_sui_aptos_2024_types_present(self, vuln):
        values = {v.value for v in MoveVulnerability}
        assert vuln in values, f"v5.1.9 Move type '{vuln}' missing"

    def test_analyzer_instantiates(self):
        analyzer = MoveAnalyzer()
        assert analyzer.chain_type is not None


# ---------------------------------------------------------------------------
# Cross-chain consistency
# ---------------------------------------------------------------------------


class TestCrossChainConsistency:
    """Verify that the multi-chain adapters share consistent API shape."""

    @pytest.mark.parametrize(
        "AnalyzerClass",
        [
            StellarAnalyzer,
            SolanaAnalyzer,
            MoveAnalyzer,
        ],
    )
    def test_analyzer_has_required_methods(self, AnalyzerClass):
        analyzer = AnalyzerClass()
        # Analyzers expose either parse() or parse_contract()
        assert hasattr(analyzer, "parse") or hasattr(analyzer, "parse_contract")
        assert hasattr(analyzer, "detect_vulnerabilities")
        assert hasattr(analyzer, "chain_type")

    def test_total_vuln_types_across_chains(self):
        total = len(StellarVulnerability) + len(SolanaVulnerability) + len(MoveVulnerability)
        assert total >= 60, (
            f"Expected 60+ multi-chain vuln types, got {total}. "
            f"Stellar={len(StellarVulnerability)}, "
            f"Solana={len(SolanaVulnerability)}, "
            f"Move={len(MoveVulnerability)}"
        )

    def test_no_duplicate_values_within_chain(self):
        for enum_cls in (StellarVulnerability, SolanaVulnerability, MoveVulnerability):
            values = [v.value for v in enum_cls]
            assert len(values) == len(set(values)), f"Duplicate values in {enum_cls.__name__}"
