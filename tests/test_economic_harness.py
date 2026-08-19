"""
Tests for the economic-invariant Echidna harness bridge.

Covers, WITHOUT requiring Echidna to be installed:
  - Harness generation (structure, imported target, driver functions, property
    functions, hoisted state declarations, round-trip augmentation).
  - Violation parsing / finding mapping via a MOCKED adapter.
  - Graceful no-op when Echidna is absent.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from miesc.core.tool_protocol import ToolStatus
from miesc.formal.economic_harness import (
    EconomicHarnessBuilder,
    _detect_target_contract_name,
    run_economic_fuzz,
    supported_invariants,
)

VAULT_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract MyVault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) {}
    function convertToShares(uint256 a) public view returns (uint256) {}
    function convertToAssets(uint256 s) public view returns (uint256) {}
    function deposit(uint256 a, address r) public returns (uint256) {}
    function redeem(uint256 s, address r, address o) public returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
}
"""


# ---------------------------------------------------------------------------
# supported_invariants
# ---------------------------------------------------------------------------


def test_supported_invariants_is_erc4626_set():
    supported = supported_invariants()
    assert "erc4626_first_deposit_guard" in supported
    assert "vault_solvency" in supported
    assert "erc4626_share_price_non_decreasing" in supported


# ---------------------------------------------------------------------------
# target contract detection
# ---------------------------------------------------------------------------


def test_detect_target_contract_prefers_vault():
    assert _detect_target_contract_name(VAULT_SRC) == "MyVault"


def test_detect_target_contract_none_when_no_contract():
    assert _detect_target_contract_name("pragma solidity ^0.8.0;") is None


# ---------------------------------------------------------------------------
# harness generation
# ---------------------------------------------------------------------------


class TestHarnessBuilder:
    def test_build_none_when_no_supported_invariants(self):
        art = EconomicHarnessBuilder().build(
            VAULT_SRC, "MyVault", ["total_supply_equals_sum_balances"], "./V.sol"
        )
        assert art is None

    def test_build_generates_runnable_harness(self):
        art = EconomicHarnessBuilder().build(
            VAULT_SRC,
            "MyVault",
            ["erc4626_first_deposit_guard", "vault_solvency"],
            "./MyVault.sol",
        )
        assert art is not None
        src = art.source
        # Pragma inherited from target
        assert "pragma solidity ^0.8.19;" in src
        # Imports the target, deploys mock + vault
        assert 'import "./MyVault.sol";' in src
        assert "contract MockERC20" in src
        assert "vault = new MyVault(address(token));" in src
        # Driver functions Echidna will fuzz
        assert "function h_deposit(" in src
        assert "function h_donate(" in src
        assert "function h_redeem(" in src
        # Property functions (deployer context — prefixed with vault.)
        assert "function echidna_deposit_mints_nonzero_shares()" in src
        assert "function echidna_vault_solvent()" in src
        assert "vault.convertToShares(1)" in src
        # Round-trip discriminator auto-added with first_deposit_guard
        assert "function echidna_no_inflation_theft()" in src

    def test_state_decls_hoisted_for_share_price(self):
        art = EconomicHarnessBuilder().build(
            VAULT_SRC,
            "MyVault",
            ["erc4626_share_price_non_decreasing"],
            "./MyVault.sol",
        )
        assert art is not None
        # The stateful property's variable is hoisted to contract scope.
        assert "_lastPricePerShare" in art.source
        assert "function echidna_share_price_non_decreasing()" in art.source

    def test_no_round_trip_when_disabled(self):
        art = EconomicHarnessBuilder().build(
            VAULT_SRC,
            "MyVault",
            ["erc4626_first_deposit_guard"],
            "./MyVault.sol",
            include_round_trip=False,
        )
        assert art is not None
        assert "echidna_no_inflation_theft" not in art.source

    def test_property_map_keys_are_function_names(self):
        art = EconomicHarnessBuilder().build(
            VAULT_SRC, "MyVault", ["vault_solvency"], "./MyVault.sol"
        )
        assert art is not None
        assert "echidna_vault_solvent" in art.property_map


# ---------------------------------------------------------------------------
# run_economic_fuzz with a MOCKED adapter (no Echidna required)
# ---------------------------------------------------------------------------


class _FakeAdapter:
    def __init__(self, available: bool, result: Dict[str, Any]):
        self._available = available
        self._result = result
        self.analyzed_path: str | None = None

    def is_available(self) -> ToolStatus:
        return ToolStatus.AVAILABLE if self._available else ToolStatus.NOT_INSTALLED

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        self.analyzed_path = contract_path
        return self._result


@pytest.fixture
def vault_file(tmp_path):
    p = tmp_path / "MyVault.sol"
    p.write_text(VAULT_SRC)
    return str(p)


def test_run_skips_gracefully_when_echidna_absent(vault_file):
    fake = _FakeAdapter(available=False, result={})
    out = run_economic_fuzz(vault_file, ["erc4626_first_deposit_guard"], adapter=fake)
    assert out["status"] == "skipped"
    assert "not installed" in out["reason"].lower()
    assert out["findings"] == []


def test_run_maps_falsified_property_to_finding(vault_file):
    echidna_result = {
        "status": "success",
        "findings": [
            {
                "type": "property_violation",
                "property": "echidna_deposit_mints_nonzero_shares",
                "description": "Property violated",
                "call_sequence": ["h_donate(1000)", "h_deposit(0)"],
            }
        ],
        "tests_run": 100,
        "execution_time": 1.0,
        "test_limit": 30000,
    }
    fake = _FakeAdapter(available=True, result=echidna_result)
    out = run_economic_fuzz(vault_file, ["erc4626_first_deposit_guard"], adapter=fake)
    assert out["status"] == "detected"
    assert len(out["findings"]) == 1
    f = out["findings"][0]
    assert f["invariant"] == "erc4626_first_deposit_guard"
    assert f["severity"] == "critical"  # importance CRITICAL -> critical
    assert f["tool"] == "echidna-economic"
    assert "erc4626-inflation" in f["related_vulnerabilities"]
    assert f["call_sequence"] == ["h_donate(1000)", "h_deposit(0)"]


def test_run_clean_when_no_violations(vault_file):
    echidna_result = {
        "status": "success",
        "findings": [],
        "tests_run": 30000,
        "execution_time": 5.0,
        "test_limit": 30000,
    }
    fake = _FakeAdapter(available=True, result=echidna_result)
    out = run_economic_fuzz(vault_file, ["vault_solvency"], adapter=fake)
    assert out["status"] == "clean"
    assert out["findings"] == []
    # Harness was actually generated and handed to the adapter.
    assert fake.analyzed_path is not None
    assert fake.analyzed_path.endswith(".sol")


def test_run_error_when_echidna_fails(vault_file):
    fake = _FakeAdapter(available=True, result={"status": "error", "error": "boom"})
    out = run_economic_fuzz(vault_file, ["vault_solvency"], adapter=fake)
    assert out["status"] == "error"
    assert "boom" in out["reason"]


def test_run_skips_when_no_runnable_invariant(vault_file):
    fake = _FakeAdapter(available=True, result={"status": "success", "findings": []})
    out = run_economic_fuzz(vault_file, ["total_supply_equals_sum_balances"], adapter=fake)
    assert out["status"] == "skipped"
