"""
Tests for miesc/formal/economic_invariants.py

Covers:
  - Template library completeness and structure
  - Contract-type-aware selection (ERC-4626, generic vault, token, AMM/spot-price)
  - Honest no-op on empty / non-economic input
  - Flash-loan resistance template is flagged not-auto-checkable (honesty)
  - Every template carries CVL + Echidna + Foundry bodies
"""

from __future__ import annotations

from miesc.formal.economic_invariants import (
    ECONOMIC_INVARIANT_TEMPLATES,
    EconomicInvariantTemplate,
    detect_economic_invariants,
)

ERC4626_VAULT = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) {}
    function convertToShares(uint256 a) public view returns (uint256) {}
    function convertToAssets(uint256 s) public view returns (uint256) {}
    function deposit(uint256 a, address r) public returns (uint256) {}
    function withdraw(uint256 a, address r, address o) public returns (uint256) {}
}
"""

PLAIN_TOKEN = """
pragma solidity ^0.8.0;
contract Token {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amt) public returns (bool) {}
}
"""

AMM_WITH_SPOT_PRICE = """
pragma solidity ^0.8.0;
contract Oracle {
    function getReserves() public view returns (uint112 reserve0, uint112 reserve1) {}
    function price() public view returns (uint256) {
        (uint112 r0, uint112 r1) = getReserves();
        return uint256(r1) / uint256(r0); // spot price -> flash-loan manipulable
    }
}
"""

NON_ECONOMIC = """
pragma solidity ^0.8.0;
contract Counter { uint256 public count; function inc() public { count++; } }
"""

COMPOUND_CTOKEN = """
pragma solidity ^0.8.0;
contract MToken {
    uint256 public totalSupply;
    function exchangeRateStored() public view returns (uint256) {}
    function mint(uint256 amount) public returns (uint256) {}
    function redeem(uint256 cTokens) public returns (uint256) {}
}
"""

# Stock Compound V2: cash is read from the raw underlying balance -> OPEN surface.
STOCK_CTOKEN_BALANCEOF = """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract CErc20 {
    uint256 public totalSupply;
    IERC20 public underlying;
    function getCashPrior() internal view returns (uint256) {
        return underlying.balanceOf(address(this));
    }
    function exchangeRateStored() public view returns (uint256) {}
    function mint(uint256 amount) public returns (uint256) {}
    function redeem(uint256 cTokens) public returns (uint256) {}
}
"""

# Malda-style: cash is an internal accumulator never reset from balance -> CLOSED.
TRACKED_CASH_MTOKEN = """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract mErc20 {
    uint256 public totalSupply;
    uint256 public totalUnderlying;
    IERC20 public underlying;
    function _getCashPrior() internal view returns (uint256) {
        return totalUnderlying;
    }
    function _doTransferIn(uint256 a) internal { totalUnderlying += a; }
    function exchangeRateStored() public view returns (uint256) {}
    function mint(uint256 amount) public returns (uint256) {}
    function redeem(uint256 cTokens) public returns (uint256) {}
}
"""

# Reopener: tracked accumulator that a sync() resets from balanceOf -> OPEN again.
REOPENER_SYNC_MTOKEN = """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
contract mErc20Sync {
    uint256 public totalSupply;
    uint256 public totalUnderlying;
    IERC20 public underlying;
    function _getCashPrior() internal view returns (uint256) {
        return totalUnderlying;
    }
    function sync() external { totalUnderlying = underlying.balanceOf(address(this)); }
    function exchangeRateStored() public view returns (uint256) {}
    function mint(uint256 amount) public returns (uint256) {}
    function redeem(uint256 cTokens) public returns (uint256) {}
}
"""

# Flattened layout: the ABSTRACT _getCashPrior declaration appears above the
# concrete override. The classifier must read the override (tracked), not stop at
# the abstract decl and mis-read a later getCash wrapper.
FLATTENED_ABSTRACT_ABOVE_OVERRIDE = """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); }
abstract contract mTokenStorage {
    uint256 public totalSupply;
    uint256 public totalUnderlying;
    function _getCashPrior() internal view virtual returns (uint256);
    function exchangeRateStored() public view returns (uint256) {}
}
abstract contract mToken is mTokenStorage {
    function getCash() external view returns (uint256) { return _getCashPrior(); }
    function mint(uint256 amount) public returns (uint256) {}
    function redeem(uint256 cTokens) public returns (uint256) {}
}
contract mErc20 is mToken {
    IERC20 public underlying;
    function _getCashPrior() internal view override returns (uint256) {
        return totalUnderlying;
    }
    function _doTransferIn(address f, uint256 a) internal returns (uint256) {
        uint256 b = underlying.balanceOf(address(this));
        return b;
    }
}
"""


class TestTemplateLibrary:
    def test_expected_templates_present(self):
        expected = {
            "erc4626_share_price_non_decreasing",
            "erc4626_first_deposit_guard",
            "vault_solvency",
            "no_withdraw_exceeds_deposit",
            "total_supply_equals_sum_balances",
            "price_not_from_spot_balance",
        }
        assert expected.issubset(set(ECONOMIC_INVARIANT_TEMPLATES))

    def test_every_template_has_all_backend_bodies(self):
        for name, tmpl in ECONOMIC_INVARIANT_TEMPLATES.items():
            assert isinstance(tmpl, EconomicInvariantTemplate)
            assert tmpl.certora_spec.strip(), f"{name} missing CVL"
            assert tmpl.echidna_property.strip(), f"{name} missing Echidna"
            assert tmpl.foundry_test.strip(), f"{name} missing Foundry"
            assert tmpl.importance in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
            assert tmpl.category in {"accounting", "solvency", "economic"}

    def test_to_dict_roundtrip(self):
        d = ECONOMIC_INVARIANT_TEMPLATES["vault_solvency"].to_dict()
        assert d["name"] == "vault_solvency"
        assert d["source"] == "economic-template"
        assert "certora_spec" in d and "echidna_property" in d and "foundry_test" in d


class TestDetection:
    def test_erc4626_gets_full_economic_set(self):
        names = {i["name"] for i in detect_economic_invariants(ERC4626_VAULT)}
        assert "erc4626_share_price_non_decreasing" in names
        assert "erc4626_first_deposit_guard" in names
        assert "vault_solvency" in names
        assert "no_withdraw_exceeds_deposit" in names

    def test_compound_ctoken_gets_lending_set(self):
        names = {i["name"] for i in detect_economic_invariants(COMPOUND_CTOKEN)}
        assert "compound_no_inflation_theft" in names
        assert "compound_mint_nonzero" in names

    def test_plain_token_gets_supply_conservation(self):
        names = {i["name"] for i in detect_economic_invariants(PLAIN_TOKEN)}
        assert "total_supply_equals_sum_balances" in names
        # A plain token is not a vault -> no share-price invariants
        assert "erc4626_share_price_non_decreasing" not in names

    def test_amm_spot_price_gets_flash_loan_template(self):
        names = {i["name"] for i in detect_economic_invariants(AMM_WITH_SPOT_PRICE)}
        assert "price_not_from_spot_balance" in names

    def test_non_economic_contract_is_honest_noop(self):
        assert detect_economic_invariants(NON_ECONOMIC) == []

    def test_empty_source_returns_empty(self):
        assert detect_economic_invariants("") == []

    def test_no_duplicate_names(self):
        results = detect_economic_invariants(ERC4626_VAULT)
        names = [i["name"] for i in results]
        assert len(names) == len(set(names))


class TestCashSourceDiscriminator:
    """The static discriminator that separates open from closed inflation surfaces."""

    def _compound_dicts(self, source):
        return {
            i["name"]: i
            for i in detect_economic_invariants(source)
            if i["name"].startswith("compound_")
        }

    def test_stock_balanceof_is_open_surface(self):
        got = self._compound_dicts(STOCK_CTOKEN_BALANCEOF)
        assert got, "stock cToken must still emit the compound templates"
        for d in got.values():
            assert d["cash_source"] == "balanceof"
            assert d["inflation_surface"] == "open"

    def test_tracked_cash_is_closed_surface(self):
        # Malda-style: templates are ANNOTATED closed, never suppressed.
        got = self._compound_dicts(TRACKED_CASH_MTOKEN)
        assert "compound_no_inflation_theft" in got
        assert "compound_mint_nonzero" in got
        for d in got.values():
            assert d["cash_source"] == "tracked"
            assert d["inflation_surface"] == "closed"

    def test_sync_reopener_is_open_again(self):
        # A tracked var reset from balanceOf() re-exposes the donation vector.
        got = self._compound_dicts(REOPENER_SYNC_MTOKEN)
        assert got
        for d in got.values():
            assert d["cash_source"] == "balanceof"
            assert d["inflation_surface"] == "open"

    def test_flattened_abstract_decl_does_not_shadow_override(self):
        # The abstract _getCashPrior above must not win over the concrete override;
        # the fee-on-transfer balanceOf in _doTransferIn must not flip it to open.
        got = self._compound_dicts(FLATTENED_ABSTRACT_ABOVE_OVERRIDE)
        assert got
        for d in got.values():
            assert d["cash_source"] == "tracked"
            assert d["inflation_surface"] == "closed"

    def test_unknown_shape_is_annotated_unknown(self):
        # No recognisable getCash shape -> classification withheld, still emitted.
        got = self._compound_dicts(COMPOUND_CTOKEN)
        assert got
        for d in got.values():
            assert d["cash_source"] == "unknown"
            assert d["inflation_surface"] == "unknown"

    def test_non_compound_dicts_carry_no_cash_source(self):
        # The annotation is compound-only; ERC-4626 templates must not grow the field.
        erc = [
            i
            for i in detect_economic_invariants(ERC4626_VAULT)
            if not i["name"].startswith("compound_")
        ]
        assert erc
        for d in erc:
            assert "cash_source" not in d
            assert "inflation_surface" not in d


class TestHonesty:
    def test_flash_loan_template_not_auto_checkable(self):
        """Flash-loan resistance fundamentally needs manual oracle-source review;
        the template must honestly flag that it is not fully auto-checkable."""
        tmpl = ECONOMIC_INVARIANT_TEMPLATES["price_not_from_spot_balance"]
        assert tmpl.auto_checkable is False

    def test_solvency_and_supply_are_auto_checkable(self):
        assert ECONOMIC_INVARIANT_TEMPLATES["vault_solvency"].auto_checkable is True
        assert (
            ECONOMIC_INVARIANT_TEMPLATES["total_supply_equals_sum_balances"].auto_checkable is True
        )

    def test_templates_marked_as_candidates(self):
        """Emitted bodies must be labelled CANDIDATE — they are not proven evidence."""
        for tmpl in ECONOMIC_INVARIANT_TEMPLATES.values():
            assert "CANDIDATE" in tmpl.certora_spec
