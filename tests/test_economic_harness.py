"""
Tests for the economic-invariant Echidna harness bridge.

Covers, WITHOUT requiring Echidna to be installed:
  - Harness generation (structure, imported target, driver functions, property
    functions, hoisted state declarations, round-trip augmentation).
  - Violation parsing / finding mapping via a MOCKED adapter.
  - Graceful no-op when Echidna is absent.
"""

from __future__ import annotations

import shutil
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
    constructor(address asset) {}
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
# honest-skip pre-flight: unsupported constructor / driver shapes
# ---------------------------------------------------------------------------

# Faithful excerpt of the real Malda mErc20Immutable: an 8-argument constructor
# with operator / interest-rate-model dependencies the harness cannot synthesise.
MALDA_MERC20 = """// SPDX-License-Identifier: BSL-1.1
pragma solidity =0.8.28;

contract mErc20Immutable is mErc20 {
    constructor(
        address underlying_,
        address operator_,
        address interestRateModel_,
        uint256 initialExchangeRateMantissa_,
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address payable admin_
    ) {}
    function exchangeRateStored() public view returns (uint256) {}
    function mint(uint256 mintAmount, address receiver, uint256 minAmountOut) external {}
    function redeem(uint256 redeemTokens) external {}
}
"""

# A single-asset-constructor cToken whose mint adds a non-fillable argument.
NONSTANDARD_MINT_CTOKEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Weird {
    uint256 public totalSupply;
    constructor(address u) {}
    function exchangeRateStored() public view returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
    function mint(uint256 amount, uint256 lockDuration) external {}
    function redeem(uint256 c) external {}
}
"""


class TestHonestSkip:
    def test_multi_arg_constructor_is_skipped_with_reason(self):
        outcome = EconomicHarnessBuilder().build_or_reason(
            MALDA_MERC20, "mErc20Immutable", ["compound_no_inflation_theft"], "./m.sol"
        )
        assert outcome.artifact is None
        assert outcome.skip_reason is not None
        reason = outcome.skip_reason
        # Names the real divergence: arity and the dependency params it can't stub.
        assert "8 argument" in reason
        assert "operator_" in reason
        assert "interestRateModel_" in reason
        assert "future work" in reason

    def test_build_returns_none_on_unsupported_shape(self):
        # The thin build() wrapper drops the reason but must not fabricate a harness.
        art = EconomicHarnessBuilder().build(
            MALDA_MERC20, "mErc20Immutable", ["compound_no_inflation_theft"], "./m.sol"
        )
        assert art is None

    def test_nonstandard_mint_arg_is_skipped(self):
        outcome = EconomicHarnessBuilder().build_or_reason(
            NONSTANDARD_MINT_CTOKEN, "Weird", ["compound_no_inflation_theft"], "./w.sol"
        )
        assert outcome.artifact is None
        assert outcome.skip_reason is not None
        # lockDuration is not a safe-default arg -> refused honestly, not zeroed.
        assert "mint()" in outcome.skip_reason
        assert "lockDuration" in outcome.skip_reason

    def test_mint_fee_arg_is_not_zeroed(self):
        # `mintFee` must NOT match the min*/slippage zero-allowlist (camelCase
        # boundary): zeroing a fee would silently change semantics, so skip instead.
        src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract FeeMkt {
    uint256 public totalSupply;
    constructor(address u) {}
    function exchangeRateStored() public view returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
    function mint(uint256 amount, uint256 mintFee) external {}
    function redeem(uint256 c) external {}
}
"""
        outcome = EconomicHarnessBuilder().build_or_reason(
            src, "FeeMkt", ["compound_no_inflation_theft"], "./f.sol"
        )
        assert outcome.artifact is None
        assert outcome.skip_reason is not None
        assert "mintFee" in outcome.skip_reason

    def test_no_explicit_constructor_is_skipped(self):
        # A compound-shaped contract with no explicit constructor cannot receive the
        # mock asset address -> honest skip naming the implicit/inherited constructor.
        src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract NoCtor {
    uint256 public totalSupply;
    function exchangeRateStored() public view returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
    function mint(uint256 amount) external {}
    function redeem(uint256 c) external {}
}
"""
        outcome = EconomicHarnessBuilder().build_or_reason(
            src, "NoCtor", ["compound_no_inflation_theft"], "./n.sol"
        )
        assert outcome.artifact is None
        assert outcome.skip_reason is not None
        assert "implicit or inherited" in outcome.skip_reason

    def test_no_runnable_invariants_has_no_skip_reason(self):
        # "nothing runnable" is distinct from "unsupported shape": both-None.
        outcome = EconomicHarnessBuilder().build_or_reason(
            VAULT_SRC, "MyVault", ["total_supply_equals_sum_balances"], "./V.sol"
        )
        assert outcome.artifact is None
        assert outcome.skip_reason is None

    def test_run_economic_fuzz_surfaces_skip_reason(self, tmp_path):
        # End-to-end: a real-fork-shaped target is skipped with the precise reason,
        # not a generic "no runnable form" message — and Echidna is never invoked.
        target = tmp_path / "mErc20Immutable.sol"
        target.write_text(MALDA_MERC20, encoding="utf-8")

        class _AlwaysAvailable:
            def is_available(self):
                return ToolStatus.AVAILABLE

            def analyze(self, *a, **k):  # pragma: no cover - must never be called
                raise AssertionError("Echidna must not run on an unbindable target")

        res = run_economic_fuzz(
            str(target),
            ["compound_no_inflation_theft"],
            target_name="mErc20Immutable",
            adapter=_AlwaysAvailable(),
        )
        assert res["status"] == "skipped"
        assert "operator_" in res["reason"]
        assert res["findings"] == []


class TestDriverResolution:
    def test_three_arg_mint_resolves_to_safe_defaults(self):
        # A single-asset-constructor market with a 3-arg mint(amount, receiver, minOut)
        # resolves to mint(amount, address(this), 0) rather than being skipped.
        src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Mkt {
    uint256 public totalSupply;
    constructor(address u) {}
    function exchangeRateStored() public view returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
    function mint(uint256 amount, address receiver, uint256 minAmountOut) external {}
    function redeem(uint256 c) external {}
}
"""
        art = EconomicHarnessBuilder().build(
            src, "Mkt", ["compound_no_inflation_theft"], "./Mkt.sol"
        )
        assert art is not None
        assert "market.mint(amount, address(this), 0);" in art.source
        assert "market.redeem(cTokens);" in art.source

    def test_mock_mint_above_target_does_not_shadow(self):
        # Flattened audit layout: a mock with mint(address,uint256) declared ABOVE the
        # target. Resolution must read the target's own body, not the mock's mint.
        src = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ERC20Mock {
    function mint(address to, uint256 amount) external {}
}
contract CToken {
    uint256 public totalSupply;
    constructor(address u) {}
    function exchangeRateStored() public view returns (uint256) {}
    function balanceOf(address) public view returns (uint256) {}
    function mint(uint256 amount) external {}
    function redeem(uint256 c) external {}
}
"""
        art = EconomicHarnessBuilder().build(
            src, "CToken", ["compound_no_inflation_theft"], "./c.sol"
        )
        assert art is not None
        assert "market.mint(amount);" in art.source

    def test_stock_shapes_emit_canonical_driver_calls(self):
        # Regression: the stock ERC-4626 shape still emits byte-identical driver calls.
        art = EconomicHarnessBuilder().build(
            VAULT_SRC, "MyVault", ["erc4626_first_deposit_guard"], "./MyVault.sol"
        )
        assert art is not None
        assert "vault.deposit(assets, address(this));" in art.source
        assert "vault.redeem(shares, address(this), address(this));" in art.source


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


# ---------------------------------------------------------------------------
# Real end-to-end run (requires Echidna) — regression guard for the output-capture bug:
# Echidna only emits its verdict lines under a controlling terminal, so a plain captured
# subprocess silently reported "clean". The mocked tests above never exercised that path.
# ---------------------------------------------------------------------------

_VULN_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IToken {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract VulnVault {
    IToken public asset; uint256 public totalSupply; mapping(address => uint256) public balanceOf;
    constructor(address a) { asset = IToken(a); }
    function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }
    function convertToShares(uint256 x) public view returns (uint256) {
        uint256 ts = totalSupply; if (ts == 0) return x; return (x * ts) / totalAssets();
    }
    function convertToAssets(uint256 s) public view returns (uint256) {
        uint256 ts = totalSupply; if (ts == 0) return s; return (s * totalAssets()) / ts;
    }
    function deposit(uint256 a, address r) public returns (uint256 sh) {
        sh = convertToShares(a); asset.transferFrom(msg.sender, address(this), a);
        totalSupply += sh; balanceOf[r] += sh;
    }
    function redeem(uint256 s, address r, address) public returns (uint256 a) {
        a = convertToAssets(s); balanceOf[msg.sender] -= s; totalSupply -= s; asset.transfer(r, a);
    }
}
"""


@pytest.mark.skipif(not shutil.which("echidna"), reason="echidna not installed")
def test_run_economic_fuzz_detects_inflation_end_to_end(tmp_path):
    """Real Echidna on a donation-inflatable vault must report `detected` with a violation.

    Regression guard: before the pty-based capture fix this returned `clean` / 0 tests because
    Echidna's output was lost to the pipe.
    """
    vault = tmp_path / "VulnVault.sol"
    vault.write_text(_VULN_VAULT, encoding="utf-8")
    out = run_economic_fuzz(
        str(vault), ["erc4626_first_deposit_guard"], test_limit=10000, timeout=240
    )
    assert out["status"] == "detected", out
    # Echidna actually evaluated the properties (the capture bug yielded 0).
    assert (out.get("echidna") or {}).get("tests_run", 0) >= 1, out
    assert any(f.get("type") == "economic_invariant_violation" for f in out["findings"]), out


# ---------------------------------------------------------------------------
# Compound-V2 lending class (mToken/cToken) — a self-contained cToken, NOT a real
# protocol (Malda's markets need an Operator / interest model / oracle).
# ---------------------------------------------------------------------------

_VULN_CTOKEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IToken {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract VulnCToken {
    IToken public underlying; uint256 public totalSupply; mapping(address => uint256) public balanceOf;
    constructor(address u) { underlying = IToken(u); }
    function getCash() public view returns (uint256) { return underlying.balanceOf(address(this)); }
    function exchangeRateStored() public view returns (uint256) {
        if (totalSupply == 0) return 1e18; return getCash() * 1e18 / totalSupply;
    }
    function mint(uint256 amount) public returns (uint256 c) {
        uint256 er = exchangeRateStored(); c = amount * 1e18 / er;
        underlying.transferFrom(msg.sender, address(this), amount); totalSupply += c; balanceOf[msg.sender] += c;
    }
    function redeem(uint256 c) public returns (uint256 a) {
        uint256 er = exchangeRateStored(); a = c * er / 1e18;
        balanceOf[msg.sender] -= c; totalSupply -= c; underlying.transfer(msg.sender, a);
    }
}
"""


class TestCompoundHarness:
    def test_build_generates_compound_harness(self):
        art = EconomicHarnessBuilder().build(
            target_source=_VULN_CTOKEN,
            target_name="VulnCToken",
            invariant_names=["compound_no_inflation_theft", "compound_mint_nonzero"],
            target_import="./VulnCToken.sol",
        )
        assert art is not None
        src = art.source
        # Deploys the market with the compound driver set and the lending properties.
        assert "VulnCToken public market" in src
        assert "market = new VulnCToken(address(token));" in src
        assert "function h_mint(" in src
        assert "function echidna_ctoken_no_inflation_theft()" in src
        assert "function echidna_ctoken_mint_nonzero()" in src
        # No ERC-4626 driver leaked in.
        assert "vault.deposit" not in src

    def test_compound_names_are_supported(self):
        assert "compound_no_inflation_theft" in supported_invariants()
        assert "compound_mint_nonzero" in supported_invariants()


@pytest.mark.skipif(not shutil.which("echidna"), reason="echidna not installed")
def test_run_economic_fuzz_detects_ctoken_inflation_end_to_end(tmp_path):
    """Real Echidna: a donation-inflatable Compound-V2-style cToken must report `detected`.

    Self-contained cToken, not malda-lending — binding these invariants to a real lending
    deployment (Operator / interest model / oracle) is a separate step.
    """
    ctoken = tmp_path / "VulnCToken.sol"
    ctoken.write_text(_VULN_CTOKEN, encoding="utf-8")
    out = run_economic_fuzz(
        str(ctoken),
        ["compound_no_inflation_theft", "compound_mint_nonzero"],
        target_name="VulnCToken",
        test_limit=15000,
        timeout=240,
    )
    assert out["status"] == "detected", out
    assert (out.get("echidna") or {}).get("tests_run", 0) >= 1, out
    assert any(f.get("type") == "economic_invariant_violation" for f in out["findings"]), out
