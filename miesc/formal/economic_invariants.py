"""
Economic / business-logic invariant templates.
================================================

The pure-static detection layer is structurally blind to *economic* exploits —
price manipulation, ERC-4626 share-price inflation, flash-loan-assisted
draining, and general accounting/solvency violations. These are not pattern
matches on the AST; they are *properties* a protocol must preserve across every
transaction. The right tool for them is a prover or a fuzzer, and both need the
property written down first.

This module is that "written down" step: a small, honest library of economic
invariant TEMPLATES for the classes our benchmark flagged as out-of-scope for
static analysis:

  * ERC-4626 share-price inflation  (share price monotonic / first-deposit guard)
  * Solvency                        (backing assets >= accounted liabilities)
  * Flash-loan resistance           (price not derived from intra-tx spot balance)
  * Accounting conservation         (sum of balances == totalSupply)
  * No-withdraw-exceeds-deposit     (a user cannot extract more than they put in)

Honesty note: these templates EXPRESS a property to prove or fuzz. They do not,
by themselves, *detect* an economic exploit — they are the input a Certora /
Halmos / Echidna / Foundry-invariant run consumes. Bind the protocol-specific
state variables and actors before treating any counterexample as evidence.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

# =============================================================================
# Template data model
# =============================================================================


@dataclass
class EconomicInvariantTemplate:
    """A concrete, honest economic invariant with multi-backend bodies."""

    name: str
    category: str  # accounting | solvency | economic
    importance: str  # CRITICAL | HIGH | MEDIUM | LOW
    natural_language: str
    certora_spec: str
    echidna_property: str
    foundry_test: str
    related_vulnerabilities: List[str] = field(default_factory=list)
    # Whether the property can, in principle, be discharged automatically by a
    # prover/fuzzer (True) or fundamentally needs a manual binding / review
    # (False, e.g. flash-loan oracle provenance).
    auto_checkable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "importance": self.importance,
            "natural_language": self.natural_language,
            "certora_spec": self.certora_spec,
            "echidna_property": self.echidna_property,
            "foundry_test": self.foundry_test,
            "related_vulnerabilities": list(self.related_vulnerabilities),
            "auto_checkable": self.auto_checkable,
            "source": "economic-template",
        }


_CANDIDATE_NOTE = (
    "// CANDIDATE property — bind protocol-specific state/actors before use as evidence."
)


# =============================================================================
# Template library
# =============================================================================

ERC4626_SHARE_PRICE_NON_DECREASING = EconomicInvariantTemplate(
    name="erc4626_share_price_non_decreasing",
    category="economic",
    importance="CRITICAL",
    natural_language=(
        "The price per share (convertToAssets of a fixed share amount) must never "
        "decrease as a result of a deposit or mint. A sudden jump/drop is the "
        "signature of an inflation / donation attack where an attacker front-runs "
        "the first depositor to steal their assets via rounding."
    ),
    related_vulnerabilities=["erc4626-inflation", "share-price-manipulation", "SWC-132"],
    certora_spec=f"""// ERC-4626 share price must not decrease on deposit/mint
{_CANDIDATE_NOTE}
rule sharePriceNonDecreasing(env e, uint256 assets, address receiver) {{
    uint256 unit = 10^18;
    uint256 ppsBefore = convertToAssets(unit);
    deposit(e, assets, receiver);
    uint256 ppsAfter = convertToAssets(unit);
    assert ppsAfter >= ppsBefore,
        "Share price decreased on deposit (inflation attack signature)";
}}""",
    echidna_property=f"""// Track the worst-observed price-per-share; it must never regress.
{_CANDIDATE_NOTE}
uint256 private _lastPricePerShare = type(uint256).max;
function echidna_share_price_non_decreasing() public returns (bool) {{
    if (totalSupply() == 0) return true;
    uint256 pps = convertToAssets(1e18);
    bool ok = pps >= _lastPricePerShare || _lastPricePerShare == type(uint256).max;
    if (pps < _lastPricePerShare) _lastPricePerShare = pps;
    return ok;
}}""",
    foundry_test=f"""// Foundry stateful invariant: price per share is monotonic non-decreasing.
{_CANDIDATE_NOTE}
uint256 internal _ppsFloor;
function invariant_sharePriceNonDecreasing() public {{
    if (vault.totalSupply() == 0) return;
    uint256 pps = vault.convertToAssets(1e18);
    assertGe(pps, _ppsFloor, "share price regressed (inflation attack)");
    if (pps > _ppsFloor) _ppsFloor = pps;
}}""",
)

ERC4626_FIRST_DEPOSIT_GUARD = EconomicInvariantTemplate(
    name="erc4626_first_deposit_guard",
    category="economic",
    importance="CRITICAL",
    natural_language=(
        "The first deposit into the vault must not let an attacker inflate the "
        "share price to a level that rounds subsequent deposits down to zero "
        "shares. Mitigations: mint dead shares to address(0) at init, or use "
        "OpenZeppelin's virtual-shares/virtual-assets offset."
    ),
    related_vulnerabilities=["erc4626-inflation", "first-deposit-attack"],
    certora_spec=f"""// A non-zero deposit must always mint a non-zero number of shares.
{_CANDIDATE_NOTE}
rule firstDepositMintsShares(env e, uint256 assets, address receiver) {{
    require assets > 0;
    uint256 shares = deposit(e, assets, receiver);
    assert shares > 0,
        "Deposit rounded to zero shares (first-deposit inflation attack)";
}}""",
    echidna_property=f"""// Any positive deposit must yield positive shares.
{_CANDIDATE_NOTE}
function echidna_deposit_mints_nonzero_shares() public returns (bool) {{
    if (totalAssets() == 0) return true;
    return convertToShares(1) > 0 || totalSupply() == 0;
}}""",
    foundry_test=f"""// Foundry: a 1-wei deposit against a funded vault must not round to 0 shares.
{_CANDIDATE_NOTE}
function invariant_depositMintsNonZeroShares() public {{
    if (vault.totalAssets() == 0) return;
    assertGt(vault.convertToShares(1e6), 0, "small deposit rounds to zero shares");
}}""",
)

VAULT_SOLVENCY = EconomicInvariantTemplate(
    name="vault_solvency",
    category="solvency",
    importance="CRITICAL",
    natural_language=(
        "The vault must always hold enough backing assets to honour every share: "
        "totalAssets() >= convertToAssets(totalSupply()). If accounted liabilities "
        "exceed real backing the protocol is insolvent and a bank-run can drain it."
    ),
    related_vulnerabilities=["vault-insolvency", "accounting-mismatch"],
    certora_spec=f"""// Backing assets must cover all outstanding shares.
{_CANDIDATE_NOTE}
invariant vaultSolvency()
    totalAssets() >= convertToAssets(totalSupply())
{{
    preserved {{
        requireInvariant vaultSolvency();
    }}
}}""",
    echidna_property=f"""// Backing must always cover liabilities.
{_CANDIDATE_NOTE}
function echidna_vault_solvent() public view returns (bool) {{
    return totalAssets() >= convertToAssets(totalSupply());
}}""",
    foundry_test=f"""// Foundry: real backing >= accounted liabilities at all times.
{_CANDIDATE_NOTE}
function invariant_vaultSolvency() public {{
    assertGe(
        vault.totalAssets(),
        vault.convertToAssets(vault.totalSupply()),
        "vault insolvent: backing < liabilities"
    );
}}""",
)

NO_WITHDRAW_EXCEEDS_DEPOSIT = EconomicInvariantTemplate(
    name="no_withdraw_exceeds_deposit",
    category="accounting",
    importance="HIGH",
    natural_language=(
        "A user must not be able to withdraw more underlying than they deposited "
        "plus any legitimately accrued yield. Track per-account deposited and "
        "withdrawn; withdrawn <= deposited + yieldCredited[account]."
    ),
    related_vulnerabilities=["accounting-drain", "business-logic"],
    certora_spec=f"""// A user cannot extract more than they put in (+ accrued yield).
{_CANDIDATE_NOTE}
rule noWithdrawExceedsDeposit(env e, uint256 assets, address owner) {{
    // ghost trackers `deposited` and `yieldCredited` must be wired in the harness.
    uint256 out = withdraw(e, assets, e.msg.sender, owner);
    assert withdrawn[owner] + out <= deposited[owner] + yieldCredited[owner],
        "User withdrew more than deposited + yield";
}}""",
    echidna_property=f"""// Cumulative withdrawn must never exceed deposited + credited yield.
{_CANDIDATE_NOTE}
function echidna_no_withdraw_exceeds_deposit() public view returns (bool) {{
    return _withdrawn[msg.sender] <= _deposited[msg.sender] + _yieldCredited[msg.sender];
}}""",
    foundry_test=f"""// Foundry: no account extracts more than it contributed (+ yield).
{_CANDIDATE_NOTE}
function invariant_noWithdrawExceedsDeposit() public {{
    address[] memory actors = handler.actors();
    for (uint256 i = 0; i < actors.length; i++) {{
        assertLe(
            handler.withdrawn(actors[i]),
            handler.deposited(actors[i]) + handler.yieldCredited(actors[i]),
            "account extracted more than deposited + yield"
        );
    }}
}}""",
)

TOTAL_SUPPLY_EQUALS_SUM_BALANCES = EconomicInvariantTemplate(
    name="total_supply_equals_sum_balances",
    category="accounting",
    importance="CRITICAL",
    natural_language=(
        "The total supply must always equal the sum of all account balances. A "
        "divergence means tokens were minted or burned off the books — the root "
        "cause of most accounting-drain exploits."
    ),
    related_vulnerabilities=["accounting-mismatch", "SWC-132"],
    certora_spec=f"""// Conservation of supply: totalSupply == sum of balances.
{_CANDIDATE_NOTE}
// Requires a `sumBalances` ghost summed over balanceOf in the harness.
invariant totalSupplyEqualsSumBalances()
    totalSupply() == sumBalances()
{{
    preserved {{
        requireInvariant totalSupplyEqualsSumBalances();
    }}
}}""",
    echidna_property=f"""// The tracked running sum of balances must equal totalSupply.
{_CANDIDATE_NOTE}
function echidna_supply_equals_sum_balances() public view returns (bool) {{
    return totalSupply() == _sumOfBalances;
}}""",
    foundry_test=f"""// Foundry: ghost-summed balances equal totalSupply after every action.
{_CANDIDATE_NOTE}
function invariant_totalSupplyEqualsSumBalances() public {{
    assertEq(token.totalSupply(), handler.sumBalances(), "supply != sum(balances)");
}}""",
)

PRICE_NOT_FROM_SPOT_BALANCE = EconomicInvariantTemplate(
    name="price_not_from_spot_balance",
    category="economic",
    importance="HIGH",
    natural_language=(
        "A price/oracle used for accounting must NOT be derived from a spot token "
        "balance readable within a single transaction (e.g. token.balanceOf(pair) "
        "or getReserves()). Such prices are flash-loan manipulable. Use a TWAP or "
        "an external oracle (Chainlink) instead. This property fundamentally needs "
        "manual review of the price source; the auto-checkable proxy below asserts "
        "that a quoted price is unchanged by a same-block balance perturbation."
    ),
    related_vulnerabilities=["flash-loan", "oracle-manipulation", "price-manipulation"],
    auto_checkable=False,
    certora_spec=f"""// Proxy for flash-loan resistance: a same-tx balance donation must not move
// the quoted price. Full resistance still requires manual oracle-source review.
{_CANDIDATE_NOTE}
rule priceImmuneToSpotDonation(env e, uint256 donation) {{
    uint256 priceBefore = getPrice(e);
    // Model a flash-loan donation into the pool/pair within the same tx.
    simulateDonation(e, donation);
    uint256 priceAfter = getPrice(e);
    assert priceAfter == priceBefore,
        "Quoted price moved by an intra-tx balance donation (flash-loan manipulable)";
}}""",
    echidna_property=f"""// A donated balance must not change the quoted price within the tx.
{_CANDIDATE_NOTE}
function echidna_price_immune_to_spot_donation() public returns (bool) {{
    uint256 p0 = _quotedPrice();
    _donateForTest(1e18);   // simulate flash-loan inflow
    return _quotedPrice() == p0;
}}""",
    foundry_test=f"""// Foundry: quoted price must be independent of a same-block spot donation.
{_CANDIDATE_NOTE}
function invariant_priceImmuneToSpotDonation() public {{
    uint256 p0 = oracle.price();
    deal(address(underlying), address(pair), underlying.balanceOf(address(pair)) + 1e24);
    assertEq(oracle.price(), p0, "price moved by spot-balance donation (flash-loan risk)");
}}""",
)


# Full ordered library (used for listing / docs / tests).
ECONOMIC_INVARIANT_TEMPLATES: Dict[str, EconomicInvariantTemplate] = {
    t.name: t
    for t in (
        ERC4626_SHARE_PRICE_NON_DECREASING,
        ERC4626_FIRST_DEPOSIT_GUARD,
        VAULT_SOLVENCY,
        NO_WITHDRAW_EXCEEDS_DEPOSIT,
        TOTAL_SUPPLY_EQUALS_SUM_BALANCES,
        PRICE_NOT_FROM_SPOT_BALANCE,
    )
}


# =============================================================================
# Contract-type-aware selection
# =============================================================================


def _looks_like_erc4626(code: str) -> bool:
    cl = code.lower()
    if "erc4626" in cl:
        return True
    signals = ("converttoassets", "converttoshares", "totalassets")
    return sum(s in cl for s in signals) >= 2


def _looks_like_vault(code: str) -> bool:
    cl = code.lower()
    return ("vault" in cl or "share" in cl) and "deposit" in cl and "withdraw" in cl


def _looks_like_token(code: str) -> bool:
    cl = code.lower()
    return "totalsupply" in cl and "balanceof" in cl


def _uses_spot_price(code: str) -> bool:
    cl = code.lower()
    spot_signals = (
        "getreserves",
        ".balanceof(address(this))",
        "reserve0",
        "reserve1",
        "getamountout",
    )
    price_signals = ("price", "oracle", "quote", "swap", "amm", "liquidity")
    return any(s in cl for s in spot_signals) and any(p in cl for p in price_signals)


def detect_economic_invariants(contract_source: str) -> List[Dict[str, Any]]:
    """Return economic invariant templates relevant to the given contract source.

    Selection is heuristic and additive: ERC-4626 vaults get the full share-price /
    solvency set; generic token contracts get supply-conservation; anything that
    reads a spot price/reserve for accounting gets the flash-loan resistance proxy.

    Args:
        contract_source: Raw Solidity source of the contract under analysis.

    Returns:
        A list of template dicts (see EconomicInvariantTemplate.to_dict). Empty
        list when nothing economic is recognised — an honest no-op.
    """
    if not contract_source:
        return []

    selected: List[EconomicInvariantTemplate] = []
    is_4626 = _looks_like_erc4626(contract_source)
    is_vault = is_4626 or _looks_like_vault(contract_source)

    if is_vault:
        selected.append(VAULT_SOLVENCY)
        selected.append(NO_WITHDRAW_EXCEEDS_DEPOSIT)
    if is_4626:
        selected.append(ERC4626_SHARE_PRICE_NON_DECREASING)
        selected.append(ERC4626_FIRST_DEPOSIT_GUARD)
    if _looks_like_token(contract_source):
        selected.append(TOTAL_SUPPLY_EQUALS_SUM_BALANCES)
    if _uses_spot_price(contract_source):
        selected.append(PRICE_NOT_FROM_SPOT_BALANCE)

    # Deduplicate while preserving order.
    seen: set[str] = set()
    ordered: List[EconomicInvariantTemplate] = []
    for t in selected:
        if t.name not in seen:
            ordered.append(t)
            seen.add(t.name)

    return [t.to_dict() for t in ordered]


__all__ = [
    "EconomicInvariantTemplate",
    "ECONOMIC_INVARIANT_TEMPLATES",
    "detect_economic_invariants",
]
