"""
Economic-invariant Echidna harness bridge.
==========================================

`economic_invariants.py` *writes down* economic properties (ERC-4626 share-price
inflation, solvency, ...). `EchidnaAdapter` *runs* Echidna on a contract that
already contains `echidna_*` properties. Neither, on its own, closes the loop:
a generated economic property is written in an *inherited/mixin* context (it
calls `totalSupply()` / `convertToAssets()` as if it lived inside the vault) and
assumes an asset token, funding and a driver that exercises the attack.

This module is the missing bridge. Given a target contract and a selected set of
economic invariants it:

  1. Generates a *runnable* Echidna harness — a self-contained deployer contract
     that deploys a mock ERC-20 asset + the target vault, funds itself, and
     exposes driver functions (deposit / donate / redeem) that Echidna fuzzes to
     drive the economic attack.
  2. Emits, at harness scope, the economic property functions in *deployer*
     context (target API calls prefixed with `vault.`), derived from the
     `economic_invariants.py` template library (single source of truth for
     severity / natural language / related vulnerabilities).
  3. Runs Echidna on the harness via `EchidnaAdapter` and maps every *falsified*
     property back to the originating economic invariant → a MIESC finding.

Honesty / scope
---------------
The harness generator is concrete for two classes `economic_invariants.py` flags
out-of-scope for static analysis: the **ERC-4626 vault** and the **Compound-V2
lending market** (cToken / mToken). It can synthesise a deployment only for a
single-ERC20-asset constructor, and drives `deposit`/`redeem` (vault) or
`mint`/`redeem` (market) whose extra arguments map to safe defaults (ERC-standard
actor positions, or name-matched `receiver`/`min*` arguments).

When the target diverges — e.g. a real fork like Malda whose `mErc20Immutable`
constructor takes operator / interest-rate-model / oracle addresses — the shape
is parsed *up front* and the run is skipped with a precise reason naming the
divergence, instead of emitting a harness that fails to compile deep in Echidna.
Binding such multi-dependency deployments (synthesising operator / IRM / oracle
stubs) is deliberately left as future work; the generator refuses them honestly
rather than fabricating a result.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

from miesc.formal.economic_invariants import ECONOMIC_INVARIANT_TEMPLATES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Runnable property forms (deployer/harness context)
# ---------------------------------------------------------------------------
#
# The raw `echidna_property` bodies in economic_invariants.py are written for an
# *inherited* context (bare `totalSupply()` etc.) and some declare their own
# state. Here we author the equivalent *deployer-context* form (calls prefixed
# with `vault.`, state hoisted to harness scope), keyed by the template name.
# Severity / natural language / related vulnerabilities are still sourced from
# the template library so there is a single source of truth for metadata.


@dataclass
class RunnableProperty:
    """A harness-context Echidna property derived from an economic template."""

    template_name: str
    function_name: str  # echidna_* function name (as Echidna reports it)
    body: str  # full Solidity function source, deployer context
    state_decls: List[str] = field(default_factory=list)  # contract-scope vars

    @property
    def importance(self) -> str:
        tmpl = ECONOMIC_INVARIANT_TEMPLATES.get(self.template_name)
        return tmpl.importance if tmpl else "HIGH"

    @property
    def natural_language(self) -> str:
        tmpl = ECONOMIC_INVARIANT_TEMPLATES.get(self.template_name)
        return tmpl.natural_language if tmpl else ""

    @property
    def related_vulnerabilities(self) -> List[str]:
        tmpl = ECONOMIC_INVARIANT_TEMPLATES.get(self.template_name)
        return list(tmpl.related_vulnerabilities) if tmpl else []

    @property
    def category(self) -> str:
        tmpl = ECONOMIC_INVARIANT_TEMPLATES.get(self.template_name)
        return tmpl.category if tmpl else "economic"


# Deployer-context runnable forms for the ERC-4626 vault class.
_RUNNABLE_ERC4626: Dict[str, RunnableProperty] = {
    "erc4626_first_deposit_guard": RunnableProperty(
        template_name="erc4626_first_deposit_guard",
        function_name="echidna_deposit_mints_nonzero_shares",
        body=(
            "    // erc4626_first_deposit_guard (deployer-context form).\n"
            "    // A positive deposit against a funded vault must mint positive shares;\n"
            "    // a donation-inflated share price rounds this to zero.\n"
            "    function echidna_deposit_mints_nonzero_shares() public view returns (bool) {\n"
            "        if (vault.totalAssets() == 0) return true;\n"
            "        return vault.convertToShares(1) > 0 || vault.totalSupply() == 0;\n"
            "    }"
        ),
    ),
    "vault_solvency": RunnableProperty(
        template_name="vault_solvency",
        function_name="echidna_vault_solvent",
        body=(
            "    // vault_solvency (deployer-context form).\n"
            "    function echidna_vault_solvent() public view returns (bool) {\n"
            "        return vault.totalAssets() >= vault.convertToAssets(vault.totalSupply());\n"
            "    }"
        ),
    ),
    "erc4626_share_price_non_decreasing": RunnableProperty(
        template_name="erc4626_share_price_non_decreasing",
        function_name="echidna_share_price_non_decreasing",
        state_decls=["    uint256 private _lastPricePerShare = type(uint256).max;"],
        body=(
            "    // erc4626_share_price_non_decreasing (deployer-context form).\n"
            "    function echidna_share_price_non_decreasing() public returns (bool) {\n"
            "        if (vault.totalSupply() == 0) return true;\n"
            "        uint256 pps = vault.convertToAssets(1e18);\n"
            "        bool ok = pps >= _lastPricePerShare"
            " || _lastPricePerShare == type(uint256).max;\n"
            "        if (pps < _lastPricePerShare) _lastPricePerShare = pps;\n"
            "        return ok;\n"
            "    }"
        ),
    ),
}

# Bridge-augmented discriminating property (not a verbatim template): a
# round-trip no-loss check. It is the most robust discriminator for the
# inflation class — a realistic depositor who deposits then redeems must recover
# ~their value. Included when first_deposit_guard is selected.
_ROUND_TRIP_NO_LOSS = RunnableProperty(
    template_name="erc4626_first_deposit_guard",
    function_name="echidna_no_inflation_theft",
    body=(
        "    // Bridge-augmented: a realistic (1-token) depositor must not lose value to\n"
        "    // share-price inflation. Robust round-trip discriminator (>=99% recovered).\n"
        "    function echidna_no_inflation_theft() public view returns (bool) {\n"
        "        if (vault.totalSupply() == 0) return true;\n"
        "        uint256 probe = 1e18;\n"
        "        uint256 shares = vault.convertToShares(probe);\n"
        "        uint256 back = vault.convertToAssets(shares);\n"
        "        return back * 100 >= probe * 99;\n"
        "    }"
    ),
)


# Deployer-context runnable forms for the Compound-V2 lending class (mToken/cToken). The
# exchange rate is cash/totalSupply; a donation that inflates cash without minting cTokens is
# the same first-depositor attack as the ERC-4626 inflation, surfaced here on `market`.
_RUNNABLE_COMPOUND: Dict[str, RunnableProperty] = {
    "compound_no_inflation_theft": RunnableProperty(
        template_name="compound_no_inflation_theft",
        function_name="echidna_ctoken_no_inflation_theft",
        body=(
            "    // compound_no_inflation_theft (deployer-context form).\n"
            "    // A realistic depositor minting cTokens must recover ~their underlying on redeem;\n"
            "    // a donation-inflated exchange rate rounds the mint to zero cTokens.\n"
            "    function echidna_ctoken_no_inflation_theft() public view returns (bool) {\n"
            "        if (market.totalSupply() == 0) return true;\n"
            "        uint256 probe = 1e18;\n"
            "        uint256 er = market.exchangeRateStored();\n"
            "        uint256 c = probe * 1e18 / er;\n"
            "        uint256 back = c * er / 1e18;\n"
            "        return back * 100 >= probe * 99;\n"
            "    }"
        ),
    ),
    "compound_mint_nonzero": RunnableProperty(
        template_name="compound_mint_nonzero",
        function_name="echidna_ctoken_mint_nonzero",
        body=(
            "    // compound_mint_nonzero (deployer-context form).\n"
            "    // A positive mint against a funded market must issue positive cTokens.\n"
            "    function echidna_ctoken_mint_nonzero() public view returns (bool) {\n"
            "        if (market.totalSupply() == 0) return true;\n"
            "        return (1e18 * 1e18) / market.exchangeRateStored() > 0;\n"
            "    }"
        ),
    ),
}


def supported_invariants() -> set[str]:
    """Economic invariant names for which a runnable harness form exists."""
    return set(_RUNNABLE_ERC4626.keys()) | set(_RUNNABLE_COMPOUND.keys())


def invariant_classes() -> Dict[str, List[str]]:
    """Supported invariant names grouped by harness class (``erc4626`` /
    ``compound``). A single harness binds one class, so a caller that wants to
    auto-detect tries each class's invariants in turn rather than passing the
    union (whose first-match-wins resolution would pick the wrong class)."""
    return {cls: sorted(cfg.runnable.keys()) for cls, cfg in _CLASSES.items()}


# ---------------------------------------------------------------------------
# Harness generation
# ---------------------------------------------------------------------------

_MOCK_ERC20 = """contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}"""


# Per-class harness wiring: which runnable forms, and the deployed instance name.
# Driver blocks are synthesised per-target (see `_DRIVER_BUILDERS`) so the call
# signatures match the real target rather than a hard-coded stock-Compound shape.
class _HarnessClass(NamedTuple):
    runnable: Dict[str, RunnableProperty]
    var: str


_CLASSES: Dict[str, _HarnessClass] = {
    "erc4626": _HarnessClass(_RUNNABLE_ERC4626, "vault"),
    "compound": _HarnessClass(_RUNNABLE_COMPOUND, "market"),
}


def _resolve_class(invariant_names: List[str]) -> Optional[str]:
    """The harness class of the first invariant name that has a runnable form, or None.

    A single harness deploys one target with one driver set, so invariants from different
    classes cannot share a harness: the first match wins and the rest are dropped.
    """
    for name in invariant_names:
        for cls, cfg in _CLASSES.items():
            if name in cfg.runnable:
                return cls
    return None


@dataclass
class HarnessArtifact:
    """A generated, runnable Echidna harness for a target contract."""

    source: str
    harness_contract_name: str
    target_name: str
    properties: List[RunnableProperty]
    import_path: str

    @property
    def property_map(self) -> Dict[str, RunnableProperty]:
        """echidna_* function name -> RunnableProperty (for violation mapping)."""
        return {p.function_name: p for p in self.properties}


def _extract_pragma(source: str) -> str:
    m = re.search(r"pragma\s+solidity[^;]+;", source)
    return m.group(0) if m else "pragma solidity ^0.8.0;"


# ---------------------------------------------------------------------------
# Target-shape resolution (honest-skip instead of silently-broken harness)
# ---------------------------------------------------------------------------
#
# The generator can only synthesise a deployment it knows how to satisfy: a
# single-ERC20-asset constructor and a driver call whose extra arguments map to
# safe defaults. Real-world Compound-V2 / ERC-4626 forks diverge (e.g. Malda's
# `mErc20Immutable` takes operator / interest-rate-model / oracle). Rather than
# emit a harness that fails to compile deep in Echidna, we parse the target's
# shape up-front and skip with a precise, honest reason when we cannot bind it.

_STORAGE_KEYWORDS = frozenset({"memory", "calldata", "storage"})
# Extra driver-call arguments we can fill with a semantically-safe default.
_ADDRESS_TYPES = frozenset({"address", "address payable", "addresspayable"})
# Address params that denote "the account acting" — safe to pass address(this).
_SELF_ADDRESS_NAMES = frozenset(
    {"receiver", "recipient", "to", "onbehalfof", "owner", "beneficiary", "dst", "account"}
)
# uint params we may zero: minimum-output / slippage guards (0 = no constraint).
# Matched against the ORIGINAL-case name with a camelCase boundary so `minAmountOut`
# qualifies but `mintFee` / `minter` do not (lowercasing would destroy that boundary).
# `maxSlippage` is excluded: zeroing a *max* tolerance is the opposite of permissive.
_ZERO_UINT_NAME_RE = re.compile(r"^(?:[mM]in(?:imum)?(?![a-z])|[sS]lippage)")


def _contract_body(source: str, contract_name: str) -> Optional[str]:
    """Brace-balanced body of `contract_name` (contract or abstract contract)."""
    decl = re.search(rf"\b(?:abstract\s+)?contract\s+{re.escape(contract_name)}\b", source)
    if not decl:
        return None
    open_idx = source.find("{", decl.end())
    if open_idx < 0:
        return None
    depth = 0
    for j in range(open_idx, len(source)):
        if source[j] == "{":
            depth += 1
        elif source[j] == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx + 1 : j]
    return None


def _split_top_level(raw: str) -> List[str]:
    """Split a parameter list on commas that are not nested inside brackets."""
    parts: List[str] = []
    depth = 0
    cur: List[str] = []
    for ch in raw:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _parse_param(part: str) -> tuple[str, str]:
    """(type, name) for one parameter; name is '' when unnamed."""
    toks = [t for t in part.split() if t not in _STORAGE_KEYWORDS]
    if not toks:
        return ("", "")
    if len(toks) == 1:
        return (toks[0], "")
    return (" ".join(toks[:-1]), toks[-1])


def _param_list(raw: str) -> List[tuple[str, str]]:
    return [_parse_param(p) for p in _split_top_level(raw)]


def _norm_type(ptype: str) -> str:
    return re.sub(r"\s+", "", ptype).lower()


def _constructor_params(source: str, contract_name: str) -> Optional[List[tuple[str, str]]]:
    """Explicit constructor params of `contract_name`, or None when there is no
    explicit constructor (implicit / inherited — not resolvable here)."""
    body = _contract_body(source, contract_name)
    if body is None:
        return None
    m = re.search(r"\bconstructor\s*\(([^)]*)\)", body)
    if not m:
        return None
    return _param_list(m.group(1))


def _resolve_constructor_arg(source: str, target_name: str) -> tuple[Optional[str], Optional[str]]:
    """(deploy-arg expression, None) when synthesisable, else (None, skip reason)."""
    params = _constructor_params(source, target_name)
    if params is None:
        return None, (
            f"no explicit single-ERC20-asset constructor found on {target_name} "
            "(implicit or inherited constructors are not resolved); the economic "
            "harness must pass the mock asset address to the target's constructor."
        )
    if len(params) == 1 and _norm_type(params[0][0]) in _ADDRESS_TYPES:
        return "address(token)", None
    shown = ", ".join(f"{t} {n}".strip() for t, n in params) or "(no parameters)"
    return None, (
        f"{target_name} constructor takes {len(params)} argument(s) [{shown}]; the "
        "economic harness can only synthesise a single ERC20-asset constructor. "
        "Deploy-dependency stub synthesis (operator / interest-rate model / oracle) "
        "is future work."
    )


def _find_function_params(
    source: str, func_name: str, target_name: str
) -> Optional[List[tuple[str, str]]]:
    """Params of `function func_name(...)` on the target contract.

    Looks inside `target_name`'s own body first so a mock declared earlier in a
    flattened audit file (e.g. `ERC20Mock.mint(address,uint256)`) cannot shadow the
    target's function. Falls back to the whole source for a function inherited from
    a parent contract (which lives outside `target_name`'s body).
    """
    pattern = rf"\bfunction\s+{re.escape(func_name)}\s*\(([^)]*)\)"
    body = _contract_body(source, target_name)
    if body is not None:
        m = re.search(pattern, body)
        if m:
            return _param_list(m.group(1))
    m = re.search(pattern, source)
    if not m:
        return None
    return _param_list(m.group(1))


def _resolve_call_args(
    params: List[tuple[str, str]], primary_expr: str, standard_self_arity: int
) -> tuple[Optional[str], Optional[str]]:
    """Build the argument list for a driver call, or a reason it cannot be filled.

    `params[0]` is the primary (amount / shares) and gets `primary_expr`. Positions
    1..standard_self_arity-1 are ERC-standard actor addresses (receiver / owner) and
    are filled with address(this) by position. Any further argument is filled only
    when its name/type matches the safe allowlist (actor-address -> address(this),
    min*/slippage uint -> 0); otherwise the shape is refused honestly.
    """
    if not params:
        return None, "function has no parameters to drive"
    args = [primary_expr]
    for idx, (ptype, pname) in enumerate(params[1:], start=1):
        tnorm = _norm_type(ptype)
        nlow = pname.lower()
        if idx < standard_self_arity and tnorm in _ADDRESS_TYPES:
            args.append("address(this)")
        elif tnorm in _ADDRESS_TYPES and nlow in _SELF_ADDRESS_NAMES:
            args.append("address(this)")
        elif tnorm.startswith("uint") and _ZERO_UINT_NAME_RE.match(pname):
            args.append("0")
        else:
            return None, f"cannot fill argument '{ptype} {pname}' from safe defaults"
    return ", ".join(args), None


def _build_erc4626_drivers(source: str, target_name: str) -> tuple[Optional[str], Optional[str]]:
    dep = _find_function_params(source, "deposit", target_name)
    red = _find_function_params(source, "redeem", target_name)
    if dep is None:
        return None, "target exposes no deposit(...) to drive the ERC-4626 harness"
    if red is None:
        return None, "target exposes no redeem(...) to drive the ERC-4626 harness"
    dep_args, reason = _resolve_call_args(dep, "assets", standard_self_arity=2)
    if reason:
        return None, f"deposit() shape unsupported: {reason}"
    red_args, reason = _resolve_call_args(red, "shares", standard_self_arity=3)
    if reason:
        return None, f"redeem() shape unsupported: {reason}"
    block = (
        "    // ---- driver functions Echidna fuzzes to drive the attack ----\n"
        "    function h_deposit(uint256 assets) public {\n"
        "        assets = 1 + (assets % 1e24);\n"
        f"        vault.deposit({dep_args});\n"
        "    }\n\n"
        "    function h_donate(uint256 amount) public {\n"
        "        amount = amount % 1e24;\n"
        "        token.transfer(address(vault), amount);\n"
        "    }\n\n"
        "    function h_redeem(uint256 shares) public {\n"
        "        uint256 bal = vault.balanceOf(address(this));\n"
        "        if (bal == 0) return;\n"
        "        shares = 1 + (shares % bal);\n"
        f"        vault.redeem({red_args});\n"
        "    }"
    )
    return block, None


def _build_compound_drivers(source: str, target_name: str) -> tuple[Optional[str], Optional[str]]:
    mnt = _find_function_params(source, "mint", target_name)
    red = _find_function_params(source, "redeem", target_name)
    if mnt is None:
        return None, "target exposes no mint(...) to drive the Compound-V2 harness"
    if red is None:
        return None, "target exposes no redeem(...) to drive the Compound-V2 harness"
    mint_args, reason = _resolve_call_args(mnt, "amount", standard_self_arity=1)
    if reason:
        return None, f"mint() shape unsupported: {reason}"
    red_args, reason = _resolve_call_args(red, "cTokens", standard_self_arity=1)
    if reason:
        return None, f"redeem() shape unsupported: {reason}"
    block = (
        "    // ---- driver functions Echidna fuzzes to drive the attack ----\n"
        "    function h_mint(uint256 amount) public {\n"
        "        amount = 1 + (amount % 1e24);\n"
        f"        market.mint({mint_args});\n"
        "    }\n\n"
        "    function h_donate(uint256 amount) public {\n"
        "        amount = amount % 1e24;\n"
        "        token.transfer(address(market), amount);\n"
        "    }\n\n"
        "    function h_redeem(uint256 cTokens) public {\n"
        "        uint256 bal = market.balanceOf(address(this));\n"
        "        if (bal == 0) return;\n"
        "        cTokens = 1 + (cTokens % bal);\n"
        f"        market.redeem({red_args});\n"
        "    }"
    )
    return block, None


_DRIVER_BUILDERS = {
    "erc4626": _build_erc4626_drivers,
    "compound": _build_compound_drivers,
}


@dataclass
class BuildOutcome:
    """Result of an attempted harness build: the artifact, or an honest skip reason.

    Exactly one of `artifact` / `skip_reason` is set when the build was attempted;
    both are None when the selected invariants have no runnable form at all.
    """

    artifact: Optional["HarnessArtifact"] = None
    skip_reason: Optional[str] = None


class EconomicHarnessBuilder:
    """Builds runnable Echidna harnesses from economic invariant selections."""

    def build(
        self,
        target_source: str,
        target_name: str,
        invariant_names: List[str],
        target_import: str,
        *,
        include_round_trip: bool = True,
    ) -> Optional[HarnessArtifact]:
        """Generate a harness for `target_name`, or None if nothing is runnable.

        Thin wrapper over :meth:`build_or_reason` that drops the skip reason; use
        :meth:`build_or_reason` when the caller needs to report *why* a target was
        not bindable (unsupported constructor / driver shape).
        """
        return self.build_or_reason(
            target_source,
            target_name,
            invariant_names,
            target_import,
            include_round_trip=include_round_trip,
        ).artifact

    def build_or_reason(
        self,
        target_source: str,
        target_name: str,
        invariant_names: List[str],
        target_import: str,
        *,
        include_round_trip: bool = True,
    ) -> BuildOutcome:
        """Generate a harness, or return a precise reason it cannot be bound.

        Returns a :class:`BuildOutcome`:
          * ``artifact`` set   -> a runnable harness was generated.
          * ``skip_reason`` set -> the target's constructor or mint/redeem shape is
            not synthesisable; the reason names the exact divergence (honest skip
            instead of a harness that fails to compile).
          * both None          -> the selected invariants have no runnable form.

        Args:
            target_source: Solidity source of the target (shape + pragma extraction).
            target_name:   Solidity contract name to deploy in the harness.
            invariant_names: Selected economic invariant names.
            target_import: Relative import path to the target file (e.g. "./Vault.sol").
            include_round_trip: Also emit the robust round-trip discriminator when
                the first-deposit guard is selected.
        """
        cls = _resolve_class(invariant_names)
        if cls is None:
            return BuildOutcome()
        config = _CLASSES[cls]
        runnable_map = config.runnable
        var = config.var

        # Honest-skip pre-flight: can we deploy and drive this target's shape?
        ctor_arg, reason = _resolve_constructor_arg(target_source, target_name)
        if reason:
            return BuildOutcome(skip_reason=reason)
        drivers, reason = _DRIVER_BUILDERS[cls](target_source, target_name)
        if reason:
            return BuildOutcome(skip_reason=reason)
        assert ctor_arg is not None and drivers is not None  # narrowed by reason checks

        props: List[RunnableProperty] = []
        seen: set[str] = set()
        for name in invariant_names:
            runnable = runnable_map.get(name)
            if runnable and runnable.function_name not in seen:
                props.append(runnable)
                seen.add(runnable.function_name)
        if (
            include_round_trip
            and cls == "erc4626"
            and "erc4626_first_deposit_guard" in invariant_names
        ):
            if _ROUND_TRIP_NO_LOSS.function_name not in seen:
                props.append(_ROUND_TRIP_NO_LOSS)
                seen.add(_ROUND_TRIP_NO_LOSS.function_name)

        if not props:
            return BuildOutcome()

        pragma = _extract_pragma(target_source)
        harness_name = "MIESCEconomicHarness"

        state_decls: List[str] = []
        for p in props:
            state_decls.extend(p.state_decls)

        parts: List[str] = [
            "// SPDX-License-Identifier: AGPL-3.0",
            "// Auto-generated by MIESC EconomicHarnessBuilder — do not edit by hand.",
            pragma,
            "",
            f'import "{target_import}";',
            "",
            _MOCK_ERC20,
            "",
            f"contract {harness_name} {{",
            "    MockERC20 public token;",
            f"    {target_name} public {var};",
        ]
        if state_decls:
            parts.extend(state_decls)
        parts += [
            "",
            "    constructor() {",
            "        token = new MockERC20();",
            f"        {var} = new {target_name}({ctor_arg});",
            "        token.mint(address(this), 1e30);",
            f"        token.approve(address({var}), type(uint256).max);",
            "    }",
            "",
            drivers,
            "",
        ]
        for p in props:
            parts.append(p.body)
            parts.append("")
        parts.append("}")

        artifact = HarnessArtifact(
            source="\n".join(parts) + "\n",
            harness_contract_name=harness_name,
            target_name=target_name,
            properties=props,
            import_path=target_import,
        )
        return BuildOutcome(artifact=artifact)


# ---------------------------------------------------------------------------
# Runner: generate harness -> run Echidna -> map violations to MIESC findings
# ---------------------------------------------------------------------------

_IMPORTANCE_TO_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _detect_target_contract_name(source: str) -> Optional[str]:
    """Best-effort: last top-level `contract X` that looks like the vault.

    Prefers a contract whose body mentions ERC-4626-ish API; falls back to the
    last declared contract.
    """
    names: List[str] = re.findall(r"\bcontract\s+([A-Za-z_]\w*)", source)
    if not names:
        return None
    # Prefer a vault-looking contract if several are declared.
    for name in names:
        block_match = re.search(rf"contract\s+{re.escape(name)}\b(.*?)$", source, re.DOTALL)
        block = block_match.group(1) if block_match else ""
        low = block.lower()
        if "converttoshares" in low or "converttoassets" in low or "totalassets" in low:
            return str(name)
    return str(names[-1])


def run_economic_fuzz(
    target_path: str,
    invariant_names: List[str],
    *,
    target_name: Optional[str] = None,
    test_limit: int = 30000,
    timeout: int = 300,
    adapter: Any = None,
    keep_harness: bool = False,
) -> Dict[str, Any]:
    """Generate a harness for the target, run Echidna, map violations to findings.

    Returns a dict:
      status: "detected" | "clean" | "skipped" | "error"
      reason: present when skipped/error
      harness_path: path to the generated harness (when written)
      properties: list of echidna_* property names run
      findings: MIESC findings (one per falsified economic property)
      echidna: raw adapter result (for auditing)

    Echidna availability is checked up-front; when absent the run is *skipped*
    gracefully (never fabricated).
    """
    from miesc.adapters.echidna_adapter import EchidnaAdapter
    from miesc.core.tool_protocol import ToolStatus

    if adapter is None:
        adapter = EchidnaAdapter(config={"test_limit": test_limit, "timeout": timeout})

    # Recursion guard: this helper drives the adapter on a GENERATED harness, so
    # the adapter must never try to generate another harness from it — whoever
    # the caller passed. Forced here (not only on the default-created adapter) so
    # recursion is impossible by construction.
    adapter.generate_harness = False

    if adapter.is_available() != ToolStatus.AVAILABLE:
        return {
            "status": "skipped",
            "reason": "Echidna not installed (brew install echidna). "
            "Economic invariants were generated but not fuzzed.",
            "properties": [],
            "findings": [],
        }

    src = Path(target_path).read_text(encoding="utf-8")
    resolved_name = target_name or _detect_target_contract_name(src)
    if not resolved_name:
        return {
            "status": "error",
            "reason": f"Could not detect a target contract name in {target_path}.",
            "properties": [],
            "findings": [],
        }

    builder = EconomicHarnessBuilder()
    outcome = builder.build_or_reason(
        target_source=src,
        target_name=resolved_name,
        invariant_names=invariant_names,
        target_import=f"./{Path(target_path).name}",
    )
    if outcome.artifact is None:
        reason = outcome.skip_reason or (
            "No runnable economic harness form for the selected invariants "
            f"(supported: {sorted(supported_invariants())})."
        )
        return {
            "status": "skipped",
            "reason": reason,
            "target_contract": resolved_name,
            "properties": [],
            "findings": [],
        }
    artifact = outcome.artifact

    # Write the harness next to the target so the relative import resolves.
    target_dir = Path(target_path).resolve().parent
    fd, harness_path = tempfile.mkstemp(
        prefix="miesc_econ_harness_", suffix=".sol", dir=str(target_dir)
    )
    os.close(fd)
    Path(harness_path).write_text(artifact.source, encoding="utf-8")

    try:
        result = adapter.analyze(
            harness_path,
            contract_name=artifact.harness_contract_name,
            test_mode="property",
        )
    finally:
        if not keep_harness:
            try:
                os.unlink(harness_path)
            except OSError:
                pass

    if result.get("status") != "success":
        return {
            "status": "error",
            "reason": result.get("error", "Echidna run failed"),
            "harness_path": harness_path if keep_harness else None,
            "properties": [p.function_name for p in artifact.properties],
            "findings": [],
            "echidna": result,
        }

    prop_map = artifact.property_map
    findings: List[Dict[str, Any]] = []
    for raw in result.get("findings", []):
        prop_name = raw.get("property", "")
        runnable = prop_map.get(prop_name)
        if runnable is None:
            # A violated property we did not author (defensive) — surface as-is.
            findings.append(
                {
                    "tool": "echidna-economic",
                    "type": "economic_invariant_violation",
                    "severity": "high",
                    "title": f"Economic property {prop_name} falsified",
                    "property": prop_name,
                    "description": raw.get("description", ""),
                    "call_sequence": raw.get("call_sequence", []),
                }
            )
            continue
        findings.append(
            {
                "tool": "echidna-economic",
                "type": "economic_invariant_violation",
                "severity": _IMPORTANCE_TO_SEVERITY.get(runnable.importance, "high"),
                "title": f"Economic invariant violated: {runnable.template_name}",
                "invariant": runnable.template_name,
                "property": prop_name,
                "category": runnable.category,
                "description": runnable.natural_language
                or f"Echidna falsified {prop_name} during fuzzing.",
                "related_vulnerabilities": runnable.related_vulnerabilities,
                "recommendation": (
                    "Echidna found a call sequence that violates this economic "
                    "invariant. Review the counterexample and harden the contract "
                    "(e.g. internal asset accounting or a first-deposit guard)."
                ),
                "call_sequence": raw.get("call_sequence", []),
                "contract": target_path,
            }
        )

    return {
        "status": "detected" if findings else "clean",
        "target": target_path,
        "target_contract": resolved_name,
        "harness_path": harness_path if keep_harness else None,
        "properties": [p.function_name for p in artifact.properties],
        "findings": findings,
        "echidna": {
            "tests_run": result.get("tests_run"),
            "execution_time": result.get("execution_time"),
            "test_limit": result.get("test_limit"),
        },
    }


__all__ = [
    "BuildOutcome",
    "EconomicHarnessBuilder",
    "HarnessArtifact",
    "RunnableProperty",
    "run_economic_fuzz",
    "supported_invariants",
    "invariant_classes",
]
