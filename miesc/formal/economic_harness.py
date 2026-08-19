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
The harness generator is concrete for the **ERC-4626 vault** class (the class
`economic_invariants.py` flags out-of-scope for static analysis). It assumes the
target vault constructor takes a single asset-token address, and exposes the
standard `deposit(assets,receiver)` / `redeem(shares,receiver,owner)` /
`convertToShares` / `convertToAssets` / `totalAssets` / `totalSupply` API. When
the target diverges the harness will fail to compile and the runner reports that
honestly rather than fabricating a result.

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
from typing import Any, Dict, List, Optional

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


def supported_invariants() -> set[str]:
    """Economic invariant names for which a runnable harness form exists."""
    return set(_RUNNABLE_ERC4626.keys())


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

_DRIVERS = """    // ---- driver functions Echidna fuzzes to drive the attack ----
    function h_deposit(uint256 assets) public {
        assets = 1 + (assets % 1e24);
        vault.deposit(assets, address(this));
    }

    function h_donate(uint256 amount) public {
        amount = amount % 1e24;
        token.transfer(address(vault), amount);
    }

    function h_redeem(uint256 shares) public {
        uint256 bal = vault.balanceOf(address(this));
        if (bal == 0) return;
        shares = 1 + (shares % bal);
        vault.redeem(shares, address(this), address(this));
    }"""


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

        Args:
            target_source: Solidity source of the target (for pragma extraction).
            target_name:   Solidity contract name to deploy in the harness.
            invariant_names: Selected economic invariant names.
            target_import: Relative import path to the target file (e.g. "./Vault.sol").
            include_round_trip: Also emit the robust round-trip discriminator when
                the first-deposit guard is selected.
        """
        props: List[RunnableProperty] = []
        seen: set[str] = set()
        for name in invariant_names:
            runnable = _RUNNABLE_ERC4626.get(name)
            if runnable and runnable.function_name not in seen:
                props.append(runnable)
                seen.add(runnable.function_name)
        if include_round_trip and "erc4626_first_deposit_guard" in invariant_names:
            if _ROUND_TRIP_NO_LOSS.function_name not in seen:
                props.append(_ROUND_TRIP_NO_LOSS)
                seen.add(_ROUND_TRIP_NO_LOSS.function_name)

        if not props:
            return None

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
            f"    {target_name} public vault;",
        ]
        if state_decls:
            parts.extend(state_decls)
        parts += [
            "",
            "    constructor() {",
            "        token = new MockERC20();",
            f"        vault = new {target_name}(address(token));",
            "        token.mint(address(this), 1e30);",
            "        token.approve(address(vault), type(uint256).max);",
            "    }",
            "",
            _DRIVERS,
            "",
        ]
        for p in props:
            parts.append(p.body)
            parts.append("")
        parts.append("}")

        return HarnessArtifact(
            source="\n".join(parts) + "\n",
            harness_contract_name=harness_name,
            target_name=target_name,
            properties=props,
            import_path=target_import,
        )


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
    artifact = builder.build(
        target_source=src,
        target_name=resolved_name,
        invariant_names=invariant_names,
        target_import=f"./{Path(target_path).name}",
    )
    if artifact is None:
        return {
            "status": "skipped",
            "reason": "No runnable economic harness form for the selected invariants "
            f"(supported: {sorted(supported_invariants())}).",
            "properties": [],
            "findings": [],
        }

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
    "EconomicHarnessBuilder",
    "HarnessArtifact",
    "RunnableProperty",
    "run_economic_fuzz",
    "supported_invariants",
]
