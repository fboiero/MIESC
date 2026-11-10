"""
Medusa harness detection + config — shared adapter helper (P1-3a).
===================================================================

Medusa fuzzes *contracts*, not a project: on a multi-contract project with no
``targetContracts`` it aborts with "specify target contract(s)". And it only
treats a function as a property test when the function name matches a configured
prefix (default ``property_``), so a Foundry ``invariant_*`` / Echidna
``echidna_*`` harness is ignored unless the prefix is configured.

This module picks what to fuzz and writes a minimal medusa config:

* **Prefer a real fuzzing harness.** Scan first-party Solidity for functions
  named ``property_* / invariant_* / echidna_*`` and target the contracts that
  declare them, with all three prefixes enabled. Foundry ``*.t.sol`` unit tests
  do not match and are correctly ignored.
* **Otherwise fall back to the first-party contracts** (``src/`` / ``contracts/``)
  so medusa at least assertion-fuzzes them. Many real contracts have
  constructors medusa cannot auto-deploy, so coverage may still be low — which
  the honest ``inconclusive`` verdict (see ``_fuzz_result``) then reports, now
  with a reason ("no fuzzable property/invariant harness found").

Deterministic, source-only; never invents an invariant.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import json
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# Directories that are never first-party.
_EXCLUDE_DIRS = {"lib", "node_modules", "out", "cache", "artifacts", ".git", "broadcast"}
# Preferred first-party source roots for the fallback target selection.
_SRC_SUBDIRS = ("src", "contracts")

#: Property/invariant/assertion function-name prefixes a fuzzing harness uses.
HARNESS_PREFIXES = ("property_", "invariant_", "echidna_")

_HARNESS_FN_RE = re.compile(r"\bfunction\s+((?:property_|invariant_|echidna_)\w+)\s*\(")
_CONTRACT_RE = re.compile(r"\bcontract\s+(\w+)")
# Concrete (deployable) contract: `contract X`, but not `abstract contract X`
# and not `interface`/`library` (the `contract` keyword already excludes those).
_DEPLOYABLE_CONTRACT_RE = re.compile(r"\b(abstract\s+)?contract\s+(\w+)")


def _iter_first_party_sol(root: Path) -> Iterator[Path]:
    """Yield first-party ``.sol`` files under ``root`` (excluding deps)."""
    for path in sorted(root.rglob("*.sol")):
        parts = set(path.relative_to(root).parts[:-1])
        if parts & _EXCLUDE_DIRS:
            continue
        yield path


def _contracts_declaring_harness_fns(source: str) -> List[str]:
    """Return the contract names in ``source`` that declare a harness function.

    A contract "owns" a harness function when a ``property_/invariant_/echidna_``
    function appears after that contract's declaration and before the next one.
    """
    if not _HARNESS_FN_RE.search(source):
        return []
    # Walk declarations in order, bucketing harness fns into the enclosing contract.
    markers: List[Tuple[int, str]] = [
        (m.start(), m.group(1)) for m in _CONTRACT_RE.finditer(source)
    ]
    if not markers:
        return []
    owning: List[str] = []
    for fn in _HARNESS_FN_RE.finditer(source):
        pos = fn.start()
        current = None
        for start, name in markers:
            if start < pos:
                current = name
            else:
                break
        if current and current not in owning:
            owning.append(current)
    return owning


def detect_harness_contracts(root: Path) -> List[str]:
    """Contract names across the project that declare a fuzzing harness function.

    Ordered, de-duplicated. Empty when the project ships no harness."""
    found: List[str] = []
    for sol in _iter_first_party_sol(root):
        try:
            source = sol.read_text(encoding="utf-8")
        except Exception:
            continue
        for name in _contracts_declaring_harness_fns(source):
            if name not in found:
                found.append(name)
    return found


def _first_party_contracts(root: Path) -> List[str]:
    """Concrete (deployable) contract names under ``src/`` / ``contracts/``.

    Used as fallback targets when the project ships no harness. Interfaces,
    libraries and ``abstract`` contracts are skipped because medusa aborts (not
    merely ignores) when asked to target a non-deployable contract."""
    bases = [root / sub for sub in _SRC_SUBDIRS if (root / sub).is_dir()]
    if not bases:
        bases = [root]
    names: List[str] = []
    for base in bases:
        for sol in base.rglob("*.sol"):
            rel = set(sol.relative_to(root).parts[:-1])
            if rel & _EXCLUDE_DIRS or sol.name.endswith(".t.sol"):
                continue
            try:
                source = sol.read_text(encoding="utf-8")
            except Exception:
                continue
            for m in _DEPLOYABLE_CONTRACT_RE.finditer(source):
                if m.group(1):  # 'abstract ' prefix -> not deployable
                    continue
                if m.group(2) not in names:
                    names.append(m.group(2))
    return names


def select_targets(contract_path: str) -> Tuple[List[str], str]:
    """Pick medusa target contracts for ``contract_path``.

    Returns ``(targets, source)`` where ``source`` is ``"harness"`` (the project
    ships property/invariant/echidna functions), ``"first-party"`` (fallback to
    ``src/`` contracts), or ``"single-file"`` (a lone ``.sol``). ``targets`` is
    empty only when nothing first-party could be found."""
    path = Path(contract_path)
    root = path if path.is_dir() else path.parent

    harness = detect_harness_contracts(root)
    if harness:
        return harness, "harness"

    if path.is_file():
        try:
            source = path.read_text(encoding="utf-8")
        except Exception:
            source = ""
        names = [m.group(1) for m in _CONTRACT_RE.finditer(source)]
        return names, "single-file"

    return _first_party_contracts(root), "first-party"


def write_medusa_config(
    directory: Path,
    *,
    targets: List[str],
    compilation_target: str,
    test_limit: int,
    timeout: int,
    workers: int,
) -> Path:
    """Write a minimal medusa.json into ``directory`` and return its path.

    Targets the given contracts, enables property testing for all three harness
    prefixes plus assertion testing, and points compilation at
    ``compilation_target`` (a project dir or a single ``.sol``)."""
    config: Dict[str, object] = {
        "fuzzing": {
            "testLimit": int(test_limit),
            "timeout": int(timeout),
            "workers": int(workers),
            "targetContracts": list(targets),
            "testing": {
                "assertionTesting": {"enabled": True},
                "propertyTesting": {"enabled": True, "testPrefixes": list(HARNESS_PREFIXES)},
            },
        },
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {"target": compilation_target},
        },
    }
    path = Path(directory) / "medusa.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def no_harness_reason(source: str) -> Optional[str]:
    """A short reason string when ``source`` fuzzing is expected to be shallow:
    no property/invariant/echidna harness present. ``None`` when a harness is."""
    if _HARNESS_FN_RE.search(source or ""):
        return None
    return "no fuzzable property/invariant/echidna harness found in the project"


__all__ = [
    "HARNESS_PREFIXES",
    "detect_harness_contracts",
    "select_targets",
    "write_medusa_config",
    "no_harness_reason",
]
