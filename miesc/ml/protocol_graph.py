"""
Protocol Graph — cross-file/cross-contract reasoning (MEJORAS.md item #5).

Merges per-file call graphs (miesc.ml.call_graph.CallGraphBuilder, now
contract-segmented) across a set of Solidity files into one picture of the
protocol: which contracts inherit from which, which contracts call which
others, and a heuristic storage-collision risk flag for upgradeable bases
missing a `__gap`. Regex-based, same rigor level as the rest of the
codebase's Solidity parsing (see call_graph.py's own docstring) — not a
real compiler/parser, and explicitly not byte-accurate storage-slot
arithmetic (see MEJORAS.md #5 for why that's out of scope).

License: AGPL-3.0
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type
from miesc.ml.call_graph import CallGraphBuilder

# Started as the same interface-call pattern proven in
# frontier_llm_adapter.py::_preprocess_codebase for spotting cross-contract
# calls, but that one requires a literal "I" prefix (`IFoo(x).bar()`) — real
# code just as often calls a sibling contract via its concrete type
# (`Vault(x).bar()`, no "I"). Any capitalized identifier now qualifies; the
# resolution below already checks both the I-prefixed and bare form against
# known contract names, so this needed no further changes there.
INTERFACE_CALL_PATTERN = re.compile(r"\b([A-Z]\w*)\((\w+)\)\.(\w+)\(")
IMPORT_PATTERN = re.compile(r"import\s+(?:\{[^}]+\}\s+from\s+)?\"([^\"]+)\"")

# `Vault vault = Vault(vaultAddress);` then `vault.tokenInsured();` on a later
# line — cast-to-a-local-variable is at least as common in real code as the
# inline-chained `Vault(vaultAddress).tokenInsured()` INTERFACE_CALL_PATTERN
# above catches, and was completely invisible before this: confirmed on Y2K
# Finance's real Controller.sol, where 6 of the protocol's real audit
# findings involve exactly this Controller->Vault relationship, written this
# way throughout. `\1` requires the declared type and the cast target to
# match (rules out e.g. `Foo x = Bar(y)` upcasts/wraps).
TYPED_LOCAL_ASSIGNMENT_PATTERN = re.compile(r"\b([A-Z]\w*)\s+(\w+)\s*=\s*\1\s*\(")
LOCAL_VAR_CALL_PATTERN = re.compile(r"\b(\w+)\.(\w+)\(")


@dataclass
class ProtocolGraph:
    contracts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    inheritance_edges: List[Tuple[str, str]] = field(default_factory=list)
    call_edges: List[Tuple[str, str]] = field(default_factory=list)
    unresolved_imports: List[str] = field(default_factory=list)
    storage_risk: List[Dict[str, Any]] = field(default_factory=list)


def _is_upgradeable_source(source: str) -> bool:
    return bool(re.search(r"Initializable|Upgradeable", source))


def _has_storage_gap(source: str) -> bool:
    return bool(re.search(r"__gap|__storage_gap", source))


def _resolve_import(import_path: str, from_file: Path, all_files: List[Path]) -> Path | None:
    if not import_path.startswith("."):
        return None  # npm-style package import (e.g. @openzeppelin/...), not resolvable here
    candidate = (from_file.parent / import_path).resolve()
    if not candidate.suffix:
        candidate = candidate.with_suffix(".sol")
    for f in all_files:
        if f.resolve() == candidate:
            return f
    return None


def build_protocol_graph(file_paths: List[str]) -> ProtocolGraph:
    """Merge per-file call graphs across `file_paths` into one protocol-wide graph."""
    graph = ProtocolGraph()
    builder = CallGraphBuilder()
    sources: Dict[Path, str] = {}
    resolved_paths = [Path(p) for p in file_paths]

    for path in resolved_paths:
        try:
            source = path.read_text()
        except OSError:
            continue
        sources[path] = source
        cg = builder.build_from_source(source)

        for contract_name in cg.contracts:
            if contract_name in graph.contracts:
                graph.contracts[contract_name]["duplicate"] = True
                continue
            graph.contracts[contract_name] = {
                "file": str(path),
                "bases": cg.inheritance.get(contract_name, []),
                "functions": list(cg.nodes_by_contract.get(contract_name, {}).keys()),
                "source": source,
                "line_range": cg.contract_line_ranges.get(contract_name),
            }
            for base in cg.inheritance.get(contract_name, []):
                graph.inheritance_edges.append((contract_name, base))

        for imp in IMPORT_PATTERN.findall(source):
            resolved = _resolve_import(imp, path, resolved_paths)
            if resolved is None:
                graph.unresolved_imports.append(imp)

    # Cross-contract call edges: for each contract's source, find type-cast
    # calls (`IVault(x).withdraw()` or the equally common `Vault(x).withdraw()`
    # with no "I") whose captured type name matches a known contract.
    known_names = set(graph.contracts.keys())

    def _resolve_type_candidates(captured: str) -> set:
        candidates = {captured}
        # Standard interface naming (capital "I" + another capital, e.g.
        # "IVault", "IERC20" — not "Interest") <-> its concrete counterpart
        # resolve to each other either direction.
        if len(captured) > 1 and captured[0] == "I" and captured[1].isupper():
            candidates.add(captured[1:])
        else:
            candidates.add(f"I{captured}")
        return candidates & known_names

    for contract_name, info in graph.contracts.items():
        source = info["source"]
        for m in INTERFACE_CALL_PATTERN.finditer(source):
            for target in _resolve_type_candidates(m.group(1)):
                if target != contract_name:
                    graph.call_edges.append((contract_name, target))

        # Second pass: `Vault vault = Vault(addr); ... vault.foo();` — cast to
        # a local variable, called on a later line. Build var name -> type for
        # this contract's source, then scan for calls on those variable names.
        var_types = {
            var_name: type_name
            for type_name, var_name in TYPED_LOCAL_ASSIGNMENT_PATTERN.findall(source)
        }
        if var_types:
            for m in LOCAL_VAR_CALL_PATTERN.finditer(source):
                type_name = var_types.get(m.group(1))
                if type_name is None:
                    continue
                for target in _resolve_type_candidates(type_name):
                    if target != contract_name:
                        graph.call_edges.append((contract_name, target))

    # Storage-risk heuristic: derived contract whose (resolved) base looks
    # upgradeable but has no __gap anywhere in the base's own source.
    for derived, base in graph.inheritance_edges:
        base_info = graph.contracts.get(base)
        if base_info is None:
            continue  # base not in this file set (e.g. OpenZeppelin import) — nothing to check
        if _is_upgradeable_source(base_info["source"]) and not _has_storage_gap(
            base_info["source"]
        ):
            graph.storage_risk.append(
                {
                    "derived": derived,
                    "base": base,
                    "reason": (
                        f"{base} looks upgradeable (Initializable/Upgradeable) but has no "
                        "__gap — heuristic only, not a slot-offset computation"
                    ),
                }
            )

    return graph


def resolve_finding_contract(finding: Dict[str, Any], graph: ProtocolGraph) -> Optional[str]:
    """Which contract in `graph` a finding's location.file/line falls under.

    Returns None (never raises) when the file isn't part of this protocol, the
    finding has no usable location, or no contract's line range contains it —
    e.g. a finding on an import/pragma line outside every contract block.
    """
    loc = finding.get("location") or {}
    file = loc.get("file")
    line = loc.get("line")
    if not file or not isinstance(line, int):
        return None

    file_path = str(Path(file).resolve()) if Path(file).exists() else file
    for name, info in graph.contracts.items():
        contract_file = info.get("file", "")
        same_file = contract_file == file or (
            Path(contract_file).exists() and str(Path(contract_file).resolve()) == file_path
        )
        if not same_file:
            continue
        line_range = info.get("line_range")
        if line_range and line_range[0] <= line <= line_range[1]:
            return name
    return None


# MEJORAS2.md backlog follow-up (found while closing "Cross-Contract
# Reasoning vs. real protocols", PR #32): this used to be its own 6-keyword
# text scan, deliberately not reusing finding_taxonomy's CanonicalCategory
# to avoid a "third incompatible vocabulary". That reasoning doesn't hold up
# against real data — CanonicalCategory is already the vocabulary
# intelligence.py's own FP-suppression rules use (same core/ml tier,
# triage_ranker.py already imports across this exact boundary), and the old
# keyword list missed denial_of_service/bad_randomness/time_manipulation
# entirely despite them being canonical categories all along. Confirmed on
# Y2K Finance's real findings: Vault.sol's real denial_of_service findings
# never matched any of the 6 old keywords.
#
# CanonicalCategory still doesn't cover MEJORAS2.md's MODERN_CATEGORIES
# (business_logic, rounding, fee_on_transfer, erc4626 — evaluate.py's own
# taxonomy extension, never folded back into finding_taxonomy.py) — that IS
# a real third vocabulary, and reusing evaluate.py's version here isn't an
# option (miesc/cli/ importing into miesc/ml/ would invert the dependency
# direction). Kept as a small, explicit text fallback instead of leaving
# those categories fully uncovered again.
_MODERN_CATEGORY_KEYWORDS = {
    "business_logic": ("business logic", "invariant", "griefing"),
    "rounding": ("rounding", "precision loss", "loss of precision"),
    "fee_on_transfer": ("fee-on-transfer", "fee on transfer", "deflationary token"),
    "erc4626": ("erc4626", "eip-4626", "eip 4626", "share price", "inflation attack"),
}

# Every CanonicalCategory is a real vulnerability class worth flagging as an
# exposure signal except OTHER (uninformative — would fire on nearly
# everything and drown out the useful cases).
_RISKY_CANONICAL_CATEGORIES = {c for c in CanonicalCategory if c is not CanonicalCategory.OTHER}


def _matches_risk_keyword(finding: Dict[str, Any]) -> Optional[str]:
    canonical = normalize_finding_type(finding)
    if canonical in _RISKY_CANONICAL_CATEGORIES:
        return canonical.value

    text = " ".join(str(finding.get(k, "")) for k in ("type", "title", "message")).lower()
    for category, keywords in _MODERN_CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return category
    return None


def find_cross_contract_chains(
    findings_by_contract: Dict[str, List[Dict[str, Any]]], graph: ProtocolGraph
) -> List[Dict[str, Any]]:
    """Flag call edges into a contract that has a risky finding.

    This is an exposure signal — "a real call path from `caller` reaches
    `callee`, which has a finding of this category" — not a proven exploit.
    Same honesty level as build_protocol_graph's storage-risk heuristic:
    useful triage signal, not a verified attack chain.
    """
    chains: List[Dict[str, Any]] = []
    for caller, callee in graph.call_edges:
        for finding in findings_by_contract.get(callee, []):
            keyword = _matches_risk_keyword(finding)
            if not keyword:
                continue
            chains.append(
                {
                    "contracts": [caller, callee],
                    "callee_finding_id": finding.get("id"),
                    "category": keyword,
                    "reason": (
                        f"{caller} calls {callee}, which has a '{keyword}' finding "
                        f"({finding.get('id', 'unknown')})"
                    ),
                }
            )
    return chains
