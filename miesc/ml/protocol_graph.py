"""
Protocol Graph - which contract calls which function of another, across Solidity files.

Finds every `contract` block across the files, what it inherits, and the calls from
one contract into another: `Vault(x).withdraw()`, or `v.withdraw()` on anything
declared with that type (state variable, parameter, local, struct field). `IVault`
resolves to `Vault`; an interface named otherwise (`IMinter` for `NextGenMinter`) is
not matched.
Regex-based, same rigor as the rest of the Solidity parsing in this package - not a
compiler.

License: AGPL-3.0
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

CONTRACT_PATTERN = re.compile(r"\bcontract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*[\s\S]*?\*/")

# `IVault(x).withdraw()` and the equally common concrete-type form `Vault(x).withdraw()`.
TYPE_CAST_CALL_PATTERN = re.compile(r"\b([A-Z]\w*)\((\w+)\)\.(\w+)\(")
# `IVault public immutable vault;`, `function f(IVault v)`, `Vault v = new Vault(...)`:
# a name declared with a type. Only types that are contracts of the protocol count.
DECLARATION_PATTERN = re.compile(
    r"\b([A-Z]\w*)\s+(?:(?:public|private|internal|immutable|constant|memory|storage"
    r"|calldata|payable)\s+)*([a-z_]\w*)\s*[;=,)]"
)
VAR_CALL_PATTERN = re.compile(r"\b(\w+)\.(\w+)\(")


@dataclass
class ProtocolGraph:
    # name -> {"file", "bases", "source"}
    contracts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # (caller, callee) -> functions of callee that caller calls
    calls: Dict[Tuple[str, str], Set[str]] = field(default_factory=dict)


def _contract_blocks(source: str) -> List[Tuple[str, List[str], int, int]]:
    """(name, bases, start, end) of each `contract` block; comments don't count."""
    code = _COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)
    blocks = []
    for match in CONTRACT_PATTERN.finditer(code):
        bases = [b.split("(")[0].strip() for b in (match.group(2) or "").split(",") if b.strip()]
        depth, end = 0, len(code)
        for i in range(match.end() - 1, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        blocks.append((match.group(1), bases, match.start(), end))
    return blocks


def build_protocol_graph(file_paths: List[str]) -> ProtocolGraph:
    """One graph of contracts and cross-contract calls across `file_paths`."""
    graph = ProtocolGraph()
    declarations: Dict[str, Dict[str, str]] = {}  # file -> {variable: type}
    for path in file_paths:
        try:
            source = Path(path).read_text()
        except (OSError, UnicodeDecodeError):
            continue
        # The whole file: a struct or a base declared outside the calling contract counts.
        declarations[str(path)] = {
            var: typ for typ, var in DECLARATION_PATTERN.findall(_COMMENT_RE.sub(" ", source))
        }
        for name, bases, start, end in _contract_blocks(source):
            if name in graph.contracts:
                continue  # same name in two files: keep the first, as the compiler would refuse both
            graph.contracts[name] = {"file": str(path), "bases": bases, "source": source[start:end]}

    known = set(graph.contracts)

    def targets(type_name: str) -> set:
        # IVault <-> Vault resolve to each other (not "Interest" -> "nterest").
        if len(type_name) > 1 and type_name[0] == "I" and type_name[1].isupper():
            return {type_name, type_name[1:]} & known
        return {type_name, f"I{type_name}"} & known

    for caller, info in graph.contracts.items():
        body = info["source"]
        called = [(m.group(1), m.group(3)) for m in TYPE_CAST_CALL_PATTERN.finditer(body)]
        var_types = declarations[info["file"]]
        called += [
            (var_types[m.group(1)], m.group(2))
            for m in VAR_CALL_PATTERN.finditer(body)
            if m.group(1) in var_types
        ]
        for type_name, method in called:
            for callee in targets(type_name) - {caller}:
                graph.calls.setdefault((caller, callee), set()).add(method)
    return graph


def cross_contract_calls(graph: ProtocolGraph) -> List[Dict[str, Any]]:
    """The calls as report rows: caller, callee and the callee functions it calls."""
    return [
        {"caller": caller, "callee": callee, "functions": sorted(methods)}
        for (caller, callee), methods in sorted(graph.calls.items())
    ]
