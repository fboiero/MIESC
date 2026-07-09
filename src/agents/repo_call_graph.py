"""
MIESC Repo Call Graph — whole-repo promotion of the single-file call graph.

Thin wrapper that lifts ``src/ml/call_graph.py`` (single-source) to a merged,
cross-contract view over every in-scope ``.sol`` file in a repository. It reuses
``CallGraphBuilder.build_from_source`` for per-contract function parsing
(visibility, modifiers, guards) and the ``CallGraph`` BFS/path machinery for
reachability, adding two things the single-file builder does not provide:

  * cross-contract and same-contract function → function edges, and
  * exact function-body extraction (the single-file builder stores none).

This is the tool backend for the Phase-1 agentic auditor (design §5): the LLM
receives ``repo_map()`` up front and pulls bodies / call chains on demand.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from src.ml.call_graph import CallEdge, CallGraph, CallGraphBuilder, FunctionNode, Visibility

logger = logging.getLogger(__name__)

# Same skip rules the benchmark harness uses (evmbench_official_detect.py:34) so
# we audit implementation code, not tests/libs/mocks/vendored deps.
_SKIP_PATH = (
    "/test",
    "/tests",
    "/lib/",
    "/libs/",
    "/mock",
    "/node_modules",
    "/interface",
    "/script",
    "/.git/",
    "/out/",
    "/cache/",
)

# Solidity keywords / built-ins that look like calls but are not functions we
# track as call-graph edges.
_CALL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "returns",
        "require",
        "assert",
        "revert",
        "emit",
        "new",
        "function",
        "modifier",
        "constructor",
        "keccak256",
        "sha256",
        "ecrecover",
        "addmod",
        "mulmod",
        "type",
        "abi",
        "payable",
        "address",
    }
)

# Receivers that denote language/global namespaces rather than another contract.
_GLOBAL_RECEIVERS = frozenset(
    {"this", "msg", "block", "tx", "abi", "address", "super", "type"}
)

# contract | interface | library <Name> ... {   (header up to the opening brace)
_CONTRACT_HEADER = re.compile(
    r"\b(contract|interface|library)\s+(\w+)[^{]*\{",
    re.MULTILINE,
)

# `receiver.method(` — candidate cross-contract call.
_MEMBER_CALL = re.compile(r"(\w+)\s*\.\s*(\w+)\s*\(")

# bare `name(` not preceded by `.` or a word char — candidate internal call.
_BARE_CALL = re.compile(r"(?<![.\w])(\w+)\s*\(")


@dataclass
class _ContractInfo:
    """Per-contract parsed state within the repository."""

    name: str
    source: str  # the contract's own source block (header + body)
    file: Path
    graph: CallGraph  # single-file graph from CallGraphBuilder (function nodes)
    bodies: Dict[str, str] = field(default_factory=dict)  # fn -> exact source


class RepoCallGraph:
    """Whole-repo, cross-contract call graph over in-scope Solidity sources.

    Node identity in the merged graph is the qualified name ``"Contract.fn"``.
    All accessors take ``(contract, fn)`` and return qualified names so callers
    can disambiguate cross-contract targets.
    """

    def __init__(
        self, contracts: Dict[str, _ContractInfo], repo_dir: Path | None = None
    ) -> None:
        self._contracts = contracts
        self._repo_dir = Path(repo_dir) if repo_dir is not None else Path(".")
        self._merged = CallGraph("repo")
        self._build_merged_graph()

    # ------------------------------------------------------------------ build

    @classmethod
    def build(cls, repo_dir: Path | str, scope: str = "") -> "RepoCallGraph":
        """Build a merged call graph across all in-scope ``.sol`` files.

        Args:
            repo_dir: Repository (or contract) root to scan recursively.
            scope: Optional subdir preference (like ``run_cmd_dir``). When it
                matches some files, the build restricts to those; otherwise it
                falls back to the whole repo.
        """
        root = Path(repo_dir)
        files = [
            p
            for p in root.rglob("*.sol")
            if not any(s in str(p).lower() for s in _SKIP_PATH)
        ]
        if scope:
            scoped = [p for p in files if scope.strip("/").lower() in str(p).lower()]
            if scoped:
                files = scoped

        builder = CallGraphBuilder()
        contracts: Dict[str, _ContractInfo] = {}
        for path in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:  # pragma: no cover - unreadable file
                logger.warning("RepoCallGraph: cannot read %s: %s", path, exc)
                continue
            for name, block in cls._split_contracts(text):
                if name in contracts:
                    # First definition wins; log the shadow but keep scanning.
                    logger.debug("RepoCallGraph: duplicate contract %s in %s", name, path)
                    continue
                graph = builder.build_from_source(block, name)
                info = _ContractInfo(name=name, source=block, file=path, graph=graph)
                info.bodies = cls._extract_bodies(block, graph)
                contracts[name] = info

        logger.info(
            "RepoCallGraph: %d contract(s) across %d file(s)",
            len(contracts),
            len(files),
        )
        return cls(contracts, repo_dir=root)

    # -------------------------------------------------------------- accessors

    def repo_map(self) -> str:
        """Compact structural digest fed to the LLM up front.

        Per contract: its external/public functions. Then the cross-contract
        call edges. No bodies — those are pulled on demand.
        """
        lines: List[str] = []
        for name in sorted(self._contracts):
            info = self._contracts[name]
            entry_fns = sorted(
                fn.name for fn in info.graph.nodes.values() if fn.is_entry_point
            )
            fns = ", ".join(entry_fns) if entry_fns else "(none)"
            lines.append(f"contract {name}: {fns}")

        edges = sorted(
            {
                (e.caller, e.callee)
                for e in self._merged.edges
                if self._contract_of(e.caller) != self._contract_of(e.callee)
            }
        )
        if edges:
            lines.append("")
            lines.append("cross-contract edges:")
            for caller, callee in edges:
                lines.append(f"  {caller} -> {callee}")
        return "\n".join(lines)

    def function_body(self, contract: str, fn: str) -> Optional[str]:
        """Exact source of ``contract.fn`` (signature + body), or None."""
        info = self._contracts.get(contract)
        if info is None:
            return None
        return info.bodies.get(fn)

    def contract_source(self, contract: str) -> str | None:
        """Full ``.sol`` source block of ``contract`` (header + body), or None."""
        info = self._contracts.get(contract)
        if info is None:
            return None
        return info.source

    def contract_file(self, contract: str) -> Path | None:
        """Real filesystem path to the ``.sol`` defining ``contract``, or None."""
        info = self._contracts.get(contract)
        if info is None:
            return None
        return info.file

    def repo_dir(self) -> Path:
        """Repository root passed to :meth:`build`."""
        return self._repo_dir

    def callers_of(self, contract: str, fn: str) -> List[str]:
        """Qualified names of functions that call ``contract.fn``."""
        return list(self._merged.get_callers(self._q(contract, fn)))

    def callees_of(self, contract: str, fn: str) -> List[str]:
        """Qualified names of functions called by ``contract.fn``."""
        return list(self._merged.get_callees(self._q(contract, fn)))

    def paths_to(self, contract: str, fn: str) -> List[List[str]]:
        """Entry-point → ``contract.fn`` call paths (reuses ``paths_to_sink``)."""
        paths = self._merged.paths_to_sink(self._q(contract, fn))
        return [p.nodes for p in paths]

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _q(contract: str, fn: str) -> str:
        return f"{contract}.{fn}"

    @staticmethod
    def _contract_of(qualified: str) -> str:
        return qualified.split(".", 1)[0]

    @classmethod
    def _split_contracts(cls, text: str) -> List[tuple[str, str]]:
        """Split a ``.sol`` file into (name, source-block) per contract.

        Uses brace matching so nested braces inside a contract don't truncate
        the block.
        """
        blocks: List[tuple[str, str]] = []
        for match in _CONTRACT_HEADER.finditer(text):
            name = match.group(2)
            open_brace = text.index("{", match.start())
            end = cls._match_brace(text, open_brace)
            if end == -1:
                continue
            blocks.append((name, text[match.start() : end + 1]))
        return blocks

    @classmethod
    def _extract_bodies(cls, source: str, graph: CallGraph) -> Dict[str, str]:
        """Extract exact source text for each function node in a contract."""
        bodies: Dict[str, str] = {}
        for fn_name in graph.nodes:
            pattern = re.compile(r"\bfunction\s+" + re.escape(fn_name) + r"\s*\(")
            m = pattern.search(source)
            if not m:
                continue
            open_brace = source.find("{", m.end())
            if open_brace == -1:
                continue
            end = cls._match_brace(source, open_brace)
            if end == -1:
                continue
            bodies[fn_name] = source[m.start() : end + 1]
        return bodies

    @staticmethod
    def _match_brace(text: str, open_index: int) -> int:
        """Return the index of the brace matching the one at ``open_index``."""
        depth = 0
        for i in range(open_index, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _build_merged_graph(self) -> None:
        """Merge per-contract nodes under qualified names and resolve edges."""
        # Map of public/external method name -> contracts exposing it (for
        # cross-contract call resolution).
        exposed: Dict[str, List[str]] = {}
        for cname, info in self._contracts.items():
            for fn in info.graph.nodes.values():
                node = copy.deepcopy(fn)
                node.name = self._q(cname, fn.name)
                self._merged.add_function(node)
                if fn.is_entry_point:
                    exposed.setdefault(fn.name, []).append(cname)

        for cname, info in self._contracts.items():
            local_fns = set(info.graph.nodes)
            for fn_name, body in info.bodies.items():
                caller = self._q(cname, fn_name)
                self._add_edges_from_body(caller, body, cname, local_fns, exposed)

    def _add_edges_from_body(
        self,
        caller: str,
        body: str,
        contract: str,
        local_fns: set[str],
        exposed: Dict[str, List[str]],
    ) -> None:
        seen: set[str] = set()

        # Cross-contract: receiver.method(...) where method is a public fn of
        # another contract.
        for m in _MEMBER_CALL.finditer(body):
            receiver, method = m.group(1), m.group(2)
            if receiver in _GLOBAL_RECEIVERS:
                continue
            for target_contract in exposed.get(method, []):
                if target_contract == contract:
                    continue
                callee = self._q(target_contract, method)
                if callee not in seen:
                    seen.add(callee)
                    self._merged.add_edge(CallEdge(caller, callee, "external"))

        # Same-contract internal calls.
        for m in _BARE_CALL.finditer(body):
            name = m.group(1)
            if name in _CALL_KEYWORDS or name not in local_fns or name == caller:
                continue
            callee = self._q(contract, name)
            if callee == caller or callee in seen:
                continue
            seen.add(callee)
            self._merged.add_edge(CallEdge(caller, callee, "internal"))


__all__ = ["RepoCallGraph"]
