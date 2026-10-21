"""Minimal intra-procedural data flow for chain attributes.

Answers two questions about a Solidity source, per line:

* **time dependence** (SWC-116): does ``block.timestamp`` / ``now`` /
  ``block.number`` reach a comparison inside a condition or a ``return``, or an
  entropy sink (hash, modulo)?
* **weak randomness** (SWC-120): does a chain attribute reach a hash or a modulo,
  or is a strong entropy source (``blockhash``, ``block.difficulty``,
  ``block.coinbase``, ``block.prevrandao``) read at all?

The flow is tracked through locals assigned, directly or transitively, from a
chain attribute inside the same function body. Reading the attribute and storing
it (``createdAt = block.timestamp``), passing it to an event, or doing arithmetic
that never reaches a comparison or an entropy sink is *not* a hit.

Why this exists: measured on SmartBugs-curated (2026-10-21), every labelled
``time_manipulation`` contract has such a flow and none of the labelled ones is
store-only, while 14 of the 43 ``time_manipulation`` false positives and 34 of
the 46 ``bad_randomness`` ones were emitted by rules that fired on the mere
presence of the attribute. See REPRODUCE.md, "Time and randomness data flow".

Scope: regex over comment-stripped source. Cross-function flow through state
variables and flow through calls are out of scope on purpose (minimal, cheap,
and auditable); the heavier analyses live in the semantic layers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Set, Tuple

__all__ = [
    "FlowHit",
    "TIME_ATTRIBUTES",
    "STRONG_ENTROPY_ATTRIBUTES",
    "time_dependence",
    "weak_randomness",
    "time_dependent_lines",
    "weak_randomness_lines",
    "has_time_dependence",
    "has_weak_randomness",
]

TIME_ATTRIBUTES = ("block.timestamp", "now", "block.number")
STRONG_ENTROPY_ATTRIBUTES = (
    "blockhash",
    "block.blockhash",
    "block.difficulty",
    "block.coinbase",
    "block.prevrandao",
)

_ATTRIBUTE_RE = re.compile(
    r"block\.(?:timestamp|number|difficulty|coinbase|prevrandao|blockhash)\b|\bblockhash\b|\bnow\b"
)
_HASH_RE = re.compile(r"\b(?:keccak256|sha3|sha256|ripemd160|abi\.encodePacked|abi\.encode)\s*\(")
_CONDITION_RE = re.compile(r"\b(?:if|require|assert|while|for)\s*\(|\?")
_RETURN_RE = re.compile(r"\breturn\b")
_COMPARISON_RE = re.compile(r"[<>]=?|==|!=")
_FUNCTION_RE = re.compile(r"\b(?:function\b|modifier\s+\w+|constructor\s*\()")
_ASSIGN_RE = re.compile(
    r"^\s*(?:(?:uint|int|bytes|bool|address|string)\w*\s+(?:memory\s+|storage\s+|calldata\s+)?)?"
    r"(\w+)(?:\s*\[[^\]]*\])*(?:\.\w+)*\s*(?:[-+*/%|&^]?=)(?!=)"
)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'")


@dataclass(frozen=True)
class FlowHit:
    """A chain-attribute read that reaches a sink."""

    line: int
    """1-based line where the chain attribute is read."""
    attribute: str
    """The attribute as written: ``block.timestamp``, ``now``, ``blockhash``, ..."""
    sink: str
    """``condition``, ``return``, ``hash``, ``modulo`` or ``strong_source``."""
    sink_line: int
    """1-based line of the statement that consumes the value."""


def _blank(match: "re.Match[str]") -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _strip(source: str) -> str:
    """Blank comments and string literals, keeping every newline (line numbers survive)."""
    source = _BLOCK_COMMENT_RE.sub(_blank, source)
    source = _LINE_COMMENT_RE.sub(_blank, source)
    return _STRING_RE.sub(_blank, source)


def _bodies(source: str) -> List[Tuple[int, str]]:
    """Return ``(offset, text)`` of every function/modifier/constructor body.

    Interface declarations (``;`` before ``{``) are skipped. A source with no
    function at all (a bare snippet) is analysed as one body.
    """
    bodies: List[Tuple[int, str]] = []
    for match in _FUNCTION_RE.finditer(source):
        open_brace = source.find("{", match.end())
        semicolon = source.find(";", match.end())
        if open_brace == -1 or (semicolon != -1 and semicolon < open_brace):
            continue
        depth = 0
        end = open_brace
        while end < len(source):
            char = source[end]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        bodies.append((open_brace + 1, source[open_brace + 1 : end]))
    if not bodies:
        bodies.append((0, source))
    return bodies


def _statements(offset: int, body: str) -> List[Tuple[int, str]]:
    """Split a body into ``(absolute_offset, text)`` statements on ``;``, ``{`` and ``}``."""
    statements: List[Tuple[int, str]] = []
    start = 0
    for index, char in enumerate(body):
        if char in ";{}":
            text = body[start:index]
            if text.strip():
                statements.append((offset + start, text))
            start = index + 1
    tail = body[start:]
    if tail.strip():
        statements.append((offset + start, tail))
    return statements


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _reads(source: str, offset: int, text: str) -> Set[Tuple[str, int]]:
    """``(attribute, line)`` for every chain attribute read in ``text``."""
    return {
        (match.group(0), _line_of(source, offset + match.start()))
        for match in _ATTRIBUTE_RE.finditer(text)
    }


def _mentions(text: str, names: Iterable[str]) -> List[str]:
    names = list(names)
    if not names:
        return []
    pattern = r"\b(?:%s)\b" % "|".join(re.escape(name) for name in names)
    return (
        [name for name in names if re.search(r"\b%s\b" % re.escape(name), text)]
        if re.search(pattern, text)
        else []
    )


def _analyze(source: str) -> List[FlowHit]:
    stripped = _strip(source)
    hits: Set[FlowHit] = set()
    for offset, body in _bodies(stripped):
        statements = _statements(offset, body)
        taint: Dict[str, Set[Tuple[str, int]]] = {}
        # Two passes so a local assigned after its first use (rare, but legal in
        # loops) still carries its sources.
        for _ in range(2):
            for stmt_offset, text in statements:
                sources = _reads(stripped, stmt_offset, text)
                for name in _mentions(text, taint):
                    sources |= taint[name]
                if not sources:
                    continue
                assign = _ASSIGN_RE.match(text)
                if assign:
                    taint.setdefault(assign.group(1), set()).update(sources)
        for stmt_offset, text in statements:
            sources = _reads(stripped, stmt_offset, text)
            for name in _mentions(text, taint):
                sources |= taint[name]
            if not sources:
                continue
            sink_line = _line_of(stripped, stmt_offset + (len(text) - len(text.lstrip())))
            is_hash = bool(_HASH_RE.search(text))
            is_modulo = "%" in text
            is_condition = bool(_CONDITION_RE.search(text)) and bool(_COMPARISON_RE.search(text))
            is_return = bool(_RETURN_RE.search(text)) and bool(_COMPARISON_RE.search(text))
            for attribute, line in sources:
                if is_hash:
                    hits.add(FlowHit(line, attribute, "hash", sink_line))
                if is_modulo:
                    hits.add(FlowHit(line, attribute, "modulo", sink_line))
                if attribute in STRONG_ENTROPY_ATTRIBUTES:
                    hits.add(FlowHit(line, attribute, "strong_source", sink_line))
                if attribute in TIME_ATTRIBUTES:
                    if is_condition:
                        hits.add(FlowHit(line, attribute, "condition", sink_line))
                    elif is_return:
                        hits.add(FlowHit(line, attribute, "return", sink_line))
    return sorted(hits, key=lambda hit: (hit.line, hit.sink_line, hit.attribute, hit.sink))


def time_dependence(source: str) -> List[FlowHit]:
    """Timestamp-like reads that reach a comparison in a condition/return or an entropy sink."""
    return [
        hit
        for hit in _analyze(source)
        if hit.attribute in TIME_ATTRIBUTES
        and hit.sink in ("condition", "return", "hash", "modulo")
    ]


def weak_randomness(source: str) -> List[FlowHit]:
    """Chain-attribute reads that reach a hash or modulo, plus every strong entropy source read."""
    return [hit for hit in _analyze(source) if hit.sink in ("hash", "modulo", "strong_source")]


def time_dependent_lines(source: str) -> Set[int]:
    """Lines (1-based) whose timestamp-like read is time-dependent; see :func:`time_dependence`."""
    return {hit.line for hit in time_dependence(source)}


def weak_randomness_lines(source: str) -> Set[int]:
    """Lines (1-based) whose chain-attribute read is an entropy source; see :func:`weak_randomness`."""
    return {hit.line for hit in weak_randomness(source)}


def has_time_dependence(source: str) -> bool:
    return bool(time_dependence(source))


def has_weak_randomness(source: str) -> bool:
    return bool(weak_randomness(source))
