"""Shared index-preserving text helpers for the deterministic Solidity source miners.

These three helpers were duplicated verbatim across the Phase-1 plan miners
(`revert_invariant_mining`, `privileged_governance_lifecycle`,
`resource_liveness_griefing`, `lending_solvency_liquidation`). They are collected here
so a single, tested copy backs all of them. Each preserves source offsets, so a miner can
mask comments, locate a line, or find a matching brace and still anchor findings to the
original source positions.

Not part of the public ``miesc.llm`` surface: the names stay underscore-prefixed and this
module is itself underscore-prefixed. ``_FUNCTION_RE`` is intentionally NOT shared — the
revert-invariant miner needs a superset that also matches ``modifier``/``constructor``,
while the others match only ``function``.
"""

from __future__ import annotations


def _strip_comments(source: str) -> str:
    """Blank ``//`` and ``/* */`` comments in place, preserving every index and newline.

    Heuristic: it does not track string or character literals, so a ``//`` or ``/*`` that
    appears inside a string is blanked too. That is acceptable for the miners' keyword
    scanning and keeps each offset aligned with the original source.
    """
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        c, nxt = source[i], source[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _line_of(source: str, index: int) -> int:
    """Return the 1-based line number of ``index`` within ``source``."""
    return source[:index].count("\n") + 1


def _match_brace(source: str, open_brace: int) -> int:
    """Return the index of the ``}`` matching the ``{`` at ``open_brace`` (or ``len`` if none)."""
    depth = 0
    for idx in range(open_brace, len(source)):
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(source)
