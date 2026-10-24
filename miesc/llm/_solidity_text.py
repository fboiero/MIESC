"""Shared index-preserving text helpers for the deterministic Solidity source miners.

The first three helpers were duplicated verbatim across the Phase-1 plan miners
(`revert_invariant_mining`, `privileged_governance_lifecycle`,
`resource_liveness_griefing`, `lending_solvency_liquidation`). They are collected here
so a single, tested copy backs all of them. ``_mask_strings`` and ``_body_brace`` were added
when the miners' loop and function-span detection turned out to trip on string literals and
on bodiless declarations. Each preserves source offsets, so a miner can mask comments and
strings, locate a line, or find a matching brace and still anchor findings to the original
source positions.

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


def _mask_strings(source: str) -> str:
    """Blank the *contents* of string and character literals in place, keeping the quotes.

    Index-preserving like ``_strip_comments``. Handles backslash escapes, so an escaped quote
    does not end the literal; an unterminated literal is blanked to the end of its line. Run it
    after ``_strip_comments`` (a ``"`` inside a comment would otherwise open a literal).
    """
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c in ('"', "'"):
            j = i + 1
            while j < n and source[j] != c and source[j] != "\n":
                if source[j] == "\\":
                    j += 1
                j += 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _body_brace(source: str, header_end: int) -> int:
    """Index of the ``{`` that opens the body declared before ``header_end``, or ``-1``.

    A ``;`` before the next ``{`` means a bodiless declaration (interface or abstract
    function): returning ``-1`` keeps a miner from adopting the *next* block in the file as
    that declaration's body, which made an interface's ``execute`` "own" the whole contract
    declared after it.
    """
    brace = source.find("{", header_end)
    if brace == -1:
        return -1
    semi = source.find(";", header_end)
    if semi != -1 and semi < brace:
        return -1
    return brace
