"""
Editor-agnostic CodeAction output for MIESC deterministic fixes.

MIESC's ``miesc fix`` command historically emitted whole *patched files*. That
is fine for CLI use, but an IDE extension (VS Code / JetBrains) needs a precise,
machine-readable contract so it can render each fix as an inline *quick fix*
instead of overwriting the file.

This module defines that contract, aligned with the LSP ``CodeAction`` /
``TextEdit`` shapes, and provides the builders that turn MIESC fixes into it.

Shape (LSP-aligned, 0-based line/character per the LSP spec)::

    {
      "finding_id": "reentrancy:12",
      "title": "Add nonReentrant guard to withdraw",
      "kind": "quickfix",
      "file": "Victim.sol",
      "edits": [
        {
          "range": {
            "start": {"line": 10, "character": 31},
            "end":   {"line": 10, "character": 31}
          },
          "newText": "nonReentrant "
        }
      ]
    }

Design note — ranges are *derived*, not hand-tracked
----------------------------------------------------
The deterministic patchers in ``miesc.cli.commands.fix`` produce a fully
rewritten source string, not (span, newText) pairs. Rather than re-plumb every
one of those regex transforms to track columns (fragile, ~1900 lines), we treat
the fix logic as the single source of truth and *derive* a minimal edit set by
diffing the original against the patched source:

* A line-level ``difflib`` pass finds the changed hunks.
* Each hunk is then refined at the character level by trimming the common
  prefix/suffix, so single-line insertions (e.g. adding ``nonReentrant ``)
  collapse to a precise zero-width or narrow range instead of a full-line blob.

Where a fix genuinely rewrites whole lines (e.g. SafeMath library injection),
the refined range naturally spans those full lines: it runs from
``(start_line, 0)`` to ``(end_line, 0)`` — i.e. the exclusive start of the line
after the last changed one, which is the standard LSP way to cover a line
*including* its terminator. This is the documented behaviour for line-only fixes
that do not know their columns.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

__all__ = [
    "FixEdit",
    "compute_text_edits",
    "to_code_actions",
]

# ``kind`` value per the LSP ``CodeActionKind`` enumeration. All MIESC fixes are
# quick fixes (they remediate a diagnostic), so this is a constant.
CODE_ACTION_KIND_QUICKFIX = "quickfix"


@dataclass(frozen=True)
class FixEdit:
    """A single fix rendered as (before, after) plus its finding metadata.

    ``original`` and ``patched`` are the *full* source before and after applying
    exactly one fix in isolation (independent of any sibling fix), so the derived
    ranges are correct against the file the user currently has open.
    """

    finding_id: str
    title: str
    file: str
    original: str
    patched: str


# ---------------------------------------------------------------------------
# Character-offset → LSP Position helpers (0-based)
# ---------------------------------------------------------------------------


def _position_at(base_line: int, text: str, offset: int) -> Dict[str, int]:
    """Map a char ``offset`` inside ``text`` to an LSP Position.

    ``base_line`` is the 0-based line of ``text``'s first character within the
    whole document; ``text`` is the hunk's original slice. Newlines inside the
    consumed prefix advance the line and reset the character column.
    """
    prefix = text[:offset]
    newlines = prefix.count("\n")
    if newlines == 0:
        return {"line": base_line, "character": offset}
    last_nl = prefix.rfind("\n")
    return {"line": base_line + newlines, "character": offset - last_nl - 1}


def _common_prefix_len(a: str, b: str) -> int:
    limit = min(len(a), len(b))
    i = 0
    while i < limit and a[i] == b[i]:
        i += 1
    return i


def _common_suffix_len(a: str, b: str, cap: int) -> int:
    limit = min(len(a), len(b), cap)
    i = 0
    while i < limit and a[-1 - i] == b[-1 - i]:
        i += 1
    return i


def _refine_hunk(base_line: int, old_text: str, new_text: str) -> Dict[str, object]:
    """Turn a changed line-hunk into a character-precise LSP ``TextEdit``.

    Trims the common leading/trailing characters shared by ``old_text`` and
    ``new_text`` so the emitted range covers only what actually changed. For a
    pure insertion (``old_text`` fully shared) the range is zero-width.
    """
    prefix = _common_prefix_len(old_text, new_text)
    remaining = min(len(old_text), len(new_text)) - prefix
    suffix = _common_suffix_len(old_text, new_text, remaining)

    start = _position_at(base_line, old_text, prefix)
    end = _position_at(base_line, old_text, len(old_text) - suffix)
    replacement = new_text[prefix : len(new_text) - suffix]
    return {"range": {"start": start, "end": end}, "newText": replacement}


# ---------------------------------------------------------------------------
# Diff → TextEdit list
# ---------------------------------------------------------------------------


def compute_text_edits(original: str, patched: str) -> List[Dict[str, object]]:
    """Derive a minimal, ordered list of LSP ``TextEdit`` dicts.

    Diffs ``original`` against ``patched`` at line granularity, then refines each
    changed hunk to a character-precise range. Returns ``[]`` when the sources
    are identical. Edits are ordered top-to-bottom and are non-overlapping, so an
    editor may apply them as a single atomic ``TextEdit[]`` against ``original``.
    """
    if original == patched:
        return []

    # Local import keeps module import cost trivial for callers that only need
    # the dataclass/typing surface.
    import difflib

    orig_lines = original.splitlines(keepends=True)
    new_lines = patched.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(a=orig_lines, b=new_lines, autojunk=False)

    edits: List[Dict[str, object]] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        old_text = "".join(orig_lines[i1:i2])
        new_text = "".join(new_lines[j1:j2])
        edits.append(_refine_hunk(i1, old_text, new_text))
    return edits


def to_code_actions(fixes: Iterable[FixEdit]) -> List[Dict[str, object]]:
    """Build the list of LSP-aligned ``CodeAction`` dicts from ``fixes``.

    Each :class:`FixEdit` whose before/after actually differ becomes one code
    action carrying its derived ``edits``. Fixes that produced no change are
    dropped. The result is JSON-serializable and deterministic for a given input.
    """
    actions: List[Dict[str, object]] = []
    for fix in fixes:
        edits = compute_text_edits(fix.original, fix.patched)
        if not edits:
            continue
        actions.append(
            {
                "finding_id": fix.finding_id,
                "title": fix.title,
                "kind": CODE_ACTION_KIND_QUICKFIX,
                "file": fix.file,
                "edits": edits,
            }
        )
    return actions
