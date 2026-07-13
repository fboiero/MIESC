"""
Map MIESC findings onto LSP ``Diagnostic`` objects.

MIESC findings use human severity labels (Critical/High/Medium/Low/Info) and
1-based line numbers. The Language Server Protocol uses a 1..4 integer severity
enum and 0-based positions. This module owns that translation so both the
server and its tests share one canonical mapping.

LSP ``DiagnosticSeverity`` enum::

    1 = Error, 2 = Warning, 3 = Information, 4 = Hint

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "SEVERITY_MAP",
    "LSP_SEVERITY_ERROR",
    "LSP_SEVERITY_WARNING",
    "LSP_SEVERITY_INFORMATION",
    "LSP_SEVERITY_HINT",
    "severity_to_lsp",
    "finding_to_diagnostic",
    "findings_in_range",
    "DIAGNOSTIC_SOURCE",
]

LSP_SEVERITY_ERROR = 1
LSP_SEVERITY_WARNING = 2
LSP_SEVERITY_INFORMATION = 3
LSP_SEVERITY_HINT = 4

DIAGNOSTIC_SOURCE = "miesc"

# Canonical MIESC severity (upper-cased) → LSP DiagnosticSeverity (1..4).
# Critical/High are actionable defects → Error; Medium → Warning; Low →
# Information; Info → Hint. Unknown labels degrade to Hint (least intrusive).
SEVERITY_MAP: Dict[str, int] = {
    "CRITICAL": LSP_SEVERITY_ERROR,
    "HIGH": LSP_SEVERITY_ERROR,
    "MEDIUM": LSP_SEVERITY_WARNING,
    "LOW": LSP_SEVERITY_INFORMATION,
    "INFO": LSP_SEVERITY_HINT,
    "INFORMATIONAL": LSP_SEVERITY_HINT,
}


def severity_to_lsp(severity: Optional[str]) -> int:
    """Translate a MIESC severity label to an LSP ``DiagnosticSeverity`` int.

    Case-insensitive. Anything unrecognized (or missing) maps to ``Hint`` so a
    stray label never masquerades as a hard error in the editor gutter.
    """
    return SEVERITY_MAP.get((severity or "").strip().upper(), LSP_SEVERITY_HINT)


def _finding_line(finding: Dict[str, Any]) -> int:
    """Resolve a finding's 1-based line across the known MIESC shapes.

    Checks ``line``, ``line_number``, then ``location.line``. Defaults to 1 when
    no usable line is present (so the diagnostic still renders on line 1).
    """
    raw = finding.get("line") or finding.get("line_number")
    if not raw:
        loc = finding.get("location")
        if isinstance(loc, dict):
            raw = loc.get("line")
    try:
        line = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 1
    return line if line >= 1 else 1


def _finding_code(finding: Dict[str, Any]) -> str:
    """Best rule identifier for the diagnostic ``code`` field."""
    return str(
        finding.get("rule_id")
        or finding.get("id")
        or finding.get("type")
        or finding.get("title")
        or ""
    )


def _finding_message(finding: Dict[str, Any]) -> str:
    """Human-readable diagnostic message."""
    return str(
        finding.get("message")
        or finding.get("description")
        or finding.get("title")
        or finding.get("type")
        or ""
    )


def finding_to_diagnostic(
    finding: Dict[str, Any], doc_text: Optional[str] = None
) -> Dict[str, Any]:
    """Build one LSP ``Diagnostic`` from a MIESC ``finding``.

    The 1-based finding line becomes a 0-based single-line range. When the open
    document text is available, the range end extends to the line's real length
    so the whole offending line is underlined; otherwise it collapses to the
    line start. ``source`` is always ``"miesc"`` and ``code`` carries the rule id.
    """
    line0 = _finding_line(finding) - 1
    end_char = 0
    if doc_text:
        lines = doc_text.splitlines()
        if 0 <= line0 < len(lines):
            end_char = len(lines[line0])
    return {
        "range": {
            "start": {"line": line0, "character": 0},
            "end": {"line": line0, "character": end_char},
        },
        "severity": severity_to_lsp(finding.get("severity")),
        "code": _finding_code(finding),
        "source": DIAGNOSTIC_SOURCE,
        "message": _finding_message(finding),
    }


def findings_in_range(
    findings: List[Dict[str, Any]], rng: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Filter ``findings`` to those whose line falls inside an LSP ``range``.

    ``rng`` is an LSP Range (0-based ``start``/``end`` positions) as sent by a
    ``textDocument/codeAction`` request. A ``None`` range (or a malformed one)
    returns all findings — the editor asked for every available action.
    """
    if not rng:
        return list(findings)
    try:
        start_line = int(rng["start"]["line"])
        end_line = int(rng["end"]["line"])
    except (KeyError, TypeError, ValueError):
        return list(findings)

    selected: List[Dict[str, Any]] = []
    for finding in findings:
        line0 = _finding_line(finding) - 1
        if start_line <= line0 <= end_line:
            selected.append(finding)
    return selected
