"""
Reentrancy Detector Plugin
==========================

Detects classic reentrancy patterns in Solidity code using regex.

The vulnerability: an external call is made (e.g. .call{value:...) BEFORE
the contract's own state is updated, allowing the callee to re-enter and
drain the contract.

Pattern detected:
    .call{value: ...}(...)    — external call with ETH transfer
    Followed by state update  — balance reset AFTER the call

Author: Example Plugin — MIESC v5.1.1
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Use the installed package when available; fall back to a relative import
# when running directly from the examples directory.
try:
    from miesc.plugins.protocol import DetectorPlugin, PluginContext, PluginMetadata, PluginType
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    from miesc.plugins.protocol import DetectorPlugin, PluginContext, PluginMetadata, PluginType


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Matches any external call that transfers ETH:
#   (bool success,) = addr.call{value: ...}(...)
#   addr.call{value: ...}("")
_EXTERNAL_CALL_RE = re.compile(
    r"\.call\s*\{[^}]*value\s*:",
    re.IGNORECASE,
)

# Matches a state-variable assignment after the call — the "too late" update.
# Heuristic: assignment where the left-hand side looks like a mapping or a
# simple state variable (e.g.  balances[msg.sender] = 0  or  balance = 0).
_STATE_UPDATE_RE = re.compile(
    r"\b(\w+)\s*(?:\[[^\]]+\])?\s*=\s*0\s*;",
)

# Checks-Effects-Interactions violation: call before zeroing balance
# Full function body match (simplified — handles single-function snippets well)
_CEI_VIOLATION_RE = re.compile(
    r"\.call\s*\{[^}]*value\s*:[^}]*\}\s*\([^)]*\)"  # the .call{value:...}(...)
    r"(?:(?!\bfunction\b).)*?"                         # anything that is NOT a new function
    r"\b\w+\s*(?:\[[^\]]+\])?\s*=\s*0\s*;",           # followed by = 0; (state reset)
    re.DOTALL,
)


class ReentrancyDetectorPlugin(DetectorPlugin):
    """
    Example detector that flags reentrancy patterns based on:

    1. Line-level: any `.call{value:` found on a line.
    2. CEI violation: `.call{value:...}` appears before a state-zeroing
       assignment within the same function body.

    Severity:
    - High   — CEI violation confirmed (call before state update)
    - Medium — Bare external ETH call (no confirmed CEI violation)
    """

    @property
    def name(self) -> str:
        return "reentrancy-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return (
            "Detects reentrancy vulnerabilities by checking for external ETH "
            "calls (.call{value:}) made before state updates (CEI violations)."
        )

    @property
    def author(self) -> str:
        return "Example Plugin — MIESC"

    def initialize(self, context: PluginContext) -> None:
        """Store context; no external resources needed."""
        self._context = context
        self._config = context.config

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            version=self.version,
            plugin_type=PluginType.DETECTOR,
            description=self.description,
            author=self.author,
            license="MIT",
            tags=["reentrancy", "security", "example"],
            min_miesc_version="5.0.0",
        )

    # ------------------------------------------------------------------
    # Core detection logic
    # ------------------------------------------------------------------

    def detect(
        self,
        code: str,
        filename: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan *code* for reentrancy patterns and return MIESC findings.

        Args:
            code:     Solidity source code as a string.
            filename: Optional file name used in findings for context.
            options:  Unused by this plugin; reserved for future use.

        Returns:
            List of finding dicts in MIESC format.
        """
        options = options or {}
        findings: List[Dict[str, Any]] = []
        lines = code.splitlines()

        # --- Pass 1: line-level scan for any .call{value: ---
        call_lines: List[int] = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if _EXTERNAL_CALL_RE.search(line):
                call_lines.append(lineno)

        # --- Pass 2: CEI violation check (full-source regex) ---
        cei_violations: set = set()
        for match in _CEI_VIOLATION_RE.finditer(code):
            # Determine which line the call starts on
            call_start_pos = match.start()
            lineno = code[:call_start_pos].count("\n") + 1
            cei_violations.add(lineno)

        # --- Build findings ---
        for lineno in call_lines:
            line_text = lines[lineno - 1].strip()
            is_cei = lineno in cei_violations

            findings.append(
                self._make_finding(
                    lineno=lineno,
                    filename=filename,
                    line_text=line_text,
                    severity="High" if is_cei else "Medium",
                    confidence=0.90 if is_cei else 0.65,
                    is_cei=is_cei,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        lineno: int,
        filename: str,
        line_text: str,
        severity: str,
        confidence: float,
        is_cei: bool,
    ) -> Dict[str, Any]:
        tag = "CEI-VIOLATION" if is_cei else "EXTERNAL-CALL"
        description = (
            "External ETH transfer (.call{value:}) detected before state update — "
            "classic reentrancy: attacker can re-enter before balance is zeroed."
            if is_cei
            else "External ETH transfer (.call{value:}) detected. "
            "Verify that all state updates precede this call (Checks-Effects-Interactions)."
        )
        return {
            "id": f"REENTRANCY-{tag}-L{lineno}",
            "tool": self.name,
            "type": "reentrancy",
            "severity": severity,
            "confidence": confidence,
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
            "owasp_category": "SC01 - Reentrancy",
            "location": {
                "file": filename or "<unknown>",
                "line": lineno,
                "column": 0,
                "code_snippet": line_text,
            },
            "message": "Potential reentrancy: external ETH call before state update",
            "description": description,
            "recommendation": (
                "Apply Checks-Effects-Interactions: update all state variables "
                "BEFORE the external call, or use a reentrancy guard (e.g. "
                "OpenZeppelin ReentrancyGuard)."
            ),
        }
