"""
tx.origin Authentication Detector Plugin
========================================

Detects the use of ``tx.origin`` for authorization in Solidity code.

The vulnerability: ``tx.origin`` returns the original external account that
started the transaction, not the immediate caller. Using it for access control
(``require(tx.origin == owner)``) lets a malicious intermediary contract trick
an authorized user into performing privileged actions on their behalf
(a phishing / man-in-the-middle attack). Authorization checks should use
``msg.sender`` instead.

Patterns detected:
    require(tx.origin == owner)      — auth check via tx.origin
    if (tx.origin == owner) { ... }  — auth branch via tx.origin
    tx.origin == <anything>          — any equality comparison on tx.origin

Author: Example Plugin — MIESC
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# Use the installed package when available; fall back to a relative import
# when running directly from the examples directory.
try:
    from miesc.plugins.protocol import (
        PLUGIN_API_VERSION,
        DetectorPlugin,
        PluginContext,
        PluginMetadata,
        PluginType,
    )
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    from miesc.plugins.protocol import (
        PLUGIN_API_VERSION,
        DetectorPlugin,
        PluginContext,
        PluginMetadata,
        PluginType,
    )


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Any comparison that puts tx.origin on either side of an == / != operator.
# This captures the authorization-check use of tx.origin, which is the risky
# one, while ignoring benign informational reads (e.g. logging tx.origin).
_TXORIGIN_COMPARE_RE = re.compile(
    r"tx\.origin\s*(?:==|!=)"  # tx.origin == / !=
    r"|(?:==|!=)\s*tx\.origin",  # ... == tx.origin
    re.IGNORECASE,
)

# Bare tx.origin reference (used to emit a lower-severity advisory when the
# value is referenced but not directly in a comparison).
_TXORIGIN_ANY_RE = re.compile(r"\btx\.origin\b", re.IGNORECASE)


class TxOriginAuthDetectorPlugin(DetectorPlugin):
    """
    Example detector that flags ``tx.origin`` usage.

    Severity:
    - High   — ``tx.origin`` used in an equality comparison (auth check).
    - Low    — ``tx.origin`` referenced elsewhere (advisory).
    """

    # Plugin API version this plugin targets (see miesc.plugins.PLUGIN_API_VERSION).
    API_VERSION = PLUGIN_API_VERSION

    @property
    def name(self) -> str:
        return "txorigin-auth-detector"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return (
            "Detects authorization checks that rely on tx.origin, which is "
            "vulnerable to phishing via malicious intermediary contracts. Use "
            "msg.sender for access control instead."
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
            tags=["tx-origin", "access-control", "authorization", "security", "example"],
            min_miesc_version="5.0.0",
            api_version=self.api_version,
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
        Scan *code* for tx.origin usage and return MIESC findings.

        Args:
            code:     Solidity source code as a string.
            filename: Optional file name used in findings for context.
            options:  Unused by this plugin; reserved for future use.

        Returns:
            List of finding dicts in MIESC format.
        """
        options = options or {}
        findings: List[Dict[str, Any]] = []

        for lineno, line in enumerate(code.splitlines(), start=1):
            stripped = line.strip()
            # Skip comments.
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            if not _TXORIGIN_ANY_RE.search(line):
                continue

            is_auth = bool(_TXORIGIN_COMPARE_RE.search(line))
            findings.append(
                self._make_finding(
                    lineno=lineno,
                    filename=filename,
                    line_text=stripped,
                    is_auth=is_auth,
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
        is_auth: bool,
    ) -> Dict[str, Any]:
        tag = "AUTH" if is_auth else "USAGE"
        description = (
            "Authorization check relies on tx.origin. A malicious intermediary "
            "contract can forward a call from an authorized user, so tx.origin "
            "still equals the victim while the attacker controls execution."
            if is_auth
            else "tx.origin is referenced. Ensure it is never used for access "
            "control; prefer msg.sender."
        )
        return {
            "id": f"TXORIGIN-{tag}-L{lineno}",
            "tool": self.name,
            "type": "tx-origin-authentication",
            "severity": "High" if is_auth else "Low",
            "confidence": 0.95 if is_auth else 0.5,
            "swc_id": "SWC-115",
            "cwe_id": "CWE-477",
            "owasp_category": "SC05 - Access Control",
            "location": {
                "file": filename or "<unknown>",
                "line": lineno,
                "column": 0,
                "code_snippet": line_text,
            },
            "message": "Use of tx.origin for authorization",
            "description": description,
            "recommendation": (
                "Replace tx.origin with msg.sender for authorization checks. "
                "Use tx.origin only where the original transaction initiator is "
                "genuinely required, and never for access control."
            ),
        }
