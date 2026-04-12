"""
Cairo (Starknet) Adapter
========================

Adapter for analyzing Cairo smart contracts on Starknet.

Features:
- Parse Cairo module source code
- Detect Cairo-specific vulnerabilities:
  - Felt overflow (252-bit field element)
  - Missing l1<->l2 message validation
  - Storage var collisions
  - Unchecked external calls to L1
  - Caller address spoofing (tx.caller vs get_caller_address)
  - Proxy upgrade issues

References:
- https://book.starknet.io/
- https://docs.starknet.io/documentation/
- https://github.com/crytic/caracal (Cairo static analyzer)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: April 2026
Version: 1.0.0
License: AGPL-3.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CairoVulnType(Enum):
    """Cairo-specific vulnerability categories."""

    FELT_OVERFLOW = "felt_overflow"
    L1_L2_MESSAGE = "l1_l2_message"
    STORAGE_COLLISION = "storage_collision"
    UNCHECKED_L1_CALL = "unchecked_l1_call"
    CALLER_SPOOFING = "caller_spoofing"
    PROXY_UPGRADE = "proxy_upgrade"
    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"


@dataclass
class CairoFinding:
    """A vulnerability finding in Cairo code."""

    vuln_type: CairoVulnType
    severity: str
    title: str
    description: str
    line: int = 0
    function: Optional[str] = None
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "miesc-cairo",
            "type": self.vuln_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": {"line": self.line, "function": self.function or "unknown"},
            "recommendation": self.recommendation,
            "chain": "starknet",
        }


# =============================================================================
# Cairo vulnerability patterns
# =============================================================================


CAIRO_PATTERNS: Dict[CairoVulnType, Dict[str, Any]] = {
    CairoVulnType.FELT_OVERFLOW: {
        "patterns": [
            r"let\s+\w+\s*=\s*\w+\s*\*\s*\w+",  # multiplication without check
            r"\w+\s*\+\s*\w+(?!\s*;\s*assert)",  # addition without assert
        ],
        "severity": "High",
        "title": "Potential felt overflow",
        "description": (
            "Cairo felts are 252-bit field elements. Operations can wrap around "
            "silently. Use `SafeUint256` or explicit range checks."
        ),
        "recommendation": "Use `uint256_check` or `assert_le_felt` to bound values.",
    },
    CairoVulnType.L1_L2_MESSAGE: {
        "patterns": [
            r"#\[l1_handler\]",
            r"send_message_to_l1",
        ],
        "severity": "High",
        "title": "L1<->L2 message without validation",
        "description": (
            "L1-to-L2 messages must validate the sender. Unvalidated l1_handlers "
            "can be called by any L1 contract."
        ),
        "recommendation": "Validate `from_address` parameter against expected L1 sender.",
    },
    CairoVulnType.CALLER_SPOOFING: {
        "patterns": [
            r"get_caller_address\(\)(?!.*assert)",
        ],
        "severity": "Medium",
        "title": "Caller address used without validation",
        "description": (
            "get_caller_address() returns the direct caller but not the transaction "
            "origin. Don't use for authentication of transaction-level intent."
        ),
        "recommendation": "Use get_caller_address() for access control, not get_tx_info().account_contract_address.",
    },
    CairoVulnType.STORAGE_COLLISION: {
        "patterns": [
            r"#\[storage\]\s*struct\s+Storage\s*\{",
        ],
        "severity": "Medium",
        "title": "Storage variable collision risk",
        "description": (
            "If this contract is upgradeable, storage slots must not change "
            "positions between versions. Review storage layout carefully."
        ),
        "recommendation": "Use explicit storage slots or StorageBase pattern for upgradeable contracts.",
    },
    CairoVulnType.UNCHECKED_L1_CALL: {
        "patterns": [
            r"send_message_to_l1\([^)]*\)(?!.*assert)",
        ],
        "severity": "High",
        "title": "Unchecked L1 message send",
        "description": "L1 message payload should be validated before sending.",
        "recommendation": "Validate payload size and content. Consider rate-limiting.",
    },
    CairoVulnType.REENTRANCY: {
        "patterns": [
            r"(IStarknet\w+Dispatcher|\.dispatcher\()",
        ],
        "severity": "High",
        "title": "Potential cross-contract reentrancy",
        "description": (
            "External calls via dispatchers can re-enter if state updates happen "
            "after the call. Follow checks-effects-interactions."
        ),
        "recommendation": "Update state before external calls. Use ReentrancyGuard component.",
    },
    CairoVulnType.ACCESS_CONTROL: {
        "patterns": [
            r"#\[external\]\s*fn\s+\w+\(",
        ],
        "severity": "Medium",
        "title": "External function may lack access control",
        "description": (
            "External Cairo functions are callable by anyone. Verify that sensitive "
            "operations check the caller."
        ),
        "recommendation": "Add OwnableComponent or assert(get_caller_address() == owner).",
    },
    CairoVulnType.PROXY_UPGRADE: {
        "patterns": [
            r"replace_class_syscall",
        ],
        "severity": "High",
        "title": "Contract class replacement without access control",
        "description": (
            "replace_class_syscall changes the contract's implementation. If "
            "unprotected, any caller can replace the logic."
        ),
        "recommendation": "Guard with onlyOwner or Upgradeable component.",
    },
}


# =============================================================================
# Analyzer
# =============================================================================


class CairoAnalyzer:
    """Static analyzer for Cairo/Starknet smart contracts."""

    name = "miesc-cairo"
    description = "Cairo/Starknet static analyzer"
    version = "1.0.0"

    def analyze(self, contract_path: str) -> Dict[str, Any]:
        """Analyze a Cairo contract file and return findings."""
        path = Path(contract_path)

        if not path.exists():
            return {
                "success": False,
                "error": f"File not found: {contract_path}",
                "findings": [],
            }

        try:
            code = path.read_text()
        except Exception as e:
            return {"success": False, "error": str(e), "findings": []}

        findings = self._scan(code)

        return {
            "success": True,
            "tool": self.name,
            "chain": "starknet",
            "file": str(path),
            "findings": [f.to_dict() for f in findings],
            "summary": self._summarize(findings),
        }

    def analyze_source(self, source: str) -> Dict[str, Any]:
        """Analyze Cairo source code directly."""
        findings = self._scan(source)
        return {
            "success": True,
            "tool": self.name,
            "chain": "starknet",
            "findings": [f.to_dict() for f in findings],
            "summary": self._summarize(findings),
        }

    def _scan(self, code: str) -> List[CairoFinding]:
        """Run all patterns against code."""
        findings: List[CairoFinding] = []
        lines = code.split("\n")

        for vuln_type, cfg in CAIRO_PATTERNS.items():
            for pattern in cfg["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        # Extract function name if in a fn
                        func = self._extract_function(lines, i)
                        findings.append(
                            CairoFinding(
                                vuln_type=vuln_type,
                                severity=cfg["severity"],
                                title=cfg["title"],
                                description=cfg["description"],
                                line=i,
                                function=func,
                                recommendation=cfg["recommendation"],
                            )
                        )
                        break  # One finding per type per scan

        return findings

    def _extract_function(self, lines: List[str], line_num: int) -> Optional[str]:
        """Find the enclosing function name for a given line."""
        for i in range(line_num, max(0, line_num - 30), -1):
            if i - 1 < 0 or i - 1 >= len(lines):
                continue
            line = lines[i - 1]
            m = re.search(r"fn\s+(\w+)\s*\(", line)
            if m:
                return m.group(1)
        return None

    def _summarize(self, findings: List[CairoFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
        return summary

    def is_available(self) -> bool:
        """Cairo analyzer is always available (pure Python)."""
        return True


def analyze_cairo_contract(contract_path: str) -> Dict[str, Any]:
    """Convenience function for Cairo analysis."""
    analyzer = CairoAnalyzer()
    return analyzer.analyze(contract_path)
