"""
Cairo (Starknet) Adapter
========================

⚠️  EXPERIMENTAL / ROADMAP — NOT production-validated.
This non-EVM adapter uses pattern-based (regex/heuristic) detection only and is
NOT registered in the active tool. EVM analysis is the production-ready surface.
Non-EVM chains are future work (in test/development). See docs/MULTICHAIN.md.

Adapter for analyzing Cairo smart contracts on Starknet.

Features:
- Parse Cairo module source code
- Detect Cairo-specific vulnerabilities:
  - Felt/u256 overflow (252-bit field element, custom u256)
  - Missing L1<->L2 message validation
  - Storage var collisions in components
  - Unchecked external calls to L1
  - Caller address spoofing (tx.caller vs get_caller_address)
  - Proxy upgrade issues (replace_class_syscall)
  - Pragma oracle staleness (zkLend Feb 2025 root cause)
  - Unchecked syscall results
  - Initializer / reinit vulnerabilities
  - Signature replay in account abstraction

References:
- https://book.starknet.io/
- https://docs.starknet.io/documentation/
- https://github.com/crytic/caracal (Cairo static analyzer)

Real-world exploits informing patterns:
- zkLend (Feb 2025, $9.6M) → PRAGMA_ORACLE_STALE + UNCHECKED_U256
- Braavos (2023)            → SIGNATURE_REPLAY + UPGRADE_NO_INIT_GUARD
- Nostra (2024)             → ACCESS_CONTROL

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: April 2026
Version: 1.1.0
License: AGPL-3.0
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
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
    # New in v1.1.0 — based on 2024-2026 real-world Starknet exploits
    UNCHECKED_U256 = "unchecked_u256"
    PRAGMA_ORACLE_STALE = "pragma_oracle_stale"
    UPGRADE_NO_INIT_GUARD = "upgrade_no_init_guard"
    UNCHECKED_SYSCALL_RESULT = "unchecked_syscall_result"
    SIGNATURE_REPLAY = "signature_replay"


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
    # -----------------------------------------------------------------------
    # New patterns informed by 2024-2026 real-world Starknet exploits
    # -----------------------------------------------------------------------
    CairoVulnType.UNCHECKED_U256: {
        "patterns": [
            # u256 arithmetic without overflowing_add / checked_add
            r"u256\s*\{[^}]*\}\s*\+\s*u256",
            r"let\s+\w+:\s*u256\s*=\s*\w+\s*[+\-*]\s*\w+(?!.*checked_|overflowing_)",
        ],
        "severity": "High",
        "title": "Unchecked u256 arithmetic",
        "description": (
            "Cairo 1.0 u256 arithmetic can still produce silent overflows in "
            "low-level operations. zkLend (Feb 2025, $9.6M) was partially "
            "caused by unchecked u256 math in lending accumulator updates."
        ),
        "recommendation": (
            "Prefer `integer::u256_checked_add`, `checked_sub`, or use the "
            "`core::num::traits::CheckedAdd` trait. Avoid raw `+` / `-` on u256."
        ),
    },
    CairoVulnType.PRAGMA_ORACLE_STALE: {
        "patterns": [
            # Pragma oracle calls without freshness validation
            r"IPragmaOracle\w*Dispatcher.*\.get_data_median",
            r"PragmaPricesResponse",
            r"\.get_data\(DataType::",
        ],
        "severity": "High",
        "title": "Pragma oracle price used without staleness check",
        "description": (
            "Reading Pragma oracle prices without validating `last_updated_timestamp` "
            "or `num_sources_aggregated` exposes the contract to stale-price "
            "manipulation. zkLend Feb 2025 exploit leveraged stale empty-market "
            "state to drain funds."
        ),
        "recommendation": (
            "Assert `get_block_timestamp() - response.last_updated_timestamp < MAX_AGE` "
            "and `response.num_sources_aggregated >= MIN_SOURCES` before using prices."
        ),
    },
    CairoVulnType.UPGRADE_NO_INIT_GUARD: {
        "patterns": [
            r"fn\s+initializ(e|er)\s*\([^)]*\)",
            r"fn\s+__validate_deploy__",
        ],
        "severity": "High",
        "title": "Initializer function may be callable more than once",
        "description": (
            "Initializer / validate_deploy functions must include a reinit guard. "
            "Braavos account contracts (2023) were re-initialized after deployment "
            "when the guard was missing, allowing full account takeover."
        ),
        "recommendation": (
            "Track initialization in a bool storage var and assert it's false "
            "at the start of the initializer (`assert(!self.initialized.read(), 'already initialized')`)."
        ),
    },
    CairoVulnType.UNCHECKED_SYSCALL_RESULT: {
        "patterns": [
            # call_contract_syscall / library_call_syscall without .unwrap_syscall()
            r"(call_contract_syscall|library_call_syscall)\([^)]*\)(?!\s*[.?])",
            r"send_message_to_l1_syscall\([^)]*\)(?!\s*[.?])",
        ],
        "severity": "Medium",
        "title": "Syscall result not checked",
        "description": (
            "Cairo syscalls return a `SyscallResult` that must be unwrapped or "
            "propagated. Ignoring failures leaves the contract in an inconsistent "
            "state (e.g. state written, external effect never happened)."
        ),
        "recommendation": (
            "Use `.unwrap_syscall()` or propagate with `?`. Never silently drop "
            "the result of a call_contract_syscall / library_call_syscall."
        ),
    },
    CairoVulnType.SIGNATURE_REPLAY: {
        "patterns": [
            # Account abstraction __execute__ / is_valid_signature missing nonce
            r"fn\s+is_valid_signature\s*\([^)]*\)(?!.*nonce)",
            r"fn\s+__execute__\s*\([^)]*\)(?!.*nonce)",
        ],
        "severity": "High",
        "title": "Account abstraction without nonce in signature scope",
        "description": (
            "Account contracts that validate signatures without binding a nonce "
            "(or chain_id) allow replay across transactions / networks. The "
            "Braavos account incident (2023) highlighted the criticality of "
            "nonce-bound signature validation."
        ),
        "recommendation": (
            "Include the current nonce and chain_id in the hashed payload before "
            "calling `is_valid_signature`. Enforce monotonicity of nonce storage."
        ),
    },
}


# =============================================================================
# Analyzer
# =============================================================================


class CairoAnalyzer:
    """Static analyzer for Cairo/Starknet smart contracts."""

    name = "miesc-cairo"
    description = "Cairo/Starknet static analyzer"
    version = "1.1.0"

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
        """Run all patterns against code (block-level, not line-by-line).

        Scanning across line boundaries is necessary because many Cairo
        patterns span multiple lines — e.g. `#[external]` followed by
        `fn foo(...)` on the next line. The previous line-by-line
        implementation silently missed those matches.
        """
        findings: List[CairoFinding] = []
        lines = code.split("\n")
        # Precompute cumulative line offsets so we can map match.start() -> line number.
        line_starts = [0]
        for line in lines:
            line_starts.append(line_starts[-1] + len(line) + 1)  # +1 for the newline

        def _line_from_offset(offset: int) -> int:
            # Binary search could be cleaner but N is small (hundreds of lines max).
            for i in range(len(line_starts) - 1):
                if line_starts[i] <= offset < line_starts[i + 1]:
                    return i + 1  # 1-indexed
            return len(lines)

        for vuln_type, cfg in CAIRO_PATTERNS.items():
            matched = False
            for pattern in cfg["patterns"]:
                if matched:
                    break  # One finding per vuln type per scan
                try:
                    # re.DOTALL lets `.` span newlines; `\s` already does.
                    m = re.search(pattern, code, re.DOTALL)
                except re.error:
                    # Defensive: a malformed pattern should not break the whole scan
                    continue
                if m:
                    line_num = _line_from_offset(m.start())
                    func = self._extract_function(lines, line_num)
                    findings.append(
                        CairoFinding(
                            vuln_type=vuln_type,
                            severity=cfg["severity"],
                            title=cfg["title"],
                            description=cfg["description"],
                            line=line_num,
                            function=func,
                            recommendation=cfg["recommendation"],
                        )
                    )
                    matched = True

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
