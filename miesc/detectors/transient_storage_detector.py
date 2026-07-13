#!/usr/bin/env python3
"""
Detector for EIP-1153 transient storage reentrancy hazards.

The detector is intentionally static and conservative: it flags functions that
mix transient storage (`tstore`, `tload`, or Solidity `transient` state syntax)
with external-call patterns, with higher severity for low-gas transfer/send
flows where TSTORE breaks the old "2300 gas prevents storage writes" assumption.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .detector_api import BaseDetector, Category, Finding, Severity

REFERENCES = [
    "https://eips.ethereum.org/EIPS/eip-1153",
    "https://www.chainsecurity.com/blog/tstore-low-gas-reentrancy",
    "https://dedaub.com/blog/transient-storage-in-the-wild-an-impact-study-on-eip-1153/",
    "https://www.soliditylang.org/blog/2024/10/09/solidity-0.8.28-release-announcement/",
]

_TRANSIENT_RE = re.compile(r"\b(?:tstore|tload)\s*\(|\btransient\b", re.IGNORECASE)
_TRANSIENT_VAR_DECL_RE = re.compile(
    r"\b(?:bool|u?int(?:\d+)?|address|bytes(?:\d+)?|bytes32)\s+transient\s+([A-Za-z_]\w*)",
    re.IGNORECASE,
)
_TSTORE_SET_RE = re.compile(r"\btstore\s*\([^,]+,\s*(?:1|true|0x0*1)\s*\)", re.IGNORECASE)
_TSTORE_CLEAR_RE = re.compile(r"\btstore\s*\([^,]+,\s*(?:0|false|0x0+)\s*\)", re.IGNORECASE)
_TRANSIENT_KEYWORD_CLEAR_RE = re.compile(
    r"\bdelete\s+\w+|\b\w+\s*=\s*(?:false|0)\s*;", re.IGNORECASE
)
_LOW_GAS_RE = re.compile(
    r"\.(?:transfer|send)\s*\(|\bgas\s*:\s*2300\b|\bcall\s*\([^;{)]*,\s*2300\s*,",
    re.IGNORECASE,
)
_EXTERNAL_CALL_RE = re.compile(
    r"\.(?:call|delegatecall|staticcall)\s*(?:\{|let|\()|"
    r"\.(?:transfer|send)\s*\(|"
    r"\bcall\s*\(",
    re.IGNORECASE,
)
_FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_]\w*)?\b|constructor\s*\(")


@dataclass(frozen=True)
class _FunctionSlice:
    start: int
    end: int
    line: int
    name: str
    body: str


class TransientStorageDetector(BaseDetector):
    """Detect transient storage patterns that can change reentrancy assumptions."""

    name = "transient-storage-detector"
    description = "Detects EIP-1153 transient storage reentrancy hazards"
    category = Category.REENTRANCY
    default_severity = Severity.MEDIUM

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        """Analyze Solidity source for transient storage plus external-call hazards."""
        if not isinstance(source_code, str) or not source_code.strip():
            return []

        masked = _mask_comments_and_strings(source_code)
        if not _TRANSIENT_RE.search(masked):
            return []

        transient_vars = {
            match.group(1)
            for match in _TRANSIENT_VAR_DECL_RE.finditer(masked)
            if isinstance(match.group(1), str)
        }
        findings: List[Finding] = []
        for function in _extract_functions(source_code, masked):
            uses_transient_var = _uses_transient_variable(function.body, transient_vars)
            if not _TRANSIENT_RE.search(function.body) and not uses_transient_var:
                continue

            finding = self._analyze_function(function, source_code, uses_transient_var)
            if finding is not None:
                findings.append(finding)

        return findings

    def _analyze_function(
        self,
        function: _FunctionSlice,
        source_code: str,
        uses_transient_var: bool,
    ) -> Optional[Finding]:
        has_external_call = bool(_EXTERNAL_CALL_RE.search(function.body))
        has_low_gas_call = bool(_LOW_GAS_RE.search(function.body))
        has_lock_set = bool(
            _TSTORE_SET_RE.search(function.body)
            or "transient" in function.body
            or (uses_transient_var and re.search(r"\b\w+\s*=\s*(?:true|1)\s*;", function.body))
        )
        has_clear = bool(
            _TSTORE_CLEAR_RE.search(function.body)
            or (
                ("transient" in function.body or uses_transient_var)
                and _TRANSIENT_KEYWORD_CLEAR_RE.search(function.body)
            )
        )

        if not has_external_call:
            return self.create_finding(
                title="Transient Storage Requires Same-Transaction Review",
                description=(
                    "Transient storage is used in a function. Review whether same-transaction "
                    "lifetime and re-entry across frames are intended."
                ),
                severity=Severity.LOW,
                line=function.line,
                code_snippet=_first_matching_line(source_code, function.start, _TRANSIENT_RE),
                recommendation=(
                    "Use transient storage only for explicitly transaction-scoped state. Clear "
                    "lock-like slots before returning unless later calls in the transaction need them."
                ),
                references=REFERENCES,
                confidence="medium",
                metadata={"pattern": "transient-storage-review", "function": function.name},
            )

        if has_low_gas_call:
            return self.create_finding(
                title="Transient Storage Low-Gas Reentrancy",
                description=(
                    "Transient storage is combined with transfer/send or an explicit 2300 gas "
                    "call. EIP-1153 allows TSTORE under the stipend where SSTORE would fail, "
                    "so low-gas call assumptions no longer rule out re-entry state changes."
                ),
                severity=Severity.HIGH,
                line=function.line,
                code_snippet=_first_matching_line(source_code, function.start, _LOW_GAS_RE),
                recommendation=(
                    "Do not rely on transfer/send as a reentrancy boundary. Use explicit "
                    "checks-effects-interactions and a reentrancy guard that is cleared before return."
                ),
                references=REFERENCES,
                confidence="high",
                metadata={"pattern": "transient-low-gas-reentrancy", "function": function.name},
            )

        if has_lock_set and not has_clear:
            return self.create_finding(
                title="Transient Storage Lock Not Cleared",
                description=(
                    "A transient lock-like value is set in a function that performs an external "
                    "call, but this function does not visibly clear it before returning."
                ),
                severity=Severity.MEDIUM,
                line=function.line,
                code_snippet=_first_matching_line(source_code, function.start, _TRANSIENT_RE),
                recommendation=(
                    "Clear lock-like transient slots before the function returns, or document why "
                    "the nonzero value must intentionally remain visible to later same-transaction calls."
                ),
                references=REFERENCES,
                confidence="medium",
                metadata={"pattern": "transient-lock-not-cleared", "function": function.name},
            )

        return self.create_finding(
            title="Transient Storage With External Call",
            description=(
                "Transient storage and an external call appear in the same function. This needs "
                "manual review because transient storage is shared across frames in a transaction."
            ),
            severity=Severity.MEDIUM,
            line=function.line,
            code_snippet=_first_matching_line(source_code, function.start, _EXTERNAL_CALL_RE),
            recommendation=(
                "Verify same-transaction state cannot be manipulated during callbacks. Prefer "
                "checks-effects-interactions and explicit guard cleanup."
            ),
            references=REFERENCES,
            confidence="medium",
            metadata={"pattern": "transient-external-call-review", "function": function.name},
        )


def detect_transient_storage_risks(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[Finding]:
    """Convenience wrapper for callers that do not need detector configuration."""
    return TransientStorageDetector().analyze(source_code, file_path)


def _mask_comments_and_strings(source: str) -> str:
    """Replace comments and string contents with spaces while preserving indexes."""
    result = list(source)
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        next_char = source[index + 1] if index + 1 < length else ""

        if char == "/" and next_char == "/":
            end = source.find("\n", index)
            if end == -1:
                end = length
            _blank_range(result, index, end)
            index = end
            continue

        if char == "/" and next_char == "*":
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            _blank_range(result, index, end)
            index = end
            continue

        if char in {'"', "'"}:
            quote = char
            start = index
            index += 1
            while index < length:
                if source[index] == "\\":
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            _blank_range(result, start, index)
            continue

        index += 1

    return "".join(result)


def _blank_range(chars: list[str], start: int, end: int) -> None:
    for position in range(start, min(end, len(chars))):
        if chars[position] != "\n":
            chars[position] = " "


def _extract_functions(source: str, masked: str) -> List[_FunctionSlice]:
    functions: List[_FunctionSlice] = []
    for match in _FUNCTION_RE.finditer(masked):
        brace = masked.find("{", match.end())
        if brace == -1:
            continue
        end = _find_matching_brace(masked, brace)
        if end == -1:
            continue

        name = match.groupdict().get("name") or "constructor"
        body = masked[match.start() : end + 1]
        functions.append(
            _FunctionSlice(
                start=match.start(),
                end=end + 1,
                line=source[: match.start()].count("\n") + 1,
                name=name,
                body=body,
            )
        )
    return functions


def _find_matching_brace(source: str, start: int) -> int:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _uses_transient_variable(body: str, transient_vars: set[str]) -> bool:
    return any(re.search(rf"\b{re.escape(name)}\b", body) for name in transient_vars)


def _first_matching_line(source_code: str, absolute_start: int, pattern: re.Pattern[str]) -> str:
    for line in source_code[absolute_start:].splitlines():
        if pattern.search(line):
            return line.strip()
    return source_code[absolute_start:].splitlines()[0].strip()
