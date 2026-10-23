#!/usr/bin/env python3
"""
Detector for Yul / inline-assembly memory and storage safety hazards.

Phase 1 (deterministic, local) of
``docs/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md``. Slither only emits an
*informational* ``assembly`` warning; this detector models a bounded set of assembly
effects and flags three high-precision hazards. It is intentionally conservative and
**advisory**: a raw ``assembly`` block is never a finding on its own — promotion requires a
concrete unsafe effect anchored to a source line and enclosing function, and every negative
check that proves a fragment bounded/benign suppresses the finding.

Hazards (each ``yul-*`` so it never collides with Slither's ``assembly`` warning):
  - ``yul-memory-safe-violation``   : a ``memory-safe`` annotated block writes memory beyond
    scratch space without managing the free-memory pointer (0x40).
  - ``yul-unbounded-returndatacopy``: ``returndatacopy(dst, 0, returndatasize())`` into a fixed
    offset with no allocation against the free-memory pointer.
  - ``yul-arbitrary-sstore``        : ``sstore(slot, _)`` where ``slot`` is attacker-influenced
    (a function parameter or a ``calldataload`` result), not a constant/keccak-derived slot.

References:
  - https://docs.soliditylang.org/en/latest/assembly.html (memory safety)
  - https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-039/ (insecure inline assembly)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set

from .detector_api import BaseDetector, Category, Finding, Severity

REFERENCES = [
    "https://docs.soliditylang.org/en/latest/assembly.html",
    "https://docs.soliditylang.org/en/latest/yul.html",
    "https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-039/",
]

# A raw ``assembly { ... }`` block, optionally with the ``("memory-safe")`` flag.
_ASSEMBLY_RE = re.compile(r"\bassembly\b\s*(?P<flags>\([^)]*\))?\s*\{")
# Developer promise that the block respects the Solidity memory model.
_MEMSAFE_FLAG_RE = re.compile(r"memory-safe", re.IGNORECASE)
_MEMSAFE_COMMENT_RE = re.compile(r"memory-safe-assembly", re.IGNORECASE)
# Memory-writing opcodes.
_MEM_WRITE_RE = re.compile(
    r"\b(?:mstore8?|calldatacopy|returndatacopy|codecopy|extcodecopy|mcopy)\s*\(",
)
_FREE_PTR_WRITE_RE = re.compile(r"\bmstore\s*\(\s*0x40\b")
# mstore to a scratch-space literal (0x00..0x60) is allowed even in memory-safe blocks.
_SCRATCH_MSTORE_RE = re.compile(r"\bmstore8?\s*\(\s*0x[0-5]?[0-9a-fA-F]\b")
_NON_SCRATCH_MSTORE_RE = re.compile(r"\bmstore8?\s*\(\s*(?P<dst>[^,]+),")
# returndatacopy(dst, 0, returndatasize()) — full copy to dst.
_RDCOPY_FULL_RE = re.compile(
    r"\breturndatacopy\s*\(\s*(?P<dst>[^,]+),\s*0x?0*\s*,\s*returndatasize\s*\(\s*\)\s*\)",
)
_LITERAL_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
# sstore(slot, value) — capture the slot expression.
_SSTORE_RE = re.compile(r"\bsstore\s*\(\s*(?P<slot>[^,]+),")
# Yul bindings fed from calldata are attacker-influenced.
_CALLDATA_BIND_RE = re.compile(r"\blet\s+(?P<name>[A-Za-z_]\w*)\s*:=\s*calldataload\b")
_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)",
)
_PARAM_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:,|$)")


@dataclass(frozen=True)
class _AssemblyBlock:
    start: int
    body: str
    line: int
    memory_safe: bool
    func_name: str
    params: Set[str]


class YulAssemblySafetyDetector(BaseDetector):
    """Flag high-precision Yul/inline-assembly memory and storage hazards (advisory)."""

    name = "yul-assembly-safety-detector"
    description = "Detects memory/storage safety hazards in Yul/inline-assembly blocks"
    category = Category.CUSTOM
    default_severity = Severity.LOW

    def analyze(self, source_code: str, file_path: Optional[Path] = None) -> List[Finding]:
        if not isinstance(source_code, str) or not source_code.strip():
            return []
        masked = _mask_comments_and_strings(source_code)
        if "assembly" not in masked:
            return []

        findings: List[Finding] = []
        for block in _extract_assembly_blocks(source_code, masked):
            findings.extend(self._classify(block, source_code))
        return findings

    def _classify(self, block: _AssemblyBlock, source_code: str) -> List[Finding]:
        out: List[Finding] = []
        body = block.body

        # H1 — memory-safe annotation violated: writes memory beyond scratch without
        # managing the free-memory pointer. Negative checks: pointer is read+restored,
        # or every memory write targets scratch space (0x00..0x60).
        if block.memory_safe and _MEM_WRITE_RE.search(body):
            manages_ptr = bool(_FREE_PTR_WRITE_RE.search(body))
            writes_non_scratch = any(
                not _LITERAL_RE.match(m.group("dst").strip())
                or int(m.group("dst").strip(), 0) > 0x60
                for m in _NON_SCRATCH_MSTORE_RE.finditer(body)
            )
            non_mstore_write = bool(
                re.search(
                    r"\b(?:calldatacopy|returndatacopy|codecopy|extcodecopy|mcopy)\s*\(", body
                )
            )
            if (writes_non_scratch or non_mstore_write) and not manages_ptr:
                out.append(
                    self.create_finding(
                        title="Unsafe memory-safe assembly annotation",
                        description=(
                            "A block annotated `memory-safe` writes memory outside scratch space "
                            "without reading and updating the free-memory pointer at 0x40. The "
                            "annotation promises the Solidity memory model is respected; here it "
                            "may not be, which the compiler trusts for optimizations."
                        ),
                        severity=Severity.MEDIUM,
                        line=block.line,
                        code_snippet=_first_line(source_code, block.start, _MEM_WRITE_RE),
                        recommendation=(
                            "Allocate from `mload(0x40)` and update it, or restrict writes to "
                            "scratch space (0x00-0x60). Remove the `memory-safe` annotation if the "
                            "block legitimately manages memory outside the model."
                        ),
                        references=REFERENCES,
                        confidence="medium",
                        swc_id="SWC-127",
                        metadata={
                            "hazard": "yul-memory-safe-violation",
                            "function": block.func_name,
                        },
                    )
                )

        # H2 — unbounded returndatacopy to a fixed offset. Negative check: the block
        # allocates returndatasize() against the free-memory pointer before copying.
        rd = _RDCOPY_FULL_RE.search(body)
        if rd:
            dst = rd.group("dst").strip()
            allocates = bool(_FREE_PTR_WRITE_RE.search(body)) or "mload(0x40)" in body.replace(
                " ", ""
            )
            dst_is_fixed = bool(_LITERAL_RE.match(dst))
            if dst_is_fixed and not allocates:
                out.append(
                    self.create_finding(
                        title="Unbounded returndatacopy into fixed memory",
                        description=(
                            "`returndatacopy(dst, 0, returndatasize())` copies the full returndata "
                            "into a fixed memory offset without allocating space against the "
                            "free-memory pointer. Large returndata can overrun adjacent memory."
                        ),
                        severity=Severity.MEDIUM,
                        line=block.line,
                        code_snippet=_first_line(source_code, block.start, _RDCOPY_FULL_RE),
                        recommendation=(
                            "Allocate `returndatasize()` bytes from `mload(0x40)` (and update it) "
                            "before copying, or copy a bounded, checked length."
                        ),
                        references=REFERENCES,
                        confidence="medium",
                        swc_id="SWC-127",
                        metadata={
                            "hazard": "yul-unbounded-returndatacopy",
                            "function": block.func_name,
                        },
                    )
                )

        # H3 — arbitrary sstore with an attacker-influenced slot. Negative checks: the slot
        # is a constant literal or derived from keccak256 (a standard mapping/array slot).
        calldata_vars = {m.group("name") for m in _CALLDATA_BIND_RE.finditer(body)}
        tainted = calldata_vars | block.params
        for m in _SSTORE_RE.finditer(body):
            slot = m.group("slot").strip()
            if _LITERAL_RE.match(slot) or "keccak256" in slot or ".slot" in slot:
                continue  # constant or storage-layout-derived slot -> benign
            slot_id = re.match(r"^([A-Za-z_]\w*)$", slot)
            if "calldataload" in slot or (slot_id and slot_id.group(1) in tainted):
                out.append(
                    self.create_finding(
                        title="Attacker-influenced storage slot in assembly",
                        description=(
                            "`sstore` writes to a slot derived from calldata or a function "
                            "parameter. An attacker-controlled slot can overwrite arbitrary "
                            "storage (owner, balances, implementation pointer)."
                        ),
                        severity=Severity.MEDIUM,
                        line=block.line,
                        code_snippet=_first_line(source_code, block.start, _SSTORE_RE),
                        recommendation=(
                            "Compute storage slots from constants or keccak256 of fixed layout "
                            "keys. Never let untrusted input choose the raw slot of an `sstore`."
                        ),
                        references=REFERENCES,
                        confidence="medium",
                        swc_id="SWC-124",
                        metadata={"hazard": "yul-arbitrary-sstore", "function": block.func_name},
                    )
                )
                break  # one finding per block for this hazard is enough

        return out


def detect_yul_assembly_safety(
    source_code: str,
    file_path: Optional[Path] = None,
) -> List[Finding]:
    """Convenience wrapper for callers that do not need detector configuration."""
    return YulAssemblySafetyDetector().analyze(source_code, file_path)


# --------------------------------------------------------------------------------------
# Parsing helpers (self-contained; mirror the conservative style of the sibling
# transient_storage_detector).
# --------------------------------------------------------------------------------------
def _extract_assembly_blocks(source: str, masked: str) -> List[_AssemblyBlock]:
    """Find assembly blocks with source anchor, enclosing function, and memory-safe flag."""
    functions = _function_spans(masked)
    blocks: List[_AssemblyBlock] = []
    for match in _ASSEMBLY_RE.finditer(masked):
        brace = masked.find("{", match.end() - 1)
        if brace == -1:
            continue
        end = _find_matching_brace(masked, brace)
        if end == -1:
            continue
        # The ``("memory-safe")`` flag is a string literal, so it is blanked in ``masked``;
        # read it from the raw source (indexes are preserved by the mask).
        memory_safe = bool(
            _MEMSAFE_FLAG_RE.search(source[match.start() : brace])
        ) or _annotated_above(source, match.start())
        func_name, params = _enclosing_function(functions, match.start())
        blocks.append(
            _AssemblyBlock(
                start=match.start(),
                body=masked[brace : end + 1],
                line=source[: match.start()].count("\n") + 1,
                memory_safe=memory_safe,
                func_name=func_name,
                params=params,
            )
        )
    return blocks


def _function_spans(masked: str) -> List[tuple]:
    """Return (start, end, name, params) for each function body in the masked source."""
    spans: List[tuple] = []
    for match in _FUNCTION_RE.finditer(masked):
        brace = masked.find("{", match.end())
        if brace == -1:
            continue
        end = _find_matching_brace(masked, brace)
        if end == -1:
            continue
        params = set(_PARAM_NAME_RE.findall(match.group("params") or ""))
        spans.append((match.start(), end, match.group("name"), params))
    return spans


def _enclosing_function(functions: List[tuple], index: int) -> tuple:
    """Name and parameter set of the innermost function containing ``index``."""
    best = ("unknown", set())
    best_start = -1
    for start, end, name, params in functions:
        if start <= index <= end and start > best_start:
            best = (name, params)
            best_start = start
    return best


def _annotated_above(source: str, index: int) -> bool:
    """True if a `/// @solidity memory-safe-assembly` comment precedes the block."""
    head = source.rfind("\n", 0, index)
    window_start = source.rfind("\n", 0, head - 1) if head > 0 else 0
    return bool(_MEMSAFE_COMMENT_RE.search(source[max(window_start, 0) : index]))


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
            end = length if end == -1 else end
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


def _blank_range(chars: list, start: int, end: int) -> None:
    for position in range(start, min(end, len(chars))):
        if chars[position] != "\n":
            chars[position] = " "


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


def _first_line(source_code: str, absolute_start: int, pattern: re.Pattern) -> str:
    for line in source_code[absolute_start:].splitlines():
        if pattern.search(line):
            return line.strip()
    tail = source_code[absolute_start:].splitlines()
    return tail[0].strip() if tail else ""
