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

A regex cannot know the runtime value of the free-memory pointer, so the memory model is
enforced only where a violation is *structural* — true regardless of what was allocated
before the block. The Solidity memory-safety rules this honors
(https://docs.soliditylang.org/en/latest/assembly.html#memory-safety): temporary use of
memory at or above ``mload(0x40)`` without updating the pointer is safe, scratch space
(``0x00``-``0x3f``) is freely usable, and only the pointer slot (``0x40``) and the zero slot
(``0x60``) carry invariants. The detector therefore does **not** flag writes to a computed
offset, writes at or above ``0x80``, or scratch writes — those are the idioms of audited
libraries (OpenZeppelin ``Clones``, Solady), not violations.

Hazards (each ``yul-*`` so it never collides with Slither's ``assembly`` warning):
  - ``yul-memory-safe-violation``   : a ``memory-safe`` block structurally corrupts the memory
    model — it sets the free pointer (``0x40``) to a literal below ``0x80`` (into the reserved
    region) or writes a non-zero value to the zero slot (``0x60``) without restoring it.
  - ``yul-unbounded-returndatacopy``: ``returndatacopy(dst, 0, returndatasize())`` into a fixed
    offset with no allocation and no terminating ``return``/``revert`` over the copied region.
  - ``yul-arbitrary-sstore``        : ``sstore(slot, _)`` where ``slot`` is attacker-influenced
    (``calldataload`` or an external/public function parameter), not a constant/keccak slot.

References:
  - https://docs.soliditylang.org/en/latest/assembly.html (memory safety)
  - https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-039/ (insecure inline assembly)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set, Tuple

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

# --- H1: structural memory-model corruption -------------------------------------------
# Setting the free-memory pointer (0x40) to a *literal* value. A valid pointer is always
# >= 0x80; a literal below that frees it into the reserved scratch/pointer/zero region.
# It is a violation only when the pointer is then *left* broken — libraries legitimately
# clobber 0x40 as scratch and either restore it or return/revert before falling through.
_FREE_PTR_LITERAL_SET_RE = re.compile(
    r"\bmstore\s*\(\s*0x40\s*,\s*(?P<val>0x[0-9a-fA-F]+|\d+)\s*\)"
)
# Any assignment to the free pointer (literal or expression) — used to detect a restore.
_FREE_PTR_ANY_SET_RE = re.compile(r"\bmstore\s*\(\s*0x40\s*,\s*(?P<val>[^,)]+?)\s*\)")
# A write to the zero slot (0x60), which Solidity requires to stay zero.
_ZERO_SLOT_WRITE_RE = re.compile(r"\bmstore8?\s*\(\s*0x60\s*,\s*(?P<val>[^,)]+?)\s*\)")
# A restore of the zero slot back to zero.
_ZERO_SLOT_RESTORE_RE = re.compile(r"\bmstore\s*\(\s*0x60\s*,\s*(?:0x0+|0)\s*\)")

# --- H2: unbounded returndatacopy -----------------------------------------------------
# returndatacopy(dst, 0, returndatasize()) — full copy to dst.
_RDCOPY_FULL_RE = re.compile(
    r"\breturndatacopy\s*\(\s*(?P<dst>[^,]+),\s*0x?0*\s*,\s*returndatasize\s*\(\s*\)\s*\)",
)
_FREE_PTR_WRITE_RE = re.compile(r"\bmstore\s*\(\s*0x40\b")
# A control-flow terminator: after one of these the block's memory no longer matters.
_TERMINATOR_RE = re.compile(r"\b(?:return|revert|stop|selfdestruct|invalid)\s*\(")
# A return/revert and the offset of its first argument (the region it forwards).
_RET_REVERT_REGION_RE = re.compile(r"\b(?:return|revert)\s*\(\s*(?P<off>[^,)\s]+)\s*,")

# --- H3: attacker-influenced sstore slot ----------------------------------------------
_SSTORE_RE = re.compile(r"\bsstore\s*\(\s*(?P<slot>[^,]+),")
# Yul bindings fed from calldata are attacker-influenced.
_CALLDATA_BIND_RE = re.compile(r"\blet\s+(?P<name>[A-Za-z_]\w*)\s*:=\s*calldataload\b")

_LITERAL_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")
# Capture a function's name, params and signature tail (modifiers/visibility/returns).
_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)(?P<tail>[^{;]*)",
)
_PARAM_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:,|$)")
_EXTERNAL_VIS = {"external", "public"}


@dataclass(frozen=True)
class _AssemblyBlock:
    start: int
    body: str
    line: int
    memory_safe: bool
    func_name: str
    params: Set[str]
    visibility: Optional[str]


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

        # H1 — a `memory-safe` block that *structurally* corrupts the memory model.
        # A regex cannot know the runtime pointer, so only two violations are flagged, both
        # unsafe regardless of prior allocation: freeing 0x40 below 0x80, or leaving the zero
        # slot (0x60) non-zero. Temporary use of [mload(0x40), inf), writes >= 0x80 and
        # scratch writes (< 0x40) are memory-safe and are NOT flagged.
        if block.memory_safe:
            violation = _memory_model_violation(body)
            if violation:
                out.append(
                    self.create_finding(
                        title="memory-safe assembly corrupts the memory model",
                        description=(
                            "A block annotated `memory-safe` " + violation + ". The annotation "
                            "promises the Solidity memory model is respected and the compiler "
                            "trusts it for optimizations; this write breaks an invariant the "
                            "model relies on regardless of what memory was allocated before."
                        ),
                        severity=Severity.MEDIUM,
                        line=block.line,
                        code_snippet=_first_line(source_code, block.start, _ASSEMBLY_RE),
                        recommendation=(
                            "Keep the free-memory pointer (0x40) at or above 0x80 and the zero "
                            "slot (0x60) zero, or remove the `memory-safe` annotation if the block "
                            "legitimately manages memory outside the model."
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

        # H2 — unbounded returndatacopy to a fixed offset. Negative checks: the block
        # allocates returndatasize() against the free pointer, OR control flow terminates
        # (return/revert/stop) after the copy — the proxy return-forwarding idiom.
        rd = _RDCOPY_FULL_RE.search(body)
        if rd:
            dst = rd.group("dst").strip()
            allocates = bool(_FREE_PTR_WRITE_RE.search(body)) or "mload(0x40)" in body.replace(
                " ", ""
            )
            # Safe only when a return/revert forwards the *same* region after the copy (the
            # proxy idiom). A terminator over a different offset does not clear the hazard.
            # (A conditional revert over the copied region that the block then survives is a
            # known blind spot of a non-control-flow heuristic.)
            terminates = _forwards_region(body[rd.end() :], dst)
            dst_is_fixed = bool(_LITERAL_RE.match(dst))
            if dst_is_fixed and not allocates and not terminates:
                out.append(
                    self.create_finding(
                        title="Unbounded returndatacopy into fixed memory",
                        description=(
                            "`returndatacopy(dst, 0, returndatasize())` copies the full returndata "
                            "into a fixed memory offset without allocating space against the "
                            "free-memory pointer, and execution continues past the copy. Large "
                            "returndata can overrun adjacent memory."
                        ),
                        severity=Severity.MEDIUM,
                        line=block.line,
                        code_snippet=_first_line(source_code, block.start, _RDCOPY_FULL_RE),
                        recommendation=(
                            "Allocate `returndatasize()` bytes from `mload(0x40)` (and update it) "
                            "before copying, return/revert over the copied region immediately, or "
                            "copy a bounded, checked length."
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

        # H3 — arbitrary sstore with an attacker-influenced slot. The slot must come from
        # calldata, or from a parameter of an external/public function; a parameter of an
        # internal/private/free function is chosen by the contract, not an attacker.
        calldata_vars = {m.group("name") for m in _CALLDATA_BIND_RE.finditer(body)}
        param_tainted = block.params if block.visibility in _EXTERNAL_VIS else set()
        tainted = calldata_vars | param_tainted
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
                            "`sstore` writes to a slot derived from calldata or an external "
                            "function parameter. An attacker-controlled slot can overwrite "
                            "arbitrary storage (owner, balances, implementation pointer)."
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


def _memory_model_violation(body: str) -> Optional[str]:
    """Return a description if ``body`` structurally corrupts the memory model, else None.

    A corruption counts only when the block *leaves* the invariant broken: it neither
    restores the slot afterwards nor terminates (return/revert/stop) before falling through.
    Clobber-then-restore and clobber-then-return are the memory-safe idioms of audited
    libraries and are not flagged.
    """
    for m in _FREE_PTR_LITERAL_SET_RE.finditer(body):
        try:
            if int(m.group("val"), 0) >= 0x80:
                continue
        except ValueError:
            continue
        rest = body[m.end() :]
        if not _restores_free_ptr(rest) and not _TERMINATOR_RE.search(rest):
            return (
                "sets the free-memory pointer (0x40) to a literal below 0x80 and leaves it "
                "there (no restore, no return/revert)"
            )
    for m in _ZERO_SLOT_WRITE_RE.finditer(body):
        if not _is_nonzero_literal(m.group("val")):
            continue
        rest = body[m.end() :]
        if not _ZERO_SLOT_RESTORE_RE.search(rest) and not _TERMINATOR_RE.search(rest):
            return "writes a non-zero value to the zero slot (0x60) and leaves it non-zero"
    return None


def _restores_free_ptr(rest: str) -> bool:
    """True if ``rest`` reassigns 0x40 to a valid pointer (an expression or a literal >= 0x80)."""
    for m in _FREE_PTR_ANY_SET_RE.finditer(rest):
        val = m.group("val").strip()
        if not _LITERAL_RE.match(val):
            return True  # restored to a computed/saved value (e.g. `m`, `add(...)`)
        try:
            if int(val, 0) >= 0x80:
                return True
        except ValueError:
            return True
    return False


def _forwards_region(body_after: str, dst: str) -> bool:
    """True if a ``return``/``revert`` after the copy forwards the same ``dst`` offset."""
    target = _as_offset(dst)
    if target is None:
        return False
    for m in _RET_REVERT_REGION_RE.finditer(body_after):
        if _as_offset(m.group("off")) == target:
            return True
    return False


def _as_offset(token: str) -> Optional[int]:
    """Integer value of a literal memory offset, or None for a non-literal expression."""
    token = token.strip()
    if not _LITERAL_RE.match(token):
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


def _is_nonzero_literal(value: str) -> bool:
    """True only when ``value`` is a numeric literal other than zero (expressions are skipped)."""
    value = value.strip()
    if not _LITERAL_RE.match(value):
        return False
    try:
        return int(value, 0) != 0
    except ValueError:
        return False


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
        func_name, params, visibility = _enclosing_function(functions, match.start())
        blocks.append(
            _AssemblyBlock(
                start=match.start(),
                body=masked[brace : end + 1],
                line=source[: match.start()].count("\n") + 1,
                memory_safe=memory_safe,
                func_name=func_name,
                params=params,
                visibility=visibility,
            )
        )
    return blocks


def _function_spans(masked: str) -> List[Tuple[int, int, str, Set[str], Optional[str]]]:
    """Return (start, end, name, params, visibility) for each function in the masked source."""
    spans: List[Tuple[int, int, str, Set[str], Optional[str]]] = []
    for match in _FUNCTION_RE.finditer(masked):
        brace = masked.find("{", match.end())
        if brace == -1:
            continue
        end = _find_matching_brace(masked, brace)
        if end == -1:
            continue
        params = set(_PARAM_NAME_RE.findall(match.group("params") or ""))
        spans.append(
            (match.start(), end, match.group("name"), params, _visibility(match.group("tail")))
        )
    return spans


def _visibility(tail: Optional[str]) -> Optional[str]:
    """Derive a function's visibility from its signature tail (modifiers/returns)."""
    tail = tail or ""
    for level in ("external", "public", "internal", "private"):
        if re.search(rf"\b{level}\b", tail):
            return level
    return None


def _enclosing_function(
    functions: List[Tuple[int, int, str, Set[str], Optional[str]]], index: int
) -> Tuple[str, Set[str], Optional[str]]:
    """Name, parameter set and visibility of the innermost function containing ``index``."""
    best: Tuple[str, Set[str], Optional[str]] = ("unknown", set(), None)
    best_start = -1
    for start, end, name, params, visibility in functions:
        if start <= index <= end and start > best_start:
            best = (name, params, visibility)
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
