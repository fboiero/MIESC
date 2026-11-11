"""
PolkaVM / pallet-revive "difference-with-EVM" adapter.

Source-level analyzer for Solidity contracts destined for PolkaVM (compiled with
``resolc`` and run on ``pallet-revive`` / Asset Hub, NOT the EVM). It flags the
class (B) *silent runtime differences* documented in the revive compiler book
("Differences to EVM"): code that compiles and is correct on the EVM but is
insecure or behaves differently on PolkaVM.

It deliberately does NOT re-flag class (A) differences (``EXTCODECOPY``, ``PC``,
``BLOBHASH`` ...) — ``resolc`` rejects those at compile time, so they are the
compiler's job, not ours.

This is a built-in pattern/source-level adapter (no external binary), the
correlation pair for the optional external PolkaGuard tool. It implements the
MIESC ``ToolAdapter`` protocol and returns the standard
``status``/``findings`` result shape.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from miesc.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)


# ---------------------------------------------------------------------------
# Comment/string-aware blanking (keeps line & column layout intact)
# ---------------------------------------------------------------------------
def blank_comments_and_strings(source: str) -> str:
    """Return ``source`` with comment and string *contents* replaced by spaces.

    Newlines are preserved, so line numbers and columns of the returned text
    match the original exactly. This lets the regex rules match real code tokens
    without tripping on the same words appearing inside the explanatory comments
    or string literals of a contract.
    """
    out: List[str] = []
    i = 0
    n = len(source)
    state = "code"  # code | line_comment | block_comment | string
    quote = ""
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                out.append("  ")
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out.append("  ")
                i += 2
                state = "block_comment"
                continue
            if ch == '"' or ch == "'":
                quote = ch
                out.append(" ")  # blank the opening quote
                i += 1
                state = "string"
                continue
            out.append(ch)
            i += 1
        elif state == "line_comment":
            if ch == "\n":
                out.append("\n")
                state = "code"
            else:
                out.append(" ")
            i += 1
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                out.append("  ")
                i += 2
                state = "code"
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif state == "string":
            if ch == "\\" and nxt:
                out.append("  ")
                i += 2
                continue
            if ch == quote:
                out.append(" ")  # blank the closing quote
                i += 1
                state = "code"
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
    return "".join(out)


_FUNC_RE = re.compile(r"\b(?:function\s+([A-Za-z_]\w*)|(constructor)\b)")


def enclosing_function(code_lines: List[str], line_index: int) -> str:
    """Nearest ``function <name>`` / ``constructor`` at or above ``line_index``."""
    for i in range(line_index, -1, -1):
        m = _FUNC_RE.search(code_lines[i])
        if m:
            return m.group(1) or m.group(2) or ""
    return ""


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    """A single PolkaVM difference-with-EVM check."""

    check: str
    severity: str
    message: str
    recommendation: str
    confidence: float = 0.75
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    # finder(blank_code, raw_lines, blank_lines) -> list of (line_index0, snippet)
    finder: Callable[[str, List[str], List[str]], List[Tuple[int, str]]] = field(
        default=lambda b, r, bl: []
    )


# --- per-rule finders -------------------------------------------------------
_CALL_RE = re.compile(r"\.(?:call|delegatecall)\s*(\{[^}]*\})?\s*\(")
_NEW_MEM_RE = re.compile(r"\bnew\s+(?:bytes|string|[A-Za-z_]\w*\s*\[\s*\])\s*\(\s*([^)]*?)\s*\)")
_CREATE2_RE = re.compile(r"\.creationCode\b|\bnew\s+[A-Za-z_]\w*\s*\{[^}]*\bsalt\s*:")
_RANDOM_RE = re.compile(r"\bblock\.(?:prevrandao|difficulty)\b")
_SELFDESTRUCT_RE = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")
_INHERIT_RE = re.compile(r"\bcontract\s+[A-Za-z_]\w*\s+is\b")
_CTOR_RE = re.compile(r"\bconstructor\b")
_STATE_INIT_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\b[^;=]*=\s*[^;]+;"
)


def _line_matches(blank_lines: List[str], raw_lines: List[str], regex: re.Pattern) -> List[
    Tuple[int, str]
]:
    hits: List[Tuple[int, str]] = []
    for idx, bline in enumerate(blank_lines):
        if regex.search(bline):
            hits.append((idx, raw_lines[idx].strip()))
    return hits


def _find_unlimited_gas(blank: str, raw_lines: List[str], blank_lines: List[str]):
    hits: List[Tuple[int, str]] = []
    for idx, bline in enumerate(blank_lines):
        for m in _CALL_RE.finditer(bline):
            opts = m.group(1) or ""
            if "gas:" in opts:
                continue  # an explicit gas cap is present
            hits.append((idx, raw_lines[idx].strip()))
            break
    return hits


def _find_unbounded_memory(blank: str, raw_lines: List[str], blank_lines: List[str]):
    hits: List[Tuple[int, str]] = []
    for idx, bline in enumerate(blank_lines):
        for m in _NEW_MEM_RE.finditer(bline):
            size = (m.group(1) or "").strip()
            # a pure numeric literal is bounded → skip
            if re.fullmatch(r"\d+", size):
                continue
            hits.append((idx, raw_lines[idx].strip()))
            break
    return hits


def _find_constructor_order(blank: str, raw_lines: List[str], blank_lines: List[str]):
    # Heuristic (lower confidence): inheritance + a constructor + an inline-
    # initialized state var → via-ir base/derived init order on PolkaVM may
    # differ from legacy EVM. Reported once, at the constructor line.
    if not _INHERIT_RE.search(blank):
        return []
    if not any(_STATE_INIT_RE.search(bl) for bl in blank_lines):
        return []
    for idx, bline in enumerate(blank_lines):
        if _CTOR_RE.search(bline):
            return [(idx, raw_lines[idx].strip())]
    return []


RULES: List[Rule] = [
    Rule(
        check="polkavm-unlimited-gas-call",
        severity="High",
        message="External low-level call forwards all gas; PolkaVM does not apply the "
        "63/64 gas rule, so this is a DoS vector when calling an untrusted contract.",
        recommendation="Cap the forwarded gas explicitly (e.g. target.call{gas: N}(data)) "
        "when calling untrusted contracts.",
        confidence=0.7,
        cwe_id="CWE-400",
        owasp_category="SC05:2025-Denial-of-Service",
        finder=_find_unlimited_gas,
    ),
    Rule(
        check="polkavm-unbounded-memory",
        severity="Medium",
        message="Unbounded, caller-controlled memory allocation; PolkaVM memory is a fixed "
        "128kb buffer and overflowing it traps the contract at runtime (OutOfBound).",
        recommendation="Bound the allocation size with a validated maximum.",
        confidence=0.65,
        cwe_id="CWE-400",
        finder=_find_unbounded_memory,
    ),
    Rule(
        check="polkavm-create2-address-assumption",
        severity="Medium",
        message="CREATE2 / creationCode address precomputation; on PolkaVM addresses derive "
        "from the code hash and creationCode returns a keccak256 hash, so EVM-style "
        "precomputation does not hold.",
        recommendation="Do not rely on EVM CREATE2 address derivation for PolkaVM deployments; "
        "read the deployed address from the deployment result.",
        confidence=0.6,
        cwe_id="CWE-668",
        finder=lambda b, r, bl: _line_matches(bl, r, _CREATE2_RE),
    ),
    Rule(
        check="polkavm-predictable-prevrandao",
        severity="High",
        message="Randomness derived from block.prevrandao/difficulty; on PolkaVM these "
        "translate to a constant, so the result is fully predictable.",
        recommendation="Use a verifiable randomness source (e.g. a VRF) instead of block "
        "randomness on PolkaVM.",
        confidence=0.8,
        cwe_id="CWE-330",
        owasp_category="SC06:2025-Bad-Randomness",
        finder=lambda b, r, bl: _line_matches(bl, r, _RANDOM_RE),
    ),
    Rule(
        check="polkavm-constructor-init-order",
        severity="Medium",
        message="Inheritance with an inline-initialized state variable and a constructor; "
        "under via-ir (how resolc compiles) base constructors run before derived "
        "state-variable initializers, so init-order-dependent values differ from EVM.",
        recommendation="Do not rely on derived state-variable initializers being set during a "
        "base constructor; initialize explicitly inside the constructor body.",
        confidence=0.4,
        cwe_id="CWE-665",
        finder=_find_constructor_order,
    ),
    Rule(
        check="polkavm-selfdestruct-semantics",
        severity="Low",
        message="Use of selfdestruct; it compiles under resolc but its semantics on "
        "pallet-revive differ from the EVM (portability/semantic risk).",
        recommendation="Avoid selfdestruct on PolkaVM; use an explicit disable/withdraw pattern.",
        confidence=0.7,
        cwe_id="CWE-710",
        finder=lambda b, r, bl: _line_matches(bl, r, _SELFDESTRUCT_RE),
    ),
]


class PolkaVMDiffAdapter(ToolAdapter):
    """Flags PolkaVM/pallet-revive differences in Solidity source (built-in)."""

    NAME = "polkavm_diff"
    VERSION = "0.1.0"

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.NAME,
            version=self.VERSION,
            category=ToolCategory.STATIC_ANALYSIS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC/blob/main/docs/MULTICHAIN.md",
            installation_cmd="pip install -e .  # built-in, no external binary",
            capabilities=[
                ToolCapability(
                    name="polkavm_difference_detection",
                    description="PolkaVM/pallet-revive difference-with-EVM checks (class B, "
                    "silent runtime differences) on Solidity source compiled via resolc.",
                    supported_languages=["solidity"],
                    detection_types=[rule.check for rule in RULES],
                )
            ],
            is_optional=True,
            requires_llm=False,
        )

    def is_available(self) -> ToolStatus:
        # Built-in pattern analyzer — always available, no external binary.
        return ToolStatus.AVAILABLE

    def can_analyze(self, contract_path: str) -> bool:
        return contract_path.endswith(".sol")

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        start = time.time()
        path = Path(contract_path)
        if not path.is_file():
            return self.create_result(
                status="error",
                error=f"File not found: {contract_path}",
                execution_time=time.time() - start,
            )
        try:
            source = path.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            return self.create_result(
                status="error",
                error=f"Could not read {contract_path}: {exc}",
                execution_time=time.time() - start,
            )
        try:
            findings = self._run_rules(source, str(path))
        except Exception as exc:  # noqa: BLE001 — honest error, never success-with-0
            return self.create_result(
                status="error",
                error=f"PolkaVM-diff analysis failed: {exc}",
                execution_time=time.time() - start,
            )
        return self.create_result(
            status="success",
            findings=findings,
            execution_time=time.time() - start,
            metadata={"checks": [rule.check for rule in RULES], "target": "polkavm"},
        )

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Accepts a (source, file_path) tuple and returns normalized findings."""
        if isinstance(raw_output, tuple) and len(raw_output) == 2:
            source, file_path = raw_output
            return self._run_rules(source, file_path)
        if isinstance(raw_output, str):
            return self._run_rules(raw_output, "")
        return []

    def _run_rules(self, source: str, file_path: str) -> List[Dict[str, Any]]:
        blank = blank_comments_and_strings(source)
        blank_lines = blank.splitlines()
        raw_lines = source.splitlines()
        # keep both lists the same length
        while len(raw_lines) < len(blank_lines):
            raw_lines.append("")
        findings: List[Dict[str, Any]] = []
        counter = 0
        for rule in RULES:
            for line_idx, snippet in rule.finder(blank, raw_lines, blank_lines):
                counter += 1
                func = enclosing_function(blank_lines, line_idx)
                finding = self.create_finding(
                    finding_id=f"{rule.check}-{counter}",
                    finding_type=rule.check,
                    severity=rule.severity,
                    message=rule.message,
                    file_path=file_path,
                    line=line_idx + 1,
                    function=func,
                    confidence=rule.confidence,
                    description=rule.message,
                    recommendation=rule.recommendation,
                    cwe_id=rule.cwe_id,
                )
                finding["owasp_category"] = rule.owasp_category
                finding["canonical_category"] = rule.check
                finding["snippet"] = snippet
                finding["tool"] = self.NAME
                findings.append(finding)
        return findings
