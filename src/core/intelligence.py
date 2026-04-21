"""
MIESC Intelligence Engine — post-detection analysis for precision + recall.

Six capabilities, all DPGA-compatible (100% local, no API keys):

  1. Cross-tool confirmation scoring
  2. Semantic deduplication via canonical taxonomy
  3. Pattern detectors for 0%-recall categories
  4. Context-aware false positive suppression
  5. LLM↔static cross-validation tagging
  6. Severity calibration across tools

Entry point: `enhance_findings(findings, source_code)` — takes raw
findings from all tools and returns a refined list with boosted confidence,
merged duplicates, suppressed FPs, and calibrated severity.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.core.finding_taxonomy import CanonicalCategory, normalize_finding_type


# =============================================================================
# 1. Cross-tool confirmation scoring
# =============================================================================

TOOL_WEIGHT = {
    "slither": 0.85,
    "aderyn": 0.75,
    "mythril": 0.90,
    "halmos": 0.90,
    "echidna": 0.85,
    "solhint": 0.40,
    "smartllm": 0.70,
    "gptscan": 0.65,
    "iaudit": 0.60,
    "gptlens": 0.60,
    "llamaaudit": 0.55,
    "llmbugscanner": 0.55,
    "classic-pattern-detector": 0.50,
    "defi-pattern-detector": 0.60,
}


def compute_cross_tool_confidence(
    tools_confirming: List[str],
    base_confidence: float = 0.5,
) -> float:
    """
    Bayesian-inspired confidence boost when multiple tools agree.

    Single tool at weight 0.85 → confidence ~0.60.
    Two tools (0.85 + 0.75) → confidence ~0.85.
    Three tools → confidence ~0.95.
    """
    if not tools_confirming:
        return base_confidence

    weights = [TOOL_WEIGHT.get(t, 0.50) for t in tools_confirming]
    combined = 1.0
    for w in weights:
        combined *= (1.0 - w)
    posterior = 1.0 - combined
    return min(round(posterior, 3), 0.99)


# =============================================================================
# 2. Semantic deduplication via taxonomy
# =============================================================================


@dataclass
class MergedFinding:
    """A finding produced by merging duplicates across tools."""

    canonical_category: str
    representative: Dict[str, Any]
    confirming_tools: List[str] = field(default_factory=list)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.5
    calibrated_severity: str = "Medium"
    is_fp_suppressed: bool = False
    fp_suppression_reason: Optional[str] = None
    cross_validated_by_llm: bool = False
    cross_validated_by_static: bool = False


def semantic_dedup(findings: List[Dict[str, Any]]) -> List[MergedFinding]:
    """
    Group findings by canonical category + function (± 15 lines).

    Returns MergedFinding objects with tool confirmations.
    """
    groups: Dict[str, MergedFinding] = {}

    for f in findings:
        canonical = normalize_finding_type(f)
        if canonical is None:
            canonical = CanonicalCategory.OTHER

        loc = f.get("location", {})
        if isinstance(loc, dict):
            func = loc.get("function", "unknown")
            line = loc.get("line", 0) or 0
        else:
            func = "unknown"
            line = 0

        file_path = loc.get("file", "") if isinstance(loc, dict) else ""
        line_bucket = (line // 15) * 15
        key = f"{canonical.value}:{file_path}:{func}:{line_bucket}"

        tool = f.get("tool", "unknown")

        if key not in groups:
            groups[key] = MergedFinding(
                canonical_category=canonical.value,
                representative=f,
                confirming_tools=[tool],
                all_findings=[f],
            )
        else:
            groups[key].confirming_tools.append(tool)
            groups[key].all_findings.append(f)
            # Keep the finding with highest severity as representative
            if _severity_rank(f.get("severity", "")) > _severity_rank(
                groups[key].representative.get("severity", "")
            ):
                groups[key].representative = f

    return list(groups.values())


# =============================================================================
# 3. Pattern detectors for 0%-recall categories
# =============================================================================

ZERO_RECALL_PATTERNS = {
    "time_manipulation": {
        "patterns": [
            r"\bblock\.timestamp\b",
            r"\bnow\b(?!.*SafeMath)",
            r"\bblock\.number\b.*(?:random|seed|lottery)",
        ],
        "severity": "Medium",
        "swc": "SWC-116",
        "message": "Block timestamp/number used — manipulable by miners (±15 seconds).",
    },
    "bad_randomness": {
        "patterns": [
            r"\bblockhash\s*\(",
            r"\bblock\.difficulty\b",
            r"\bblock\.prevrandao\b",
            r"keccak256\s*\(.*block\.",
            r"uint256\s*\(.*keccak.*block",
        ],
        "severity": "High",
        "swc": "SWC-120",
        "message": "On-chain randomness source is predictable — use Chainlink VRF or commit-reveal.",
    },
    "arithmetic_pre08": {
        "patterns": [
            r"pragma\s+solidity\s*[\^~]?\s*0\.[4-7]\.",
        ],
        "severity": "High",
        "swc": "SWC-101",
        "message": "Solidity <0.8 without SafeMath — integer overflow/underflow possible.",
        "requires_no_safemath": True,
    },
    "front_running": {
        "patterns": [
            r"\.approve\s*\(",
            r"function\s+approve\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-114",
        "message": "Approval pattern susceptible to front-running race condition. Consider increaseAllowance/decreaseAllowance.",
        "requires_no_safe_approve": True,
    },
}


def detect_zero_recall_categories(
    source_code: str,
) -> List[Dict[str, Any]]:
    """Detect vulnerabilities in the 5 categories that currently show 0% recall."""
    findings = []
    code_lower = source_code.lower()
    has_safemath = "safemath" in code_lower or "using safemath" in code_lower
    has_safe_approve = "increaseallowance" in code_lower or "safeapprove" in code_lower

    for category, cfg in ZERO_RECALL_PATTERNS.items():
        if cfg.get("requires_no_safemath") and has_safemath:
            continue
        if cfg.get("requires_no_safe_approve") and has_safe_approve:
            continue

        for pattern in cfg["patterns"]:
            for i, line in enumerate(source_code.split("\n"), 1):
                if re.search(pattern, line):
                    findings.append({
                        "type": category,
                        "severity": cfg["severity"],
                        "swc_id": cfg.get("swc"),
                        "tool": "miesc-intelligence",
                        "confidence": 0.65,
                        "location": {"file": "", "line": i, "function": "unknown"},
                        "message": cfg["message"],
                        "description": cfg["message"],
                        "recommendation": cfg["message"],
                    })
                    break  # One per category
    return findings


# =============================================================================
# 4. Context-aware FP suppression
# =============================================================================

_ADMIN_MODIFIERS = re.compile(
    r"\bonlyOwner\b|\bonlyRole\b|\bonlyAdmin\b|\brequire\s*\(\s*msg\.sender\s*==\s*owner",
    re.IGNORECASE,
)
_TEST_FILE = re.compile(r"test[_/]|mock[_/]|\.t\.sol$|Test\.sol$", re.IGNORECASE)
_OZ_IMPORT = re.compile(r"@openzeppelin|import.*openzeppelin|import.*solmate", re.IGNORECASE)


def context_aware_fp_check(
    finding: Dict[str, Any],
    source_code: str,
    file_path: str = "",
) -> Tuple[bool, Optional[str]]:
    """
    Check if a finding is likely a false positive based on context.

    Returns:
        (is_likely_fp, reason) — True means suppress.
    """
    canonical = normalize_finding_type(finding)
    loc = finding.get("location", {})
    func_name = loc.get("function", "") if isinstance(loc, dict) else ""

    # Rule 1: access-control findings on functions with admin modifiers → FP
    if canonical == CanonicalCategory.ACCESS_CONTROL and func_name:
        func_pattern = re.compile(
            rf"function\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*\{{",
            re.DOTALL,
        )
        match = func_pattern.search(source_code)
        if match:
            # Check the function signature + first 200 chars of body for admin modifiers
            context = source_code[match.start():match.start() + 500]
            if _ADMIN_MODIFIERS.search(context):
                return True, f"Function {func_name} has admin modifier"

    # Rule 2: findings in test/mock files → FP
    if file_path and _TEST_FILE.search(file_path):
        return True, f"Finding in test/mock file: {file_path}"

    # Rule 3: arithmetic overflow on Solidity 0.8+ → FP (built-in protection)
    if canonical == CanonicalCategory.ARITHMETIC:
        version_match = re.search(r"pragma\s+solidity\s*[\^>=]*\s*(\d+)\.(\d+)", source_code)
        if version_match:
            major, minor = int(version_match.group(1)), int(version_match.group(2))
            if major > 0 or minor >= 8:
                return True, "Arithmetic overflow impossible in Solidity >= 0.8"

    # Rule 4: OpenZeppelin-imported contract with reentrancy finding
    # AND the function has nonReentrant modifier → FP
    if canonical == CanonicalCategory.REENTRANCY and _OZ_IMPORT.search(source_code):
        if func_name:
            func_context = _get_function_context(source_code, func_name)
            if "nonReentrant" in func_context or "nonreentrant" in func_context.lower():
                return True, f"Function {func_name} has nonReentrant guard (OpenZeppelin)"

    return False, None


def _get_function_context(source_code: str, func_name: str, chars: int = 500) -> str:
    match = re.search(rf"function\s+{re.escape(func_name)}", source_code)
    if match:
        return source_code[match.start():match.start() + chars]
    return ""


# =============================================================================
# 5. LLM↔static cross-validation tagging
# =============================================================================

STATIC_TOOLS = {"slither", "aderyn", "solhint", "mythril", "halmos", "echidna",
                "semgrep", "wake", "foundry", "solcmc"}
LLM_TOOLS = {"smartllm", "gptscan", "iaudit", "gptlens", "llamaaudit",
             "llmbugscanner", "audit_consensus"}


def tag_cross_validation(merged: MergedFinding) -> None:
    """Tag whether a merged finding is confirmed by both static AND LLM tools."""
    tools = set(merged.confirming_tools)
    merged.cross_validated_by_static = bool(tools & STATIC_TOOLS)
    merged.cross_validated_by_llm = bool(tools & LLM_TOOLS)

    if merged.cross_validated_by_static and merged.cross_validated_by_llm:
        merged.confidence = min(merged.confidence + 0.15, 0.99)


# =============================================================================
# 6. Severity calibration across tools
# =============================================================================

SEVERITY_CALIBRATION = {
    ("aderyn", "Low"): "Medium",
    ("aderyn", "Info"): "Low",
    ("solhint", "error"): "Medium",
    ("solhint", "warning"): "Low",
    ("slither", "Informational"): "Info",
    ("slither", "Optimization"): "Info",
}


def calibrate_severity(finding: Dict[str, Any]) -> str:
    """Return calibrated severity, accounting for tool-specific biases."""
    tool = finding.get("tool", "")
    raw_severity = finding.get("severity", "Medium")

    calibrated = SEVERITY_CALIBRATION.get((tool, raw_severity))
    if calibrated:
        return calibrated

    severity_map = {
        "critical": "Critical", "high": "High", "medium": "Medium",
        "low": "Low", "info": "Info", "informational": "Info",
        "optimization": "Info", "warning": "Low", "error": "Medium",
    }
    return severity_map.get(raw_severity.lower(), raw_severity)


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
        severity.lower(), 0
    )


# =============================================================================
# Main entry point
# =============================================================================


def enhance_findings(
    findings: List[Dict[str, Any]],
    source_code: str = "",
    file_path: str = "",
) -> List[Dict[str, Any]]:
    """
    Run all 6 intelligence improvements on raw findings.

    Returns a refined findings list with:
      - Duplicates merged (same canonical type + function + line bucket)
      - Confidence boosted by cross-tool agreement
      - FPs suppressed with reason
      - Severity calibrated
      - Cross-validation tags (static + LLM)
      - Additional patterns for 0%-recall categories
    """
    # Step 0: Add pattern-based findings for 0%-recall categories
    if source_code:
        pattern_findings = detect_zero_recall_categories(source_code)
        findings = list(findings) + pattern_findings

    # Step 1+2: Semantic dedup + cross-tool grouping
    merged = semantic_dedup(findings)

    # Step 3-6: Enhance each group
    results = []
    for group in merged:
        # 1. Cross-tool confidence
        group.confidence = compute_cross_tool_confidence(group.confirming_tools)

        # 4. Context-aware FP check
        if source_code:
            is_fp, reason = context_aware_fp_check(
                group.representative, source_code, file_path
            )
            if is_fp:
                group.is_fp_suppressed = True
                group.fp_suppression_reason = reason

        # 5. Cross-validation tagging
        tag_cross_validation(group)

        # 6. Severity calibration
        group.calibrated_severity = calibrate_severity(group.representative)

        # Build output finding
        out = dict(group.representative)
        out["confidence"] = group.confidence
        out["severity"] = group.calibrated_severity
        out["canonical_category"] = group.canonical_category
        out["confirming_tools"] = list(set(group.confirming_tools))
        out["tool_count"] = len(set(group.confirming_tools))
        out["cross_validated_static"] = group.cross_validated_by_static
        out["cross_validated_llm"] = group.cross_validated_by_llm

        if group.is_fp_suppressed:
            out["fp_suppressed"] = True
            out["fp_reason"] = group.fp_suppression_reason
        else:
            out["fp_suppressed"] = False

        results.append(out)

    # Sort: non-suppressed first, then by severity rank, then by confidence
    results.sort(
        key=lambda f: (
            f.get("fp_suppressed", False),
            -_severity_rank(f.get("severity", "")),
            -f.get("confidence", 0),
        )
    )

    return results
