"""
MIESC Intelligence Engine — post-detection analysis for precision + recall.

Eight capabilities, all DPGA-compatible (100% local, no API keys):

  1. Cross-tool confirmation scoring
  2. Semantic deduplication via canonical taxonomy
  3. Pattern detectors for 0%-recall categories
  4. Context-aware false positive suppression
  5. LLM↔static cross-validation tagging
  6. Severity calibration across tools
  7. Recommendation enrichment from canonical knowledge base
  8. Fix-code generation (Solidity patches per finding)
  9. Exploit scenario generation (step-by-step attack descriptions)

Entry point: `enhance_findings(findings, source_code)` — takes raw
findings from all tools and returns a refined list with boosted confidence,
merged duplicates, suppressed FPs, calibrated severity, fix_code, and
exploit_scenario fields.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
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
    # v5.2.0: Additional patterns for common vulnerability shapes
    "unprotected_selfdestruct": {
        "patterns": [
            r"\bselfdestruct\s*\(",
            r"\bsuicide\s*\(",
        ],
        "severity": "Critical",
        "swc": "SWC-106",
        "message": "selfdestruct/suicide found — if reachable by unauthorized caller, contract can be permanently destroyed.",
    },
    "delegatecall_to_untrusted": {
        "patterns": [
            r"\.delegatecall\s*\(",
        ],
        "severity": "High",
        "swc": "SWC-112",
        "message": "delegatecall to potentially untrusted address — storage layout collision or logic injection risk.",
    },
    "uninitialized_proxy": {
        "patterns": [
            r"function\s+initialize\s*\(",
            r"function\s+__init\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-109",
        "message": "Initializer function detected — verify it cannot be called more than once (use OpenZeppelin's initializer modifier).",
        "requires_no_initializer_guard": True,
    },
    "unchecked_return_value": {
        "patterns": [
            r"\.call\s*\{",
            r"\.call\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-104",
        "message": "Low-level call without explicit success check — use require(success) or SafeERC20.",
    },
    # v5.2.0: More EVM patterns for parity with multi-chain analyzers
    "tx_origin_auth": {
        "patterns": [
            r"\btx\.origin\b",
        ],
        "severity": "High",
        "swc": "SWC-115",
        "message": "tx.origin used for authentication — vulnerable to phishing via intermediate contracts. Use msg.sender instead.",
    },
    "hardcoded_gas": {
        "patterns": [
            r"\.transfer\s*\(",
            r"\.send\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-134",
        "message": "transfer()/send() forwards only 2300 gas — will fail with contract recipients after EIP-1884. Use call{value:}() with reentrancy guard.",
    },
    "missing_event_emission": {
        "patterns": [
            r"function\s+set\w+\s*\([^)]*\)\s*(external|public)[^{]*\{(?!.*emit\b)",
        ],
        "severity": "Low",
        "swc": "SWC-100",
        "message": "State-changing function without event emission — limits off-chain monitoring and indexing.",
    },
    "storage_collision_proxy": {
        "patterns": [
            r"\bstorage\s+slot\b",
            r"assembly\s*\{[^}]*sstore",
            r"assembly\s*\{[^}]*sload",
        ],
        "severity": "Medium",
        "swc": "SWC-124",
        "message": "Direct storage slot access (sload/sstore) — risk of collision in upgradeable proxy patterns.",
    },
    "dos_gas_limit": {
        "patterns": [
            r"for\s*\([^)]*\.length",
            r"while\s*\([^)]*\.length",
        ],
        "severity": "Medium",
        "swc": "SWC-128",
        "message": "Loop bounded by dynamic array length — may exceed block gas limit on large arrays. Consider pagination.",
    },
    "erc20_return_check": {
        "patterns": [
            r"\.transfer\s*\([^)]+\)(?!\s*;?\s*\n?\s*(require|assert|if))",
            r"IERC20\([^)]+\)\.transfer\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-104",
        "message": "ERC20 transfer without return value check — some tokens (USDT) don't return bool. Use SafeERC20.",
    },
    "reentrancy_crossfunction": {
        "patterns": [
            r"\.call\s*\{value:",
        ],
        "severity": "High",
        "swc": "SWC-107",
        "message": "External call with value — potential cross-function reentrancy if state is shared. Verify CEI pattern across ALL functions that read the same state.",
    },
    # v5.3.1: Business logic patterns (EVMBench-informed)
    "price_oracle_stale": {
        "patterns": [
            r"latestRoundData\s*\(",
        ],
        "severity": "High",
        "swc": "SWC-120",
        "message": "Chainlink latestRoundData() without staleness/validity check — price can be stale or zero. Check updatedAt, answeredInRound, and answer > 0.",
    },
    "flash_loan_governance": {
        "patterns": [
            r"balanceOf\s*\(\s*msg\.sender\s*\).*vote|vote.*balanceOf\s*\(\s*msg\.sender\s*\)",
        ],
        "severity": "Critical",
        "swc": "SWC-120",
        "message": "Governance voting based on current balance — vulnerable to flash loan attack. Use snapshot-based voting (ERC20Votes) with timelock.",
    },
    "unprotected_initialize": {
        "patterns": [
            r"function\s+initialize\s*\([^)]*\)\s*(external|public)(?!.*initializer)",
        ],
        "severity": "Critical",
        "swc": "SWC-118",
        "message": "Public initialize() without initializer modifier — can be called by anyone to take ownership. Use OpenZeppelin's Initializable.",
        "requires_no_initializer_guard": True,
    },
    "arbitrary_token_transfer": {
        "patterns": [
            r"transferFrom\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)(?!.*require|.*assert)",
        ],
        "severity": "High",
        "swc": "SWC-104",
        "message": "transferFrom with user-controlled from address — attacker can transfer other users' approved tokens.",
    },
    "rounding_error_division": {
        "patterns": [
            r"\*\s*\w+\s*/\s*\w+",
            r"/\s*\w+\s*\*\s*\w+",
        ],
        "severity": "Medium",
        "swc": "SWC-101",
        "message": "Division before multiplication — Solidity integer division truncates. Multiply first to preserve precision.",
    },
    "missing_slippage_check": {
        "patterns": [
            r"swap\s*\([^)]*\)(?!.*minAmount|.*deadline|.*amountOutMin)",
        ],
        "severity": "High",
        "swc": "SWC-120",
        "message": "Swap without slippage protection (no minAmountOut/deadline) — vulnerable to sandwich attacks and MEV extraction.",
    },
    "unchecked_mint_burn": {
        "patterns": [
            r"\b_mint\s*\([^)]*\)(?!.*require|.*onlyOwner|.*onlyRole)",
            r"\b_burn\s*\([^)]*\)(?!.*require|.*balanceOf)",
        ],
        "severity": "High",
        "swc": "SWC-105",
        "message": "Unrestricted _mint() or _burn() — can cause inflation/deflation attacks. Add access control or balance checks.",
    },
    "return_value_token": {
        "patterns": [
            r"IERC20\([^)]+\)\.approve\s*\(",
        ],
        "severity": "Medium",
        "swc": "SWC-104",
        "message": "ERC20 approve() before transferFrom — vulnerable to allowance front-running. Use increaseAllowance/decreaseAllowance or SafeERC20.",
        "requires_no_safe_approve": True,
    },
    "signature_replay": {
        "patterns": [
            r"ecrecover\s*\(",
            r"ECDSA\.recover\s*\(",
        ],
        "severity": "High",
        "swc": "SWC-121",
        "message": "Signature verification without nonce/deadline — replay attacks possible. Include nonce, chainId, and deadline in signed payload.",
    },
    "withdrawal_rug": {
        "patterns": [
            r"function\s+withdraw\w*\s*\([^)]*\)\s*(external|public).*onlyOwner",
        ],
        "severity": "High",
        "swc": "SWC-105",
        "message": "Owner-only withdrawal of user funds — centralization risk / rug vector. Consider timelock or multi-sig governance.",
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
    has_initializer_guard = "initializer" in code_lower and ("initialized" in code_lower or "initializable" in code_lower)

    for category, cfg in ZERO_RECALL_PATTERNS.items():
        if cfg.get("requires_no_safemath") and has_safemath:
            continue
        if cfg.get("requires_no_safe_approve") and has_safe_approve:
            continue
        if cfg.get("requires_no_initializer_guard") and has_initializer_guard:
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

    # Rule 5: Proxy upgrade findings when contract uses OpenZeppelin's
    # Initializable or UUPSUpgradeable → likely already guarded
    if canonical == CanonicalCategory.PROXY_UPGRADE:
        if re.search(r"Initializable|UUPSUpgradeable|TransparentUpgradeableProxy", source_code):
            return True, "Contract uses OpenZeppelin upgrade infrastructure"

    # Rule 6: unchecked_call on SafeERC20-imported contracts → FP
    if canonical == CanonicalCategory.UNCHECKED_CALL and _OZ_IMPORT.search(source_code):
        if re.search(r"SafeERC20|safeTransfer|safeTransferFrom|safeApprove", source_code):
            return True, "Contract uses SafeERC20 for token operations"

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
    Run all intelligence improvements on raw findings.

    Returns a refined findings list with:
      - Duplicates merged (same canonical type + function + line bucket)
      - Confidence boosted by cross-tool agreement
      - FPs suppressed with reason
      - Severity calibrated
      - Cross-validation tags (static + LLM)
      - Additional patterns for 0%-recall categories
      - fix_code: copy-pasteable Solidity fix snippet (when category is known)
      - exploit_scenario: step-by-step attack description (when category is known)
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

        # 7. Fix-code generation (capability 8)
        fix = generate_fix_code(out, source_code)
        if fix is not None:
            out["fix_code"] = fix

        # 8. Exploit scenario generation (capability 9)
        scenario = generate_exploit_scenario(out)
        if scenario is not None:
            out["exploit_scenario"] = scenario

        results.append(out)

    # Enrich generic recommendations from the RAG knowledge base
    _enrich_recommendations(results)

    # Sort: non-suppressed first, then by severity rank, then by confidence
    results.sort(
        key=lambda f: (
            f.get("fp_suppressed", False),
            -_severity_rank(f.get("severity", "")),
            -f.get("confidence", 0),
        )
    )

    return results


# =============================================================================
# 7. Recommendation enrichment from RAG
# =============================================================================

_CANONICAL_RECOMMENDATIONS: Dict[str, str] = {
    "reentrancy": "Apply Checks-Effects-Interactions pattern: update state BEFORE external calls. Use OpenZeppelin's ReentrancyGuard (`nonReentrant` modifier).",
    "access_control": "Add access control modifier (`onlyOwner`, `onlyRole`) or `require(msg.sender == owner)` check. Use OpenZeppelin's Ownable or AccessControl.",
    "oracle_manipulation": "Use time-weighted average prices (TWAP) instead of spot prices. Add staleness checks on Chainlink `latestRoundData()`. Never use `getReserves()` for pricing.",
    "flash_loan": "Add same-block protection (compare `block.number` at entry/exit). Use snapshot-based governance voting. Add timelock delays on sensitive operations.",
    "arithmetic": "Use Solidity ≥0.8.0 (built-in overflow checks) or OpenZeppelin's SafeMath for older versions. Avoid `unchecked` blocks on user-controlled inputs.",
    "unchecked_call": "Use SafeERC20 for token transfers. Check return values of `.call()`, `.send()`, `.delegatecall()` with `require(success)`.",
    "initialization": "Add `initializer` modifier from OpenZeppelin. Use a storage flag (`initialized = true`) and assert it's false at the start.",
    "signature_verification": "Use OpenZeppelin's ECDSA library. Check for `address(0)` after `ecrecover`. Include nonce + chain_id in signed payloads to prevent replay.",
    "bad_randomness": "Use Chainlink VRF for verifiable randomness. Never use `block.timestamp`, `blockhash`, or `block.difficulty` as entropy sources.",
    "time_manipulation": "Avoid relying on `block.timestamp` for critical logic — miners can manipulate by ±15 seconds. Use block numbers for ordering if precision needed.",
    "denial_of_service": "Avoid unbounded loops over dynamic arrays. Use pull-over-push pattern for payouts. Set gas limits on external calls.",
    "front_running": "Use commit-reveal scheme for sensitive operations. Use `increaseAllowance`/`decreaseAllowance` instead of `approve` to prevent race conditions.",
    "proxy_upgrade": "Use OpenZeppelin's UUPSUpgradeable or TransparentUpgradeableProxy. Guard `upgradeTo` with admin-only access. Maintain storage layout compatibility.",
    "centralization": "Implement multi-sig governance for admin functions. Add timelock delays on ownership transfers. Consider renouncing ownership when no longer needed.",
    "price_oracle_stale": "Add staleness check: `require(updatedAt > block.timestamp - MAX_DELAY)`. Check `answer > 0` and `answeredInRound >= roundId`.",
    "flash_loan_governance": "Use ERC20Votes with block-number snapshots for governance. Add timelock (48h+) on proposals. Check `getVotes(account, blockNumber)` at proposal creation.",
    "unprotected_initialize": "Use OpenZeppelin's `initializer` modifier. Add `require(!initialized)` guard. Call in constructor or deployment script only.",
    "arbitrary_token_transfer": "Validate that `from == msg.sender` or use SafeERC20. Never let external callers specify arbitrary `from` addresses.",
    "rounding_error_division": "Multiply before dividing to preserve precision. Use `(a * b) / c` instead of `(a / c) * b`. Consider using fixed-point math libraries.",
    "missing_slippage_check": "Add `minAmountOut` parameter and deadline check. `require(amountOut >= minAmountOut, 'slippage')`. Use DEX router with built-in protection.",
    "unchecked_mint_burn": "Restrict _mint/_burn with access control (onlyOwner, onlyRole). Add supply caps for mint. Verify balance >= amount for burn.",
    "signature_replay": "Include nonce (auto-increment), chainId, deadline, and contract address in the signed payload. Use EIP-712 typed data signing.",
    "withdrawal_rug": "Replace onlyOwner withdrawal with timelock + multi-sig. Implement pull-over-push pattern where users withdraw their own funds.",
}

_GENERIC_RECOMMENDATIONS = {"review and fix", "review the", "check the", "see the"}


def _enrich_recommendations(findings: List[Dict[str, Any]]) -> None:
    """Replace generic recommendations with canonical per-category advice."""
    for f in findings:
        rec = (f.get("recommendation") or f.get("message") or "").strip().lower()
        if not rec or any(g in rec for g in _GENERIC_RECOMMENDATIONS):
            canonical = f.get("canonical_category", "")
            better = _CANONICAL_RECOMMENDATIONS.get(canonical)
            if better:
                f["recommendation"] = better


# =============================================================================
# 8. Fix-code generation (Solidity patches per finding)
# =============================================================================

_FIX_CODE_TEMPLATES: Dict[str, str] = {
    "reentrancy": """\
// Fix: Apply Checks-Effects-Interactions (CEI) pattern + ReentrancyGuard
// 1. Import OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) private balances;

    function withdraw(uint256 amount) external nonReentrant {
        // CHECKS
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // EFFECTS — update state BEFORE external call
        balances[msg.sender] -= amount;
        // INTERACTIONS — external call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}""",

    "access_control": """\
// Fix: Add onlyOwner modifier using OpenZeppelin Ownable
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureContract is Ownable {
    uint256 public sensitiveValue;

    // Restrict sensitive function to owner only
    function setSensitiveValue(uint256 newValue) external onlyOwner {
        sensitiveValue = newValue;
    }

    // For role-based access, use AccessControl instead:
    // import "@openzeppelin/contracts/access/AccessControl.sol";
    // bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    // function setSensitiveValue(uint256 v) external onlyRole(ADMIN_ROLE) { ... }
}""",

    "oracle_manipulation": """\
// Fix: Use Chainlink latestRoundData with staleness and validity checks
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract SafeOracle {
    AggregatorV3Interface public immutable priceFeed;
    uint256 public constant STALENESS_THRESHOLD = 1 hours;

    constructor(address _feed) {
        priceFeed = AggregatorV3Interface(_feed);
    }

    function getPrice() public view returns (uint256) {
        (
            uint80 roundId,
            int256 answer,
            ,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();
        require(answer > 0, "Invalid price");
        require(updatedAt != 0, "Round not complete");
        require(block.timestamp - updatedAt <= STALENESS_THRESHOLD, "Stale price");
        require(answeredInRound >= roundId, "Round incomplete");
        return uint256(answer);
    }
}""",

    "arithmetic": """\
// Fix for Solidity < 0.8: Use OpenZeppelin SafeMath
// pragma solidity ^0.7.6;
import "@openzeppelin/contracts/math/SafeMath.sol";

contract SafeArithmetic {
    using SafeMath for uint256;

    function safeAdd(uint256 a, uint256 b) external pure returns (uint256) {
        return a.add(b);   // reverts on overflow
    }

    function safeSub(uint256 a, uint256 b) external pure returns (uint256) {
        return a.sub(b);   // reverts on underflow
    }
}

// Fix for Solidity >= 0.8: overflow is built-in; avoid unchecked on user input
// pragma solidity ^0.8.0;
// WARNING: only use `unchecked` blocks when overflow is mathematically impossible
// contract Example {
//     function counter(uint256 i) external pure returns (uint256) {
//         unchecked { return i + 1; }  // SAFE only if i < type(uint256).max is guaranteed
//     }
// }""",

    "unchecked_call": """\
// Fix: Use SafeERC20 for token transfers; require(success) for low-level calls
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SafeTransfer {
    using SafeERC20 for IERC20;

    function transferTokens(IERC20 token, address to, uint256 amount) external {
        // SafeERC20 wraps transfer/transferFrom and reverts on failure
        token.safeTransfer(to, amount);
    }

    function sendEther(address payable recipient, uint256 amount) external {
        // Always check the return value of low-level calls
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "ETH transfer failed");
    }
}""",

    "bad_randomness": """\
// Fix: Use Chainlink VRF v2 for verifiable on-chain randomness
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract SecureRandom is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface public immutable coordinator;
    uint64 public immutable subscriptionId;
    bytes32 public immutable keyHash;
    uint256 public randomResult;

    constructor(address _coord, uint64 _subId, bytes32 _keyHash)
        VRFConsumerBaseV2(_coord)
    {
        coordinator = VRFCoordinatorV2Interface(_coord);
        subscriptionId = _subId;
        keyHash = _keyHash;
    }

    function requestRandom() external returns (uint256 requestId) {
        return coordinator.requestRandomWords(keyHash, subscriptionId, 3, 100000, 1);
    }

    function fulfillRandomWords(uint256, uint256[] memory randomWords) internal override {
        randomResult = randomWords[0];
    }
}""",

    "time_manipulation": """\
// Fix: Replace block.timestamp with block.number for ordering-sensitive logic
// block.number cannot be manipulated by miners beyond normal mining variance

contract TimeSafe {
    uint256 public immutable deployBlock;
    uint256 public constant LOCK_BLOCKS = 7200; // ~24 hours at 12s/block

    constructor() {
        deployBlock = block.number;
    }

    function isLockExpired() public view returns (bool) {
        // Use block.number instead of block.timestamp for sequencing
        return block.number >= deployBlock + LOCK_BLOCKS;
    }

    // If wall-clock time is truly required, document the ±15s miner tolerance:
    // require(block.timestamp >= deadline, "Too early");  // acceptable for non-critical deadlines
    // require(block.timestamp <= deadline + 15, "Too late with tolerance");
}""",

    "front_running": """\
// Fix: Use increaseAllowance/decreaseAllowance instead of approve
// Prevents the ERC-20 approval race condition (SWC-114)

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract SafeToken is ERC20 {
    constructor() ERC20("SafeToken", "STK") {}

    // Use increaseAllowance to avoid front-running on approve:
    function safeIncreaseAllowance(address spender, uint256 addedValue) external {
        _approve(msg.sender, spender, allowance(msg.sender, spender) + addedValue);
    }

    function safeDecreaseAllowance(address spender, uint256 subtractedValue) external {
        uint256 current = allowance(msg.sender, spender);
        require(current >= subtractedValue, "Allowance below zero");
        _approve(msg.sender, spender, current - subtractedValue);
    }
    // NOTE: OpenZeppelin's ERC20 already includes increaseAllowance/decreaseAllowance
}""",

    "proxy_upgrade": """\
// Fix: Use OpenZeppelin UUPSUpgradeable with _authorizeUpgrade access control
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyContractV2 is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 public value;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    // Only owner can authorize upgrades — critical access control
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}

    function setValue(uint256 v) external onlyOwner { value = v; }
}""",

    "initialization": """\
// Fix: Use OpenZeppelin Initializable with initializer modifier
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract SecureProxy is Initializable, OwnableUpgradeable {
    uint256 public protectedValue;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        // Prevent the implementation contract from being initialized directly
        _disableInitializers();
    }

    // initializer modifier ensures this can only be called once
    function initialize(address owner, uint256 initial) public initializer {
        __Ownable_init(owner);
        protectedValue = initial;
    }

    // If re-initialization is needed for upgrades, use reinitializer(version):
    // function initializeV2(uint256 v) public reinitializer(2) { ... }
}""",
}


def generate_fix_code(
    finding: Dict[str, Any],
    source_code: str = "",
) -> Optional[str]:
    """
    Return a copy-pasteable Solidity fix snippet for a given finding.

    Looks up the finding's canonical_category (or normalizes it if absent)
    against the FIX_CODE_TEMPLATES dictionary.  Returns None for unknown or
    "other" categories so callers can omit the field cleanly.

    Args:
        finding: A finding dict (must contain at least 'canonical_category'
                 or enough fields for normalize_finding_type to resolve one).
        source_code: Optional contract source — reserved for future context-
                     aware template selection (e.g. pragma version detection).

    Returns:
        Solidity code string, or None if no template exists for this category.
    """
    canonical = finding.get("canonical_category", "")
    if not canonical or canonical == "other":
        # Try to resolve from the finding itself
        resolved = normalize_finding_type(finding)
        if resolved is None or resolved.value == "other":
            return None
        canonical = resolved.value

    return _FIX_CODE_TEMPLATES.get(canonical)


# =============================================================================
# 9. Exploit scenario generation
# =============================================================================

_EXPLOIT_SCENARIOS: Dict[str, List[str]] = {
    "reentrancy": [
        "1. Attacker deploys a malicious contract with a fallback/receive function that calls back into the victim.",
        "2. Attacker calls the victim's withdraw() function with a valid balance.",
        "3. Victim sends ETH to attacker — attacker's fallback immediately calls withdraw() again before state is updated.",
        "4. Re-entry loop drains the contract balance in a single transaction (no per-call state update blocks it).",
        "5. Attack ends when gas runs out or balance is exhausted; attacker keeps all drained ETH.",
    ],
    "access_control": [
        "1. Attacker inspects the contract ABI and identifies a privileged function lacking an access modifier.",
        "2. Attacker calls the unprotected function (e.g. setOwner, mint, pause) directly from any EOA.",
        "3. Without an onlyOwner or role check, the call succeeds immediately.",
        "4. Attacker takes ownership, mints unlimited tokens, or pauses the protocol at will.",
        "5. Legitimate users lose access or funds; attacker drains or disables the contract.",
    ],
    "oracle_manipulation": [
        "1. Attacker takes a flash loan of a large amount of the quote token from a lending protocol.",
        "2. Attacker dumps the borrowed token into the DEX pool, crashing the spot price.",
        "3. Victim contract reads the manipulated spot price via getReserves() or similar — treats it as market price.",
        "4. Attacker exploits the mispriced collateral: borrows against inflated collateral or liquidates positions unfairly.",
        "5. Attacker swaps back to restore the price, repays the flash loan, and pockets the arbitrage profit.",
        "6. Entire attack is atomic — completes within a single transaction with no capital at risk.",
    ],
    "arithmetic": [
        "1. Attacker identifies a Solidity <0.8 contract that performs arithmetic on user-supplied values without SafeMath.",
        "2. Attacker provides a large uint256 value that, when added to an existing balance, wraps around to 0 or a small number.",
        "3. Overflow causes the balance check (require(balance >= amount)) to pass with an effectively zeroed balance.",
        "4. Attacker withdraws far more than their actual deposit.",
        "5. For underflow: attacker triggers a subtraction that wraps to type(uint256).max, granting near-infinite allowance.",
    ],
    "unchecked_call": [
        "1. Contract calls an external address using .call() or .send() but does not check the boolean return value.",
        "2. The external call silently fails (e.g. recipient is a contract that reverts, or gas stipend is exceeded).",
        "3. Because the return value is ignored, the contract continues execution and marks the operation as successful.",
        "4. Tokens or ETH are never delivered, but the contract's internal state (balances, flags) is updated as if they were.",
        "5. Attacker exploits the accounting discrepancy to double-spend or claim funds they should not have.",
    ],
    "bad_randomness": [
        "1. Attacker inspects the on-chain randomness source (blockhash, block.timestamp, block.difficulty).",
        "2. Before the target transaction is mined, attacker simulates possible block values to predict the 'random' outcome.",
        "3. Attacker submits their exploit transaction in the same block as or immediately after the target, controlling the outcome.",
        "4. For lottery contracts: attacker only submits when they know they will win; reverts otherwise (cost: only gas).",
        "5. Attacker drains the prize pool repeatedly with a guaranteed-win strategy.",
    ],
    "time_manipulation": [
        "1. Contract uses block.timestamp to enforce a time lock or deadline (e.g. 'require(block.timestamp >= unlock)').",
        "2. Miner (or validator in PoS) can adjust block.timestamp within the ~15-second tolerance window.",
        "3. Attacker who is also a miner sets the timestamp slightly ahead to satisfy the time condition prematurely.",
        "4. Attacker calls the time-locked function before the intended unlock time, bypassing the control.",
        "5. For auctions or games: manipulating the timestamp extends or shortens windows to benefit the attacker.",
    ],
    "front_running": [
        "1. Victim calls token.approve(spender, 100) to change an existing approval from 50 to 100.",
        "2. Attacker monitors the mempool and sees the approve transaction before it is mined.",
        "3. Attacker front-runs by calling transferFrom(victim, attacker, 50) while the old allowance of 50 is still active.",
        "4. After the victim's approve is mined, attacker calls transferFrom again using the new allowance of 100.",
        "5. Attacker steals 150 tokens even though the victim intended to grant only 100.",
        "6. Fix: use increaseAllowance/decreaseAllowance which are atomic and race-free.",
    ],
    "proxy_upgrade": [
        "1. Proxy contract has a public upgradeTo(address) function without onlyOwner or equivalent guard.",
        "2. Attacker deploys a malicious implementation contract with a drain() function.",
        "3. Attacker calls upgradeTo(maliciousImpl) on the proxy — succeeds because there is no access check.",
        "4. All calls to the proxy now delegate to the malicious implementation.",
        "5. Attacker calls drain() through the proxy, stealing all ETH and tokens held by the proxy's storage.",
        "6. Storage layout mismatch between old and new implementation can also corrupt state silently.",
    ],
    "initialization": [
        "1. Upgradeable contract's initialize() function lacks the initializer modifier.",
        "2. The implementation contract is deployed without calling initialize() (normal for proxy patterns).",
        "3. Attacker calls initialize() directly on the implementation, setting themselves as owner.",
        "4. Since the implementation is the logic target of a delegatecall-based proxy, attacker now controls admin functions.",
        "5. Attacker calls selfdestruct on the implementation (if present), bricking the proxy permanently.",
        "6. Alternatively, attacker upgrades to a malicious implementation and drains all proxy storage.",
    ],
}


def generate_exploit_scenario(finding: Dict[str, Any]) -> Optional[List[str]]:
    """
    Return a step-by-step attack description for a given finding.

    Uses the finding's canonical_category to look up a pre-defined scenario
    modelled on the RAG attack_steps format.  Returns None for unknown or
    "other" categories.

    Args:
        finding: A finding dict with at least 'canonical_category', or enough
                 fields for normalize_finding_type to resolve a category.

    Returns:
        List of step strings, or None if no scenario exists for this category.
    """
    canonical = finding.get("canonical_category", "")
    if not canonical or canonical == "other":
        resolved = normalize_finding_type(finding)
        if resolved is None or resolved.value == "other":
            return None
        canonical = resolved.value

    scenario = _EXPLOIT_SCENARIOS.get(canonical)
    return list(scenario) if scenario is not None else None
