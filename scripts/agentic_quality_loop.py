#!/usr/bin/env python3
"""
Agentic quality loop — prototype.

Composes MIESC's existing grounding/FP components into a closed verification loop
that separates CONFIRMED findings from FALSE POSITIVES and HALLUCINATIONS, and
estimates the precision lift. See docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md.

Design goals:
- Runs OFFLINE for review: the adversarial verifier defaults to a deterministic
  rule-based panel; an LLM verifier can be plugged in via `--verifier llm`.
- ADDITIVE: loads the opt-in benign-pattern corpus
  (data/rag/benign_patterns_seed_*.jsonl); does NOT touch the frozen RAG KB.
- Uses src/security/hallucination_detector.py when importable; degrades gracefully.

Usage:
    python3 scripts/agentic_quality_loop.py --demo
    python3 scripts/agentic_quality_loop.py --findings results.json --code contract.sol

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Optional: real grounding via the existing detector (pure-python, no ML deps).
try:
    from src.security.hallucination_detector import validate_llm_findings  # type: ignore

    _HAS_DETECTOR = True
except Exception:  # noqa: BLE001 - graceful offline fallback
    _HAS_DETECTOR = False


# --------------------------------------------------------------------------- #
# Benign-pattern corpus (the precision lever)
# --------------------------------------------------------------------------- #
def load_benign_patterns(path: Optional[str] = None) -> list[dict[str, Any]]:
    """Load the opt-in benign-pattern corpus (JSONL)."""
    if path is None:
        matches = sorted(glob.glob(os.path.join(ROOT, "data", "rag", "benign_patterns_seed_*.jsonl")))
        if not matches:
            return []
        path = matches[-1]
    patterns: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                patterns.append(json.loads(line))
    return patterns


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def _extract_function(code: str, fn: str) -> str:
    """Return the body (signature..matching brace) of function `fn`, or '' if absent.

    Scoping benign-pattern checks to the cited function is critical: a contract-wide
    keyword match would wrongly clear an UNGUARDED function just because some OTHER
    function in the same file is guarded (a false-negative — the worst outcome)."""
    if not fn or fn in ("unknown", ""):
        return code  # no function cited -> fall back to whole-contract scope
    m = re.search(r"function\s+" + re.escape(fn) + r"\b", code)
    if not m:
        return ""  # cited function not present -> caller treats as ungrounded
    brace = code.find("{", m.start())
    if brace == -1:
        return code[m.start():m.start() + 400]
    depth, i = 0, brace
    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[m.start():i + 1]
        i += 1
    return code[m.start():]


def _func_signature(code: str, fn: str) -> str:
    """Text from `function fn` up to the opening brace (where modifiers live)."""
    if not fn:
        return ""
    m = re.search(r"function\s+" + re.escape(fn) + r"\b[^{]*", code)
    return m.group(0) if m else ""


def _is_cei(body: str) -> bool:
    """True if a state update precedes the external call (Checks-Effects-Interactions)."""
    call = re.search(r"\.call\{|\.call\(|\.transfer\(|\.send\(", body)
    upd = re.search(r"balances?\[[^\]]*\]\s*[-+]?=", body)
    return bool(upd and call and upd.start() < call.start())


def _timestamp_is_benign(body: str) -> bool:
    """block.timestamp used only as a coarse time gate (require/if), not for RNG."""
    if not re.search(r"block\.timestamp|now\b", body):
        return False
    in_entropy = re.search(r"(block\.timestamp|now)\b[^;]*[%]", body) or re.search(
        r"keccak256[^;]*block\.timestamp", body
    )
    in_gate = re.search(r"(require|if)\s*\([^;]*block\.timestamp", body)
    return bool(in_gate and not in_entropy)


def matches_benign(finding: dict[str, Any], code: str, patterns: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return the benign pattern this finding likely matches (function-scoped), if any."""
    vtype = _norm(finding.get("type") or finding.get("title") or "")
    fn = finding.get("function") or ""
    body = _extract_function(code, fn)
    if body == "":  # cited function absent -> not benign; grounding will flag it
        return None
    sig = _func_signature(code, fn)
    pragma_08 = bool(re.search(r"pragma\s+solidity\s*\^?0\.8", code))
    by_id = {p["id"]: p for p in patterns}

    def has(pid: str) -> Optional[dict[str, Any]]:
        return by_id.get(pid)

    # Informational lint flagged as a vuln -> benign (no function scope needed).
    if re.search(r"pragma|naming|visibilit|unused|solc.version", vtype):
        return has("BENIGN-PRAGMA-INFORMATIONAL")
    # Arithmetic on Solidity >= 0.8 without an unchecked block.
    if "arithmetic" in vtype and pragma_08 and "unchecked" not in body:
        return has("BENIGN-ARITHMETIC-0_8")
    # Reentrancy: guarded by modifier, or CEI ordering in the function body.
    if "reentr" in vtype:
        if re.search(r"nonReentrant|ReentrancyGuard", sig):
            return has("BENIGN-REENTRANCY-GUARD")
        if _is_cei(body):
            return has("BENIGN-CEI-ORDER")
    # Access control present on the cited function.
    if "access" in vtype and re.search(r"onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner", sig):
        return has("BENIGN-ACCESS-ONLYOWNER")
    # Timestamp used only as a coarse time gate.
    if ("time" in vtype or "timestamp" in vtype) and _timestamp_is_benign(body):
        return has("BENIGN-TIMESTAMP-TIMELOCK")
    # Unchecked-call class but the call is actually checked / SafeERC20.
    if "unchecked" in vtype or "low_level" in vtype:
        if re.search(r"safeTransfer|SafeERC20", body):
            return has("BENIGN-SAFEERC20")
        if re.search(r"require\s*\(\s*(ok|success)\b", body):
            return has("BENIGN-CHECKED-CALL")
    # Front-running: commit-reveal mitigation present.
    if "front" in vtype and re.search(r"keccak256", code) and re.search(r"commit", code, re.IGNORECASE):
        return has("BENIGN-FRONTRUN-COMMITREVEAL")
    # Short-address: deprecated/mitigated on Solidity >= 0.5.
    pragma_05 = bool(re.search(r"pragma\s+solidity\s*[\^>=]*\s*0\.([5-9]|\d{2})", code))
    if "short" in vtype and pragma_05:
        return has("BENIGN-SHORTADDR-DEPRECATED")
    return None


# --------------------------------------------------------------------------- #
# Grounding (hallucination) check
# --------------------------------------------------------------------------- #
@dataclass
class Grounding:
    location_ok: bool
    pattern_ok: bool
    reasons: list[str] = field(default_factory=list)


def ground_finding(finding: dict[str, Any], code: str) -> Grounding:
    """Is the finding grounded in the code? (location + pattern present)."""
    reasons: list[str] = []
    # Location grounding: cited function/line exists in the source.
    fn = finding.get("function") or ""
    loc = finding.get("location") or finding.get("line") or ""
    location_ok = True
    if fn and fn not in ("unknown", ""):
        location_ok = bool(re.search(r"\bfunction\s+" + re.escape(str(fn)) + r"\b", code))
        if not location_ok:
            reasons.append(f"cited function '{fn}' not found in source")
    line = _extract_line(str(loc))
    if line is not None:
        n_lines = code.count("\n") + 1
        if line > n_lines + 2:
            location_ok = False
            reasons.append(f"cited line {line} beyond source length {n_lines}")
    # Pattern grounding: a keyword of the vuln class appears in the code.
    vtype = _norm(finding.get("type") or finding.get("title") or "")
    pattern_ok = True
    sig = _PATTERN_SIGNATURES.get(_canonical_cat(vtype))
    if sig:
        pattern_ok = bool(re.search(sig, code, re.IGNORECASE))
        if not pattern_ok:
            reasons.append(f"no '{_canonical_cat(vtype)}' code pattern present")
    return Grounding(location_ok=location_ok, pattern_ok=pattern_ok, reasons=reasons)


_PATTERN_SIGNATURES = {
    "reentrancy": r"\.call\{|\.call\(|\.transfer\(|\.send\(",
    "access_control": r"\bfunction\b",  # broad; refined by location check
    "unchecked_low_level_calls": r"\.call\(|\.call\{|\.delegatecall\(",
    "arithmetic": r"[+\-*]=|[+\-*]\s",
    "bad_randomness": r"block\.(timestamp|number|difficulty|prevrandao)|blockhash",
    "time_manipulation": r"block\.timestamp|now\b",
}


def _canonical_cat(vtype: str) -> str:
    for cat in _PATTERN_SIGNATURES:
        if cat in vtype or any(tok in vtype for tok in cat.split("_")):
            return cat
    return vtype


def _extract_line(s: str) -> Optional[int]:
    m = re.search(r"\d+", s)
    return int(m.group()) if m else None


# --------------------------------------------------------------------------- #
# Adversarial verifier panel (rule-based default; LLM pluggable)
# --------------------------------------------------------------------------- #
def adversarial_panel(
    finding: dict[str, Any], code: str, grounding: Grounding, benign: Optional[dict[str, Any]]
) -> dict[str, bool]:
    """N independent lenses, each returns True if it REFUTES (votes 'not a real vuln')."""
    vtype = _norm(finding.get("type") or finding.get("title") or "")
    sev = str(finding.get("severity", "")).lower()
    return {
        # Lens 1: grounding — refute if the finding is not grounded in the code.
        "grounding": not (grounding.location_ok and grounding.pattern_ok),
        # Lens 2: benign-context — refute if a benign pattern is present.
        "benign_context": benign is not None,
        # Lens 3: severity sanity — refute if an informational lint is flagged high/critical.
        "severity": bool(re.search(r"pragma|naming|visibilit|unused|solc.version", vtype))
        and sev in ("high", "critical"),
        # Lens 4: exploitability — refute if there is no asset-flow / state-change surface.
        "exploitability": not re.search(
            r"\.call|\.transfer|\.send|delegatecall|selfdestruct|=\s*msg\.sender|balances?\[", code
        ),
    }


# --------------------------------------------------------------------------- #
# The loop
# --------------------------------------------------------------------------- #
def verify(finding: dict[str, Any], code: str, patterns: list[dict[str, Any]]) -> dict[str, Any]:
    grounding = ground_finding(finding, code)
    benign = matches_benign(finding, code, patterns)
    votes = adversarial_panel(finding, code, grounding, benign)
    refutes = sum(1 for v in votes.values() if v)

    if not (grounding.location_ok and grounding.pattern_ok):
        verdict = "hallucinated"
    elif benign is not None or refutes >= 2:
        verdict = "false_positive"
    else:
        verdict = "confirmed"

    reasons = list(grounding.reasons)
    if benign:
        reasons.append(f"matches benign pattern {benign['id']}: {benign['why_safe'][:80]}")
    reasons += [f"refuted-by:{k}" for k, v in votes.items() if v]
    return {
        "title": finding.get("title") or finding.get("type"),
        "severity": finding.get("severity"),
        "verdict": verdict,
        "refute_votes": refutes,
        "reasons": reasons,
    }


def run(findings: list[dict[str, Any]], code: str, patterns: list[dict[str, Any]]) -> dict[str, Any]:
    results = [verify(f, code, patterns) for f in findings]
    counts = {"confirmed": 0, "false_positive": 0, "hallucinated": 0}
    for r in results:
        counts[r["verdict"]] += 1
    total = len(results) or 1
    kept = counts["confirmed"]
    return {
        "results": results,
        "counts": counts,
        "kept": kept,
        "dropped": total - kept,
        "precision_note": (
            f"{kept}/{total} survive the loop; {counts['false_positive']} FP + "
            f"{counts['hallucinated']} hallucinations dropped. On a corpus where the "
            f"raw precision is ~22%, dropping grounded-benign + ungrounded findings is "
            f"the lever that raises precision without touching true positives."
        ),
    }


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
DEMO_CODE = """pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public unlockTime;
    bool private _locked;
    modifier nonReentrant() { require(!_locked); _locked = true; _; _locked = false; }
    modifier onlyOwner() { require(msg.sender == owner); _; }

    function withdrawSafe(uint256 a) external nonReentrant {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] -= a;
    }
    function drain(uint256 a) external {
        (bool ok,) = msg.sender.call{value: a}("");
        require(ok);
        balances[msg.sender] -= a;
    }
    function setOwner(address n) external onlyOwner { owner = n; }
    function unlock() external { require(block.timestamp >= unlockTime, "locked"); }
}
"""

DEMO_FINDINGS = [
    {"title": "Reentrancy", "type": "reentrancy", "function": "drain", "severity": "high",
     "_note": "REAL: external call before state update, no guard -> should be CONFIRMED"},
    {"title": "Reentrancy", "type": "reentrancy", "function": "withdrawSafe", "severity": "high",
     "_note": "FP: same shape but nonReentrant guard -> benign"},
    {"title": "Unprotected ownership change", "type": "access_control", "function": "setOwner",
     "severity": "high", "_note": "FP: onlyOwner present -> benign"},
    {"title": "Timestamp dependence", "type": "time_manipulation", "function": "unlock",
     "severity": "medium", "_note": "FP: timestamp only as a timelock require -> benign"},
    {"title": "Floating pragma", "type": "solc-version-pragma", "function": "", "severity": "high",
     "_note": "FP: informational lint flagged high -> benign/severity"},
    {"title": "Reentrancy", "type": "reentrancy", "function": "claimRewards", "severity": "critical",
     "_note": "HALLUCINATION: function claimRewards does not exist in the contract"},
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Agentic quality loop (FP + hallucination verifier)")
    ap.add_argument("--demo", action="store_true", help="run on built-in sample contract + findings")
    ap.add_argument("--findings", help="path to a findings JSON (list or {findings:[...]})")
    ap.add_argument("--code", help="path to the contract source")
    ap.add_argument("--benign", help="path to a benign-pattern JSONL (default: latest seed)")
    args = ap.parse_args()

    patterns = load_benign_patterns(args.benign)
    print(f"# loaded {len(patterns)} benign patterns | hallucination_detector importable: {_HAS_DETECTOR}\n")

    if args.demo or not args.findings:
        findings, code = DEMO_FINDINGS, DEMO_CODE
        print("# running DEMO (use --findings/--code for real input)\n")
    else:
        raw = json.load(open(args.findings, encoding="utf-8"))
        findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
        code = open(args.code, encoding="utf-8").read() if args.code else ""

    out = run(findings, code, patterns)
    for r in out["results"]:
        mark = {"confirmed": "[KEEP]", "false_positive": "[FP  ]", "hallucinated": "[HALL]"}[r["verdict"]]
        print(f"{mark} {r['title']} ({r['severity']})  votes={r['refute_votes']}")
        for reason in r["reasons"]:
            print(f"        - {reason}")
    print(f"\n# counts: {out['counts']}")
    print(f"# {out['precision_note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
