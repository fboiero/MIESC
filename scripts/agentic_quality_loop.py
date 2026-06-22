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

    # Informational / style-lint detector flagged as a vuln -> benign (type-determined,
    # no function scope needed). These detector classes are never vulnerabilities, so
    # dropping them is recall-safe (real vulns carry real types like reentrancy).
    if re.search(
        r"pragma|naming|visibilit|unused|solc.version|useless_public|constants_instead"
        r"|instead_of_literal|boolean_equality|constant_functions_assembly|style|lint",
        vtype,
    ):
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
# LLM verifier (Ollama) — the semantic panel that the rule-based fallback proxies
# --------------------------------------------------------------------------- #
def _ollama_generate(prompt: str, model: str, host: str, timeout: int = 60) -> str:
    import urllib.request

    body = json.dumps(
        {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0}}
    ).encode()
    req = urllib.request.Request(
        host.rstrip("/") + "/api/generate", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read()).get("response", "")


def make_llm_verifier(
    model: str,
    host: str = "http://localhost:11434",
    timeout: int = 60,
    patterns: Optional[list[dict[str, Any]]] = None,
):
    """Return llm_fn(finding, code, benign) -> True if the model judges it a FALSE POSITIVE.

    Recall-safe by construction: the prompt instructs the model to default to NOT a false
    positive under any uncertainty, so a real vuln is never dropped on a hedge.

    RAG-grounded: if `patterns` is given, the benign patterns whose `resembles_category`
    matches the finding's category are injected into the prompt as reference knowledge —
    so the model can recognize semantic mitigations (VRF, pull-payment, transfer-reverts,
    commit-reveal, ...) even when the keyword matcher does not fire.
    """
    pats = patterns or []

    def _category_grounding(finding: dict[str, Any]) -> str:
        vtype = _norm(finding.get("type") or finding.get("title") or "")
        rel = [
            p for p in pats
            if (lambda c: c and (c in vtype or vtype in c))(_norm(p.get("resembles_category", "")))
        ]
        if not rel:
            return ""
        lines = [f"- {p['title']}: {p['why_safe']}" for p in rel[:6]]
        header = (
            "Known BENIGN patterns for this finding's category (the finding is a FALSE "
            "POSITIVE if the code clearly matches one of these):\n"
        )
        return header + "\n".join(lines) + "\n"

    def llm_fn(finding: dict[str, Any], code: str, benign: Optional[dict[str, Any]]) -> bool:
        grounding = _category_grounding(finding)
        hint = ("\n" + grounding) if grounding else (
            f"\nA reference benign pattern may apply: {benign['why_safe']}" if benign else ""
        )
        prompt = (
            "You are a smart-contract security verifier. Decide whether a reported finding "
            "is a TRUE vulnerability or a FALSE POSITIVE *in the context of this contract*.\n"
            f"Finding: {finding.get('type')} (severity {finding.get('severity')}) "
            f"in function '{finding.get('function') or 'unknown'}'.\n"
            "A finding is a FALSE POSITIVE only if the code shows it is mitigated or benign "
            "in context (reentrancy guard / CEI, onlyOwner/role guard, block.timestamp used "
            "only as a coarse timelock, Solidity >=0.8 arithmetic, checked low-level call / "
            "SafeERC20, or an informational lint).\n"
            f"{hint}\n\nContract:\n```solidity\n{code[:6000]}\n```\n\n"
            'Respond with ONLY one JSON object: {"false_positive": true|false, "reason": "<=15 words"}. '
            "If you are at all uncertain, answer false_positive=false (never drop a real vulnerability)."
        )
        try:
            raw = _ollama_generate(prompt, model, host, timeout)
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if not m:
                return False  # unparseable -> recall-safe keep
            return bool(json.loads(m.group(0)).get("false_positive") is True)
        except Exception:  # noqa: BLE001 - any LLM failure -> recall-safe keep
            return False

    return llm_fn


# --------------------------------------------------------------------------- #
# The loop
# --------------------------------------------------------------------------- #
def verify(
    finding: dict[str, Any],
    code: str,
    patterns: list[dict[str, Any]],
    llm_fn: Optional[Any] = None,
) -> dict[str, Any]:
    """Recall-SAFE verdict.

    Hard lesson from measuring on data/fp_seed.jsonl: brittle rule-based grounding
    (regex pattern/function checks) mislabels REAL vulns as hallucinations on legacy
    Solidity (e.g. `.call.value()` != `.call(`, truncated snippets), destroying
    recall. So we DROP a finding only on a STRONG positive benign signal; weak/ambiguous
    grounding routes to `needs_review` (kept, flagged), never auto-dropped. Auto-drop
    on grounding alone requires the robust HallucinationDetector or an LLM verifier,
    not these heuristics.
    """
    grounding = ground_finding(finding, code)
    benign = matches_benign(finding, code, patterns)
    votes = adversarial_panel(finding, code, grounding, benign)
    refutes = sum(1 for v in votes.values() if v)
    llm_fp = bool(llm_fn(finding, code, benign)) if llm_fn is not None else False

    if benign is not None or llm_fp:
        verdict = "false_positive"  # strong signal (benign pattern OR LLM judgment) -> safe to drop
    elif not (grounding.location_ok and grounding.pattern_ok):
        verdict = "needs_review"  # weak signal -> FLAG, do not drop (protect recall)
    else:
        verdict = "confirmed"

    reasons = list(grounding.reasons)
    if benign:
        reasons.append(f"matches benign pattern {benign['id']}: {benign['why_safe'][:80]}")
    if llm_fp:
        reasons.append("llm-verifier: false_positive")
    reasons += [f"weak-refute:{k}" for k, v in votes.items() if v]
    return {
        "title": finding.get("title") or finding.get("type"),
        "severity": finding.get("severity"),
        "verdict": verdict,
        "refute_votes": refutes,
        "reasons": reasons,
    }


def run(findings: list[dict[str, Any]], code: str, patterns: list[dict[str, Any]]) -> dict[str, Any]:
    results = [verify(f, code, patterns) for f in findings]
    counts = {"confirmed": 0, "false_positive": 0, "needs_review": 0}
    for r in results:
        counts[r["verdict"]] += 1
    total = len(results) or 1
    dropped = counts["false_positive"]  # recall-safe: only strong benign matches drop
    kept = total - dropped
    return {
        "results": results,
        "counts": counts,
        "kept": kept,
        "dropped": dropped,
        "precision_note": (
            f"{dropped}/{total} dropped as false positives (strong benign match); "
            f"{counts['needs_review']} flagged needs_review (KEPT, not dropped); "
            f"{counts['confirmed']} confirmed. Recall-safe: a finding is dropped only on "
            f"a strong benign signal, never on brittle grounding alone."
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


def measure(
    records: list[dict[str, Any]], patterns: list[dict[str, Any]], llm_fn: Optional[Any] = None
) -> dict[str, Any]:
    """Measure the loop against a LABELED per-finding dataset (data/fp_seed.jsonl).

    Each record: {finding:{type,location:{function,line},severity,...}, context:<code>,
    label: bool}  where label=True means a real vulnerability, False means FP/noise.
    """
    tot_real = tot_fp = correct_fp_drop = leaked_fp = retained_real = lost_real = 0
    for r in records:
        f = r.get("finding", {})
        loc = f.get("location") or {}
        finding = {
            "type": f.get("type"),
            "title": f.get("type"),
            "function": (loc.get("function") if isinstance(loc, dict) else "") or "",
            "severity": f.get("severity", ""),
        }
        verdict = verify(finding, r.get("context", ""), patterns, llm_fn=llm_fn)["verdict"]
        dropped = verdict == "false_positive"  # recall-safe: needs_review is KEPT, not dropped
        if r.get("label") is True:  # real vulnerability
            tot_real += 1
            if dropped:
                lost_real += 1
            else:
                retained_real += 1
        else:  # FP / noise
            tot_fp += 1
            if dropped:
                correct_fp_drop += 1
            else:
                leaked_fp += 1
    kept = retained_real + leaked_fp
    prec_before = tot_real / (tot_real + tot_fp) if (tot_real + tot_fp) else 0.0
    prec_after = retained_real / kept if kept else 0.0
    return {
        "total_real": tot_real,
        "total_fp": tot_fp,
        "fp_dropped": correct_fp_drop,
        "fp_leaked": leaked_fp,
        "real_retained": retained_real,
        "real_lost": lost_real,
        "fp_drop_rate": round(correct_fp_drop / tot_fp, 4) if tot_fp else 0.0,
        "recall_retained": round(retained_real / tot_real, 4) if tot_real else 0.0,
        "precision_before": round(prec_before, 4),
        "precision_after": round(prec_after, 4),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Agentic quality loop (FP + hallucination verifier)")
    ap.add_argument("--demo", action="store_true", help="run on built-in sample contract + findings")
    ap.add_argument("--findings", help="path to a findings JSON (list or {findings:[...]})")
    ap.add_argument("--code", help="path to the contract source")
    ap.add_argument("--benign", help="path to a benign-pattern JSONL (default: latest seed)")
    ap.add_argument("--measure", help="path to a LABELED per-finding JSONL (e.g. data/fp_seed.jsonl)")
    ap.add_argument("--verifier", choices=["rule", "llm"], default="rule")
    ap.add_argument("--model", default="qwen2.5-coder:32b")
    ap.add_argument("--host", default="http://localhost:11434")
    args = ap.parse_args()

    patterns = load_benign_patterns(args.benign)
    print(f"# loaded {len(patterns)} benign patterns | hallucination_detector importable: {_HAS_DETECTOR}\n")

    if args.measure:
        records = [json.loads(line) for line in open(args.measure, encoding="utf-8") if line.strip()]
        llm_fn = make_llm_verifier(args.model, args.host, patterns=patterns) if args.verifier == "llm" else None
        if llm_fn:
            print(f"# verifier: LLM via Ollama ({args.model})\n")
        m = measure(records, patterns, llm_fn=llm_fn)
        print(f"# MEASURE on {args.measure} ({m['total_real']} real + {m['total_fp']} FP/noise)\n")
        print(f"  FP/noise dropped     : {m['fp_dropped']}/{m['total_fp']}  ({m['fp_drop_rate']:.1%})")
        print(f"  FP/noise leaked      : {m['fp_leaked']}/{m['total_fp']}")
        print(f"  real vulns retained  : {m['real_retained']}/{m['total_real']}  (recall {m['recall_retained']:.1%})")
        print(f"  real vulns LOST      : {m['real_lost']}/{m['total_real']}  (false-negative cost)")
        print(f"  precision  before    : {m['precision_before']:.1%}")
        print(f"  precision  after loop: {m['precision_after']:.1%}")
        lift = m["precision_after"] - m["precision_before"]
        print(f"  precision lift       : +{lift:.1%}" if lift >= 0 else f"  precision lift: {lift:.1%}")
        return 0

    if args.demo or not args.findings:
        findings, code = DEMO_FINDINGS, DEMO_CODE
        print("# running DEMO (use --findings/--code for real input)\n")
    else:
        raw = json.load(open(args.findings, encoding="utf-8"))
        findings = raw.get("findings", raw) if isinstance(raw, dict) else raw
        code = open(args.code, encoding="utf-8").read() if args.code else ""

    out = run(findings, code, patterns)
    for r in out["results"]:
        mark = {"confirmed": "[KEEP]", "false_positive": "[FP  ]", "needs_review": "[REVW]"}[r["verdict"]]
        print(f"{mark} {r['title']} ({r['severity']})  votes={r['refute_votes']}")
        for reason in r["reasons"]:
            print(f"        - {reason}")
    print(f"\n# counts: {out['counts']}")
    print(f"# {out['precision_note']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
