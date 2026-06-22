"""
Benign-context verifier — recall-safe false-positive / hallucination filter.

Productionization of the agentic-loop research in
docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md. Given findings + the contract
source, it classifies each finding as:

  - false_positive : the code unambiguously mitigates this finding (benign context)
  - needs_review   : weakly/ambiguously grounded -> FLAG, do not drop
  - confirmed      : keep

CARDINAL RULE — recall-safety: a finding is dropped (false_positive) ONLY on a STRONG
benign signal (a function-scoped/type-determined benign-pattern match, or a recall-safe
LLM judgment). Weak grounding never drops. Measured on a realistic benign-context set:
+28.6pp precision (42.9% -> 71.4%) at ZERO recall loss with an RAG-grounded local LLM;
the rule-only path gives +12.7pp, also at zero recall loss.

Opt-in: the LLM path requires a local Ollama model; without one the rule-only path runs.

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_BENIGN_GLOB = os.path.join(_ROOT, "data", "rag", "benign_patterns_seed_*.jsonl")


def load_benign_patterns(path: Optional[str] = None) -> list[dict[str, Any]]:
    """Load the benign-pattern corpus (latest dated seed by default)."""
    if path is None:
        matches = sorted(glob.glob(_DEFAULT_BENIGN_GLOB))
        if not matches:
            return []
        path = matches[-1]
    out: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).lower()).strip("_")


def _extract_function(code: str, fn: str) -> str:
    """Body of function `fn` (signature..matching brace); '' if absent; whole code if no fn."""
    if not fn or fn in ("unknown", ""):
        return code
    m = re.search(r"function\s+" + re.escape(fn) + r"\b", code)
    if not m:
        return ""
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
    if not fn:
        return ""
    m = re.search(r"function\s+" + re.escape(fn) + r"\b[^{]*", code)
    return m.group(0) if m else ""


def _is_cei(body: str) -> bool:
    call = re.search(r"\.call\{|\.call\(|\.transfer\(|\.send\(", body)
    upd = re.search(r"balances?\[[^\]]*\]\s*[-+]?=", body)
    return bool(upd and call and upd.start() < call.start())


def _timestamp_is_benign(body: str) -> bool:
    if not re.search(r"block\.timestamp|now\b", body):
        return False
    in_entropy = re.search(r"(block\.timestamp|now)\b[^;]*[%]", body) or re.search(
        r"keccak256[^;]*block\.timestamp", body
    )
    in_gate = re.search(r"(require|if)\s*\([^;]*block\.timestamp", body)
    return bool(in_gate and not in_entropy)


def match_benign(finding: dict[str, Any], code: str, patterns: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Return the benign pattern this finding function-scopedly matches, else None."""
    vtype = _norm(finding.get("type") or finding.get("title") or "")
    fn = finding.get("function") or ((finding.get("location") or {}).get("function") if isinstance(finding.get("location"), dict) else "") or ""
    body = _extract_function(code, fn)
    if body == "":
        return None
    sig = _func_signature(code, fn)
    pragma_08 = bool(re.search(r"pragma\s+solidity\s*\^?0\.8", code))
    by_id = {p["id"]: p for p in patterns}

    def has(pid: str) -> Optional[dict[str, Any]]:
        return by_id.get(pid)

    if re.search(r"pragma|naming|visibilit|unused|solc.version|useless_public|constants_instead"
                 r"|instead_of_literal|boolean_equality|constant_functions_assembly|style|lint", vtype):
        return has("BENIGN-PRAGMA-INFORMATIONAL")
    if "arithmetic" in vtype and pragma_08 and "unchecked" not in body:
        return has("BENIGN-ARITHMETIC-0_8")
    if "reentr" in vtype:
        if re.search(r"nonReentrant|ReentrancyGuard", sig):
            return has("BENIGN-REENTRANCY-GUARD")
        if _is_cei(body):
            return has("BENIGN-CEI-ORDER")
    if "access" in vtype and re.search(r"onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner", sig):
        return has("BENIGN-ACCESS-ONLYOWNER")
    if ("time" in vtype or "timestamp" in vtype) and _timestamp_is_benign(body):
        return has("BENIGN-TIMESTAMP-TIMELOCK")
    if "unchecked" in vtype or "low_level" in vtype:
        if re.search(r"safeTransfer|SafeERC20", body):
            return has("BENIGN-SAFEERC20")
        if re.search(r"require\s*\(\s*(ok|success)\b", body):
            return has("BENIGN-CHECKED-CALL")
        if re.search(r"\.transfer\(", body):
            return has("BENIGN-TRANSFER-REVERTS")
    if "front" in vtype and re.search(r"keccak256", code) and re.search(r"commit", code, re.IGNORECASE):
        return has("BENIGN-FRONTRUN-COMMITREVEAL")
    if "short" in vtype and re.search(r"pragma\s+solidity\s*[\^>=]*\s*0\.([5-9]|\d{2})", code):
        return has("BENIGN-SHORTADDR-DEPRECATED")
    return None


class BenignContextVerifier:
    """Recall-safe FP/hallucination verifier. Opt-in LLM grounding via local Ollama."""

    def __init__(
        self,
        model: Optional[str] = None,
        host: str = "http://localhost:11434",
        benign_path: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.patterns = load_benign_patterns(benign_path)
        self.model = model
        self.host = host
        self.timeout = timeout

    # -- LLM grounding (recall-safe, reference-not-directive) -------------------
    def _llm_false_positive(self, finding: dict[str, Any], code: str) -> bool:
        if not self.model:
            return False
        import urllib.request

        vtype = _norm(finding.get("type") or "")
        rel = [p for p in self.patterns if (lambda c: c and (c in vtype or vtype in c))(_norm(p.get("resembles_category", "")))]
        ref = ""
        if rel:
            lines = "\n".join(f"- {p['title']}: {p['why_safe']}" for p in rel[:6])
            ref = ("REFERENCE — known benign mitigations for this category (a finding is a "
                   "false positive ONLY if the code UNAMBIGUOUSLY implements one of these for "
                   "THIS exact finding; if absent/partial/unsure, keep it):\n" + lines + "\n")
        prompt = (
            "You are a smart-contract security verifier. Decide if a reported finding is a "
            "TRUE vulnerability or a FALSE POSITIVE in the context of this contract.\n"
            f"Finding: {finding.get('type')} in function "
            f"'{finding.get('function') or 'unknown'}'.\n{ref}\nContract:\n```solidity\n{code[:6000]}\n```\n"
            'Respond with ONLY: {"false_positive": true|false}. If at all uncertain, answer '
            "false_positive=false (never drop a real vulnerability)."
        )
        try:
            body = json.dumps({"model": self.model, "prompt": prompt, "stream": False,
                               "options": {"temperature": 0}}).encode()
            req = urllib.request.Request(self.host.rstrip("/") + "/api/generate", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = json.loads(r.read()).get("response", "")
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            return bool(m and json.loads(m.group(0)).get("false_positive") is True)
        except Exception:  # noqa: BLE001 - any failure -> recall-safe keep
            return False

    # -- public API ------------------------------------------------------------
    def verify(self, finding: dict[str, Any], code: str) -> str:
        """Return 'false_positive' | 'needs_review' | 'confirmed' (recall-safe)."""
        benign = match_benign(finding, code, self.patterns)
        if benign is not None or self._llm_false_positive(finding, code):
            return "false_positive"
        fn = finding.get("function") or ""
        if fn and fn not in ("unknown", "") and _extract_function(code, fn) == "":
            return "needs_review"  # cited function absent -> flag, do not drop
        return "confirmed"

    def filter(self, findings: list[dict[str, Any]], code: str) -> dict[str, list[dict[str, Any]]]:
        """Split findings into kept / dropped / flagged (recall-safe). 'kept' = report."""
        kept, dropped, flagged = [], [], []
        for f in findings:
            v = self.verify(f, code)
            f = {**f, "verifier_verdict": v}
            (dropped if v == "false_positive" else flagged if v == "needs_review" else kept).append(f)
        return {"kept": kept + flagged, "dropped": dropped, "flagged": flagged, "confirmed": kept}
