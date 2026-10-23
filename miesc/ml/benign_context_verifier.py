"""
Benign-context verifier — recall-safe false-positive / hallucination filter.

Productionization of the agentic-loop research in
docs/research/AGENTIC_RAG_QUALITY_LOOPS_20260621.md. Given findings + the contract
source, it classifies each finding as:

  - false_positive : the code unambiguously mitigates this finding (benign context)
  - needs_review   : weakly/ambiguously grounded -> FLAG, do not drop
  - confirmed      : keep

CARDINAL RULE — recall-safety: a finding is dropped (false_positive) ONLY on a
TYPE-DETERMINISTIC benign pattern — a language/library guarantee or a finding-type fact
(Solidity >=0.8 overflow protection EXCLUDING rounding, informational lint, compiler-
deprecated short-address, checked return value, SafeERC20, reverting .transfer). Two weaker
signals can only FLAG (needs_review), never drop:
  - the LLM (advisory) — on real contracts it reasoned genuine vulns away, losing 3/21
    anchored findings (recall 0.857), so its drop authority was removed;
  - CONTEXTUAL guard patterns (onlyOwner / nonReentrant / CEI / timestamp-timelock /
    commit-reveal) — a guard's PRESENCE is not proof of benignity; a wild eval across
    audit-grade sources (DAppSCAN, Code4rena) showed auditors flag guarded code for subtler
    issues, and these patterns over-dropped real findings.
This was hardened via wild real-data evaluation (docs/research/WILD_FIELD_MEASUREMENT_20260622.md):
recall is now 1.0 across all six ground-truth sources. The earlier +28.6pp LLM-drop figure
came from controlled synthetic pairs and did NOT generalize — that is why it no longer drops.

Opt-in: the advisory LLM path runs on a local Ollama model (default) or a configurable
API provider (OpenAI/GPT, Anthropic/Claude, DeepSeek, Moonshot/Kimi); without one, or
without the provider's key, the rule-only path runs. See ``_VERIFIER_PROVIDERS``.

Author: Fernando Boiero · License: AGPL-3.0
"""

from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Optional, cast

from miesc.core.llm_config import get_ollama_host

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
        return code[m.start() : m.start() + 400]
    depth, i = 0, brace
    while i < len(code):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[m.start() : i + 1]
        i += 1
    return code[m.start() :]


def _func_signature(code: str, fn: str) -> str:
    if not fn:
        return ""
    m = re.search(r"function\s+" + re.escape(fn) + r"\b[^{]*", code)
    return m.group(0) if m else ""


def _function_at_line(code: str, line: int) -> tuple[str, str]:
    """Return (body, signature) of the function whose brace-span contains `line`.

    Real detector findings often carry function='unknown' but a valid line number;
    locating the enclosing function by line lets benign matching stay function-scoped
    (so a guard on the SAME function is detected, without contract-wide over-matching)."""
    try:
        target = int(line)
    except (TypeError, ValueError):
        return "", ""
    for m in re.finditer(r"function\s+\w+\b[^{};]*\{", code):
        brace = code.rindex("{", m.start(), m.end())
        depth, i, end = 0, brace, brace
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
            i += 1
        if code.count("\n", 0, m.start()) + 1 <= target <= code.count("\n", 0, end) + 1:
            return code[m.start() : end + 1], code[m.start() : brace]
    return "", ""


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


# CONTEXTUAL benign patterns: a mitigation is PRESENT (a guard/ordering), but its presence
# does NOT prove the finding benign — professional auditors flag guarded code for subtler
# issues (owner-rug, read-only/cross-function reentrancy). A wild eval across audit-grade
# sources (DAppSCAN, Code4rena) confirmed these over-drop real findings. So they FLAG
# (needs_review), never drop. Only TYPE-DETERMINISTIC patterns below (language/library
# guarantees, finding-type facts) are allowed to drop.
_CONTEXTUAL_BENIGN = {
    "BENIGN-ACCESS-ONLYOWNER",
    "BENIGN-REENTRANCY-GUARD",
    "BENIGN-CEI-ORDER",
    "BENIGN-TIMESTAMP-TIMELOCK",
    "BENIGN-FRONTRUN-COMMITREVEAL",
}


def match_benign(
    finding: dict[str, Any], code: str, patterns: list[dict[str, Any]]
) -> Optional[dict[str, Any]]:
    """Return the benign pattern this finding matches, else None.

    Type-deterministic patterns (finding-type facts / compiler guarantees) are checked first
    and need no function scope; contextual/scope-dependent patterns follow.
    """
    vtype = _norm(finding.get("type") or finding.get("title") or "")
    raw_type = (finding.get("title") or finding.get("check") or finding.get("type") or "").lower()
    by_id = {p["id"]: p for p in patterns}

    def has(pid: str) -> Optional[dict[str, Any]]:
        return by_id.get(pid)

    # --- Type-deterministic, scope-INDEPENDENT (fire regardless of function resolution) ---
    if re.search(
        r"pragma|naming|visibilit|unused|solc.version|useless_public|constants_instead"
        r"|instead_of_literal|boolean_equality|constant_functions_assembly|style|lint"
        r"|missing_event|event_emission|missing.event",
        vtype + " " + raw_type,
    ):
        return has("BENIGN-PRAGMA-INFORMATIONAL")
    # SWC-118 (wrong-constructor-name) is impossible on Solidity >=0.5: the `constructor`
    # keyword is mandatory, so a same-name function is just a regular function. Compiler-
    # guaranteed benign on >=0.5 (validated: 0 real across sources).
    if "constructor" in raw_type and re.search(
        r"pragma\s+solidity\s*[\^>=]*\s*0\.([5-9]|\d{2})", code
    ):
        return has("BENIGN-CONSTRUCTOR-MODERN")

    # --- Scope-dependent patterns need the enclosing function ---
    _loc = finding.get("location")
    loc = _loc if isinstance(_loc, dict) else {}
    fn = finding.get("function") or loc.get("function") or ""
    line = loc.get("line")
    if fn and fn not in ("unknown", ""):
        body, sig = _extract_function(code, fn), _func_signature(code, fn)
    elif line:
        body, sig = _function_at_line(code, line)  # scope by line when fn is 'unknown'
    else:
        body, sig = code, ""  # no scope available -> whole code, no signature
    if body == "":
        return None
    pragma_08 = bool(re.search(r"pragma\s+solidity\s*\^?0\.8", code))
    # Solidity >=0.8 guarantees overflow/underflow reverts ONLY — it does NOT prevent
    # precision/rounding loss (mul-before-div, integer truncation). A wild eval saw a real
    # rounding bug dropped here; never treat rounding/division findings as 0.8-benign.
    is_rounding = bool(re.search(r"round|divi|precision|truncat", raw_type))
    if "arithmetic" in vtype and pragma_08 and "unchecked" not in body and not is_rounding:
        return has("BENIGN-ARITHMETIC-0_8")
    if "reentr" in vtype:
        if re.search(r"nonReentrant|ReentrancyGuard", sig):
            return has("BENIGN-REENTRANCY-GUARD")
        if _is_cei(body):
            return has("BENIGN-CEI-ORDER")
    if "access" in vtype and re.search(
        r"onlyOwner|onlyRole|require\s*\(\s*msg\.sender\s*==\s*owner", sig
    ):
        return has("BENIGN-ACCESS-ONLYOWNER")
    if ("time" in vtype or "timestamp" in vtype) and _timestamp_is_benign(body):
        return has("BENIGN-TIMESTAMP-TIMELOCK")
    if "unchecked" in vtype or "low_level" in vtype:
        # Scope to the FLAGGED call line, not the whole function: a .transfer()/require()
        # elsewhere does NOT make THIS .call()/.send() benign. (A wild eval at scale caught
        # real unchecked .call()/.send() vulns dropped because the function held a .transfer.)
        lines_arr = code.splitlines()
        if isinstance(line, int) and 1 <= line <= len(lines_arr):
            scope = lines_arr[line - 1]
            window = " ".join(lines_arr[line - 1 : line + 2])
        else:
            scope = window = body  # no line -> fall back to function body
        if re.search(r"safeTransfer|SafeERC20", scope):
            return has("BENIGN-SAFEERC20")
        # Native address.transfer(amount) reverts on failure -> benign. But ERC20
        # token.transfer(to, amount) returns a bool and many tokens fail silently (SWC-104),
        # so an unchecked ERC20 transfer is a REAL vuln. Distinguish by the 2-arg ERC20
        # signature (a comma in the transfer args) and only treat the 1-arg native form as
        # benign. (A wild eval at scale caught 7 real ERC20-transfer vulns dropped here.)
        if (
            re.search(r"\.transfer\(", scope)
            and not re.search(r"\.transfer\([^)]*,", scope)  # exclude ERC20 2-arg transfer
            and not re.search(r"\.send\(|\.call\b", scope)
        ):
            return has("BENIGN-TRANSFER-REVERTS")
        if re.search(r"require\s*\(\s*(ok|success)\b", window):
            return has("BENIGN-CHECKED-CALL")
    if (
        "front" in vtype
        and re.search(r"keccak256", code)
        and re.search(r"commit", code, re.IGNORECASE)
    ):
        return has("BENIGN-FRONTRUN-COMMITREVEAL")
    if "short" in vtype and re.search(r"pragma\s+solidity\s*[\^>=]*\s*0\.([5-9]|\d{2})", code):
        return has("BENIGN-SHORTADDR-DEPRECATED")
    return None


# -- Configurable verifier LLM providers -------------------------------------------
# The advisory LLM pass can run on a local Ollama model (default, free, reproducible)
# or on any configured API provider. Each API provider is reached with the same
# dependency-free urllib path already used for the DeepSeek failover; a missing key or
# any error returns '' which the caller treats as a recall-safe KEEP (never a drop).
#
# provider -> (api_style, api-key env vars, base-url env, default base-url, chat path,
#              model env, default model)
_VERIFIER_PROVIDERS: dict[str, tuple[str, tuple[str, ...], str, str, str, str, str]] = {
    "deepseek": (
        "openai",
        ("DEEPSEEK_API_KEY",),
        "DEEPSEEK_BASE_URL",
        "https://api.deepseek.com",
        "/chat/completions",
        "DEEPSEEK_MODEL",
        "deepseek-chat",
    ),
    "openai": (
        "openai",
        ("OPENAI_API_KEY",),
        "OPENAI_BASE_URL",
        "https://api.openai.com",
        "/v1/chat/completions",
        "MIESC_VERIFY_OPENAI_MODEL",
        "gpt-4o-mini",
    ),
    "kimi": (
        "openai",
        ("KIMI_API_KEY", "MOONSHOT_API_KEY"),
        "KIMI_BASE_URL",
        "https://api.moonshot.ai",
        "/v1/chat/completions",
        "KIMI_MODEL",
        "moonshot-v1-8k",
    ),
    "anthropic": (
        "anthropic",
        ("ANTHROPIC_API_KEY",),
        "ANTHROPIC_BASE_URL",
        "https://api.anthropic.com",
        "/v1/messages",
        "MIESC_VERIFY_ANTHROPIC_MODEL",
        "claude-3-5-sonnet-latest",
    ),
}

#: Spoken aliases accepted on the CLI / config -> canonical provider key above.
_PROVIDER_ALIASES: dict[str, str] = {
    "gpt": "openai",
    "openai": "openai",
    "claude": "anthropic",
    "anthropic": "anthropic",
    "kimi": "kimi",
    "moonshot": "kimi",
    "deepseek": "deepseek",
}


def _parse_verifier_model(model: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Resolve a verify-model string to ``(provider, model_name)``.

    Accepts ``provider`` or ``provider:model`` (e.g. ``gpt``, ``claude:claude-3-5-sonnet``,
    ``ollama:qwen2.5-coder:32b``). A bare string that is not a known provider alias is
    treated as an Ollama model name (backward compatible). ``(None, None)`` disables the
    LLM pass.
    """
    if not model:
        return None, None
    raw = model.strip()
    head, sep, tail = raw.partition(":")
    hl = head.lower()
    if sep:
        if hl in _PROVIDER_ALIASES:
            return _PROVIDER_ALIASES[hl], (tail or None)
        if hl == "ollama":
            return "ollama", tail or None
    if raw.lower() in _PROVIDER_ALIASES:
        return _PROVIDER_ALIASES[raw.lower()], None
    return "ollama", raw


class BenignContextVerifier:
    """Recall-safe FP/hallucination verifier.

    Opt-in LLM grounding runs on a local Ollama model (default, free, reproducible) or on
    a configurable API provider (OpenAI/GPT, Anthropic/Claude, DeepSeek, Moonshot/Kimi),
    selected by the ``model`` string. The LLM is always ADVISORY — it can only FLAG
    (needs_review), never drop.
    """

    def __init__(
        self,
        model: Optional[str] = None,
        host: Optional[str] = None,
        benign_path: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.patterns = load_benign_patterns(benign_path)
        self.model = model
        # Resolve the Ollama host as the LLM adapters do (OLLAMA_HOST env, then config,
        # then localhost) so Docker/remote daemons are reachable, not silently skipped.
        self.host = host or get_ollama_host()
        self.timeout = timeout

    # -- LLM grounding (recall-safe, reference-not-directive) -------------------
    def _llm_false_positive(self, finding: dict[str, Any], code: str) -> bool:
        if not self.model:
            return False
        vtype = _norm(finding.get("type") or "")
        rel = [
            p
            for p in self.patterns
            if (lambda c: c and (c in vtype or vtype in c))(_norm(p.get("resembles_category", "")))
        ]
        ref = ""
        if rel:
            lines = "\n".join(f"- {p['title']}: {p['why_safe']}" for p in rel[:6])
            ref = (
                "REFERENCE — known benign mitigations for this category (a finding is a "
                "false positive ONLY if the code UNAMBIGUOUSLY implements one of these for "
                "THIS exact finding; if absent/partial/unsure, keep it):\n" + lines + "\n"
            )
        prompt = (
            "You are a smart-contract security verifier. Decide if a reported finding is a "
            "TRUE vulnerability or a FALSE POSITIVE in the context of this contract.\n"
            f"Finding: {finding.get('type')} in function "
            f"'{finding.get('function') or 'unknown'}'.\n{ref}\nContract:\n```solidity\n{code[:6000]}\n```\n"
            'Respond with ONLY: {"false_positive": true|false}. If at all uncertain, answer '
            "false_positive=false (never drop a real vulnerability)."
        )
        raw = self._query(prompt)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return bool(m and json.loads(m.group(0)).get("false_positive") is True)

    def _query(self, prompt: str) -> str:
        """Route the advisory prompt to the configured provider. '' on any failure.

        Provider is derived from ``self.model`` by :func:`_parse_verifier_model`:

        - ``ollama:<m>`` / bare name -> local Ollama; on failure (e.g. Ollama down) AND
          ``DEEPSEEK_API_KEY`` set -> automatic DeepSeek failover (backward compatible).
        - ``deepseek[:<m>]``         -> DeepSeek API (OpenAI-compatible).
        - ``gpt``/``openai[:<m>]``   -> OpenAI API (``OPENAI_API_KEY``).
        - ``claude``/``anthropic[:<m>]`` -> Anthropic Messages API (``ANTHROPIC_API_KEY``).
        - ``kimi``/``moonshot[:<m>]``    -> Moonshot API (OpenAI-compatible).

        Any failure or missing key returns '' which the caller treats as recall-safe KEEP.
        """
        provider, name = _parse_verifier_model(self.model)
        if provider is None:
            return ""
        if provider == "ollama":
            out = self._query_ollama(name or "", prompt)
            # backward-compatible failover: Ollama down -> DeepSeek if a key is set
            return out or self._query_openai_compatible("deepseek", prompt)
        if provider == "anthropic":
            return self._query_anthropic(prompt, model=name)
        return self._query_openai_compatible(provider, prompt, model=name)

    def _query_ollama(self, model: str, prompt: str) -> str:
        """Local Ollama generate call. '' on any failure (recall-safe KEEP)."""
        if not model:
            return ""
        import urllib.request

        try:
            body = json.dumps(
                {"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0}}
            ).encode()
            req = urllib.request.Request(
                self.host.rstrip("/") + "/api/generate",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return cast(str, json.loads(r.read()).get("response", ""))
        except Exception:  # noqa: BLE001 - recall-safe: failure -> keep
            return ""

    def _query_openai_compatible(
        self, provider: str, prompt: str, model: Optional[str] = None
    ) -> str:
        """OpenAI-style chat/completions call (OpenAI, DeepSeek, Moonshot/Kimi)."""
        import urllib.request

        _, key_envs, base_env, base_default, chat_path, model_env, model_default = (
            _VERIFIER_PROVIDERS[provider]
        )
        key = next((os.environ[k] for k in key_envs if os.environ.get(k)), "")
        if not key:
            return ""
        base = os.environ.get(base_env, base_default).rstrip("/")
        mdl = model or os.environ.get(model_env) or model_default
        try:
            body = json.dumps(
                {
                    "model": mdl,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0,
                    "stream": False,
                }
            ).encode()
            req = urllib.request.Request(
                base + chat_path,
                data=body,
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return cast(str, json.loads(r.read())["choices"][0]["message"]["content"])
        except Exception:  # noqa: BLE001 - recall-safe: failure -> keep
            return ""

    def _query_anthropic(self, prompt: str, model: Optional[str] = None) -> str:
        """Anthropic Messages API call. '' on any failure (recall-safe KEEP)."""
        import urllib.request

        _, key_envs, base_env, base_default, chat_path, model_env, model_default = (
            _VERIFIER_PROVIDERS["anthropic"]
        )
        key = next((os.environ[k] for k in key_envs if os.environ.get(k)), "")
        if not key:
            return ""
        base = os.environ.get(base_env, base_default).rstrip("/")
        mdl = model or os.environ.get(model_env) or model_default
        try:
            body = json.dumps(
                {
                    "model": mdl,
                    "max_tokens": 512,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode()
            req = urllib.request.Request(
                base + chat_path,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                parts = json.loads(r.read()).get("content", [])
                return cast(str, parts[0].get("text", "")) if parts else ""
        except Exception:  # noqa: BLE001 - recall-safe: failure -> keep
            return ""

    # -- public API ------------------------------------------------------------
    def verify(self, finding: dict[str, Any], code: str) -> str:
        """Return 'false_positive' | 'needs_review' | 'confirmed' (recall-safe).

        DROP (false_positive) only on the deterministic, function-scoped benign-pattern
        match. The LLM is ADVISORY: a real-data evaluation (see
        docs/research/WILD_BENIGN_CONTEXT_EVAL_INSTRUCTIONS.md) showed it reasons genuine
        vulns away on complex contracts (lost 3/21 anchored real findings), so an LLM
        "false_positive" only FLAGS (needs_review) — it can never drop a finding.
        """
        benign = match_benign(finding, code, self.patterns)
        if benign is not None:
            # contextual mitigations (guards) only FLAG; type-deterministic patterns drop
            return "needs_review" if benign["id"] in _CONTEXTUAL_BENIGN else "false_positive"
        _loc = finding.get("location")
        loc = _loc if isinstance(_loc, dict) else {}
        fn = finding.get("function") or loc.get("function") or ""
        if fn and fn not in ("unknown", "") and _extract_function(code, fn) == "":
            return "needs_review"  # cited function absent -> flag, do not drop
        if self._llm_false_positive(finding, code):
            return "needs_review"  # LLM suspects benign -> FLAG for human review, never drop
        return "confirmed"

    def filter(self, findings: list[dict[str, Any]], code: str) -> dict[str, list[dict[str, Any]]]:
        """Split findings into kept / dropped / flagged (recall-safe). 'kept' = report."""
        kept: list[dict[str, Any]] = []
        dropped: list[dict[str, Any]] = []
        flagged: list[dict[str, Any]] = []
        for f in findings:
            v = self.verify(f, code)
            f = {**f, "verifier_verdict": v}
            (dropped if v == "false_positive" else flagged if v == "needs_review" else kept).append(
                f
            )
        return {"kept": kept + flagged, "dropped": dropped, "flagged": flagged, "confirmed": kept}


def apply_to_results(
    all_results: list[dict[str, Any]], *, contract: str = "", model: str | None = None
) -> tuple[int, int]:
    """Recall-safe verify, in place over a [{tool, findings:[...]}] result list.

    Shared by `miesc scan --verify-fp` and `miesc audit ... --verify-fp`. Reads each
    finding's contract code (from finding['file'], result['contract'], or `contract`),
    drops only false_positive verdicts, keeps confirmed + needs_review. Returns
    (dropped_count, flagged_count)."""
    verifier = BenignContextVerifier(model=model)
    code_cache: dict[str, str] = {}

    def _code(fp: str) -> str:
        if fp not in code_cache:
            try:
                code_cache[fp] = (
                    open(fp, encoding="utf-8").read() if fp and os.path.isfile(fp) else ""
                )
            except Exception:
                code_cache[fp] = ""
        return code_cache[fp]

    dropped = flagged = 0
    for result in all_results:
        kept: list[dict[str, Any]] = []
        for f in result.get("findings", []):
            fp = f.get("file") or result.get("contract") or contract
            verdict = verifier.verify(f, _code(fp))
            f["verifier_verdict"] = verdict
            if verdict == "false_positive":
                dropped += 1
            else:
                if verdict == "needs_review":
                    flagged += 1
                kept.append(f)
        result["findings"] = kept
    return dropped, flagged
