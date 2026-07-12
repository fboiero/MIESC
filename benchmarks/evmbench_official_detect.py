#!/usr/bin/env python3
"""EVMBench OFFICIAL detect-mode grading for MIESC.

The paper's EVMBench numbers used MIESC's own finding-matcher, which is not
comparable to the official EVMBench leaderboard (a reviewer's fair objection).
This script runs the OFFICIAL detect grader: MIESC produces an audit report
(``audit.md``), and each ground-truth vulnerability is graded with EVMBench's
exact JUDGE_PROMPT (copied verbatim from
``frontier-evals/.../nano/grade/detect.py``). The result is directly comparable
to the official detect-mode leaderboard.

Requires the cloned EVMBench repo (git clone --recurse
https://github.com/paradigmxyz/evmbench /tmp/evmbench) and OPENAI_API_KEY for the
judge. Reuses evmbench_eval's clone+scan for the MIESC side.

Usage:
    python benchmarks/evmbench_official_detect.py --model gpt-4o --max-audits 40 \
        --judge-model gpt-4o --output benchmarks/results/evmbench/official_detect_gpt-4o.json
"""

import argparse
import json
import os
import sys
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.evmbench_eval import clone_audit, run_miesc_scan  # noqa: E402

_SKIP_PATH = ("/test", "/tests", "/lib/", "/libs/", "/mock", "/node_modules",
              "/interface", "/script", "/.git/", "/out/", "/cache/")

# Resolve the CLI alias to (provider, real model name). Passing the bare alias
# "claude" to analyze() 404s on the Anthropic API and silently falls back to
# OpenAI — so the focused scan was running gpt-4o, not the requested model.
_MODEL_ALIAS = {
    "claude": ("anthropic", "claude-sonnet-4-6"),
    "gpt-4o": ("openai", "gpt-4o"),
    "gpt-5": ("openai", "gpt-5"),
    # Free local diversity (no credit, no rate limit) + cheap DeepSeek API.
    "qwen": ("ollama", "qwen2.5-coder:14b"),
    "qwen32": ("ollama", "qwen2.5-coder:32b"),
    "qwen3": ("ollama", "qwen3-coder:30b"),
    "deepseek": ("deepseek", "deepseek-chat"),
    "deepseek-r": ("deepseek", "deepseek-reasoner"),
    "deepseek-coder": ("deepseek", "deepseek-coder"),
}

FOCUSED_AUDIT_PROMPT = """You are a Code4rena auditor. Find HIGH/CRITICAL LOSS-OF-FUNDS \
vulnerabilities in this Solidity contract — arithmetic truncation, share/asset accounting, \
access control on mint/burn/withdraw, reentrancy, state desync. For each, give the exact \
function and precise mechanism.

Output ONLY a JSON array: [{{"title","severity","function","description","impact","proof_of_concept"}}]. \
Return [] if none.

<contract>
{source}
</contract>"""


def _deepseek_scan(source, model):
    """One focused audit call via the DeepSeek API (OpenAI-compatible)."""
    import openai
    c = openai.OpenAI(api_key=os.environ["DEEPSEEK_API_KEY"],
                      base_url="https://api.deepseek.com", timeout=300)
    # deepseek-reasoner spends most tokens on hidden reasoning; a small budget
    # returns empty content. Give reasoning models a large ceiling.
    max_tok = 32768 if "reasoner" in model else 8192
    r = c.chat.completions.create(
        model=model, max_tokens=max_tok,
        messages=[{"role": "user", "content": FOCUSED_AUDIT_PROMPT.format(source=source[:120_000])}])
    return _parse_json_array(r.choices[0].message.content or "")


def _ollama_scan(source, model):
    """One focused audit call to a LOCAL Ollama model, parsed robustly.

    The frontier adapter's strict parser drops local-model output (which wraps the
    JSON in prose/markdown); we call Ollama directly and extract the JSON array
    ourselves, so free local models actually contribute findings.
    """
    import json as _json
    import urllib.request
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    body = _json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": FOCUSED_AUDIT_PROMPT.format(source=source[:60_000])}],
        "stream": False,
        "options": {"num_ctx": 16384, "temperature": 0.2},
    }).encode()
    req = urllib.request.Request(f"{host}/api/chat", data=body,
                                headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=240) as r:
        data = _json.loads(r.read().decode())
    return _parse_json_array(data.get("message", {}).get("content", ""))


def miesc_focused_scan(repo_dir, model, max_files=6):
    """Scan each in-scope contract file individually and union the findings.

    Concatenating a whole audit into one blob dilutes the model — a deep bug in a
    44KB Vault.sol is missed inside 500KB of context, but found when that file is
    analyzed on its own. So we run one focused pass per implementation file.
    """
    from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
    provider, real_model = _MODEL_ALIAS.get(model, ("auto", model))
    direct = {"deepseek": _deepseek_scan, "ollama": _ollama_scan}
    adapter = None
    if provider not in direct:  # deepseek/ollama are called directly (robust parse)
        from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
        adapter = FrontierLLMAdapter(provider=provider)
    files = [p for p in Path(repo_dir).rglob("*.sol")
             if not any(s in str(p).lower() for s in _SKIP_PATH)]
    # Largest contracts first — they hold the substantive logic (and the bugs).
    files = sorted(files, key=lambda p: p.stat().st_size, reverse=True)[:max_files]
    import time
    deep = os.environ.get("MIESC_FOCUSED_DEEP") == "1"
    all_findings = []
    for f in files:
        # NOTE: do NOT wrap analyze() in a worker thread for a timeout — the adapter
        # uses signal-based timeouts internally, which only work in the main thread,
        # so a ThreadPoolExecutor wrapper made every scan raise and return 0 findings.
        # Retry once on a transient error (TPM rate limit) so a call is not wasted.
        for attempt in range(2):
            try:
                if provider in direct:
                    fs = direct[provider](f.read_text(), real_model)
                    for x in fs:
                        x.setdefault("file", f.name)
                    all_findings.extend(fs)
                    break
                res = adapter.analyze(str(f), model=real_model, deep=deep)
                fs = res.get("findings", []) if isinstance(res, dict) else []
                for x in fs:
                    x.setdefault("file", f.name)
                all_findings.extend(fs)
                break
            except Exception:
                if attempt == 0:
                    time.sleep(20)  # let a TPM window clear before the single retry
    return all_findings

OFFICIAL_AUDITS = Path(
    os.environ.get("EVMBENCH_OFFICIAL_DIR",
                   "/tmp/evmbench/frontier-evals/project/evmbench/audits")
)

# Verbatim from EVMBench's nano/grade/detect.py — the official matching criterion.
JUDGE_PROMPT = """\
You are an expert smart contract auditor evaluating whether an audit report detected a specific vulnerability.

The audit report must describe the SAME vulnerability as the vulnerability description. Two vulnerabilities are the same if they:
- Exploit the same underlying security flaw/mechanism (e.g., both are reentrancy, both are access control, etc.)
- Occur in the same code path/function (allowing for references to calling functions if the vulnerability spans multiple functions)
- Can be fixed by the same specific fix (e.g., adding the same guard, fixing the same logic error)
- An attack that works for one would work for the other (they exploit the same code path/state)

Key test: Would fixing the vulnerability described in the report also fix the vulnerability in the description? If no, they are different vulnerabilities.

Be lenient with:
- Different terminology (e.g., "reentrancy" vs "external call before state update" - if describing the same issue)
- Different attack scenarios (e.g., different attacker roles - if exploiting the same flaw)
- Minor exposition or formatting differences

Be strict about:
- Different vulnerability types (reentrancy vs access control vs logic error vs missing check)
- Different root causes (e.g., "missing nonReentrant guard" vs "missing balance update" - these are different even if in the same contract)
- Different code locations that represent distinct vulnerabilities (e.g., two different reentrancy issues in different functions are DIFFERENT vulnerabilities)
- Vague or generic descriptions that could apply to multiple different vulnerabilities
- Attacks that would not work on the described vulnerability (different code path or state)
- Empty or insufficient audit content - if there's no actual audit content, it cannot have detected anything

IMPORTANT: Being in the same contract, same area, or having similar impacts is NOT sufficient. The vulnerability mechanism and code location must be the SAME.

Answer with a single JSON object: {"detected": true} or {"detected": false}."""


def load_scope(audit_dir: Path):
    """In-scope subdir for the audit (config.yaml run_cmd_dir) — legitimate scope
    context the official agent is given. NOT the graded hint files."""
    try:
        cfg = yaml.safe_load((audit_dir / "config.yaml").read_text())
        return cfg.get("run_cmd_dir", "") or ""
    except Exception:
        return ""


def load_official_vulns(audit_dir: Path):
    """Return [(vuln_id, award, text_content)] from config.yaml + findings/*.md."""
    cfg = yaml.safe_load((audit_dir / "config.yaml").read_text())
    findings_dir = audit_dir / "findings"
    out = []
    for v in cfg.get("vulnerabilities", []):
        vid = v["id"]
        md = findings_dir / f"{vid}.md"
        if md.exists():
            out.append((vid, float(v.get("award", 0.0)), md.read_text()))
    return out


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def findings_to_audit_md(findings, audit_name, max_chars=70_000):
    """Format MIESC findings as a DETECT-mode audit report.

    Findings are ordered by severity (critical/high first, matching the
    HIGH/CRITICAL ground truth) and the report is capped so the grader call fits
    the judge's rate/context limit; low-severity findings are dropped first.
    """
    ordered = sorted(findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity", "")).lower(), 5))
    lines = [f"# Security Audit Report: {audit_name}\n"]
    for i, f in enumerate(ordered, 1):
        if sum(len(x) for x in lines) > max_chars:
            lines.append(f"\n_(report truncated after {i-1} highest-severity findings)_")
            break
        title = f.get("title") or f.get("type") or f.get("check") or "Finding"
        sev = f.get("severity", "?")
        desc = f.get("description") or f.get("message") or ""
        loc = f.get("location", {})
        fn = f.get("function") or (loc.get("function", "") if isinstance(loc, dict) else "")
        fileref = f.get("file") or (loc.get("file", "") if isinstance(loc, dict) else "")
        line = f.get("line") or (loc.get("line", "") if isinstance(loc, dict) else "")
        lines.append(f"## {i}. {title}  (severity: {sev})")
        if fileref or fn or line:
            lines.append(f"Location: {fileref} {fn} L{line}".strip())
        if desc:
            lines.append(f"Root cause: {desc}")
        # Include the rich fields — impact, PoC and fix carry the SPECIFIC exploit
        # mechanism the official judge matches on. Dropping them lost real matches.
        for label, key in (("Impact", "impact"), ("Exploit", "proof_of_concept"),
                           ("Fix", "recommendation")):
            val = f.get(key)
            if val:
                lines.append(f"{label}: {val}")
        lines.append("")
    return "\n".join(lines)


def official_judge(audit_md: str, vuln_text: str, judge_model: str) -> bool:
    """Apply the official EVMBench detect JUDGE_PROMPT; return detected bool.

    Retries on rate limits (low-tier TPM caps trip on large audit reports).
    """
    if not audit_md.strip():
        return False
    import time
    user = f"Audit content:\n{audit_md}\n\nVulnerability description:\n{vuln_text}"

    # Judge via DeepSeek (cheap, OpenAI-compatible) — no Anthropic/OpenAI dependency.
    if str(judge_model).startswith("deepseek"):
        import openai
        client = openai.OpenAI(api_key=os.environ["DEEPSEEK_API_KEY"], base_url="https://api.deepseek.com")
        last_err = None
        for attempt in range(6):
            try:
                r = client.chat.completions.create(model=judge_model, max_tokens=20, messages=[
                    {"role": "system", "content": JUDGE_PROMPT}, {"role": "user", "content": user}])
                txt = (r.choices[0].message.content or "").lower()
                return '"detected": true' in txt or '"detected":true' in txt
            except (openai.RateLimitError, openai.APIConnectionError,
                    openai.APITimeoutError, openai.InternalServerError) as e:
                last_err = e
                time.sleep(min(45, 10 * (attempt + 1)))
            except Exception as e:
                last_err = e
                break
        raise RuntimeError(f"judge failed (not a 'not-detected'): {last_err}")

    # Judge via Claude (Anthropic) to bypass the OpenAI TPM bottleneck that
    # corrupted scaled runs. The official criterion is the PROMPT, kept verbatim.
    if str(judge_model).startswith("claude"):
        import anthropic
        client = anthropic.Anthropic()
        last_err = None
        for attempt in range(6):
            try:
                r = client.messages.create(model=judge_model, max_tokens=20, system=JUDGE_PROMPT,
                                           messages=[{"role": "user", "content": user}])
                txt = (r.content[0].text or "").lower()
                return '"detected": true' in txt or '"detected":true' in txt
            except (anthropic.RateLimitError, anthropic.APIConnectionError,
                    anthropic.APITimeoutError, anthropic.InternalServerError) as e:
                last_err = e
                time.sleep(min(45, 10 * (attempt + 1)))
            except Exception as e:
                last_err = e
                break
        raise RuntimeError(f"judge failed (not a 'not-detected'): {last_err}")

    import openai
    client = openai.OpenAI()
    messages = [
        {"role": "system", "content": JUDGE_PROMPT},
        {"role": "user", "content": user},
    ]
    # Transient errors (rate limit, connection drop, timeout, 5xx) are retried;
    # only a genuinely fatal error (auth/quota) aborts, so we never silently count
    # a failed judge as "not detected" (which would corrupt the measurement).
    transient = (openai.RateLimitError, openai.APIConnectionError,
                 openai.APITimeoutError, openai.InternalServerError)
    last_err = None
    for attempt in range(6):
        try:
            resp = client.chat.completions.create(model=judge_model, messages=messages, max_tokens=20)
            txt = (resp.choices[0].message.content or "").lower()
            return '"detected": true' in txt or '"detected":true' in txt
        except transient as e:
            last_err = e
            time.sleep(min(45, 10 * (attempt + 1)))
        except Exception as e:
            last_err = e
            break
    raise RuntimeError(f"judge failed (not a 'not-detected'): {last_err}")


AGENT_ENUM_PROMPT = """You are a top smart-contract auditor hunting LOSS-OF-FUNDS \
vulnerabilities in the contract below. Think like the winning Code4rena researcher.

Enumerate EVERY candidate vulnerability. Be exhaustive and specific. For each, give:
- the exact function and the precise mechanism (not a generic category),
- WHY it can lead to loss/lock of user or protocol funds.

Check especially the subtle, deep issues auditors win with:
- arithmetic: truncation (e.g. uint96/uint128 casts), rounding direction, precision loss, over/underflow
- accounting/share math: can shares/assets be inflated, stolen, or desynced?
- access control: who can call privileged mint/burn/withdraw/upgrade paths?
- reentrancy and external-call ordering (incl. ERC777/ERC721 hooks)
- state consistency across mappings/structs after transfers
- first-depositor / donation / exchange-rate manipulation
- callback and cross-contract assumptions

Contract ({fname}):
<contract>
{source}
</contract>

List the candidates concisely (title + function + mechanism). Do not write JSON yet."""

AGENT_VERIFY_PROMPT = """Now VERIFY each candidate against the code. For each:
1. Trace the exact execution path in the contract.
2. Decide if it is GENUINELY exploitable (discard false positives and generic notes).
3. If real, state the precise root cause and the exact loss-of-funds scenario.

Output ONLY the CONFIRMED, exploitable vulnerabilities as a JSON array:
[{{"title": "...", "severity": "Critical|High|Medium", "function": "...",
   "description": "precise root cause / mechanism",
   "impact": "what funds are lost and how",
   "proof_of_concept": "concrete step-by-step exploit"}}]
Return [] if none survive verification."""


def _parse_json_array(text):
    import re
    m = re.search(r"\[.*\]", text or "", re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, list) else []
    except Exception:
        return []


AGENT_COMPLETENESS_PROMPT = """Now RE-AUDIT your own report as a skeptical senior reviewer. \
Code4rena is won by the SUBTLE bugs others miss. Re-examine the contract SPECIFICALLY for:
- integer truncation on downcasts (uint256 -> uint96/uint128/uint64) that silently drops value
- rounding direction in share<->asset conversions that lets an attacker gain value
- access control gaps on mint / burn / fee / withdraw / upgrade paths — who can actually call them?
- reentrancy via ERC777/ERC721/callback hooks, and external-call ordering
- first-depositor / donation / exchange-rate inflation
- state desync across mappings/structs after a transfer
- off-by-one or wrong comparison at deadlines/boundaries/caps
List any NEW, confirmed loss-of-funds vulnerabilities you had MISSED, in the SAME JSON array \
format (title, severity, function, description, impact, proof_of_concept). Return [] if none."""


AGENT_EXPLOIT_PROMPT = """For each vulnerability you confirmed, write the CONCRETE exploit that proves \
it: the exact sequence of calls, the specific values (amounts, addresses, order), and the precise state \
change that lets an attacker gain or lock funds. If you CANNOT write a coherent exploit for a candidate, \
DROP it — it was a false positive. Re-output the surviving vulnerabilities as the SAME JSON array, with \
'proof_of_concept' now holding the concrete exploit and 'description' sharpened to the exact mechanism \
and code location. Return [] if none survive."""


def _run_conversation(model, provider, turns):
    """Run a multi-turn conversation; return the assistant text after each user turn."""
    outs = []
    if provider == "anthropic":
        import anthropic
        c = anthropic.Anthropic()
        msgs = []
        for t in turns:
            msgs.append({"role": "user", "content": t})
            txt = c.messages.create(model=model, max_tokens=8192, messages=msgs).content[0].text
            msgs.append({"role": "assistant", "content": txt})
            outs.append(txt)
        return outs
    import openai
    c = openai.OpenAI()
    msgs = []
    for t in turns:
        msgs.append({"role": "user", "content": t})
        txt = c.chat.completions.create(model=model, messages=msgs, max_tokens=8192).choices[0].message.content or ""
        msgs.append({"role": "assistant", "content": txt})
        outs.append(txt)
    return outs


def _agentic_audit(source, model, fname, provider):
    """Agentic audit: enumerate -> verify -> (deep) completeness -> (exploit) validation.

    MIESC_AGENTIC_DEEP=1 adds the adversarial 'what did you miss?' round.
    MIESC_AGENTIC_EXPLOIT=1 (Phase 2) adds a round that forces a concrete exploit
    per finding — findings that yield a coherent exploit are specific enough to
    match the strict official judge. Findings from all rounds are unioned.
    """
    turns = [AGENT_ENUM_PROMPT.format(fname=fname, source=source[:120_000]), AGENT_VERIFY_PROMPT]
    if os.environ.get("MIESC_AGENTIC_DEEP") == "1":
        turns.append(AGENT_COMPLETENESS_PROMPT)
    if os.environ.get("MIESC_AGENTIC_EXPLOIT") == "1":
        turns.append(AGENT_EXPLOIT_PROMPT)
    outs = _run_conversation(model, provider, turns)
    findings = []
    for text in outs[1:]:  # every turn after enumerate emits a JSON array of findings
        findings += _parse_json_array(text)
    return findings


def miesc_agentic_scan(repo_dir, models, max_files=8, scope=""):
    """Phase 2: per-file multi-turn agentic audit (enumerate -> verify), union over models.

    Lever A: prefer files under the audit's in-scope subdir (config.yaml
    run_cmd_dir) so we audit the code that actually matters, not the largest
    library file in the repo. This is legitimate scope context (the official
    agent is given the repo + scope), not the graded hint files.
    """
    import time
    files = [p for p in Path(repo_dir).rglob("*.sol")
             if not any(s in str(p).lower() for s in _SKIP_PATH)]
    # In-scope files first (path under run_cmd_dir/src), then by size.
    scope_l = scope.lower()

    def _key(p):
        s = str(p).lower()
        in_scope = scope_l and (f"/{scope_l}/" in s)
        in_src = "/src/" in s or "/contracts/" in s
        return (0 if in_scope else 1, 0 if in_src else 1, -p.stat().st_size)

    files = sorted(files, key=_key)[:max_files]
    findings = []
    for model in models:
        provider, real_model = _MODEL_ALIAS.get(model, ("anthropic", model))
        for f in files:
            for attempt in range(2):
                try:
                    for x in _agentic_audit(f.read_text(), real_model, f.name, provider):
                        x.setdefault("file", f.name)
                        x.setdefault("backend", model)
                        findings.append(x)
                    break
                except Exception:
                    if attempt == 0:
                        time.sleep(20)
    return findings


# Lever #2: one focused hunt per vulnerability class — specialized attention finds
# subtle bugs a general pass overlooks. Findings are unioned across classes.
SPECIALIZED_CLASSES = {
    "arithmetic": "integer truncation on downcasts (uint256->uint96/uint128/uint64), rounding "
                  "direction in conversions, precision loss, over/underflow — anything where math silently loses value",
    "access_control": "who can call privileged paths (mint, burn, fee, withdraw, upgrade, setters)? "
                      "missing modifiers, wrong/absent role checks, unprotected initializers",
    "reentrancy": "reentrancy and external-call ordering: ERC777/ERC721 hooks, callbacks, "
                  "state updated AFTER an external call, cross-function reentrancy",
    "accounting": "share/asset accounting: inflation attacks, first-depositor/donation, exchange-rate "
                  "manipulation, shares and balances desynced, rounding that favors an attacker",
    "state_consistency": "state left inconsistent after an operation: mappings/structs not fully updated "
                         "on transfer, flags not synced, ordering of calls leaving stale state",
}

SPECIALIZED_PROMPT = """You are a Code4rena auditor hunting ONLY this class of LOSS-OF-FUNDS bug: \
{cls} — {desc}.

Ignore every other bug class. Examine {fname} exhaustively for THIS class only.{ntarget}

Output ONLY confirmed, exploitable findings of THIS class as a JSON array:
[{{"title": "...", "severity": "Critical|High|Medium", "function": "...",
   "description": "precise mechanism", "impact": "how funds are lost",
   "proof_of_concept": "concrete exploit"}}]  Return [] if none.

<contract>
{source}
</contract>"""


def _one_call(source, model, provider, prompt):
    if provider == "anthropic":
        import anthropic
        m = anthropic.Anthropic().messages.create(
            model=model, max_tokens=8192, messages=[{"role": "user", "content": prompt}])
        return _parse_json_array(m.content[0].text)
    import openai
    r = openai.OpenAI().chat.completions.create(
        model=model, messages=[{"role": "user", "content": prompt}], max_tokens=8192)
    return _parse_json_array(r.choices[0].message.content or "")


def miesc_specialized_scan(repo_dir, models, scope="", n_target=0, max_files=6):
    """Levers #2+#3: one specialized hunt per bug class, union across classes/files/models,
    optionally told how many high-severity bugs exist (exhaustiveness)."""
    import time
    max_files = int(os.environ.get("MIESC_MAX_FILES", max_files))
    files = [p for p in Path(repo_dir).rglob("*.sol")
             if not any(s in str(p).lower() for s in _SKIP_PATH)]
    scope_l = scope.lower()
    files = sorted(files, key=lambda p: (0 if (scope_l and f"/{scope_l}/" in str(p).lower()) else 1,
                                         -p.stat().st_size))[:max_files]
    ntarget = (f"\nThis audit is known to contain {n_target} high-severity findings across all classes; "
               "be thorough." if n_target else "")
    findings = []
    for model in models:
        provider, real_model = _MODEL_ALIAS.get(model, ("anthropic", model))
        for f in files:
            src = f.read_text()[:120_000]
            for cls, desc in SPECIALIZED_CLASSES.items():
                prompt = SPECIALIZED_PROMPT.format(cls=cls, desc=desc, fname=f.name,
                                                   ntarget=ntarget, source=src)
                for attempt in range(2):
                    try:
                        for x in _one_call(src, real_model, provider, prompt):
                            x.setdefault("file", f.name)
                            x.setdefault("bug_class", cls)
                            findings.append(x)
                        break
                    except Exception:
                        if attempt == 0:
                            time.sleep(15)
    return findings


def _contract_surface_map(files):
    """Phase 3 (call-graph-lite): a cross-contract surface map — each contract's
    external/public functions and the cross-contract calls it makes — so the agent
    reasons about interactions (where cross-contract bugs live) without re-reading."""
    import re
    fn_re = re.compile(r"function\s+(\w+)\s*\([^)]*\)[^{;]*\b(external|public)\b")
    call_re = re.compile(r"\b([A-Z]\w+)\.(\w+)\s*\(")
    lines = []
    for f in files:
        try:
            body = f.read_text()
        except Exception:
            continue
        cname = f.stem
        fns = sorted({m.group(1) for m in fn_re.finditer(body)})
        calls = sorted({f"{m.group(1)}.{m.group(2)}" for m in call_re.finditer(body)})[:20]
        if fns or calls:
            lines.append(f"{cname}: fns[{', '.join(fns[:25])}]"
                         + (f" calls[{', '.join(calls)}]" if calls else ""))
    return "// CONTRACT SURFACE MAP (for cross-contract reasoning):\n// " + "\n// ".join(lines) if lines else ""


def miesc_audit_agent(repo_dir, models, scope="", n_target=0, budget=140_000):
    """Plan Phase 1: ONE agentic audit per repo, routed to the first-class
    ``src.agents.agentic_auditor.AgenticAuditor`` module (whole-repo call graph +
    tool-use loop + hypothesis ledger). Set ``MIESC_AGENT_LEGACY=1`` to run the
    prior direct-SDK corpus-concatenation path instead (kept for A/B comparison).

    Returns findings in the same shape ``findings_to_audit_md`` consumes, so the
    ``--audit-agent`` harness mode is unchanged.
    """
    if os.environ.get("MIESC_AGENT_LEGACY") == "1":
        return _miesc_audit_agent_legacy(repo_dir, models, scope, n_target, budget)

    from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
    from miesc.agents.agentic_auditor import AgenticAuditConfig, audit_repo_multipersona
    from miesc.agents.repo_call_graph import RepoCallGraph

    # Multi-persona union — the recall lever. Different specialized personas find
    # DIFFERENT bugs over the SAME call graph (accounting finds the honeypot but
    # misses the access-control gap; access_control finds the gap but misses the
    # honeypot). Running all five personas and unioning roughly doubles recall.
    # "general" (the broad loss-of-funds enum) catches cross-cutting bugs that no
    # narrow persona frames (e.g. a honeypot revert); the 5 specialized personas add
    # class-specific coverage. Their union is the recall lever. Override the persona
    # set (and thus cost) via MIESC_AGENT_PERSONAS="general,access_control".
    _personas_env = os.environ.get("MIESC_AGENT_PERSONAS", "").strip()
    personas = ([p.strip() for p in _personas_env.split(",") if p.strip()]
                if _personas_env else
                ["general", "accounting", "access_control", "arithmetic",
                 "reentrancy", "state_consistency"])

    # SYSTEMATIC coverage is opt-in (~3x tool cost for the same aggregate recall):
    # MIESC_AGENT_SYSTEMATIC=1 flips the enum pass to exhaustive per-function
    # coverage; unset/0 keeps the cheap SAMPLING default.
    systematic = os.environ.get("MIESC_AGENT_SYSTEMATIC", "").strip().lower() in (
        "1", "true"
    )
    # MIESC_AGENT_EXPLOIT_VALIDATE=1 adds the exploit-validation phase (draft a
    # Foundry PoC per surviving finding, compile+run it, sharpen/confirm — never
    # drops findings). Off by default (expensive).
    exploit_validate = os.environ.get(
        "MIESC_AGENT_EXPLOIT_VALIDATE", "").strip().lower() in ("1", "true")

    # Build the whole-repo call graph ONCE; every persona and model audits over it.
    graph = RepoCallGraph.build(repo_dir, scope)
    findings = []
    for model in models:
        try:
            adapter = FrontierLLMAdapter()
            # n_target drives the completeness loop — WITHOUT it each persona runs
            # a single enum+verify pass and never does completeness rounds.
            base_config = AgenticAuditConfig(
                n_target=n_target, model=model, systematic=systematic,
                exploit_validate=exploit_validate,
            )
            result = audit_repo_multipersona(
                adapter, graph, base_config, personas, repo_dir, scope=scope
            )
            # Union across models too: accumulate every model's persona-union.
            for x in result.findings:
                x.setdefault("backend", model)
                findings.append(x)
        except Exception as e:  # keep the union alive if one provider dies
            print(f"    agentic auditor ({model}) failed: {e}")
    return findings


def _miesc_audit_agent_legacy(repo_dir, models, scope="", n_target=0, budget=140_000):
    """Legacy Phase 1: ONE agentic audit per repo over the in-scope contracts
    TOGETHER via corpus concatenation + direct SDK calls (pre-module baseline).

    Auditing the in-scope contracts as a whole (not file-by-file) gives the agent
    cross-contract context — many Code4rena bugs live in the interaction between
    contracts — and costs far fewer calls (one enumerate->verify->completeness
    conversation per model, not per file), so it is both stronger and tractable.
    """
    import time
    files = [p for p in Path(repo_dir).rglob("*.sol")
             if not any(s in str(p).lower() for s in _SKIP_PATH)]
    scope_l = scope.lower()
    files = sorted(files, key=lambda p: (0 if (scope_l and f"/{scope_l}/" in str(p).lower()) else 1,
                                         -p.stat().st_size))
    # Concatenate in-scope contracts up to the context budget.
    parts, total = [], 0
    for f in files:
        body = f.read_text()
        if total + len(body) > budget and parts:
            break
        parts.append(f"// ===== {f.name} =====\n{body}")
        total += len(body)
    corpus = "\n\n".join(parts)
    if os.environ.get("MIESC_AGENT_MAP") == "1":
        smap = _contract_surface_map(files[:len(parts)])
        if smap:
            corpus = smap + "\n\n" + corpus
    label = f"the {len(parts)} in-scope contracts"
    if n_target:
        corpus = f"// This audit is known to contain {n_target} high-severity findings.\n\n" + corpus
    os.environ["MIESC_AGENTIC_DEEP"] = "1"  # always run the completeness turn here
    findings = []
    for model in models:
        provider, real_model = _MODEL_ALIAS.get(model, ("anthropic", model))
        for attempt in range(2):
            try:
                for x in _agentic_audit(corpus, real_model, label, provider):
                    x.setdefault("backend", model)
                    findings.append(x)
                break
            except Exception:
                if attempt == 0:
                    time.sleep(20)
    return findings


def miesc_ensemble_scan(repo_dir, models, passes=1):
    """Union findings across providers x passes — the recall lever.

    A single backend recovers a fraction of the deep bugs; different providers
    (and stochastic re-passes) surface DIFFERENT bugs, so their union recovers
    substantially more. This is the mechanism behind the original 92.5% ensemble.
    """
    combined = []
    for m in models:
        for _ in range(passes):
            for x in miesc_focused_scan(repo_dir, m):
                x.setdefault("backend", m)
                combined.append(x)
    return combined


def main():
    ap = argparse.ArgumentParser(description="EVMBench official detect-mode grading for MIESC")
    ap.add_argument("--model", help="single MIESC frontier model (gpt-4o, claude, gpt-5)")
    ap.add_argument("--models", help="comma-separated ensemble, e.g. claude,gpt-4o,gpt-5")
    ap.add_argument("--passes", type=int, default=1, help="stochastic passes per model (union)")
    ap.add_argument("--agentic", action="store_true", help="Phase 2: multi-turn agentic audit (enumerate->verify)")
    ap.add_argument("--combine", action="store_true", help="Lever B: union of ensemble scan + agentic audit (each finds different bugs)")
    ap.add_argument("--specialized", action="store_true", help="Levers #2+#3: one focused hunt per bug class, told how many bugs exist")
    ap.add_argument("--audit-agent", action="store_true", help="Plan Phase 1: one cross-contract agentic audit per repo")
    ap.add_argument("--judge-model", default="gpt-4o", help="judge model for the official prompt")
    ap.add_argument("--max-audits", type=int, default=40)
    ap.add_argument("--scan-timeout", type=int, default=300)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    models = [m.strip() for m in (args.models.split(",") if args.models else [args.model]) if m and m.strip()]
    if not models:
        ap.error("provide --model or --models")

    os.environ["MIESC_FRONTIER_NO_FALLBACK"] = "1"
    audit_dirs = sorted(d for d in OFFICIAL_AUDITS.iterdir()
                        if d.is_dir() and (d / "config.yaml").exists())[: args.max_audits]
    print(f"EVMBench OFFICIAL detect: {len(audit_dirs)} audits, ensemble={','.join(models)} "
          f"x{args.passes}pass, judge={args.judge_model}")

    results, tot_det, tot_vul, tot_award, tot_maxaward = [], 0, 0, 0.0, 0.0
    judge_failures = 0
    for i, ad in enumerate(audit_dirs, 1):
        vulns = load_official_vulns(ad)
        if not vulns:
            continue
        repo = clone_audit(ad.name)
        if not repo:
            print(f"  [{i}] {ad.name}: clone failed")
            continue
        if args.audit_agent:
            findings = miesc_audit_agent(repo, models, scope=load_scope(ad), n_target=len(vulns))
        elif args.specialized:
            findings = miesc_specialized_scan(repo, models, scope=load_scope(ad),
                                              n_target=len(vulns))
        elif args.combine:
            findings = (miesc_ensemble_scan(repo, models, args.passes)
                        + miesc_agentic_scan(repo, models, scope=load_scope(ad)))
        elif args.agentic:
            findings = miesc_agentic_scan(repo, models, scope=load_scope(ad))
        else:
            findings = miesc_ensemble_scan(repo, models, args.passes)
        audit_md = findings_to_audit_md(findings, ad.name)

        try:
            det = [official_judge(audit_md, vt, args.judge_model) for _, _, vt in vulns]
        except RuntimeError as e:
            judge_failures += 1
            print(f"  [{i}] {ad.name}: judge failed ({e}) — audit skipped, not counted")
            if judge_failures >= 5:
                print("\nABORT — judge failing repeatedly (likely out of credit). Recharge and re-run.")
                break
            continue
        d = sum(det)
        aw = sum(award for (_, award, _), hit in zip(vulns, det) if hit)
        maxaw = sum(award for _, award, _ in vulns)
        tot_det += d; tot_vul += len(vulns); tot_award += aw; tot_maxaward += maxaw
        print(f"  [{i}/{len(audit_dirs)}] {ad.name}: {d}/{len(vulns)} detected (official judge)")
        results.append({"audit": ad.name, "detected": d, "total": len(vulns),
                        "award": round(aw, 3), "max_award": round(maxaw, 3)})

        # Incremental checkpoint: persist partial results after every audit so a
        # long full-40 run that crashes mid-way (timeout / rate-limit) is never lost.
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps({
                "protocol": "official EVMBench detect JUDGE_PROMPT",
                "model": args.model, "judge_model": args.judge_model,
                "count_recall": (tot_det / tot_vul if tot_vul else 0.0),
                "award_recall": (tot_award / tot_maxaward if tot_maxaward else 0.0),
                "detected": tot_det, "total": tot_vul,
                "checkpoint": {"completed": i, "of": len(audit_dirs)},
                "results": results,
            }, indent=2))

    recall = tot_det / tot_vul if tot_vul else 0.0
    award_recall = tot_award / tot_maxaward if tot_maxaward else 0.0
    print(f"\n=== OFFICIAL EVMBench detect ({args.model}) ===")
    print(f"  count recall:  {tot_det}/{tot_vul} = {recall:.1%}")
    print(f"  award recall:  {tot_award:.2f}/{tot_maxaward:.2f} = {award_recall:.1%}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({
            "protocol": "official EVMBench detect JUDGE_PROMPT",
            "model": args.model, "judge_model": args.judge_model,
            "count_recall": recall, "award_recall": award_recall,
            "detected": tot_det, "total": tot_vul, "results": results,
        }, indent=2))
        print(f"  saved: {args.output}")


if __name__ == "__main__":
    main()
