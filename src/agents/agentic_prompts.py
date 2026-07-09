"""
MIESC Agentic Auditor - Turn Prompts

The four turn prompts that drive the per-audit agentic loop, adapted from the
benchmark harness (``benchmarks/evmbench_official_detect.py``) for a *tool-using,
structured-output* agent. Unlike the original one-shot prompts, these:

- reference the tool set the agent can call to inspect exact code on demand
  (``get_function_body``, ``list_callers``, ``list_callees``, ``get_paths_to``)
  instead of reasoning over a truncated source blob, and
- instruct the model to emit hypotheses as STRUCTURED JSON whose field names
  align EXACTLY with :class:`src.agents.hypothesis_ledger.Hypothesis`, so the
  orchestrator can parse each candidate into a ledger entry.

Prompt roles in the §7 loop (design: docs/design/agentic_auditor_phase1_20260707.md):
  - :data:`AGENT_ENUM_PROMPT`         — Round 0, enumerate candidate hypotheses.
  - :data:`AGENT_VERIFY_PROMPT`       — verify each open hypothesis via tools.
  - :data:`AGENT_COMPLETENESS_PROMPT` — adversarial "what did you MISS?" gate.
  - :data:`AGENT_EXPLOIT_PROMPT`      — retained; its EXECUTION is Phase 2.

The static tool block and the hypothesis schema are baked into each constant at
import time, so the constants are self-describing. The orchestrator only fills the
remaining ``{repo_map}`` / ``{ledger}`` placeholders via ``str.format`` per round.

Design references: §3 D6 (reuse the prompts), §4 (Hypothesis shape), §7 (loop).

Author: Fernando Boiero
License: AGPL-3.0
"""

# Structured output contract for enumerated hypotheses. Field names MUST match
# src.agents.hypothesis_ledger.Hypothesis so the orchestrator can parse directly.
HYPOTHESIS_JSON_SCHEMA: dict = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "contract": {"type": "string", "description": "contract name"},
            "function": {"type": "string", "description": "function name"},
            "vuln_class": {
                "type": "string",
                "enum": [
                    "arithmetic",
                    "access_control",
                    "reentrancy",
                    "accounting",
                    "state_consistency",
                    "other",
                ],
            },
            "claim": {
                "type": "string",
                "description": "the suspected bug, one sentence",
            },
        },
        "required": ["contract", "function", "vuln_class", "claim"],
    },
}

# Human-readable rendering of the enum schema, embedded into the enum/completeness
# prompts. Double braces survive import-time injection and collapse to single
# braces when the orchestrator later calls str.format on the prompt.
_HYPOTHESIS_SCHEMA_TEXT = """\
[{{"contract": "<contract name>",
   "function": "<function name>",
   "vuln_class": "arithmetic|access_control|reentrancy|accounting|state_consistency|other",
   "claim": "<one sentence describing the suspected loss-of-funds bug>"}}]"""

# The tools the agent may call to inspect exact code. These names MUST match the
# ToolSpecs the orchestrator registers (design §6).
_TOOLS_TEXT = """\
You have TOOLS to inspect the exact source on demand. USE them to read real code
instead of guessing from the repo map:
  - get_function_body(contract, function) -> the exact source of that function.
  - list_callers(contract, function)      -> every function that calls it.
  - list_callees(contract, function)      -> every function it calls.
  - get_paths_to(contract, function)      -> call paths that reach that sink.
Prefer pulling the real body with get_function_body over reasoning from memory."""


# ---------------------------------------------------------------------------
# COVERAGE MODES — the cost/recall lever, parameterized into every enum prompt.
#
# SAMPLING (default): inspect the most suspicious functions and STOP early. Cheap
#   (~10 tool calls); aggregate recall across the persona union is unchanged.
# SYSTEMATIC (opt-in): inspect EVERY in-scope function before concluding. ~3x the
#   tool budget for the same aggregate recall, so it must be explicitly enabled.
#
# Each enum template carries a {coverage} placeholder filled at import time. The
# persona variants interpolate {focus_title}, so they are pre-formatted per
# persona before being baked into the template (see _build_persona_enum_prompt).
# ---------------------------------------------------------------------------

_COVERAGE_SAMPLING = (
    "Use the tools to inspect the MOST suspicious functions first, but do NOT "
    "explore indefinitely. After inspecting a handful of functions (aim for FEWER "
    "than ~10 tool calls total), STOP calling tools and OUTPUT the JSON list of "
    "hypotheses. A partial-but-concluded list is FAR better than never answering: "
    "once you have enough to name concrete candidates, emit the JSON immediately "
    "and stop."
)

_COVERAGE_SYSTEMATIC = (
    "SYSTEMATIC COVERAGE (critical): do NOT sample or guess which functions to "
    "look at. The repository map lists EVERY in-scope function. Call "
    "get_function_body on EVERY external / public / state-changing function and "
    "inspect it before concluding — do NOT skip any. Being exhaustive across ALL "
    "functions matters more than depth on any one; a function you never inspect is "
    "a bug you will miss. When you have inspected the in-scope functions, OUTPUT "
    "the JSON list."
)

# Persona variants carry a {focus_title} placeholder (pre-formatted per persona).
_COVERAGE_SAMPLING_PERSONA = (
    "Use the tools to inspect the MOST suspicious functions for the {focus_title} "
    "flaw first, but do NOT explore indefinitely. After inspecting a handful of "
    "functions (aim for FEWER than ~10 tool calls total), STOP calling tools and "
    "OUTPUT the JSON list of hypotheses. A partial-but-concluded list is FAR "
    "better than never answering: once you have enough to name concrete "
    "candidates, emit the JSON immediately and stop."
)

_COVERAGE_SYSTEMATIC_PERSONA = (
    "SYSTEMATIC COVERAGE (critical): do NOT sample or guess which functions to "
    "look at. The repository map lists EVERY in-scope function. Call "
    "get_function_body on EVERY external / public / state-changing function and "
    "inspect it for the {focus_title} flaw before concluding — do NOT skip any. "
    "Being exhaustive across ALL functions matters more than depth on any one; a "
    "function you never inspect is a bug you will miss. When you have inspected "
    "the in-scope functions, OUTPUT the JSON list."
)


_ENUM_TEMPLATE = """You are a top smart-contract auditor hunting LOSS-OF-FUNDS \
vulnerabilities. Think like the winning Code4rena researcher.

{tools}

Enumerate EVERY candidate vulnerability across the in-scope contracts. Be \
exhaustive and specific. For each candidate, name the exact contract and function \
and the precise mechanism (not a generic category), and WHY it can lead to loss or \
lock of user or protocol funds. Call get_function_body on any function you suspect \
BEFORE claiming a bug in it.

Check especially the subtle, deep issues auditors win with:
- arithmetic: truncation (e.g. uint96/uint128 casts), rounding direction, precision loss, over/underflow
- accounting/share math: can shares/assets be inflated, stolen, or desynced?
- access control: who can call privileged mint/burn/withdraw/upgrade paths?
- reentrancy and external-call ordering (incl. ERC777/ERC721 hooks)
- state consistency across mappings/structs after transfers
- first-depositor / donation / exchange-rate manipulation
- callback and cross-contract assumptions

Repo map (contracts, their public/external functions, and cross-contract edges):
<repo_map>
{{repo_map}}
</repo_map>

Emit each candidate as ONE object in a single JSON array, using EXACTLY these fields:
{schema}
- contract: the contract the suspect function lives in.
- function: the suspect function name.
- vuln_class: one of arithmetic, access_control, reentrancy, accounting, state_consistency, other.
- claim: one sentence naming the precise mechanism and the loss/lock of funds.

{coverage}
Output ONLY the JSON array. Return [] if you genuinely find no candidates."""


_VERIFY_TEMPLATE = """Now VERIFY each OPEN hypothesis against the real code. Your \
job here is to DROP clear false positives, NOT to gate on positive proof: these \
candidates were surfaced by careful enumeration and are surfaced as findings \
UNLESS you can concretely demonstrate they are false.

{tools}

For EACH open hypothesis below, you MUST pull the exact function body with \
get_function_body (and trace callers/callees/paths as needed) and then decide:
1. Trace the exact execution path in the pulled source.
2. Look for a CONCRETE reason the hypothesis is false or non-exploitable — e.g. a \
guard/modifier exists, the state IS updated before the external call, the input is \
bounded, or the path is unreachable from any entry point.
3. If real, state the precise root cause and the exact loss-of-funds scenario.

Open hypotheses to verify:
<ledger>
{{ledger}}
</ledger>

DECISION RULE (bias toward KEEPING):
- Use "ruled_out" ONLY when you can point at concrete evidence in the pulled code \
that the bug cannot happen (a guard exists, the state is updated, the value is \
bounded, the path is unreachable). Set "severity": null.
- Otherwise use "confirmed". If the hypothesis is plausibly real OR you are simply \
uncertain, mark it "confirmed" — do NOT rule out merely because you could not fully \
prove exploitability. Set severity to high|medium|low.

Return ONE verdict object per hypothesis in a single JSON array, EXACTLY:
[{{{{"id": "<hypothesis id>",
   "verdict": "confirmed|ruled_out",
   "reason": "<precise root cause + loss scenario if confirmed, or the concrete code evidence that makes it false if ruled_out>",
   "severity": "high|medium|low"}}}}]
Output ONLY the JSON array."""


_COMPLETENESS_TEMPLATE = """Now RE-AUDIT as a skeptical senior reviewer: what did \
you MISS? Code4rena is won by the SUBTLE bugs others overlook. Below is the ledger \
digest of everything already opened or ruled out — do NOT re-raise any of those.

{tools}

Ledger so far (already checked — do NOT repeat):
<ledger>
{{ledger}}
</ledger>

Re-examine the in-scope contracts SPECIFICALLY for classes that are easy to miss, \
pulling the real code with get_function_body / get_paths_to before claiming a bug:
- integer truncation on downcasts (uint256 -> uint96/uint128/uint64) that silently drops value
- rounding direction in share<->asset conversions that lets an attacker gain value
- access control gaps on mint / burn / fee / withdraw / upgrade paths — who can actually call them?
- reentrancy via ERC777/ERC721/callback hooks, and external-call ordering
- first-depositor / donation / exchange-rate inflation
- state desync across mappings/structs after a transfer
- off-by-one or wrong comparison at deadlines/boundaries/caps

Emit any NEW candidates you had missed as a JSON array in the SAME hypothesis \
schema (do NOT include anything already in the ledger):
{schema}
Output ONLY the JSON array. Return [] if you find no new candidates."""


# Bake the static tool block, schema, and coverage mode into each constant at
# import time. The remaining {repo_map} / {ledger} placeholders (and {{...}} JSON
# braces) are left for the orchestrator's per-round str.format call.
def _build_enum_prompt(coverage: str) -> str:
    return _ENUM_TEMPLATE.format(
        tools=_TOOLS_TEXT, schema=_HYPOTHESIS_SCHEMA_TEXT, coverage=coverage
    )


# SAMPLING is the default (cheap); SYSTEMATIC is opt-in (~3x tool budget).
AGENT_ENUM_PROMPT: str = _build_enum_prompt(_COVERAGE_SAMPLING)
AGENT_ENUM_PROMPT_SYSTEMATIC: str = _build_enum_prompt(_COVERAGE_SYSTEMATIC)

AGENT_VERIFY_PROMPT: str = _VERIFY_TEMPLATE.format(tools=_TOOLS_TEXT)

AGENT_COMPLETENESS_PROMPT: str = _COMPLETENESS_TEMPLATE.format(
    tools=_TOOLS_TEXT, schema=_HYPOTHESIS_SCHEMA_TEXT
)

# ---------------------------------------------------------------------------
# PERSONA enum prompts (multi-persona union — the recall lever).
#
# Different specialized personas find DIFFERENT bugs over the SAME call graph:
# a general/accounting enum finds the honeypot but misses the access-control
# gap; an access-control-focused enum finds the gap but misses the honeypot.
# Their UNION doubles recall. Each persona hunts EXCLUSIVELY its own vuln class
# but keeps AGENT_ENUM_PROMPT's contract verbatim: a {repo_map} placeholder, the
# same four tools, and the same {"contract","function","vuln_class","claim"}
# JSON array — so the orchestrator parses persona output identically.
# ---------------------------------------------------------------------------

_PERSONA_ENUM_TEMPLATE = """You are a top smart-contract auditor hunting \
LOSS-OF-FUNDS vulnerabilities. Think like the winning Code4rena researcher.

You are focusing EXCLUSIVELY on {focus_title} vulnerabilities. IGNORE every \
other bug class on this pass — a separate specialized pass covers those. Your \
whole job is to find the {focus_title} bugs the other personas will MISS.

{tools}

Enumerate EVERY {focus_title} candidate across the in-scope contracts. Be \
exhaustive and specific. For each candidate, name the exact contract and \
function and the precise mechanism (not a generic category), and WHY it leads \
to loss or lock of user or protocol funds. Call get_function_body on any \
function you suspect BEFORE claiming a bug in it.

{focus_title} focus — hunt SPECIFICALLY for:
{focus_bullets}

Repo map (contracts, their public/external functions, and cross-contract edges):
<repo_map>
{{repo_map}}
</repo_map>

Emit each candidate as ONE object in a single JSON array, using EXACTLY these fields:
{schema}
- contract: the contract the suspect function lives in.
- function: the suspect function name.
- vuln_class: ALWAYS "{vuln_class}" on this persona pass.
- claim: one sentence naming the precise {focus_title} mechanism and the loss/lock of funds.

{coverage}
Output ONLY the JSON array. Return [] if you genuinely find no {focus_title} candidates."""


# Per-persona focus: (human title, canonical vuln_class, hunting bullets).
_PERSONA_FOCUS: dict = {
    "access_control": (
        "ACCESS CONTROL",
        "access_control",
        "- unguarded state-changing / admin / setter functions (missing onlyOwner/onlyManager or equivalent)\n"
        "- access-control modifiers that DO NOT actually revert (empty body, wrong comparison, `||` instead of `&&`)\n"
        "- unprotected ownership / reference / upgrade pointers (setOwner, upgradeTo, setImplementation, init/initialize)\n"
        "- privileged mint / burn / withdraw / pause / rescue paths callable by anyone\n"
        "- missing or bypassable initializer guards (re-initialization, front-runnable init)",
    ),
    "arithmetic": (
        "ARITHMETIC",
        "arithmetic",
        "- over/underflow (incl. unchecked blocks and pre-0.8 math)\n"
        "- precision / rounding loss and rounding DIRECTION that favors the attacker\n"
        "- decimals / scaling (PRECISION constant) mismatches between tokens\n"
        "- division-before-multiplication that truncates value to zero\n"
        "- truncating downcasts (uint256 -> uint128/uint96/uint64) that silently drop value",
    ),
    "reentrancy": (
        "REENTRANCY",
        "reentrancy",
        "- external calls made BEFORE state updates (violated checks-effects-interactions)\n"
        "- cross-function reentrancy (a second function reachable during the external call reads stale state)\n"
        "- cross-contract reentrancy through a shared/mirrored state\n"
        "- missing nonReentrant on funds-moving paths\n"
        "- reentrancy via ERC777/ERC721/ERC1155 receiver hooks and native-token callbacks",
    ),
    "accounting": (
        "ACCOUNTING",
        "accounting",
        "- fee / reward accounting that is skipped, double-counted, or applied to the wrong balance\n"
        "- balance-change bookkeeping not updated on transfer (e.g. onBalanceChange / _afterTokenTransfer not called)\n"
        "- share / supply accounting drift: totalSupply vs. sum of balances desync, inflation, or dilution\n"
        "- funds locked or lost because an internal ledger diverges from the real token balance\n"
        "- first-depositor / donation / exchange-rate manipulation of share<->asset conversions",
    ),
    "state_consistency": (
        "STATE CONSISTENCY",
        "state_consistency",
        "- invariants broken ACROSS functions (one function assumes state another never maintains)\n"
        "- stale or uninitialized state read as if valid (missing init, default-zero used as real value)\n"
        "- unbounded arrays / loops causing gas-griefing or permanently locked funds\n"
        "- mismatched mirrored state between two mappings/structs/contracts kept in sync by hand\n"
        "- ordering / status-flag bugs where a transition leaves the contract in an impossible state",
    ),
}


def _build_persona_enum_prompt(persona: str, coverage_tmpl: str) -> str:
    focus_title, vuln_class, focus_bullets = _PERSONA_FOCUS[persona]
    # Pre-format the coverage text's {focus_title} BEFORE baking it into the
    # template (str.format does a single pass and would not recurse otherwise).
    coverage = coverage_tmpl.format(focus_title=focus_title)
    return _PERSONA_ENUM_TEMPLATE.format(
        tools=_TOOLS_TEXT,
        schema=_HYPOTHESIS_SCHEMA_TEXT,
        focus_title=focus_title,
        vuln_class=vuln_class,
        focus_bullets=focus_bullets,
        coverage=coverage,
    )


# Five specialized enum prompts keyed by vuln class. Run them all over the SAME
# call graph and union the findings (see src.agents.agentic_auditor.audit_repo_multipersona).
# SAMPLING is the default (cheap); SYSTEMATIC is the opt-in exhaustive variant.
PERSONA_ENUM_PROMPTS: dict = {
    persona: _build_persona_enum_prompt(persona, _COVERAGE_SAMPLING_PERSONA)
    for persona in _PERSONA_FOCUS
}

PERSONA_ENUM_PROMPTS_SYSTEMATIC: dict = {
    persona: _build_persona_enum_prompt(persona, _COVERAGE_SYSTEMATIC_PERSONA)
    for persona in _PERSONA_FOCUS
}


# Retained verbatim from the harness. Its EXECUTION is Phase 2 (design §3 D6, §9).
AGENT_EXPLOIT_PROMPT: str = """For each vulnerability you confirmed, write the CONCRETE exploit that proves \
it: the exact sequence of calls, the specific values (amounts, addresses, order), and the precise state \
change that lets an attacker gain or lock funds. If you CANNOT write a coherent exploit for a candidate, \
DROP it — it was a false positive. Re-output the surviving vulnerabilities as the SAME JSON array, with \
'proof_of_concept' now holding the concrete exploit and 'description' sharpened to the exact mechanism \
and code location. Return [] if none survive."""


__all__ = [
    "HYPOTHESIS_JSON_SCHEMA",
    "AGENT_ENUM_PROMPT",
    "AGENT_ENUM_PROMPT_SYSTEMATIC",
    "AGENT_VERIFY_PROMPT",
    "AGENT_COMPLETENESS_PROMPT",
    "AGENT_EXPLOIT_PROMPT",
    "PERSONA_ENUM_PROMPTS",
    "PERSONA_ENUM_PROMPTS_SYSTEMATIC",
]
