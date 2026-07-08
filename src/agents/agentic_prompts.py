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

Use the tools to inspect the MOST suspicious functions first, but do NOT explore \
indefinitely. After inspecting a handful of functions (aim for FEWER than ~10 tool \
calls total), STOP calling tools and OUTPUT the JSON list of hypotheses. A \
partial-but-concluded list is FAR better than never answering: once you have \
enough to name concrete candidates, emit the JSON immediately and stop.
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


# Bake the static tool block and schema into each constant at import time. The
# remaining {repo_map} / {ledger} placeholders (and {{...}} JSON braces) are left
# for the orchestrator's per-round str.format call.
AGENT_ENUM_PROMPT: str = _ENUM_TEMPLATE.format(
    tools=_TOOLS_TEXT, schema=_HYPOTHESIS_SCHEMA_TEXT
)

AGENT_VERIFY_PROMPT: str = _VERIFY_TEMPLATE.format(tools=_TOOLS_TEXT)

AGENT_COMPLETENESS_PROMPT: str = _COMPLETENESS_TEMPLATE.format(
    tools=_TOOLS_TEXT, schema=_HYPOTHESIS_SCHEMA_TEXT
)

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
    "AGENT_VERIFY_PROMPT",
    "AGENT_COMPLETENESS_PROMPT",
    "AGENT_EXPLOIT_PROMPT",
]
