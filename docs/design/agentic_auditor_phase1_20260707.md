# Design — Agentic Auditor, Phase 1 (2026-07-07)

> Additive, dated engineering design. Elaborates
> `paper/ribci-cyted-2026/plan_agentic_auditor_to_90_20260706.md` into a concrete,
> reviewable Phase-1 architecture. **No code is written until this design is
> approved.** Does not touch paper evidence, claims matrices, or frozen benchmark
> artifacts.

## 1. Scope of Phase 1

Plan 2 defines four phases with measured targets:

| Phase | Deliverable | Target (official judge) |
|---|---|---|
| **1** | **Core agentic loop: multi-turn per audit, memory, in-scope context, TOOL-USE** | **reliably ~35–40%** |
| 2 | Exploit-validated findings | ~50% |
| 3 | Cross-contract + call-graph reasoning (whole-repo) | ~65% |
| 4 | Multi-persona union + tuning | ~80–90% |

**This document designs Phase 1 only.** Phases 2–4 are explicitly out of scope
(see §9 Non-goals) and are named only where a Phase-1 interface must not preclude
them.

### Honest framing
- We are at **~33%** (official judge) with one-shot / multi-pass scanning. That is
  the ceiling of a *scanner*.
- The single capability that separates a 33% scanner from an ~87% agent
  (Cecuro et al.) is **tool-use**: the agent pulls the exact function body / traces
  a call chain **on demand**, instead of reasoning over a truncated 120–140k-char
  blob. Phase 1's whole reason to exist is to add that.
- Phase 1's honest target is **~35–40%** — a modest, *measured* rung, not 90%.

## 2. Problem statement (from the current-state map)

The six Plan-2 capabilities already exist **in fragments across three layers that
do not share context**:

1. **Benchmark direct-SDK functions** (`benchmarks/evmbench_official_detect.py`) —
   `miesc_audit_agent` (`:563`), `miesc_agentic_scan` (`:428`), `_run_conversation`
   (`:384`). Multi-turn + whole-repo-lite corpus, but they **call the anthropic/
   openai SDKs directly and bypass the frontier adapter**.
2. **`src/agents/deep_audit_agent.py`** — a **real call graph**
   (`src/ml/call_graph.py`, `CallGraphBuilder.build_from_source`, `paths_to_sink`)
   + a triage loop with a `investigated` dedup ledger (`:642,:649`), but it runs on
   a **single file** and never exposes the graph to the LLM.
3. **`src/adapters/exploit_synthesizer_adapter.py`** — runs `forge test` for real,
   but from **hardcoded templates**, not LLM-drafted exploits.

The one clean LLM entry point, `src/adapters/frontier_llm_adapter.py`
(`FrontierLLMAdapter.analyze`, `:322`), is **stateless and has no tool-use**
(grep for `tools=`/`tool_use` returns nothing) — and the agentic code bypasses it.

**Consequence:** no component both (a) generates hypotheses across a multi-turn
conversation AND (b) can fetch code on demand AND (c) tracks a ruled-out ledger
with a convergence criterion. Phase 1 builds exactly that component, **wiring in the
existing call graph and prompts rather than reinventing them.**

## 3. Design decisions

**D1 — One new first-class module, not a fourth scattered layer.**
`src/agents/agentic_auditor.py`, a `BaseAgent` subclass, becomes the single home of
the per-audit agentic loop. The benchmark's `miesc_audit_agent` becomes a thin
caller of it (so the harness measures the real module, not a parallel copy).

**D2 — Tool-use goes into the frontier adapter, additively.**
Add an *opt-in* conversational tool-use surface to `FrontierLLMAdapter`. The
existing stateless `analyze()` is untouched (no regression to the paper baseline).
New capability is a new method (§6), gated so nothing changes unless called.

**D3 — The call graph is the tool backend.**
The LLM does not receive the whole repo up front. It receives (i) a compact
**repo map** (contracts, their external/public functions, cross-contract edges) and
(ii) **tools** to pull any function body or trace any call path — backed by
`src/ml/call_graph.py`, promoted from single-file to whole-repo (§5).

**D4 — Memory is an explicit ledger, not just chat history.**
A `HypothesisLedger` records every hypothesis with a status
(`open | ruled_out | confirmed`) and the evidence/tool-calls that decided it. This
is what makes passes *compound* instead of repeat, and gives the loop a real
stopping condition.

**D5 — Completeness is a loop to N, not a single pass.**
`n_target` (known bug count, already loaded by the harness) becomes a
*continuation condition*: keep hunting until `confirmed >= n_target` OR
`rounds >= max_rounds` OR a round adds nothing new (convergence).

**D6 — Reuse the existing prompts.**
`AGENT_ENUM_PROMPT`, `AGENT_VERIFY_PROMPT`, `AGENT_COMPLETENESS_PROMPT`
(`evmbench_official_detect.py:315/:338/:363`) move into the module as the loop's
turn prompts, adapted to allow tool calls. `AGENT_EXPLOIT_PROMPT` is retained but
its *execution* is Phase 2.

## 4. Module interface — `src/agents/agentic_auditor.py`

Proposed shapes (names/contracts to review; not final code):

```python
@dataclass
class Hypothesis:
    id: str                       # stable hash of (contract, function, claim)
    contract: str
    function: str
    vuln_class: str               # arithmetic | access_control | reentrancy | ...
    claim: str                    # the suspected bug, one sentence
    status: str = "open"          # open | ruled_out | confirmed
    evidence: list[str] = field(default_factory=list)   # tool calls / reasoning
    severity: str | None = None

class HypothesisLedger:
    def add(self, h: Hypothesis) -> bool: ...        # False if dup (id seen)
    def rule_out(self, id: str, reason: str) -> None: ...
    def confirm(self, id: str, evidence: str, severity: str) -> None: ...
    def open_ids(self) -> list[str]: ...
    def confirmed(self) -> list[Hypothesis]: ...
    def summary_for_prompt(self) -> str: ...          # compact "already checked" digest

@dataclass
class AgenticAuditConfig:
    max_rounds: int = 4
    max_tool_calls_per_round: int = 12
    token_budget: int = 200_000
    n_target: int = 0             # known bug count (continuation hint)
    model: str = "claude"         # frontier alias

class AgenticAuditor(BaseAgent):
    def __init__(self, adapter: FrontierLLMAdapter,
                 graph: RepoCallGraph, config: AgenticAuditConfig): ...

    def audit_repo(self, repo_dir: Path, scope: str = "") -> AuditResult:
        """Whole-repo agentic audit. Orchestrates §7 loop. Returns findings
        + the full ledger + a run trace (tokens, tool calls, rounds)."""
```

`AuditResult` carries `findings: list[dict]` (same shape the harness's
`findings_to_audit_md` already consumes) so integration is drop-in.

## 5. The call graph, promoted to whole-repo — `RepoCallGraph`

Wrap the existing `src/ml/call_graph.py` builder over *all* in-scope contracts:

```python
class RepoCallGraph:
    @classmethod
    def build(cls, repo_dir: Path, scope: str = "") -> "RepoCallGraph": ...
    def repo_map(self) -> str:            # compact: contract -> [public fns], edges
    def function_body(self, contract: str, fn: str) -> str | None
    def callers_of(self, contract: str, fn: str) -> list[str]
    def callees_of(self, contract: str, fn: str) -> list[str]
    def paths_to(self, contract: str, fn: str) -> list[list[str]]   # reuse paths_to_sink
```

`repo_map()` is what the agent sees up front (cheap, structural). Everything else is
fetched **on demand via tools** (§6). This is the mechanism, not a prompt trick.

## 6. Tool-use surface on `FrontierLLMAdapter` (additive)

New method, does not touch `analyze()`:

```python
def converse_with_tools(
    self,
    system: str,
    messages: list[dict],
    tools: list[ToolSpec],
    on_tool_call: Callable[[str, dict], str],   # name, args -> result string
    model: str | None = None,
    max_iterations: int = 12,
) -> ConversationResult:
    """Multi-turn loop: model may emit tool_use blocks; we execute them via
    on_tool_call and feed tool_result back until the model returns a final
    answer or max_iterations is hit. Anthropic tool-use first; OpenAI
    function-calling behind the same ToolSpec abstraction."""
```

Tools exposed to the model in Phase 1 (all backed by `RepoCallGraph`):
- `get_function_body(contract, function)` → source of exactly that function.
- `list_callers(contract, function)` / `list_callees(...)` → trace the call chain.
- `get_paths_to(contract, function)` → call paths reaching a sink.

`ToolSpec` is provider-neutral; the adapter translates to Anthropic `tools=` or
OpenAI `functions`. **No new SDK dependency** — both SDKs already vendored.

## 7. The loop contract

```
graph  = RepoCallGraph.build(repo, scope)
ledger = HypothesisLedger()
msgs   = [ system(role + repo_map) ]

# Round 0 — ENUMERATE (tool-augmented)
enumerate: model reads repo_map, may call tools to inspect suspects,
           emits candidate Hypotheses -> ledger.add (dedup by id)

# Rounds 1..max_rounds — VERIFY open hypotheses
for each open hypothesis:
    model must pull the exact code via tools and decide:
    rule_out(reason)  OR  confirm(evidence, severity)
    -> ledger updated; ruled-out ids never re-opened

# COMPLETENESS gate (loop, not single pass)
while confirmed < n_target and round < max_rounds and made_progress:
    ask "given the ledger digest, what did you MISS?" (adversarial self-review)
    new hypotheses -> ledger -> verify them

stop when: confirmed >= n_target  OR  no new hypotheses in a full round
           OR  max_rounds / token_budget hit
emit: ledger.confirmed() -> findings
```

`ledger.summary_for_prompt()` is injected each round so the model never re-checks a
ruled-out claim — this is what makes it an *agent*, not a re-prompted scanner.

## 8. Reuse map (build vs. wire-in)

| Component | Status | Source |
|---|---|---|
| Multi-turn conversation | wire-in + extend | `_run_conversation` `evmbench…:384` → adapter `converse_with_tools` |
| Turn prompts (enum/verify/completeness) | wire-in | `evmbench…:315/:338/:363` |
| Call graph builder | wire-in + promote to repo | `src/ml/call_graph.py`, `deep_audit_agent.py:334` |
| Triage/dedup ledger idea | rebuild cleanly | pattern from `deep_audit_agent.py:649` |
| Findings→audit.md | wire-in unchanged | `evmbench…findings_to_audit_md` |
| Frontier adapter provider select | wire-in | `frontier_llm_adapter.py:284` |
| **Tool-use conversational layer** | **BUILD (new)** | — (the AUSENTE capability) |
| **RepoCallGraph (whole-repo)** | **BUILD (thin wrapper)** | over `src/ml/call_graph.py` |
| **HypothesisLedger** | **BUILD (new)** | — |
| **AgenticAuditor orchestrator** | **BUILD (new)** | — |

Net new code is small and focused; the heavy lifting (graph, prompts, providers)
already exists.

## 9. Non-goals for Phase 1 (explicitly deferred)

- **Exploit-validated findings** (draft + `forge test` per hypothesis) → Phase 2.
  Interface leaves room: a confirmed `Hypothesis` can later gain an `exploit` field.
- **Multi-persona union** (per-vuln-class hunters over full context) → Phase 4.
  `vuln_class` on `Hypothesis` is the seam; Phase 1 runs a single generalist agent.
- **Any change to the paper baseline defaults or claims matrices.**

## 10. How we measure

- Harness flag already exists: `--audit-agent` (`evmbench…:659`). Repoint
  `miesc_audit_agent` to call `AgenticAuditor.audit_repo`.
- **Discipline (from Plan 1):** prove on the 5-sample first; scale to 40 only if it
  climbs. Dated, additive outputs:
  `benchmarks/results/evmbench/official_auditagent_v1_5_YYYYMMDD.json` then `_40_`.
- Incremental checkpoint (added 2026-07-07) protects the long 40-run.
- **Measurement is blocked until the Anthropic API key has credit** (direct probe
  currently returns "credit balance too low"). Building proceeds without it.

## 11. Risks & honest ceiling

- **Tool-use latency/cost.** Each round can fan out many tool calls; `token_budget`
  + `max_tool_calls_per_round` cap it. Measure cost per audit on the 5-sample.
- **Provider parity.** Anthropic tool-use and OpenAI function-calling differ; the
  `ToolSpec` abstraction must hide that. Anthropic-first, OpenAI validated on the 5.
- **The ceiling still holds.** Phase 1 targets ~35–40%. Some ultra-subtle bugs
  (e.g. `uint96(_shares)` truncation in pooltogether) may resist even tool-use;
  those are the Phase 2–4 (exploit validation + personas) job. **We measure and
  report what we actually reach — no lenient-matcher shortcut.**

## 12. Task breakdown (Phase 1)

1. `RepoCallGraph` wrapper over `src/ml/call_graph.py` (whole-repo build + accessors).
2. `ToolSpec` + `converse_with_tools` on `FrontierLLMAdapter` (Anthropic tool-use).
3. `HypothesisLedger` (add/dedup/rule_out/confirm/summary).
4. `AgenticAuditor.audit_repo` orchestrator implementing the §7 loop.
5. Move/adapt the four AGENT_* prompts into the module.
6. OpenAI function-calling parity in `converse_with_tools`.
7. Repoint harness `miesc_audit_agent` → `AgenticAuditor`; dated 5-sample run.
8. Measure on 5 (when credit available); iterate prompts/tool set; then 40.

Unit-testable without API: 1, 3, and the tool-dispatch of 2/4 (mock the adapter).
