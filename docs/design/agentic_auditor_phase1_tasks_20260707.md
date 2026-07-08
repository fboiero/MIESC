# Phase 1 Tasks — Agentic Auditor (2026-07-07)

> Executable breakdown of `agentic_auditor_phase1_20260707.md` §12. Additive,
> dated. Each task lists files, acceptance criteria, dependencies, and whether it
> needs a funded API key. **Approved 2026-07-07.**

## Legend
- **API?** `no` = buildable + unit-testable offline; `yes` = needs funded frontier key to validate.
- Tasks are ordered by dependency. Independent tasks (T1, T3, T5) can be done in any order / parallel.

---

## T1 — `RepoCallGraph` (whole-repo call graph wrapper) · API: no
**File:** `src/agents/repo_call_graph.py` (new)
**Build:** Thin wrapper promoting `src/ml/call_graph.py` from single-file to whole-repo.
- `RepoCallGraph.build(repo_dir, scope="") -> RepoCallGraph` — glob in-scope `.sol` (reuse `_SKIP_PATH` skip rules), build a merged graph across all contracts.
- `repo_map() -> str` — compact digest: each contract → its external/public fns + cross-contract edges. This is the only thing fed up-front to the LLM.
- `function_body(contract, fn) -> str | None`
- `callers_of(contract, fn) -> list[str]` / `callees_of(contract, fn) -> list[str]`
- `paths_to(contract, fn) -> list[list[str]]` (reuse `paths_to_sink`).
**Acceptance:**
- Unit test on 2–3 fixture contracts: `repo_map()` lists every public fn; `function_body` returns exact source; `callers_of`/`callees_of` correct on a known cross-contract call.
- No network, no API. Runs in `pytest tests/test_repo_call_graph.py` < 2s.
**Depends on:** nothing.

---

## T2 — `ToolSpec` + `converse_with_tools` (Anthropic tool-use) · API: partial
**File:** `src/adapters/frontier_llm_adapter.py` (extend, additive)
**Build:**
- `@dataclass ToolSpec` — provider-neutral: `name`, `description`, `input_schema` (JSON schema).
- `converse_with_tools(system, messages, tools, on_tool_call, model=None, max_iterations=12) -> ConversationResult` — Anthropic branch: loop that feeds `tools=`, executes any `tool_use` block via `on_tool_call(name, args) -> str`, appends `tool_result`, repeats until final text or `max_iterations`.
- `ConversationResult`: final text, full message history, tool-call trace, token usage.
- **Do NOT touch `analyze()`.** New method only.
**Acceptance:**
- Unit test with a **mocked** anthropic client: given a scripted `tool_use` response then a final response, verify `on_tool_call` is invoked with parsed args and the loop terminates with final text (offline).
- Live smoke test (1 cheap call, when credit available): model calls `get_function_body` on a fixture and returns.
**Depends on:** nothing to build; T1 provides real tools for the live test.

---

## T3 — `HypothesisLedger` (explicit memory) · API: no
**File:** `src/agents/hypothesis_ledger.py` (new)
**Build:** `Hypothesis` dataclass (`id`, `contract`, `function`, `vuln_class`, `claim`, `status`, `evidence`, `severity`) + `HypothesisLedger` with `add` (dedup by stable id → False on dup), `rule_out(id, reason)`, `confirm(id, evidence, severity)`, `open_ids()`, `confirmed()`, `summary_for_prompt()`.
- `id` = stable hash of `(contract, function, normalized_claim)`.
**Acceptance:**
- Unit test: dup `add` returns False; `rule_out` removes from `open_ids`; a ruled-out id can never be re-opened by `add`; `summary_for_prompt()` renders open + ruled-out digest.
- No API.
**Depends on:** nothing.

---

## T4 — Prompts module (move/adapt AGENT_*) · API: no
**File:** `src/agents/agentic_prompts.py` (new)
**Build:** Move `AGENT_ENUM_PROMPT`, `AGENT_VERIFY_PROMPT`, `AGENT_COMPLETENESS_PROMPT`, `AGENT_EXPLOIT_PROMPT` out of `evmbench_official_detect.py:315/:338/:363/:376` into the module. Adapt enum/verify to (a) reference the tool set and (b) instruct the model to emit structured hypotheses (so the orchestrator can parse into `Hypothesis`).
**Acceptance:**
- Prompts import cleanly; a golden-string test pins the tool-instruction section.
- Benchmark still imports its copies OR is repointed (coordinate with T8 — until then, duplicate is acceptable, no behavior change).
**Depends on:** nothing (parsing contract informs T5).

---

## T5 — `AgenticAuditor.audit_repo` orchestrator (the loop) · API: partial
**File:** `src/agents/agentic_auditor.py` (new)
**Build:** `AgenticAuditConfig`, `AgenticAuditor(BaseAgent)`, `audit_repo(repo_dir, scope="") -> AuditResult` implementing design §7:
- Round 0 ENUMERATE (tool-augmented) → `ledger.add`.
- Rounds VERIFY each open hypothesis via tools → `rule_out`/`confirm`.
- COMPLETENESS loop until `confirmed >= n_target` OR `max_rounds` OR no progress.
- Inject `ledger.summary_for_prompt()` each round.
- `AuditResult.findings` in the shape `findings_to_audit_md` consumes.
- Parse the model's structured hypothesis output (contract with T4's format).
**Acceptance:**
- Unit test with a **mocked** `converse_with_tools` + real `RepoCallGraph`/`HypothesisLedger`: scripted turns drive enumerate→verify→confirm; assert loop stops on `n_target` and on convergence; assert findings shape.
- Live 1-audit run (when credit) produces non-empty findings on a fixture.
**Depends on:** T1, T2, T3, T4.

---

## T6 — OpenAI function-calling parity · API: partial
**File:** `src/adapters/frontier_llm_adapter.py` (extend `converse_with_tools`)
**Build:** OpenAI branch of `converse_with_tools` translating `ToolSpec` → OpenAI `tools`/`function` calling, same `on_tool_call` contract, same `ConversationResult`.
**Acceptance:**
- Unit test with mocked OpenAI client mirrors T2's test.
- Live smoke (when credit): `--models gpt-4o` path drives one tool call.
**Depends on:** T2.

---

## T7 — Repoint harness `miesc_audit_agent` → module · API: no (to wire)
**File:** `benchmarks/evmbench_official_detect.py` (edit `miesc_audit_agent:563`)
**Build:** Replace the body of `miesc_audit_agent` so it constructs `AgenticAuditor` (adapter + `RepoCallGraph.build` + config with `n_target`) and returns `audit_repo(...).findings`. Keep the signature so `--audit-agent` (`:659`) is unchanged. Old direct-SDK path preserved behind an env flag (`MIESC_AGENT_LEGACY=1`) for A/B.
**Acceptance:**
- `--audit-agent --max-audits 1` constructs the module without import/wiring errors (dataset cloned; can run offline up to the first LLM call, which will fail cleanly without credit).
- No change to other scan modes (focused/ensemble/agentic/specialized).
**Depends on:** T5.

---

## T8 — Measure: 5-sample → iterate → 40 · API: YES (blocked on credit)
**Command (5-sample first, per cost discipline):**
```
source ./apik.sh && python3 benchmarks/evmbench_official_detect.py \
  --audit-agent --models claude --max-audits 5 --judge-model gpt-4o \
  --output benchmarks/results/evmbench/official_auditagent_v1_5_20260707.json
```
**Build/act:** Run on 5; read the checkpointed JSON; iterate prompts/tool set/`max_rounds`; only scale to `--max-audits 40` (dated `_40_`) once the 5-sample **beats the 33% ensemble ceiling**.
**Acceptance:**
- 5-sample official-judge recall recorded in a dated, additive file.
- Decision logged: climbs → scale to 40; flat → iterate design before spending on 40.
**Depends on:** T7 **AND funded Anthropic (and/or OpenAI) credit** — currently the direct probe fails. Building T1–T7 proceeds without it.

---

## Execution order & parallelism
```
T1 ─┐
T3 ─┼─→ T5 ─→ T7 ─→ T8 (needs credit)
T4 ─┘        ↑
T2 ──────────┘ (T2 also → T6)
```
- **Offline now (no credit):** T1, T2 (build+mock), T3, T4, T5 (build+mock), T6, T7.
- **Gated on credit:** live smokes of T2/T5/T6 and all of T8.

## Definition of done for Phase 1
All of T1–T7 merged with green unit tests, and T8's 5-sample measured on the
official judge with a recorded number. Target ~35–40%; report what we actually hit.
</content>
