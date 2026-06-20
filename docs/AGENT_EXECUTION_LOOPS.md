# Agent Execution Loops

This runbook defines how an AI lane should keep making useful progress without
requiring Fernando to supervise every small step. It complements `LANES.md`;
when there is a conflict, `LANES.md` wins.

## Objectives

- Keep work moving in small, validated checkpoints.
- Prefer evidence-producing work over open-ended exploration.
- Preserve the frozen paper/benchmark baseline unless Fernando explicitly asks
  for a new baseline.
- Turn each pass into reusable learning: what failed, what test caught it, and
  what the next agent should do.

## Hard Boundaries

An agent may continue autonomously only when all of these are true:

- The target files are inside its lane ownership, or the claim is recorded in
  `LANES.md` before editing shared files.
- The change can be verified with focused tests, lint, artifact generation, or a
  deterministic inspection command.
- The work does not touch frozen paper/benchmark artifacts unless Fernando has
  explicitly requested that baseline change.
- The next step is reversible and can be committed as a small checkpoint.

Stop and ask Fernando when:

- A result would change a paper number, claims matrix, frozen PDF, benchmark
  baseline, or public publication package.
- A fix requires changing another lane's owned files.
- The same blocker repeats across three attempts.
- Tests require credentials, paid API calls, long benchmark runs, or external
  services not already running.
- The next action is destructive, ambiguous, or likely to rewrite unrelated
  history.

## Default Loop

Each autonomous pass should follow this cycle:

1. Observe
   - Read `LANES.md`.
   - Confirm current worktree and branch.
   - Inspect current claims, recent commits, and relevant docs/tests.

2. Select
   - Pick one bounded task from the active initiative, backlog, failing test, or
     directly observed code debt.
   - Prefer tasks that reduce future supervision: tests, runbooks, helpers,
     deterministic scripts, clearer evidence, or smaller modules.

3. Claim
   - If the task touches shared or frozen areas, add a `CLAIMED` row to
     `LANES.md` before editing.
   - Owned lane files do not need a claim, but the final summary should still
     name the touched scope.

4. Execute
   - Make the smallest coherent change.
   - Avoid unrelated refactors.
   - Keep generated artifacts out of commits unless they are canonical outputs.

5. Validate
   - Run the narrowest meaningful tests first.
   - Run lint/format on touched code.
   - For paper or benchmark changes, run the documented reproducibility/freeze
     command or explicitly record why it is expected to fail.

6. Record
   - Commit to the lane branch only.
   - Mark shared/frozen claims `DONE`.
   - In the final response, report commit id, validation, residual risk, and the
     next recommended loop.

## Learning Loop

When a pass uncovers a repeated issue, convert it into a durable learning item.

Use this rule:

- One-off defect: fix with a focused regression test.
- Repeated defect class: extract a helper, parser, mixin, or validation utility.
- Repeated workflow confusion: add or update a guide in `docs/`.
- Repeated benchmark/paper ambiguity: add an evidence card or claims-matrix
  entry, but only after Fernando authorizes any baseline change.

Learning items should be written in this shape:

```text
Observation:
  What happened, with file/test/artifact reference.

Root cause:
  The smallest defensible explanation.

Decision:
  What pattern should future work follow.

Validation:
  Test, command, artifact, or manual check that proves the decision.

Next loop:
  The next bounded task that follows from this learning.
```

## Task Selection Policy

When Fernando says "seguimos", pick from this priority order:

1. Active `LANES.md` claim already assigned to Codex.
2. Failing tests or regressions in Codex-owned files.
3. Paper 2/remediation evidence tasks assigned to Codex.
4. `src/llm/**` and `src/poc/**` maintainability that reduces future bugs.
5. Documentation/runbook updates that remove repeated supervision.
6. Integration to `main`, only when the integration worktree is safe and no
   other lane is integrating.

Do not start with broad rewrites, whole-repo test runs, or publication changes
unless Fernando explicitly asks.

## Validation Matrix

| Work type | Minimum validation |
|---|---|
| `src/llm/**` helper/refactor | Focused unit tests plus `ruff check` and `ruff format --check` on touched files |
| `src/poc/**` helper/refactor | Focused PoC/Foundry tests plus lint/format on touched files |
| Remediation pipeline | Focused remediation tests; if benchmark behavior changes, dated additive artifact only |
| Docs only | Spell/consistency inspection with `rg`; no benchmark claims unless backed by canonical artifacts |
| Paper metadata | LaTeX build if `.tex` changes; freeze validation with expected-changed artifacts recorded |
| Benchmark claims | Artifact generation command plus claims matrix update; Fernando approval required for frozen artifacts |

## Commit Shape

Autonomous commits should be small and reviewable:

```text
<verb> <bounded scope>

<why this matters in one or two lines>
```

Examples:

- `Extract RAG cache utilities`
- `Harden Foundry command builders`
- `Record remediation regression loop`
- `Align Paper 1 revision note`

## Status Response Template

Use this shape when closing a loop:

```text
Done: <commit short sha> <subject>

Changed:
- <file/scope>: <effect>

Validation:
- <command>: <result>

Residual risk:
- <anything not run or not safe to infer>

Next recommended loop:
- <one bounded next task>
```

## Current Recommended Loops

These are safe defaults as of 2026-06-20:

1. Remediation regression loop
   - Scope: Codex claim in `LANES.md` for Paper 2 remediation.
   - Goal: identify whether unchecked-low-level-call compile regression is real,
     artifact drift, or harness drift.
   - Output: dated additive evidence artifact, no frozen overwrite.

2. LLM/PoC maintainability loop
   - Scope: `src/llm/**`, `src/poc/**`, related tests.
   - Goal: keep extracting pure helpers from large modules while preserving
     behavior.
   - Output: small commits plus focused tests.

3. Paper claim hygiene loop
   - Scope: docs/reproducibility notes only, unless Fernando approves paper
     baseline edits.
   - Goal: remove stale or ambiguous wording that conflicts with current
     canonical artifacts.
   - Output: doc-only commits with no changed benchmark numbers.

4. Integration readiness loop
   - Scope: lane branch health.
   - Goal: verify staged commits, no locks, no long-running local processes, and
     clear merge order.
   - Output: recommendation to integrate or defer, not blind merge.
