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

## Autopilot Contract

When Fernando says "sigamos" or "seguimos" without adding a new target, Codex
should continue the highest-priority safe loop and complete one bounded
checkpoint end-to-end:

1. Claim if needed.
2. Run the next probe or focused inspection.
3. Fix one concrete failure class if found.
4. Add a regression test when code changed.
5. Generate dated additive evidence when benchmark behavior changed.
6. Commit locally to `lane/codex`.
7. Mark `LANES.md` `DONE`.
8. Report commit id, validation, and the next recommended loop.

This is the default operating mode. Do not wait for Fernando to choose the next
small step when the next step is discoverable from the current evidence.

### Current Autopilot State

Maintain state in three places:

- `LANES.md`: the lock and current claim status.
- Git commits on `lane/codex`: durable checkpoints.
- Dated additive artifacts in `benchmarks/results/*_codex.json`: benchmark
  evidence that does not overwrite canonical paper baselines.

Do not create hidden local state files for coordination. If a future agent needs
to resume, it must be able to read `LANES.md`, inspect the latest commits, and
continue.

### Resume Procedure

At the start of every autonomous turn:

```bash
cd /Users/fboiero/Documents/GitHub/MIESC-codex
sed -n '1,180p' /Users/fboiero/Documents/GitHub/MIESC/LANES.md
git branch --show-current
git status --short
git log --oneline -8
```

Then choose the first applicable item from the next-action queue below. If the
queue is stale, rebuild it from the latest evidence artifacts and commits before
editing code.

### Next-Action Queue

Use this queue when Fernando says "sigamos" and there is no active claim:

1. Paper 2 expanded remediation probe
   - Precondition: `fix_eval_all_categories_limit25_*_codex.json` has
     `fix_failed == 0` and empty `compile_failure_taxonomy`.
   - Next action: run a bounded `limit50` aggregate probe with a new dated
     additive artifact.
   - Stop if: it reveals a new compile failure or `fix_failed`; fix one failure
     class and rerun the smallest affected category first.

2. Paper 2 full-run readiness review
   - Precondition: `limit50` is clean or only records expected `scan_empty` /
     `no_high` states.
   - Next action: prepare a short readiness note in the final response.
   - Stop if: the next step would overwrite canonical benchmark artifacts or
     change paper claims; Fernando approval is required.

3. LLM/PoC maintainability sweep
   - Precondition: no active Paper 2 failure class remains.
   - Next action: inspect `src/llm/**` and `src/poc/**` for one large or brittle
     function, extract one pure helper, add focused tests, commit.
   - Stop if: the change crosses into another lane or requires external
     services.

4. Integration readiness check
   - Precondition: lane has several clean commits and no current coding loop.
   - Next action: report merge readiness, outstanding risks, and exact merge
     order. Do not merge unless Fernando asks.

The queue is deliberately conservative. It favors bounded evidence and
single-failure-class fixes over broad refactors.

## Paper 2 Remediation Autopilot

Use this ladder for remediation work unless Fernando directs otherwise:

| Stage | Command shape | Purpose | Commit when |
|---|---|---|---|
| Category probe | `python3 benchmarks/fix_eval.py --category <cat> --limit 10 --skip-rescan --scan-timeout 15 --details-output benchmarks/results/fix_eval_<cat>_limit10_<date>_codex.json` | Find one category-specific failure class cheaply | New evidence or code fix |
| Aggregate probe | `python3 benchmarks/fix_eval.py --limit 10 --skip-rescan --scan-timeout 15 --details-output benchmarks/results/fix_eval_all_categories_limit10_<date>_codex.json` | Confirm cross-category behavior | Applied fixes compile or failure taxonomy changes |
| Expanded probe | same command with `--limit 25` | Search for less common real-world failure classes | New failure class fixed or evidence milestone |
| Full dry evidence | same command without `--limit`, only after smaller probes are stable | Candidate evidence for a future paper update | Only with explicit Fernando approval if it changes canonical claims |

### Paper 2 Stop Rules

Stop and ask Fernando before:

- Overwriting `benchmarks/results/fix_eval_results.json` or any canonical
  paper artifact.
- Updating Paper 2 claims, tables, `.tex`, PDFs, or reproducibility baselines.
- Running full-corpus remediation repeatedly if prior bounded probes show no
  new failure class.

Continue autonomously when:

- The next run is bounded with `--limit`, `--skip-rescan`, and
  `--details-output`.
- The output is a new dated `*_codex.json` artifact.
- A failure class maps to a local patcher/harness bug in Codex-owned scope.

### Failure Response Rules

Use the first matching rule:

| Observed state | Action |
|---|---|
| `compile_failure_taxonomy` has entries | Reproduce one failing contract, add a focused patcher test, fix, rerun category probe |
| `fix_failed > 0` and `fixable_findings == 0` | Inspect finding fields; synthesize conservative `fix_code` only for stable, known detector types |
| `scan_empty > 0` | Record it as scanner coverage/evidence state; do not patch remediation unless scan output is malformed |
| `no_high > 0` | Record it; no remediation patch needed |
| applied fixes compile but elimination is 0 with `--skip-rescan` | Expected; do not infer vulnerability elimination without rescan |
| same failure recurs after three focused attempts | Mark blocked in LANES/final summary and ask Fernando |

### Evidence Naming

Use additive names:

```text
benchmarks/results/fix_eval_<category>_limit<N>_YYYYMMDD_codex.json
benchmarks/results/fix_eval_all_categories_limit<N>_YYYYMMDD_codex.json
```

Never overwrite frozen/paper canonical artifacts during autopilot loops.

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

## Handoff Template

Use this block in final summaries after substantial autonomous work:

```text
Autopilot state:
- Lane/worktree: lane/codex at ../MIESC-codex
- Last commit: <sha> <subject>
- Latest evidence: <artifact path> with <key totals>
- LANES: <claim line marked DONE>

Validated:
- <commands and results>

Residual risk:
- <what remains unknown or deliberately gated>

Next queue item:
- <exact next bounded command or inspection>
```

## Self-Execution Checklist

Before final response, verify:

- `git status --short` is clean for the Codex worktree, except local-only
  `LANES.md` in the main worktree.
- No `.lock` files exist under `.git/worktrees/MIESC-codex`.
- No Codex-owned `fix_eval`, `pytest`, or git update process is still running.
- Every shared claim touched by the loop is marked `DONE`.
- The final answer includes the commit id and exact validation result.

## Current Recommended Loops

These are safe defaults as of 2026-06-20:

1. Remediation regression loop
   - Scope: Codex claim in `LANES.md` for Paper 2 remediation.
   - Goal: keep escalating bounded Paper 2 probes while fixing concrete patcher
     failure classes.
   - Current milestone: limit-25 aggregate evidence compiles all applied fixes.
   - Next safe step: inspect whether a limit-50 or category-specific expanded
     probe is worth running before any full-corpus claim.
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
