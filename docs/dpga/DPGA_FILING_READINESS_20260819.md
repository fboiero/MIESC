# MIESC DPGA Filing Readiness - 2026-08-19

This checkpoint records the DPGA submission state after the August 2026
integration pass. It is additive filing support: it does not replace
`docs/dpga/DPGA_SUBMISSION.md` or `docs/policies/DPG-COMPLIANCE.md`, and it does
not modify frozen paper, benchmark, or claims artifacts.

## Repository State

| Item | Status | Evidence |
|---|---|---|
| Default branch | Ready for filing snapshot | `origin/main` at `f5a800c4` |
| Latest merged fix | Integrated | PR #125, `fix(adapters): stop Mythril cross-validation crashing on null swc_id` |
| DPGA submission package | Present | `docs/dpga/DPGA_SUBMISSION.md` |
| DPG compliance statement | Present | `docs/policies/DPG-COMPLIANCE.md` |
| Hosted documentation | Live | `https://fboiero.github.io/MIESC/` returned HTTP 200 on 2026-08-19 |
| Open MIESC PRs | None observed | `gh pr list --state open` returned an empty list |

## Recent Integration Closures

| PR | Status | Why it matters for filing |
|---|---|---|
| #125 | Merged 2026-08-19 04:15 UTC | Removes a Mythril adapter crash on `null` SWC ids, improving robustness of symbolic-execution evidence. |
| #124 | Merged 2026-08-18 15:56 UTC | Removes the dead quick-scanner module after scan-path consolidation. |
| #123 | Merged 2026-08-18 15:45 UTC | Fails closed on invalid LLM output instead of accepting unsafe partial parses. |
| #122 | Merged 2026-08-18 15:36 UTC | Python dependency hygiene. |
| #121 | Merged 2026-08-18 15:36 UTC | Changelog action hygiene. |
| #120 | Merged 2026-08-18 15:36 UTC | CodeQL action hygiene. |
| #119 | Merged 2026-08-18 15:36 UTC | Adds full `miesc scan` arena re-score evidence without overwriting frozen benchmark artifacts. |
| #118 | Merged 2026-08-18 15:36 UTC | Adds economic invariant wiring and ERC4626/solvency templates. |
| #117 | Merged 2026-08-18 15:36 UTC | Documents the arena methodology finding that access-control was under-measured by Slither-only scoring. |

## CI Status

At the time of this checkpoint, the post-merge workflows for `origin/main`
triggered by PR #125 were partially complete:

| Workflow | Observed status |
|---|---|
| MIESC Security Audit | success |
| OpenSSF Scorecard | success |
| MIESC CI/CD Pipeline | in progress |
| Documentation | in progress |
| Research Evaluation | in progress |
| Docker Build and Publish | in progress |

Filing recommendation: do not state "all latest CI is green" until the four
in-progress workflows complete successfully. It is accurate to state that the
repository has no open PRs and that the hosted documentation endpoint is live.

## Filing Checklist Delta

- Application id and GID still need portal confirmation before final submission:
  `#13478` and `GID0092948` are carried from existing DPGA records.
- Hosted docs were reachable on 2026-08-19 with HTTP 200 and a MkDocs page title
  for MIESC.
- Keep the current self-assessment framing: "self-assessed 9/9 indicators met,
  DPGA review under way" unless the DPGA portal shows a decided status.
- Use `docs/dpga/DPGA_SUBMISSION.md` as the reviewer-facing index and this file
  as the dated readiness delta.
- Refresh the CI row after the pending post-merge workflows finish.

## Non-Blocking Local Notes

- `MIESC-main` was on `docs/dpga-filing-ready`, tracking `origin/main`, with only
  the longstanding untracked `benchmarks/smartbugs_fp_filter_effect_20260710.py`.
- `MIESC-secfix-validator` remained locally divergent after PR #123 was merged;
  this does not affect the default branch filing snapshot.
- The frozen paper worktree still contains unrelated untracked paper build
  outputs and was not touched.
