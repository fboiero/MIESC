# v6.0 Validated Capabilities Ledger

This ledger tracks MIESC v6.0 capabilities as they land on `main` and pass the
full validation gate. It exists so the impact narrative for the DPGA review and
the product positioning work can cite concrete, already-shipped capabilities
instead of roadmap intentions.

A capability only enters this ledger after it is merged and its gate is green.
There are no speculative or roadmap-only rows here. If something is still in
flight, it belongs in a plan document, not in this table.

## Capabilities

| Capability | Commit | What it unlocks | Evidence (tests) | Status |
| --- | --- | --- | --- | --- |
| T1.1 - Finding baseline & suppression engine | `929157e8` | CI adoption on existing codebases (fail-only-on-new) | 36 tests; freeze intact; zero regressions | Validated (main `929157e8`) |

## Capability Notes

### T1.1 - Finding baseline & suppression engine

New `miesc/core/baseline.py`, the `miesc baseline generate|diff` commands, and
`--baseline` / `--fail-on-new` flags on `scan` and `audit`. A team baselines the
findings that already exist in their codebase, then wires MIESC into CI so the
build fails only when a *new* finding appears. Fingerprints are content-hash
based, so they stay stable when unrelated edits shift line numbers.

Why this matters for scaling and DPGA:

The single biggest blocker to adopting any static analyzer in CI is the
first-run finding flood. Point a fresh tool at a mature codebase and it returns
hundreds of pre-existing findings, the pipeline goes red on day one, and the
team turns the gate off. The baseline engine removes that blocker: existing
findings are acknowledged once and suppressed from the pass/fail decision, and
only newly introduced issues break the build.

For the DPGA impact narrative this speaks directly to platform independence and
real-world use. MIESC no longer assumes a greenfield project; it meets teams
where their code already is, which is the state of nearly every enterprise and
public-sector codebase. For go-to-market it lowers adoption friction to almost
zero for exactly the users who were previously hardest to onboard, teams with
large existing codebases who could not afford to fix everything before turning
the gate on. Adopt on a Friday, fail only on what you ship next week.
