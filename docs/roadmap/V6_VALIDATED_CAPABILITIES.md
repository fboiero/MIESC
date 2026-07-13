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
| T1.2 - SARIF inline PR annotations | `371ef149` | Findings render inline on the PR diff, scoped to new findings | 25 tests | Validated (main `371ef149`) |
| T2.1 - Structured code-action / textEdit output | `56d847ce` | Editor-agnostic fix contract for one-click IDE quick-fixes | 21 tests | Validated (main `56d847ce`) |
| T3.1 - Unified formal-verification report + SARIF | `b6a1bf35` | Formal-verification results as one artifact in the SARIF pipeline | 38 tests | Validated (main `b6a1bf35`) |

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

### T1.2 - SARIF inline PR annotations

Each finding is emitted as a GitHub workflow annotation
(`::error`/`::warning file=,line=`), so it renders inline on the PR diff at the
exact line it refers to. It composes with T1.1: when a baseline is in play, only
the *new* findings get annotated, so a reviewer sees just what this change
introduced.

Why this matters for scaling and DPGA:

A finding is only useful if someone acts on it, and people act on what is in
front of them. Buried in a CI log, a finding competes with build output nobody
scrolls through. Rendered inline on the diff, it sits on the line of code the
developer is already reading during review. This closes the loop from detection
to remediation without asking anyone to leave the pull request. For adoption it
removes a step, and every removed step is friction that no longer costs us a
user.

### T2.1 - Structured code-action / textEdit output

`fix --format code-actions` emits LSP-shaped JSON, one object per fix with
`finding_id`, `title`, `file`, and an `edits` array of `{range, newText}`. This
is the same shape an editor already understands as a code action, so it is an
editor-agnostic contract rather than a MIESC-specific format.

Why this matters for scaling and DPGA:

This is a deliberate separation of concerns. The core exposes the contract, and
the product layer builds the experience on top of it. An IDE integration (VS
Code, JetBrains, built in the platform repo) can render each fix as a one-click
quick-fix without the core knowing anything about any particular editor. It also
keeps the open-source core honest: it ships the interoperable standard, and the
commercial surface is the UI that consumes it. For go-to-market that is the hook
that turns a scanner into something a developer keeps open all day.

### T3.1 - Unified formal-verification report + SARIF

`verify --sarif` aggregates results from certora, halmos, and the Solidity
SMTChecker into one deterministic JSON report and a matching SARIF file, linking
counterexamples back to the source findings they refute or confirm. The
different verifiers stop being separate tools with separate output formats and
become one report.

Why this matters for scaling and DPGA:

Formal verification has always sat apart from the rest of a security pipeline:
different tools, different formats, a separate mental model. Folding it into the
same SARIF artifact as everything else means a consumer, whether that is a
dashboard, a code host, or a reviewer, gets one security signal regardless of
whether it came from a linter or a theorem prover. That is a real step toward
MIESC being the single place a team looks, which is the whole positioning bet
for both the DPGA narrative and the product.

## Engineering Notes

Beyond the individual capabilities, the validation suite itself is now
deterministic regardless of machine state, and line coverage sits at 81.12%.
These are not features, but they are the foundation that lets the ledger above
mean what it says: a green gate is reproducible rather than incidental. For the
DPGA review and go-to-market work this signals the kind of engineering maturity
that makes the shipped-capability claims trustworthy.
