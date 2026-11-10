# ADR: Caracal ↔ Cairo/Scarb version compatibility for the Cairo PoC

> Created: 2026-11-10 · Owner: Fernando Boiero
> Phase: **F0 — Compatibility spike (BLOCKING)** of
> `docs/plans/2026-11-10_CAIRO_CARACAL_POC.md`
> Status: **DECISION PENDING — escalated to the owner.** A functional combo
> exists only against **Cairo/Scarb 2.5.0**, not against a *recent* Cairo 2.x
> (the user's toolchain is 2.9.2). Per the plan's F0 stop condition, work does
> **not** advance to F1/F2 until the owner picks an option in §6.

---

## 1. Context

Caracal (`crytic/caracal`) analyzes the **Sierra** representation that the Cairo
compiler emits. It fixes its `cairo-lang-*` dependencies to one exact compiler
tag, so the Cairo/Scarb version Caracal can consume is bounded by that pin. F0's
job is to find — and verify end-to-end — a Caracal ↔ Scarb/Cairo combination
that actually runs, and to write the strategy down before any fixtures or
adapter code are built.

## 2. Evidence gathered (upstream, no execution required)

All facts below come from the pinned release `v0.2.3` and the GitHub API; none
depend on running the binary (which is separately blocked — see §5).

### 2.1 Caracal release state

| Fact | Value | Source |
|---|---|---|
| Latest release | **v0.2.3** | `gh api .../releases/tags/v0.2.3` |
| Published | **2024-01-25** | `published_at` |
| Default branch | `master` | `gh api repos/crytic/caracal` |
| Repo last push | **2024-01-25** | `pushed_at` |
| Open PRs | **0** | `gh api .../pulls?state=open` |
| Other branches | `cairo-comp-1` (the Cairo **1.x** line) | `gh api .../branches` |
| `master` HEAD `Cargo.toml` | identical pins to the `v0.2.3` tag | API read |

**Implication:** Caracal has had **no commits for ~2 years** (as of 2026-11-10)
and no open PRs. `master` == `v0.2.3`. There is no upstream work in flight that
bumps the compiler. v0.2.3 is the ceiling; there is no newer line to wait for.

### 2.2 The hard compiler pin

`Cargo.toml` (both the `v0.2.3` tag and `master` HEAD) pins **every**
`cairo-lang-*` crate to the git tag **`v2.5.0`** of `starkware-libs/cairo`:

```
cairo-lang-compiler        = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-defs            = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-plugins         = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-starknet        = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-filesystem      = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-parser          = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-syntax          = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-semantic        = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-utils           = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-sierra-generator = { git = "…/cairo.git", tag = "v2.5.0" }
cairo-lang-sierra          = { git = "…/cairo.git", tag = "v2.5.0" }
```

Package version `0.2.3`, Rust edition `2021`. Release notes for v0.2.3 state it
*"adds the support for Cairo up to 2.5.0."* Caracal bundles the 2.5.0 compiler
front-end and (per `src/compilation/{scarb.rs,standard.rs,cairo_project.rs}`)
compiles the input itself to Sierra before running detectors — it is **not** a
pure consumer of Scarb-produced artifacts, so the input must be compilable by
the **2.5.0** front-end.

### 2.3 The user's / current toolchain — the gap

| Component | User's local | Caracal v0.2.3 supports |
|---|---|---|
| Scarb | **2.9.2** (`~/.local/bin/scarb`, **not** asdf-managed) | ~2.5.x |
| Cairo | **2.9.2** | **≤ 2.5.0** |
| Sierra | **1.6.0** | ~1.4.0 (the 2.5.0 line) |

The user is **four minor Cairo releases ahead** of what Caracal can parse, and
the public Starknet toolchain has moved further still (2.11+). A contract
written for edition `2024_07`/Cairo 2.9 is not guaranteed to compile under the
2.5.0 front-end Caracal carries.

> ⚠️ PATH note: `scarb` resolves to `~/.local/bin/scarb`, which **asdf does not
> manage**. A `.tool-versions` pin can therefore be silently ignored. Any pin
> for the Caracal path must be verified with `which -a scarb && scarb --version`
> from the spike directory, and kept **local** (never `asdf global`).

### 2.4 Output format — **text only, no JSON/SARIF**

Caracal v0.2.3 documents only `detect` / `print`; there is **no** `--json`,
`--format`, or SARIF flag. The `detect` command prints human-readable text to
stdout. The internal result record (captured from the upstream `insta`
snapshots, `tests/snapshots/integration_tests__detectors@*.snap`) has four
fields:

```
Result { impact: High|Medium|Low, name: "<detector-slug>", confidence: Medium, message: "<detail>" }
```

- `confidence` is **always `Medium`** for every detector in v0.2.3.
- `impact` is the severity signal (High / Medium / Low).
- `message` is a per-detector templated sentence (Sierra-level, e.g.
  `"Reentrancy in <fully::qualified::path>\n\tExternal call … \n\tVariable
  written after …"`; `"The function <path> uses the felt252 operation
  felt252_add(...) … which is not overflow/underflow safe"`).

**Implication:** the F2 adapter must **parse text** (plan risk #2, confirmed).
The snapshots give the exact field set and message templates to build the
parser against. The precise *CLI stdout layout* (how the four fields are laid
out on screen, and the exit codes for findings / no-findings / compile-failure)
still needs one authorized run to capture verbatim — see §5.

### 2.5 Detectors — **13 in v0.2.3, not 14**

`src/detectors/mod.rs::get_detectors()` registers exactly **13** detectors:

| # | Detector (`name`) | Impact | Confidence |
|---|---|---|---|
| 1 | `use-after-pop-front` | Low | Medium |
| 2 | `controlled-library-call` | High | Medium |
| 3 | `unused-events` | Medium | Medium |
| 4 | `dead-code` | Low | Medium |
| 5 | `unused-arguments` | Low | Medium |
| 6 | `unused-return` | Medium | Medium |
| 7 | `reentrancy-benign` | Low | Medium |
| 8 | `reentrancy` | Medium | Medium |
| 9 | `reentrancy-events` | Low | Medium |
| 10 | `read-only-reentrancy` | Medium | Medium |
| 11 | `unchecked-l1-handler-from` | High | Medium |
| 12 | `felt252-unsafe-arithmetic` (src: `felt252_overflow.rs`) | Medium | Medium |
| 13 | `tx-origin` | Medium | Medium |

**`unenforced-view` is NOT shipped in the Cairo-2.x build.** The plan listed 14
and already flagged `unenforced-view` as "Cairo 1 only — document if N/A". This
is confirmed: it exists only on the `cairo-comp-1` (Cairo 1.x) branch, not in
`master`/`v0.2.3`. So the Cairo-2.x PoC target is **13 detectors**, each with a
real upstream `tests/detectors/<name>.cairo` fixture **and** an `insta`
snapshot that documents its expected findings (reusable for F1/F5, with
attribution to crytic/caracal).

### 2.6 Distribution / install

- Prebuilt release assets: `caracal-v0.2.3-{linux,macos,windows}`.
- The **macOS** asset is **Mach-O x86_64** (`file` → `Mach-O 64-bit executable
  x86_64`). This host is **arm64**; Rosetta 2 (`oahd`) is present, so the x86_64
  binary runs under translation. For CI/Docker (linux/amd64) use the linux
  tarball.
- `cargo install --git … --tag v0.2.3 --locked` builds cairo-lang **2.5.0** from
  source. Building a ~2-year-old cairo-lang against **rustc 1.90.0** is not
  guaranteed; if that is the chosen reproducible route it must be verified in a
  background build and the result recorded here.

## 3. The two input modes (for whichever path is chosen)

1. **Standalone `.cairo`**: `caracal detect <file.cairo> --corelib <corelib/src>`
   (or `CORELIB_PATH`). The `--corelib` must be the **2.5.0** corelib `src` dir
   that matches Caracal's bundled front-end.
2. **Scarb project**: `caracal detect <dir>` where `<dir>/Scarb.toml` declares:
   ```toml
   [[target.starknet-contract]]
   sierra = true

   [cairo]
   sierra-replace-ids = true
   ```
   `sierra-replace-ids = true` is what turns the opaque Sierra ids in `message`
   into readable `module::Contract::function` paths (see §2.4).

## 4. Honest-error contract (non-negotiable, carried into F2)

Same rule as the recent fuzzing-adapter fix: if Caracal is absent, incompatible,
fails to compile the input, or times out, the adapter returns
`status: "error"` with a clear message — **never** `success` with 0 findings.
A version mismatch (input compiled for Cairo > 2.5.0 that the 2.5.0 front-end
rejects) is an **error**, not an empty success.

## 5. Second blocker: executing the binary

End-to-end verification (and capturing the real CLI stdout + exit codes) needs
to **run the Caracal binary**. In this session the auto-mode permission
classifier denied executing the downloaded binary (`[Code from External]`). So
even the Cairo-2.5.0 combo is **upstream-documented-as-working but not yet
locally verified here**. Finishing F0 requires the owner to allow running
`caracal` (add a `Bash` permission rule for the installed path, e.g.
`~/.local/bin/caracal`), or to run the smoke test themselves and paste the
output.

## 6. Decision required (owner) — options

A functional combo exists **only** at **Caracal v0.2.3 ⇄ Cairo/Scarb 2.5.0**.
That is a Cairo *2.x* combo upstream calls supported, but it is **not recent**
(the user is on 2.9.2; Starknet is on 2.11+). The plan's F0 gate says: if there
is no functional combo with a *recent* Cairo 2.x, **stop and report options**.

- **Option A — Pin to Cairo/Scarb 2.5.0 (lowest effort, recommended for the
  PoC).** Pin a spike-local Scarb 2.5.x (verified on PATH, not asdf-global),
  author all F1 fixtures for the **2.5.0** front-end (edition `2023_11`), and
  ship the adapter as *experimental, Cairo ≤ 2.5.0*. Honest error for newer
  input. Satisfies the grant's M1/M3 "Caracal integrated" demonstration without
  overclaiming. Limitation documented in `docs/MULTICHAIN.md`/`CHANGELOG`.
- **Option B — Fork Caracal and bump `cairo-lang-*` to 2.9.x.** High effort and
  risk: cairo-lang internals (Sierra IR, semantic model, plugin API) changed a
  lot across 2.5 → 2.9, so detectors likely need non-trivial porting. Could
  become an upstream PR (real community value for the Starknet grant), but it is
  a project in itself, well beyond this PoC's scope.
- **Option C — Plan B analyzer (different premise).** Drop Caracal as the
  first-class engine and integrate a different Cairo/Sierra analyzer that
  tracks recent Cairo (e.g. Starknet-focused Semgrep rulesets or another
  linter), keeping `cairo_adapter.py` (patterns) as the correlation partner.
  Changes the whole adapter design and the grant narrative.

**Recommendation:** **Option A** for this PoC (it is additive, honest, and
demonstrable now), with a note in the ADR that an upstream `cairo-lang` bump
(Option B, as a PR) is the right *grant-funded* follow-up — it is explicitly the
kind of community contribution M2/M3 anticipate, not PoC work.

## 7. If Option A is chosen — concrete F0 close-out checklist

1. Owner grants permission to execute `caracal`.
2. Install `caracal` v0.2.3 to a standard path (prefer the reproducible route;
   record whether it is the prebuilt binary under Rosetta or a `cargo`/linux
   build).
3. Install a **spike-local** Scarb 2.5.x; verify `scarb --version` reports Cairo
   2.5.0 from the spike dir; keep the pin local.
4. Create a minimal 2.5.0 Scarb project (`sierra = true`,
   `sierra-replace-ids = true`), run `caracal detect <dir>`, and confirm a
   known-vulnerable function fires its detector (exit 0 + printed findings; an
   empty exit 0 is **not** a pass).
5. Verify standalone mode on one loose `.cairo` with the 2.5.0 `--corelib`.
6. Capture verbatim stdout/stderr/exit-code for: findings, no-findings, and a
   deliberately-uncompilable input → save under `tests/fixtures/caracal/` for
   the F2 parser and F5 error-path tests.
7. Update this ADR's status from *DECISION PENDING* to *ACCEPTED (Option A,
   Cairo 2.5.0)* with the captured evidence, then proceed to F1.

---

### Appendix — reproduction commands (read-only; no binary execution)

```bash
gh api repos/crytic/caracal --jq '{default_branch,archived,pushed_at}'
gh api repos/crytic/caracal/releases/tags/v0.2.3 --jq '.published_at'
gh api repos/crytic/caracal/branches --jq '.[].name'
gh api repos/crytic/caracal/contents/Cargo.toml --jq '.content' | base64 -d
gh api 'repos/crytic/caracal/git/trees/v0.2.3?recursive=1' --jq '.tree[].path'
gh api repos/crytic/caracal/contents/src/detectors/mod.rs -f ref=v0.2.3 --jq '.content' | base64 -d
# output format: tests/snapshots/integration_tests__detectors@<detector>.cairo.snap
```

---

## 8. Landscape update — 2026-11-10 (owner rejected Option A)

The owner **rejected Option A** (pin Caracal v0.2.3 ⇄ Cairo 2.5.0): shipping an
adapter capped at a 2-year-old, unmaintained Cairo is too weak for the paper /
grant context. The gate stands — no external tool has yet run end-to-end here —
so this section only re-scouts the alternatives (B / C). **Every detector-count
and capability claim below is a repository/README claim relayed via web search,
NOT yet verified by running the tool.** The F0 gate (one authorized run on a
fixture compiled by the Scarb we pin, before F2) is unchanged.

### Hard evidence (verified via GitHub API, read-only)

- **Upstream Caracal crashes on current Cairo.** `crytic/caracal` issue **#62**
  (OPEN): `UnsupportedId("Const")` panic on **Cairo 2.9.4** contracts — the exact
  local toolchain band. Confirms upstream v0.2.3 cannot analyze 2.9.x.
- **Option B is no longer a from-scratch port — a recent fork already did it.**
  `adrienlacombe/caracal` (fork of `crytic/caracal`, default branch `master`,
  pushed **2026-08-29**, v**0.3.0**) pins **all** `cairo-lang-*` crates to git
  tag **v2.20.0** (ahead of local 2.9.2). PR #1 `upgrade-cairo` merged; adds
  native fmt/clippy CI, preserves the `insta` snapshots, fixes the baseline
  e2e test. Single author, **0 stars**, one PR — transparent but not
  community-validated. Still **unbuilt/unrun here** (building cairo-lang 2.20 +
  one authorized `detect` run required); output format almost certainly still
  **text** (the fork is a compiler bump, not a reporting change) — confirm on
  the one authorized run. Detectors: the same 13 (crytic lineage).

### Plan-B candidates (Option C)

- **shadowhare** (`Shadowhare/shadow-hare`, crates.io `shadowhare` v0.9.0, owner
  `br0wnD3v`, MIT/Apache-2.0). *Claims* **71** security detectors, **JSON (schema
  1.0.0) + SARIF 2.1.0** output, `scarb shadowhare detect` subcommand, `detect-diff`.
  Pins `cairo-lang-sierra 2.16.0`; support tiers T1 `~2.16` / T2 `~2.15` / T3
  `≤2.14 best-effort` (local 2.9.2 ⇒ **tier-3 best-effort**). **Provenance is the
  problem**: repo created 2026-02-21, last push **2026-03-11** (18-day lifespan,
  now ~8 months stale and already behind Scarb 2.19.1), **0 stars**, single
  author, unaudited. Same staleness trajectory as Caracal, one stage earlier.
- **cairo-lint / `scarb lint`** (software-mansion, versioned in lockstep with the
  compiler, `--json` via Scarb): maintained and current, structured output, uses
  the installed `scarb` (**no external-binary permission wall**) — but **lint-grade**
  (style/correctness), not security-grade detectors. Viable only as a low-value
  enricher, not the primary security tool.
- **Amarna** (crytic): **archived**, Cairo-0.x only. Dead end for Cairo 1/2.

### Assessment (recommendation, owner decides)

| Option | Current Cairo? | Provenance | Detectors | Output | Cost to first run | Permission wall |
|---|---|---|---|---|---|---|
| A (rejected) | ❌ ≤2.5.0 | crytic, but unmaintained 2yr | 13 | text | low | binary-exec denied |
| **B★ adrienlacombe fork** | ✅ v2.20.0 | crytic-derived, 1-author fork | 13 | text (confirm) | **low–med** (build + 1 run) | binary-exec |
| C shadowhare | ⚠️ ≤2.16 (local=T3) | 0★, 18-day, unaudited | 71 *claimed* | JSON+SARIF | med | binary-exec |
| C cairo-lint | ✅ lockstep | swmansion, maintained | lint-grade | JSON | low | **none** |

**Recommended: Option B★ (adrienlacombe fork at cairo-lang v2.20.0).** Keeps the
battle-tested crytic/Trail-of-Bits detector lineage (defensible in a paper),
tracks current Cairo (fixes A's fatal flaw), and the expensive port is already
done — so B's original "grant-sized" cost objection no longer holds. shadowhare
is more capable *on paper* but bets reproducibility on a 0-star, unaudited,
already-stale crate. Either way: `cairo_adapter.py` stays the correlation pair,
and the gate (one authorized run on a pinned-Scarb fixture) must pass before F2.

### Common to every option (no decision needed)

Registering/wrapping the existing `miesc/adapters/cairo_adapter.py`
(`CairoAnalyzer`) as a first-class `ToolAdapter` and routing `.cairo` / `Scarb.toml`
to it is required under A, B★ **and** C — it is the correlation pair in all three.
This piece can start independently of the tool choice.

### Sources

- crytic/caracal issue #62, forks, Cargo.toml — GitHub API (read-only).
- `adrienlacombe/caracal` Cargo.toml + commit log — GitHub API.
- shadowhare: docs.rs/crate/shadowhare/0.9.0 (README + Cargo.toml), GitHub API
  `Shadowhare/shadow-hare`.
- cairo-lint / scarb lint: docs.swmansion.com (cairo-lint, scarb linter + JSON output).

---

## 9. Option B ACCEPTED (owner) — fork execution plan

**Status: Option B ACCEPTED** by Fernando (relayed 2026-11-10): fork Caracal and
run it against recent Cairo. The PoC absorbs the fork as the prerequisite that
unblocks F1–F6 against current Cairo; the fork is a candidate upstream PR (grant
milestone M3).

### Material discovery — the port already exists (and is green)

The owner's decision was relayed framing B as a **from-scratch** 2.5.0 → 2.9.x
bump ("the cairo-lang API changed a lot, may be deep"). That framing crossed in
flight with this scouting result:

- **`adrienlacombe/caracal` v0.3.0 (2026-08-29) already performed the bump to
  Cairo `v2.20.0`**, stepping through **every** intermediate release — 2.6.4,
  2.7.1, 2.8.5, **2.9.4**, 2.10.1 … 2.20.0 — **with per-step `insta` snapshot
  review** (per its CHANGELOG). All `cairo-lang-*` pinned to tag `v2.20.0`;
  vendored corelib matches.
- **Corelib is embedded in the binary** (`src/compilation/corelib.rs`) → no
  `--corelib` / `CORELIB_PATH` setup; this removes the standalone-mode friction
  §4 flagged.
- **CI is green on `master`** (scheduled builds 2026-09-27 / 10-04 / 10-11 all
  `success`; the only red runs are automated Dependabot dependency PRs, not the
  mainline build). Workflows: CI, Release, CodeQL.
- **Build requirement:** Cairo ≥2.19 needs **rustc ≥ 1.94** (local is **1.90** →
  Rust toolchain must be updated). Still **text output**, same 13 detectors.

This collapses B's cost from "weeks of porting / possibly infeasible" to "base
off an existing, CI-green v2.20.0 fork, update the local Rust + Scarb toolchain,
and clear the one authorized `detect` run (gate)."

### Open sub-decisions (owner) — pending before any build/push

1. **Base vs from-scratch:** base the work on `adrienlacombe/caracal` v2.20.0
   (recommended — the careful per-version port is done and green; attribute it)
   **vs** redo the 2.5→2.x port from scratch for sole authorship. The latter is
   weeks of redundant work; the former can still land as an upstream PR /
   collaboration.
2. **Target Cairo version:** `v2.20.0` (recommended — newest, and it already
   covers local 2.9.2) vs pinning down to 2.9.x specifically.
3. **Fork remote:** the fork lives under **Fernando's GitHub** — the exact
   owner/repo for the remote is required before any push (do not assume).
4. **Toolchain bump (local env):** rustc 1.90 → ≥1.94, and Scarb 2.9.2 → match
   the chosen Cairo tag (asdf; keep the pin local; mind the `~/.local/bin/scarb`
   PATH trap from §4).

### Gate (unchanged)

Whichever base/version: the fork must **compile and run end-to-end** on a real
Scarb/Cairo project (known-vulnerable function fires its detector; empty exit 0
is not a pass) **before F2**. Executing the binary hits the `[Code from External]`
permission wall — resolve with the owner in-session (permission rule, or owner
runs the step); do not bypass. If the bump proves infeasible on this host, STOP
and report.

### Sources

- `adrienlacombe/caracal` CHANGELOG, Cargo.toml, Actions runs/workflows — GitHub API.

---

## 10. Corrections from the fork's own docs (2026-11-10, pre-gate)

Inspecting `adrienlacombe/caracal`'s `AGENTS.md` + `README.md` corrects two
assumptions carried from upstream v0.2.3 (all documented upstream-of-run; the
gate run confirms them):

- **Structured output EXISTS in the fork.** `caracal detect --format json|sarif`
  (`src/output/mod.rs`, snapshot-tested in `tests/output_formats.rs`) writes a
  JSON (or SARIF 2.1.0) document to stdout; compilation progress goes to stderr.
  So **F2 parses JSON, not text**, and F3 can map the fork's native SARIF
  (incl. `partialFingerprints["caracalFingerprint/v1"]`) onto MIESC's SARIF.
  The earlier "text-only" note held only for upstream v0.2.3's default `human`.
- **Honest-error signal is built in.** `--fail-on <impact>` exits 1 on findings
  at/above the threshold; **exit code 2 means caracal itself failed** → maps
  directly to MIESC's `status: "error"` (never success-with-0-findings).
- **Detector set ≈ 18, not 13.** The fork restores the detector families that
  went inert on Cairo ≥2.6 codegen (reentrancy family, tx-origin,
  use-after-pop-front, unused-return/events/arguments, unchecked-l1-handler-from)
  and adds 5 (controlled-replace-class, controlled-deploy, controlled-l1-message,
  unprotected-replace-class, unchecked-transfer). `dead_code` stays inert by
  design (compiler drops unreachable fns from SIERRA).
- **No corelib setup needed** (embedded in the binary); two Scarb paths
  (in-process + artifact fallback), standalone-file and cairo-project flows.

Gate plan (once the build finishes): `caracal detect --format json
tests/detectors/reentrancy.cairo` → confirm the reentrancy detector fires with a
non-empty JSON document and exit code reflects findings; capture stdout/exit for
the F2 parser and F5 error-path tests.

### Sources

- `adrienlacombe/caracal` `AGENTS.md` §§ output/format, fail-on, detectors,
  compilation; `README.md` fork notice. (Documented; pending the gate run.)
