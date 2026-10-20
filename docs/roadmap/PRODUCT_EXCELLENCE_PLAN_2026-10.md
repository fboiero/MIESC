# Product Excellence Plan — MIESC through a security researcher's eyes (2026-10)

**Status:** proposal for Fernando Boiero's review. Nothing here is started unless it says so.
**Evidence base:** the new-user walkthrough on `main` 6.1.0
([`docs/internal/TOOL_E2E_TEST_2026-10.md`](../internal/TOOL_E2E_TEST_2026-10.md)), the
SmartBugs-curated re-runs of 2026-10-20 (`benchmarks/results/smartbugs_eval_layers_1_6_7_20261020*.json`,
read via [`REPRODUCE.md`](../../REPRODUCE.md)), one `miesc scan` of
`examples/contracts/VulnerableBank.sol` on `main` 8f872577, and the pull requests merged on
2026-10-20 (#167, #168, #169, #171, #172, #173, #174; release 6.1.1 via #170).
**Companions:** [`TECHNICAL_DEBT_REMEDIATION_PLAN.md`](TECHNICAL_DEBT_REMEDIATION_PLAN.md)
(code debt), [`V6_VALIDATED_CAPABILITIES.md`](V6_VALIDATED_CAPABILITIES.md) (what 6.0 validated).
This document does not repeat them; it ranks what a researcher still trips over.

The question this plan answers: *a blockchain security researcher installs MIESC from the
docs, runs it on a contract, reads the findings, tries to reproduce the paper, and wires it
into CI. Where does the experience fall short of excellent, and in what order do we fix it?*

---

## Part A — Scorecard by journey stage

| Stage | What the researcher does | What happened (evidence) | State after 2026-10-20 |
|---|---|---|---|
| A1 Install | `pip install miesc`, `miesc doctor`, `verify_installation.py` | Install ~17 s; `verify_installation.py` exited 1 on the minimal install (Django false alarm); `pip install 'miesc[mcp]'` pulled mcp 2.x and `miesc-mcp` crashed with a misleading message (E2E #4, #15) | **Fixed** (#167; 6.1.1 on PyPI). Regression tests in #171 |
| A2 First scan | `miesc scan VulnerableBank.sol` | Exit 0, ~1 s tool time, 11 findings (4 High / 7 Medium) (E2E #8; reproduced) | Works. Finding *quality* issues → Part B.1 |
| A3 Reading findings | opens the JSON / HTML | Every finding carries tool, SWC, confidence, fix and exploit scenario. But: Aderyn `send-ether-no-checks` on `withdraw()` is categorised `access_control` and gets the fix "Add onlyOwner modifier" (wrong for a user withdrawal); five `useless-public-function` lint hits arrive as **Medium**; the intelligence engine's own cross-function reentrancy has `location.file == ""` and confidence 0.36 while the lint hits have 0.57 | **Open** → B.1 |
| A4 Full audit | `miesc audit full --skip-unavailable` | Exit 0 in ~234 s on an 83-line contract; 67 findings with **29 CRITICAL**; unavailable tools reported as "Failed"; `dagnn`/`smartbugs_ml` counted as successes via fallbacks (E2E #17, not re-run here) | **Open** → B.1, B.3, B.6 |
| A5 Reports & exports | `report -f html/pdf/markdown`, `export -f sarif` | HTML/Markdown/SARIF 2.1.0 fine; `-f pdf` silently wrote HTML with exit 0 (E2E #11) | **Fixed** (#167 exits 1; test in #171) |
| A6 Local LLM path | `scan --model ollama` | 0 LLM findings: the model returned JSON with unescaped quotes inside Solidity snippets; 14b failed the same way; SmartGuard logs "JSON parse error in CoT response" per function | **Partly fixed** (#174 tolerant parser on the scan path). SmartGuard and per-adapter fragility open → B.5 |
| A7 CI / MCP | GitHub Action, SARIF, `baseline diff`, MCP tools | Baseline/suppression and SARIF exist and work; MCP exposes 22 tools once the SDK is pinned; README listed 11 incl. a non-existent one | **Fixed docs** (#167). Drift prevention open → B.7 |
| A8 Reproduce the paper | `make reproduce`, `make bench` | `make reproduce` green (all claims recompute). `make bench` on main: recall 143/143 vs paper 137/143; precision 20.5 % → 22.4 % after #172 (paper 22.2 %); the "LLM-free" profile silently called Ollama through SmartGuard until #168 added `--no-llm` | **Fixed** path; precision lever remaining → B.4 |
| A9 Trust the docs | version strings, tool counts, package layout | Docs said 6.0.0 / `src/` / "35 modules" / 11 MCP tools while the code said 6.1.0 / `miesc/` / 50 adapters / 22 tools (E2E b, c, d, h) | **Fixed** (#167, #169, #173). `docs/ROADMAP.md` still described 6.0.0 → this PR |
| A10 Release | `pip install miesc` gets the fixes | PyPI served 6.0.0 for three months of fixes; 6.1.0 was never tagged; the release-notes job overwrote the release body | 6.1.1 **published** 2026-10-20; workflow fix in #175 (open) → B.8 |

Reading the table: install, docs and reproducibility were the 2026-10-20 sprint and are
largely closed. What a researcher now meets first is **the quality of what the tool says
about their contract**. That is Part B.

---

## Part B — Gaps ranked by impact on a researcher

### B.1 Finding trust (highest impact)

What we saw on one 83-line contract (`miesc scan examples/contracts/VulnerableBank.sol`,
main 8f872577, LLM off):

| Symptom | Mechanism | Where |
|---|---|---|
| "Add onlyOwner modifier" suggested as the fix for a public `withdraw()` flagged by Aderyn `send-ether-no-checks` | Fix templates are keyed by *canonical category* (`access_control`), not by the detector or the code context; Aderyn's rule is mapped to that category | `miesc/core/intelligence.py` (template block near line 1125), category mapping in the correlation layer |
| Lint-class rules (`useless-public-function`, `unspecific-solidity-pragma`) shown as **Medium** | Severity is taken from the tool bucket and never capped by rule class; the E2E audit shows the same inflation at scale (29 CRITICAL on a toy) | `miesc/adapters/aderyn_adapter.py` `SEVERITY_MAP`; audit aggregation |
| Intelligence findings with `location.file == ""` and `function == "unknown"` | Location literal hard-coded in two emitters | `miesc/core/intelligence.py` lines 742 and 780 |
| Confidence 0.57 for lint, 0.36 for a true cross-function reentrancy | Calibration mixes detector reliability and agreement count but has no notion of rule class or ground-truth per rule | confidence calibration in the correlation engine |
| Same rule reported once per function with no grouping | No grouping of identical rule hits per file | finding aggregation |

**Target state.** Every finding has a non-empty file and line; a fix suggestion is tied to the
detector rule (or omitted) rather than to a category; lint and informational rules cannot
exceed Low/Info in any report; confidence is monotone with the rule's measured precision on
SmartBugs-curated (we now have per-rule TP/FP from the 2026-10-20 artifacts); identical rule
hits in one file are grouped with a count.

**Acceptance (checkable):** a test over the 143 SmartBugs-curated contracts asserting no
finding with empty `location.file`; a severity-class table in `miesc/data/config` with a test
that no `Info`/`Low` class rule reaches Medium; the `VulnerableBank.sol` scan shows no
`onlyOwner` advice on `withdraw()`; precision on the corpus does not drop.

### B.2 Run provenance

A researcher cannot cite a run. The scan JSON carries `version` and `timestamp` but no
tool versions, no `solc` version per contract, no config hash, no seed, no `llm_free`
flag outside `evaluate`. The paper artifacts needed a hand-written environment table for
that reason (`paper/PAPER1_REPRODUCIBILITY.md` §Environment).

**Target state.** Every result JSON (`scan`, `audit`, `evaluate`, `fix`) carries a
`provenance` block: MIESC version and git SHA when available, Python, OS/arch, each tool's
version string as reported by the binary, solc version chosen per contract, config file
hash, `MIESC_SEED`, `llm_free`, and the exact CLI. `evaluate compare` prints both blocks.

**Acceptance:** `jq .provenance results.json` is non-empty for every command; REPRODUCE.md
drops its hand-maintained tool-version table in favour of the artifact's block.

### B.3 Honest denominators

The same run yields 42/50 (doctor), 44/50 "successful" (audit, counting built-in fallbacks)
and "50 adapters run"; unavailable tools with no fallback are labelled **Failed** under
`--skip-unavailable` (E2E "two wrinkles"). #171 started this for Aderyn panics
(`status: skipped`, `reason: unsupported_source`).

**Target state.** One status vocabulary everywhere: `success`, `skipped` (not installed,
unsupported source, disabled by `--no-llm`), `timeout`, `error`; audit and doctor report the
same denominator; fallbacks are shown as `success (fallback)`.

**Acceptance:** `miesc doctor` and `miesc audit full` on the same machine print the same
"available" count; `tools_failed` on a clean machine with `--skip-unavailable` is 0.

### B.4 Precision on the paper corpus

After #172 main is at recall 143/143, precision 22.4 % (paper 22.2 %). The next lever is
measured: **72 false positives come only from the intelligence engine and carry 0 true
positives** (session *Require tool corroboration*, 2026-10-20). Removing them would put
precision near 26 % with recall unchanged.

**Decision for Fernando (methodology):** approve the two category-mapping corrections, and
choose between tightening or deleting the two broad gap-filler patterns. Both change what
the paper profile measures, so the result goes into a new dated artifact and REPRODUCE.md,
never into the frozen paper files.

**Acceptance:** recall 143/143 kept; precision ≥ 25 % on `make bench --no-llm`; per-category
table shows no category with TP 0 and FP > 0 coming from the intelligence engine.

### B.5 LLM path robustness

#174 made the `scan --model` parser tolerant of malformed JSON from local models. The same
failure class remains in SmartGuard (chain-of-thought JSON per function, 10–125 s per
contract) and is latent in every adapter that parses LLM output with its own code.

**Target state.** One shared, tested "LLM JSON extraction" utility used by all LLM adapters
(SmartGuard, GPTScan, GPTLens, iAudit, LlamaAudit, LLMSmartAudit, SmartLLM, LLMBugScanner,
PropertyGPT, FrontierLLM), with a corpus of real malformed responses as fixtures; a per-run
budget per LLM adapter; a `--llm-timeout` that is honoured.

**Acceptance:** fixtures from the 2026-10-20 Ollama runs parse; `audit full` with Ollama on
`VulnerableBank.sol` reports LLM findings from every enabled LLM adapter or an explicit
`skipped (parse)` with the raw response saved.

### B.6 Performance

`audit full --skip-unavailable` took ~234 s on an 83-line contract (E2E #17, LLM adapters
included); `make bench` went from 836 s to 115 s once availability was probed once per run
(#168). The same probe-per-contract pattern likely exists in `audit` and `scan`.

**Acceptance:** `audit full --no-llm` on `VulnerableBank.sol` under 60 s on a laptop; a
timing table per adapter in the audit summary so slow tools are visible.

### B.7 Docs that cannot drift

Three doc sweeps in one day fixed version strings, tool counts, the MCP list and `src/`
references. Sweeps do not prevent recurrence; tests do.

**Target state.** CI tests that: the README MCP tool list equals the server's `tools/list`;
`docs/INSTALLATION*.md` version matches `miesc.__version__` (or is version-agnostic); every
`python -m miesc...` command quoted in README/docs imports; every relative link resolves
(the Links job covers URLs, not module paths).

### B.8 Release hygiene

6.1.0 was never tagged, so 6.1.1 ships minor features under a patch number; the
`release.yml` notes job overwrote the release body (#175 fixes it); `docs/ROADMAP.md`
still said 6.0.0 (fixed in this PR). PyPI 6.1.1 carries the 20.5 % precision profile; #172
is only on `main`.

**Target state.** Tag on every version bump; release notes generated from `CHANGELOG.md`
by the workflow and never overwritten; a 6.1.2 (or 6.2.0 if B.1/B.4 land) so `pip install
miesc` reproduces the numbers REPRODUCE.md describes.

---

## Part C — Waves

| Wave | Scope | Measurable exit |
|---|---|---|
| **C0 (done 2026-10-20)** | install path, docs, Makefile, REPRODUCE.md, `--no-llm`, Aderyn skip, FP tightening, Ollama parser, release 6.1.1 | `make reproduce` green; `make bench --no-llm` = 143/143, 22.4 %; PyPI 6.1.1 installs `[mcp]` and `[ml]` working |
| **C1 — Trust the findings** | B.1 (locations, severity classes, rule-keyed fixes, grouping, calibration), B.3 (status vocabulary) | acceptance lines of B.1 and B.3; `VulnerableBank.sol` scan reads correctly to a reviewer |
| **C2 — Cite the run** | B.2 provenance block; REPRODUCE.md consumes it | `jq .provenance` non-empty on every command |
| **C3 — Precision** | B.4 after Fernando's methodology decision | ≥ 25 % precision, recall unchanged, new dated artifact |
| **C4 — LLM path** | B.5 shared extractor + fixtures + budgets; B.6 timing table | acceptance lines of B.5/B.6 |
| **C5 — Guardrails and release** | B.7 drift tests; B.8 tag discipline, 6.1.2/6.2.0 | drift tests in CI; PyPI version matches REPRODUCE.md numbers |

C1 and C2 touch different files and can run in parallel; C3 waits for the decision; C4
after C1 (it reuses the status vocabulary); C5 closes the cycle.

---

## Part D — Governance decisions that are Fernando's

1. **Freeze manifest branch.** The local manifest's `README.md` hash is the camera-ready
   branch's, not `main`'s; refreshing it to `main` would break validation on the paper
   checkout. Decide which checkout the validator guards, or split the manifest in two.
2. **Paper-facing changes.** B.1 and B.4 change what the paper profile measures. Proposed
   rule: results go to new dated artifacts and REPRODUCE.md; the frozen `paper1_*` files and
   the claims matrices change only with an explicit new baseline (as `CLAUDE.md` already says).
3. **Version semantics.** Whether the next release is 6.1.2 (fixes only) or 6.2.0 (B.1 changes
   severities and fixes users may have baselined against).
4. **Ollama default model.** `default_model` stays `qwen2.5-coder:32b` (the EVMBench "fully
   local" claim used it); docs now say how to force 14b. Keep, or change with a new measurement.

---

## Backlog (small, no wave needed)

- `docs/ROADMAP.md` Near-term still lists "95.8 % → 99.3 % pending baseline"; reconcile with
  the 2026-10-20 artifacts when the next baseline is cut (paper-facing, Fernando's call).
- `doctor` should report the interpreter it runs under, not the `python` on `PATH` (E2E note).
- Merge or close PR #134 (four `call-arg` bugs in `mcp_server.py` still visible to mypy).
- `CHANGELOG.md` has a second, older `## [Unreleased]` heading further down (DPGA entry).
- COMPARISON.md and TOOLS.md still say "35 analysis modules"; #173 explained the 13+6+16
  split, the phrase can now point to it.
