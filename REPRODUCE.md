# Reproducing the MIESC paper results

This guide takes a clean machine to the headline Paper 1 number (SmartBugs-curated,
143 contracts: **recall 95.8 %, precision 22.2 %, F1 36.0 %**) and tells you how close
your run should land. It needs no LLM, no GPU and no API key; the whole profile is
static tools plus MIESC's built-in detectors.

Two levels of reproduction are available:

| Level | What it does | Time | Command |
|---|---|---|---|
| **Verify** | Recomputes every Paper 1 and Paper 2 claim from the stored artifacts in `benchmarks/results/` and checks that each named artifact exists | < 1 min, offline | `make reproduce` |
| **Re-measure** | Re-runs the Paper 1 SmartBugs profile on your machine and compares it with the published artifact | 15–90 min depending on CPU | `make bench` + `miesc evaluate compare` |

The authoritative mapping from each paper claim to its artifact and command lives in
[`paper/PAPER1_REPRODUCIBILITY.md`](paper/PAPER1_REPRODUCIBILITY.md) and
[`paper/PAPER2_REPRODUCIBILITY.md`](paper/PAPER2_REPRODUCIBILITY.md). This page is the
practical walkthrough; those files are the record.

## 1. Prerequisites

| Component | Version used for the paper | Notes |
|---|---|---|
| Python | 3.12+ (paper runs: 3.14.4 / 3.12.6) | `python3 --version` |
| Node.js | 18+ | for Solhint |
| Rust/Cargo or Homebrew | — | for Aderyn |
| Git | — | the corpus ships in the repository |

Operating systems exercised: macOS ARM64 (canonical runs) and Linux/Docker (revalidation).
Windows users should use WSL2.

## 2. Install the reproducible profile

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC
python3.12 -m venv .venv && source .venv/bin/activate

# MIESC + Slither (core) + the built-in ML detectors (scikit-learn)
pip install -e '.[ml]'

# Solidity compilers: SmartBugs-curated is 139/143 ^0.4.x; MIESC picks, per contract,
# the installed solc-select version that satisfies the pragma.
pip install solc-select
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20
solc-select use 0.8.20

# The other two static tools of the paper profile
cargo install aderyn        # or: brew install aderyn
npm install -g solhint
```

Check that the six tools of the profile are visible:

```bash
miesc doctor
```

The paper profile uses exactly these adapters (from the artifact's `tools_used`):
`slither`, `aderyn`, `solhint`, `fouranalyzer`, `smartbugs_ml`, `smartbugs_detector`.
`fouranalyzer` and `smartbugs_detector` are built in; `smartbugs_ml` needs scikit-learn
(the `ml` extra). Layers 6 and 7 also run other built-in detectors (`smartguard`,
`peculiar`, `threat_model`, `mev_detector`, `gas_analyzer`, `upgradability_checker`);
they were part of the paper run as well and the layer membership has not changed since
v5.4.1. Optional tools that are *not* installed (Wake, Semgrep, DA-GNN) are skipped and
were not part of the paper number either.

Tool versions are part of every result MIESC writes (the `provenance` block, see
[docs/guides/RESEARCH.md](docs/guides/RESEARCH.md#run-provenance)). Read them from the
artifact you are comparing against instead of from this file:

```bash
jq '.provenance.tools' <run>.json            # each tool that ran, as its binary reports it
jq '.provenance.solc.binaries' <run>.json    # the solc builds the Slither adapter selected
jq '.provenance.python_packages' <run>.json  # slither-analyzer, scikit-learn, solc-select, ...
jq '.provenance | {miesc, python, platform, config, env, llm_free, command_line}' <run>.json
miesc evaluate compare <run_a>.json <run_b>.json   # both blocks side by side, differences marked
```

The two runs documented below predate the block, so what is known about them lives only
here: the paper run (v5.4.1, 2026-05) used Slither 0.11.5 (`requirements-lock.txt`); its
Aderyn, Solhint and scikit-learn releases were not recorded. The 2026-10-20 re-run on
`main` (v6.1.0) used Slither 0.11.6, Aderyn 0.1.9, Solhint 6.0.1 and scikit-learn 1.9.1,
noted by hand at run time. Every later `make bench` artifact carries its own block.

## 3. Verify the claims (fast)

```bash
make reproduce          # = python benchmarks/verify_paper_claims.py
```

Expected tail:

```
Data Availability: 6 named artifacts found, 0 missing.

All claims recomputed match the paper (documented items in ERRATA.md marked DOC), and every named artifact exists.
```

The script exits non-zero on any mismatch. Documented rounding differences are listed in
`paper/ribci-cyted-2026/ERRATA.md`.

Two related targets:

```bash
make dataset-verify     # corpus sanity: 143 contracts, 10 categories
make ablation           # LLM-free layer ablation: 82.5 % -> 93.0 % -> 97.9 % recall
```

## 4. Re-measure on your machine

```bash
make bench
```

which runs the documented command in its LLM-free profile:

```bash
python -m miesc.cli.main evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \
  --layers 1,6,7 --timeout 120 --no-llm \
  --output benchmarks/results/smartbugs_eval_layers_1_6_7_<YYYYMMDD>.json \
  --jsonl  benchmarks/results/smartbugs_eval_layers_1_6_7_<YYYYMMDD>.jsonl
```

`--layers 1,6,7` matters: the CLI default is `1,5,7,9`, which is a different profile.

`--no-llm` matters too. The paper profile is LLM-free, but `smartguard` (layer 6) calls a
local Ollama model whenever `ollama list` shows one. On the paper machine it did not run
(layer 6 took 0.1 s per contract in the artifact's timing); on a workstation with Ollama
and a coder model installed it does, adding LLM findings to the count and taking 10–120 s
per contract. `--no-llm` skips every adapter that declares an LLM backend (SmartGuard
here; the layer 5 and 9 adapters when those layers are selected) without probing it, and
records `"llm_free": true` plus the skipped tools in the result's `experiment_card`.

Two runs on the same day go to the same file name; `make bench BENCH_TAG=<label>` adds a
suffix (`..._<YYYYMMDD>_<label>.json`) so a before/after pair does not overwrite itself.

Then compare with the paper artifact:

```bash
python -m miesc.cli.main evaluate compare \
  benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json \
  benchmarks/results/smartbugs_eval_layers_1_6_7_<YYYYMMDD>.json
```

### What "similar" means

The pipeline is deterministic given the same tool versions; what drifts between machines
is the external tools (Slither/Aderyn/Solhint releases change detectors and messages) and
the solc build chosen for each pragma. Expect:

| Metric | Paper (tag `v5.4.1`) | At tag `v5.4.1` on a fresh machine | On `main` (6.1.0) |
|---|---|---|---|
| Recall (contracts) | 137/143 = 95.8 % | 136–138 / 143 (one contract either way) | ≥ 141/143 (measured 143/143) |
| Precision | 22.2 % | 20–24 % (FP count moves with tool versions) | 19–22 % (measured 20.5 %) |
| F1 | 36.0 % | 33–38 % | 33–36 % (measured 34.1 %) |
| Per-category recall | 100 % in 7 of 10 categories; `front_running` 2/4; `other` 0/3; `short_addresses` 0/1 | the same three categories carry the misses | all ten categories at 100 % |

If recall drops by more than one contract, look at the per-category table of the
comparison first: a whole category at 0 % means a tool did not run (missing solc
version, Aderyn or Solhint not on `PATH`). A precision shift larger than ~2 points
usually means a different Slither major/minor release.

### Re-run on main (2026-10-20)

Command: `make bench` (Ollama unreachable), MIESC 6.1.0 @ `main`, macOS ARM64, Python 3.12.6,
Slither 0.11.6, Aderyn 0.1.9, Solhint 6.0.1, scikit-learn 1.9.1. Artifact:
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261020.{json,jsonl}` (new dated files; the
paper artifact is untouched).

| Metric | Paper (v5.4.1) | Re-run on `main` (6.1.0) | Δ |
|---|---|---|---|
| Recall (contracts) | 137/143 = 95.8 % | **143/143 = 100 %** | +6 contracts |
| Precision | 22.2 % (481 FP) | 20.5 % (553 FP) | −1.6 pt (+72 FP) |
| F1 | 36.0 % | 34.1 % | −2.0 pt |
| Wall time | 737 s | 836 s | 0.9× |
| Contracts lost vs. paper | — | 0 | |

Where the difference comes from (per-contract diff of the two `.jsonl` files):

- **Gained, 9 contracts.** The six `access_control` misses of the paper
  (`incorrect_constructor_name{1,2,3}`, `mapping_write`, `proxy`, `unprotected0`) are now
  caught by the layer 6 built-in detectors; the three `other/*` contracts are caught at layer
  1. These are detector improvements shipped in 6.0/6.1, not tool-version noise.
- **False positives, +72.** Almost all of them are two categories the layer 6
  `smartbugs_detector` now emits broadly: `short_addresses` (1 TP / 42 FP) and
  `front_running` (4 TP / 43 FP vs. 2 TP / 5 FP in the paper). Reentrancy FPs went down
  (109 → 75) and `access_control` FPs up (47 → 68).
- **Aderyn 0.1.9 fails (exit 101) on 36 of the 143 contracts** (pre-0.4.22 syntax). It did
  not cost a contract because Slither and the built-in detectors cover them, but it is a
  reason a different Aderyn release moves the FP count.

Reading: `main` detects a superset of what the paper measured (no contract lost, the three
hard categories now at 100 %) and pays for it with 1.6 precision points. The paper's
measurement was taken at tag `v5.4.1`; checking that tag out puts a fresh machine inside the
"at tag" tolerance above (the `ml` extra and the `make bench` target do not exist there, so
install scikit-learn by hand and run the command explicitly):

```bash
git checkout v5.4.1          # the version the artifact was produced with
pip install -e . scikit-learn solc-select
# --no-llm does not exist at the tag: make Ollama unreachable instead
OLLAMA_HOST=http://127.0.0.1:1 python -m miesc.cli.main evaluate corpus \
  benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 --timeout 120 \
  --output smartbugs_eval_v541_rerun.json --jsonl smartbugs_eval_v541_rerun.jsonl
```

If you need the paper's precision on `main`, the item to fix is the FP gap, not the recall:
the `short_addresses` and `front_running` patterns live in
`miesc/detectors/smartbugs_detectors.py` (wired by `miesc/adapters/smartbugs_detector_adapter.py`).

### Tightened `short_addresses` / `front_running` patterns (2026-10-20)

Same command and environment as above (`make bench`, `--no-llm`), after tightening the two
layer 6 patterns. Artifact:
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261020_fp_tightened.{json,jsonl}`.

| Metric | Paper (v5.4.1) | Re-run on `main` (morning) | Tightened patterns | Δ vs. paper |
|---|---|---|---|---|
| Recall (contracts) | 137/143 = 95.8 % | 143/143 = 100 % | **143/143 = 100 %** | +6 contracts |
| Precision | 22.2 % (481 FP) | 20.5 % (553 FP) | **22.4 % (496 FP)** | +0.2 pt |
| F1 | 36.0 % | 34.1 % | **36.6 %** | +0.5 pt |
| `short_addresses` TP / FP | 0 / 0 | 1 / 42 | 1 / 6 | |
| `front_running` TP / FP | 2 / 5 | 4 / 43 | 4 / 20 | |

What changed (`miesc/detectors/smartbugs_detectors.py`, unit tests in
`tests/test_smartbugs_detectors.py` use the ground-truth contracts as positives and former
false positives as negatives):

- `short_addresses` now needs the DASP scenario, not just an `(address, uint)` signature:
  an externally callable function with a body, compiled for solc < 0.5 (0.5+ rejects short
  calldata), not owner-only, whose body credits the address parameter with the amount
  parameter (ledger write or ether send), and no `msg.data.length` check. Interface
  declarations, `internal` helpers and `AddMessage(address, uint, string)`-style loggers no
  longer fire. The 6 remaining FPs are 0.4.x ERC20 `transfer` functions identical in shape
  to the labelled contract.
- `front_running` dropped the two line patterns that produced most of the noise: any
  `keccak256`/`sha3` call (function selectors, `sha3(msg.data)` in multisig modifiers,
  randomness) and any `function approve(...)` line (including interface declarations). The
  hash-puzzle check is now per function (hash of a *parameter* compared with `==`, then a
  transfer in the same function); the approve check needs an implemented `approve` that
  overwrites the allowance without a zero-allowance guard or increase/decrease helpers; the
  TOD check needs `msg.sender.transfer(<reward state variable>)`. Only 3 of the 20 remaining
  `front_running` FPs come from this detector (unguarded ERC20 `approve` functions, same
  shape as the labelled contract). 15 are the layer 7 `defi` adapter's "MEV Exposure"
  finding (plus `mev_detector` on one contract), mapped to `front_running` by the keyword
  fallback in `evaluate._normalize_category`; 2 are the intelligence engine's own
  `front_running` source patterns in `miesc/core/intelligence.py` (`require(sha3(...) ==`,
  `function approve(`), which the detector used to mask. Both are separate code paths, left
  for a separate change.

The 496 include the two `unchecked_low_level_calls` FPs on `reentrancy/*` contracts that the
`--no-llm` re-run attributed to Slither drift (553 in the morning run, 555 with `--no-llm`);
the comparison above therefore understates the gain by two.

Note on the paper figures: the paper's JSON summary reports `front_running` 2 TP / 5 FP and
`short_addresses` 0 / 0 (481 FP in total), while the per-contract `.jsonl` next to it records
4 / 43 and 1 / 42 (569 FP). The published number is the JSON summary; the comparison above
uses it. The frozen artifacts are not modified.


### Wave C1 "Trust the findings" (2026-10-20)

Same command and environment as above (`make bench`, `--no-llm`) after the finding-quality
changes of wave C1 (real file path and function on every finding, lint rules capped at
Low/Info by `miesc/data/config/rule_classes.yaml`, fix templates keyed by detector rule,
identical rule hits grouped per file, one tool-status vocabulary). Artifact:
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261020_trust_findings.{json,jsonl}`.

| Metric | Tightened patterns (reference) | Wave C1 | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 = 100 % | **143/143 = 100 %** | 0 |
| Precision | 22.4 % (496 FP) | **22.4 % (495 FP)** | −1 FP |
| F1 | 36.6 % | **36.6 %** | 0 |
| Wall time | 195 s | 179 s | |

Nothing in C1 changes which tools run or what they report; the only step that can move the
score is the location fill (findings now carry file and function *before* the semantic
dedup, so groups form differently and the context-aware FP check can look the function up).
A run of that step alone also landed on 496 FP, but it is not clean evidence: a `miesc scan`
executed during that bench contaminated two contracts (`other/random_number_generator`,
`other/lucky_doubler`) because the Aderyn and Slither adapters write fixed
`/tmp/aderyn_output.json` / `/tmp/slither_output.json` paths and concurrent runs read each
other's output; those two accidental flips cancelled the five real ones. The final run above
was made with nothing else running and equals the reference plus five deterministic flips
(re-checked twice on a five-contract corpus), all in the false-positive column of the
intelligence layer and all in `reentrancy`: lost on `unchecked_low_level_calls/mishandled`,
`access_control/mycontract`, `arithmetic/timelock`; gained on
`access_control/incorrect_constructor_name3`, `access_control/mapping_write`. The mechanism is
not C1 itself but a scoring quirk it exposes: `_normalize_category` in
`miesc/cli/commands/evaluate.py` matches an **empty** finding type against every alias
(`"" in alias` is true), so a layer 6/7 finding that carries only a title (`Integer
Overflow/Underflow`, `MEV Exposure Detected`, ...) is counted as `reentrancy`; which such
finding survives dedup decides whether that contract gets the spurious `reentrancy` FP.
Fixing the scorer is a methodology change (plan B.4) and is left for wave C3.

Tool statuses are now the same vocabulary in every output (`success`, `success (fallback)`,
`skipped` with a reason, `timeout`, `error`); the per-layer `tool_status` in the `.jsonl`
reads `skipped` + `tool_reason: not_installed | no_llm` where the earlier artifacts read
`not_available` / `skipped`. Comparisons with `miesc evaluate compare` are unaffected.


### Wave C4 "LLM path robustness" (2026-10-20)

Same command (`make bench`, `--no-llm`) after routing every LLM adapter through the shared
JSON extractor and adding the `--llm-timeout` budget. The profile is LLM-free, so nothing
should move, and nothing did. Artifact:
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261020_c4.{json,jsonl}`.

| Metric | Wave C1 (reference) | Wave C4 | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 = 100 % | **143/143 = 100 %** | 0 |
| Precision | 22.4 % (495 FP) | **22.4 % (495 FP)** | 0 |
| F1 | 36.6 % | **36.6 %** | 0 |
| Wall time | 179 s | 310 s | run overlapped with an Ollama audit on the same machine |

The LLM-path measurements of the wave are on `examples/contracts/VulnerableBank.sol`:
`scan --model ollama` (qwen2.5-coder:32b) now parses the 1,419-character response that
yielded zero findings in the walkthrough (`json_repair` strategy, 1 finding); `audit full`
with Ollama reachable took 724 s with three LLM adapters hitting the 120 s per-call budget
(GPTScan, GPTLens, LLM-SmartAudit, reported as `timeout`, not as empty success); with
Ollama unreachable the same audit takes 15 s.

## 5. What is not covered here

- **LLM follow-up (97.9 %)**: Paper 1 reports a local-Ollama pass on the six misses as a
  secondary claim; it needs `qwen2.5-coder` models and is not part of the reproducible
  profile above.
- **EVMBench and the real-world exploit set**: their commands and artifacts are listed in
  `paper/PAPER1_REPRODUCIBILITY.md`; the EVMBench provider runs need paid or local LLM
  access and are kept as stored artifacts verified by `make reproduce`.
- **Paper 2 (remediation)**: the four stages (fix applied, compiles, vulnerability
  eliminated, no regression) are recomputed from the stored artifacts by `make reproduce`;
  re-running the generation needs Foundry 1.3.x and the external Slither pass described in
  `paper/PAPER2_REPRODUCIBILITY.md`.

## 6. Keep the record intact

`benchmarks/results/paper1_*` and `paper2_*` are the frozen evidence of the published
papers. New runs go into new dated files (as `make bench` does); do not overwrite the
paper artifacts. `benchmarks/results/` is git-ignored with a per-file allow-list, so a run you
want to keep as evidence needs its own `!benchmarks/results/<file>` line in `.gitignore`. The claims matrices (`benchmarks/results/paper*_claims_matrix.json`) are
only replaced when a new baseline is intentionally published.
