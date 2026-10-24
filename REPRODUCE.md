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

### Wave C3 "Score what the tools found" (2026-10-21)

Same command and environment (`make bench`, `--no-llm`, Python 3.12.6, Slither 0.11.3 resolved
first, Aderyn 0.1.9, Solhint 6.0.1). Two runs, nothing else executing on the machine:
`main` after #188 (clean detached worktree at `ea7cce4f`), then the same `main` plus the three
C3 commits. Artifacts:
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261021_main_after_188.{json,jsonl}` and
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261021_intel_fix.{json,jsonl}`.

| Metric | Wave C4 (reference) | `main` + #188 | + wave C3 | Δ vs. reference |
|---|---|---|---|---|
| Recall (contracts) | 143/143 = 100 % | 143/143 = 100 % | **143/143 = 100 %** | 0 |
| Precision | 22.4 % (495 FP) | 22.4 % (495 FP) | **25.7 % (414 FP)** | +3.3 pt, −81 FP |
| F1 | 36.6 % | 36.6 % | **40.9 %** | +4.2 pt |
| Wall time | 310 s | 143 s | 153 s | |

#188 (ArithmeticDetector cast operands) does not move this profile: `main` + #188 equals C4
contract by contract. Every one of the 81 removed false positives is attributed below; no
false positive was added and no contract lost a true category (per-contract diff of the two
`.jsonl` files). The C3 run is deterministic: a first run on the pre-#188 base also gave 414.

The change is three commits, each measured on the corpus before it was written:

1. **Scorer (`miesc/cli/commands/evaluate.py`), the methodology change.**
   `_normalize_category` falls back to keyword matching on title/description when a finding's
   type is unknown. Two finding kinds that are not SmartBugs categories were being coerced into
   one by that fallback reading their own *remediation text*: the `hardcoded_gas` gap-filler
   (SWC-134, "use call{value:}() with reentrancy guard") scored as `reentrancy`, 36 FP / 0 TP;
   the DeFi adapter's `mev_exposure` rule ("Public withdrawal - can be front-run", ships
   `category` but no `type`) scored as `front_running`, 14 FP / 0 TP. Both existed in the paper
   run (the paper `.jsonl` carries the same 15 layer-7 `front_running` contracts). An explicit
   `OUT_OF_TAXONOMY_TYPES` set (hardcoded_gas, missing_event_emission, the `DeFiCategory`
   values) is now checked against the finding's `type` and `category` before any alias or
   keyword match. Only those names consult `category`, so `smartbugs_detector` findings (also
   category-without-type) are untouched. The empty-type quirk recorded under wave C1 is fixed
   in the same commit (an empty type no longer reaches the substring match). `mev_detector`'s
   balance-dependent `require` on `bad_randomness/smart_billions` is real SWC-114 and is the one
   layer-7 `front_running` finding that still counts (1 FP).
2. **Two gap-fillers removed (`miesc/core/intelligence.py`).** `dos_push_unbounded` fired on
   any `x.push(`: 33 FP (19 of them `History.push(LastMsg)` in reentrancy samples), 0 TP that a
   tool had not already found. `reentrancy_crossfunction` fired on any `.call{value:}` /
   `.call.value(`: 35 FP, 0 exclusive TP; its callback-into-caller pattern
   (`Bank(msg.sender).cb()`, 1 TP / 0 FP) is kept.
3. **Three rule bugs.** `incorrect_constructor_name` never checked the contract name and fired
   on real pre-0.4.22 constructors (`function EthTxOrderDependenceMinimal()` inside that
   contract); it now skips a function named after its *enclosing* contract (a function named
   after a different contract in the file, the copy-paste bug, still fires: the six
   `initTokenBank` / `DranMe` cases). `unchecked_call_pattern` fired on
   `(bool success, ) = x.call.value(..)("")` with `require(success)` on the next line; anchored
   at the statement start (35 TP / 5 FP → 35 TP / 0 FP). `front_running` fired on a bodyless
   `function approve(...) returns (bool);` in an abstract ERC20 declaration; approve now needs a
   body.

What the intelligence layer contributes to this profile after C3: 4 false positives, 0 true
positives that no tool had found (`layers.intelligence.new_categories` in the `.jsonl`:
`access_control` ×2 from `access_control_initwallet` on Parity-style `init()` in arithmetic
samples, `denial_of_service` ×1 on `etherpot_lotto`'s real loop over buyers, `front_running`
×1 on `require(sha3(status) == sha3("Married"))`). That is consistent with the paper-era
ablation: at v5.4.1 the gap-fillers were worth +7 contracts (93.0 % → 97.9 %); the layer 6
detectors shipped since then cover all of them, so the gap-fillers' recall contribution on
`main` is nil and only their precision cost remained.

The alternative that was measured and not taken: ignoring every intelligence-only category in
the scorer (equivalent to `--no-intelligence` for the score, since the FP suppression never
removes a tool category) gives 410 FP / 25.9 %, 0.4 pt more, by scoring a pipeline the paper's
own ablation says mattered and by hiding the noisy rules from `miesc audit` users instead of
fixing them.

Remaining FP sources are now tool-side: `arithmetic` 128 (Slither/Aderyn pre-0.8 overflow
heuristics), `time_manipulation` 43, `access_control` 67, `bad_randomness` 46.
### ArithmeticDetector fix (#188), corpus check (2026-10-21)

#188 made the built-in `ArithmeticDetector` recognise cast operands (`uint256(cnt) * _value`,
the BECToken batchOverflow) and stop flagging SafeMath's own internals. On this corpus it
moves nothing: the "`main` + #188" column of the wave C3 table above equals wave C4 contract
by contract (143/143, 495 FP; `arithmetic` 15/15 with 128 FP). SmartBugs-curated's 15
arithmetic contracts were already covered by Slither and the other detectors, so the fix shows
up on the arena contracts (BECToken, `insecure_transfer`, `integer_overflow_1`: detector-level
recall 33 % → 100 %). Plan wave C7 keeps
`smartbugs_eval_layers_1_6_7_20261021_main_after_188` as the baseline for the next coverage
item.


### Arithmetic false positives (2026-10-21)

Same command (`make bench`, `--no-llm`). Artifact
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261021_arith_fp2.{json,jsonl}`.

| Metric | Wave C3 (reference) | Arithmetic fix | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 | **143/143** | 0 |
| Precision | 25.7 % (414 FP) | **28.9 % (352 FP)** | +3.2 pt, −62 FP |
| F1 | 40.9 % | **44.8 %** | +3.9 pt |
| `arithmetic` category | 15 TP / 128 FP | 15 TP / 66 FP | −62 FP |

Three causes, each measured before it was changed. The scorer's keyword fallback read
Slither's `solc-version` description ("known severe issues: … overflow") as a diagnosis, so
layer 1 "detected" arithmetic on 95 of the 128 non-arithmetic contracts; informational
detectors are now out of taxonomy. The layer-6 `smartbugs_detector` arithmetic rule reported
any pre-0.8 arithmetic assignment at "low" confidence and the `smartbugs_ml` fallback fired
on any pre-0.8 code without SafeMath (126/128 contracts); the rule now needs a state or
financial context, and the fallback a balance-like state write with raw arithmetic.

A first cut that dropped the context-free bucket outright lost five contracts
(`integer_overflow_minimal/add/mul/multitx_*`: `count -= input;`, a contract-level counter
written with a function parameter, no financial term, no index); the earlier claim that
layer 1 covered all 15 arithmetic contracts was itself an artifact of the `solc-version`
mis-mapping. The rule therefore also counts a contract-level variable written with an
external input, which brings the five back (138 → 143) and keeps the precision gain.
The remaining 66 arithmetic false positives are Slither's own pre-0.8 heuristics.

### Time and randomness data flow (2026-10-21)

Same command (`make bench`, `--no-llm`), run with a fresh `HOME` so no adapter cache is
reused. Artifact `benchmarks/results/smartbugs_eval_layers_1_6_7_20261021_time_rand_flow.{json,jsonl}`.

A measurement note first, because it bit this run: the `smartbugs_ml` fallback caches its
predictions for 24 h in the *system temp directory*, outside `HOME`, keyed by contract
hash only. The first bench after the rule change was served the previous rules' findings
and reported `bad_randomness` unchanged at 46. The key now includes a fingerprint of the
rule code, so a rule change invalidates the cache; if you compare two runs made with
different rules on the same machine within a day, that fingerprint is what keeps the
comparison honest.

| Metric | Arithmetic fix (reference) | Data-flow fix | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 | **143/143** | 0 |
| Precision | 28.9 % (352 FP) | **31.9 % (305 FP)** | +3.0 pt, −47 FP |
| F1 | 44.8 % | **48.4 %** | +3.6 pt |
| `time_manipulation` category | 5 TP / 43 FP | 5 TP / 30 FP | −13 FP |
| `bad_randomness` category | 8 TP / 46 FP | 8 TP / 14 FP | −32 FP |

The other two moves are one false positive each: `access_control` 67 → 66 (the path leak
below) and `arithmetic` 66 → 65 (a stale cached `smartbugs_ml` prediction in the reference
run, see the measurement note). Tool statuses are identical in both runs (4 Slither errors,
18 Aderyn skips/errors on the same contracts); the reference ran under Python 3.14 and this
one under 3.12, and an offline re-score of the reference run's stored findings with the new
scorer and rules predicted 306 FP, so the two runs are comparable.

Attribution first (every layer-1/6/7 tool run on the 89 false-positive and 13 labelled
contracts, each finding passed through the scorer): the `bad_randomness` false positives
came from the `smartbugs_ml` fallback rule on all 46 contracts (it fired when the file
contained `block.timestamp` or the *substring* `now`, which also matches `known`), from
Slither's `timestamp` detector mis-scored as randomness on 22 (the alias `block.timestamp`
made `timestamp` a substring match), and from the layer-6 "Timestamp Dependency" rule on 13
(its `block.number` description says "predictable", a randomness keyword). The
`time_manipulation` false positives came from 4naly3er's `use_of_block_timestamp` on 35 of
43 (any line with the attribute) and from the intelligence gap-filler, whose
"non-timelock" filter flagged `x = block.timestamp` and suppressed comparisons, the
inverse of the labelled shapes.

The fix is one shared, deliberately minimal data flow
(`miesc/detectors/chain_attribute_flow.py`): the chain attribute, or a local assigned from
it in the same function, has to reach a comparison inside a condition or a `return`
(time dependence), or a hash, a modulo or be a strong entropy source such as `blockhash`
or `block.difficulty` (weak randomness). Storing the timestamp, logging it or doing
arithmetic that never reaches such a sink is not a finding. Measured before changing
anything: all 5 labelled `time_manipulation` and all 8 labelled `bad_randomness` contracts
have such a flow (`ether_lotto.sol` only through the entropy branch, `old_blockhash.sol`
only through the strong-source branch); 34 of the 46 and 14 of the 43 false positives do
not. The three emitters above are gated on it; the layer-6 detectors and the Peculiar rule
already required a comparison or an entropy context and were left alone.

What remains is not a detector defect. The `time_manipulation` false positives left are
comparison shapes (`require(now > unlockTime[msg.sender])` cooldowns in reentrancy
contracts, deadline checks) that SmartBugs' single label per contract cannot credit, and the
`bad_randomness` ones are lottery contracts filed under another category plus Slither's
own `weak-prng`. Cutting those would fit the labels, not improve the tool.

Two scorer corrections ride along, each measured on the stored findings of the reference
run: Slither `timestamp` now scores as `time_manipulation` (it moved 22 contracts between
categories and created no new false positive), and path-like tokens are removed before the
keyword fallback, because Slither embeds the file path in its descriptions and on a
labelled corpus the path *is* the label (`dataset/bad_randomness/lottery.sol` contains
"randomness"): 1 false positive, 0 hits on the reference run, but a leak worth closing.

### Access-control false positives (2026-10-23)

Same command (`make bench`, `--no-llm`, fresh `HOME`, temp caches cleared). Artifact
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261023_access_control_fp.{json,jsonl}`.

| Metric | Data-flow fix (reference) | Access-control fix | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 | **143/143** | 0 |
| Precision | 31.9 % (305 FP) | **33.7 % (281 FP)** | +1.8 pt, −24 FP |
| F1 | 48.4 % | **50.4 %** | +2.0 pt |
| `access_control` category | 18 TP / 66 FP | 18 TP / 42 FP | −24 FP |

Every other category is unchanged and the tool statuses match the reference run contract
for contract (Aderyn 17 skips and 1 error, Slither 4 errors). Two harness hazards surfaced
on the way and are worth knowing before you compare runs: Aderyn installs the solc it needs
per pragma through `svm` under `HOME`, so a "fresh HOME" given as a *relative* path makes it
fail on every contract with "Error running solc command" (use an absolute path); and
aderyn 0.1.x panics when its GitHub version check is rate-limited, which the adapter now
avoids with `--skip-update-check`. Both failures used to be reported as "unsupported
Solidity dialect" skips.

The ceiling first. Of the 66 contracts wrongly credited with `access_control`, 36 carry a
finding that is not ours to remove: Slither's own `arbitrary-send-eth` on 26 (SmartBugs maps
it to this category), or a real `tx.origin` / unguarded `selfdestruct` in a contract filed
under another label. That left 30 reachable, and 24 are gone; the 6 that stay are public
`init*` functions that assign `owner = msg.sender` with no real constructor in the contract,
and a constructor typo (`DranMe`), which are genuine access-control bugs whatever the label.

Attribution of the 30 (every layer-1/6/7 tool re-run on today's `main`, each finding passed
through the scorer): the layer-6 "Missing Access Control" rule flagged any public `withdraw`
without `onlyOwner`, including users taking back their own deposit; Peculiar's rule flagged a
function that merely *mentioned* `withdraw`, `pause` (`if (paused)`) or `mint`; the advanced
detector's "Ownership Not Renounced" note (22 contracts, 0 labelled ones) reached the
category through the keyword "onlyOwner"; and the intelligence `constructor_mismatch` regex
ran across contracts (`.*?`), pairing `contract SafeMath` with `function Ownable()`.

The fix is a shared pair of predicates (`miesc/detectors/access_guards.py`): a function is
*guarded* when it has any `only*` modifier, compares `msg.sender` in a condition, or uses a
role mapping indexed by `msg.sender` as a boolean (a balance comparison on such a mapping
is not a guard); a withdrawal is *self-service* when the value goes to the caller or to a
recipient whose own mapping entry is read, or refunds `msg.value`, and never when the amount
mentions the contract balance. The layer-6 rules, Peculiar and the intelligence
gap-fillers use them; the legacy-constructor rules additionally require a public, unguarded
function assigning `msg.sender` to an owner-like variable inside a contract that has no
function named after itself; array writes count only when the array shrinks or the caller
supplies the length or the index. "Ownership Not Renounced" is out of taxonomy, as
`solc-version` was in the arithmetic fix. Every labelled access-control contract keeps its
hit (measured before and after on the stored findings, then with the run above).

### DeFi detectors and Phase-1 miners on `main` (2026-10-24)

Same command (`make bench`, `--no-llm`, fresh `HOME`, temp caches cleared), on `main` at
`05607c3a` (v6.5.0 plus the export fix, the four DeFi detectors of #211 and the Phase-1
miners of #209, #214 and #213). Artifact
`benchmarks/results/smartbugs_eval_layers_1_6_7_20261024_post_pr211_213.{json,jsonl}`.

| Metric | Access-control fix (reference) | This run | Δ |
|---|---|---|---|
| Recall (contracts) | 143/143 | **143/143** | 0 |
| Precision | 33.7 % (281 FP) | **33.7 % (281 FP)** | 0 |
| F1 | 50.4 % | **50.4 %** | 0 |

Identical to the reference, contract for contract: the 143 per-contract false-positive lists match, every category count matches, and every tool ran on the same number of contracts (Slither 139, Aderyn 125, the rest 143). The four DeFi detectors ran on all 143 contracts and produced only the fee-on-transfer hits the scorer ignores (outside the SmartBugs taxonomy); the Phase-1 miners emit plans, not findings, so they cannot move the line either. This is the baseline the next release ships with.

A harness hazard first, because the first attempt at this run was wrong and looked like
good news: it reported precision 38.4 % (229 FP) with recall intact. `tools_used` showed
why: Slither had run on 0 of 143 contracts. The Slither adapter picks the compiler from
`~/.solc-select/artifacts`; a fresh `HOME` has none, so it falls back to
`--solc-solcs-select`, and the machine's `solc-select` wrapper no longer starts (its
interpreter line points at a Command Line Tools python that an Xcode update removed).
Every Slither run failed, 52 of Slither's false positives vanished with it (17
`access_control`, 27 `unchecked_low_level_calls`, 7 `reentrancy`, 1
`time_manipulation`) and the aggregate improved. The fresh `HOME` used for a comparable run
must link the compiler store that is not a cache, `ln -s ~/.solc-select $H/.solc-select`,
and nothing else: Aderyn populates its own `svm` store under the fresh `HOME` on first use
(it downloads the solc each pragma needs), and a pre-created `~/.svm` symlink to a path that
does not exist makes it panic on every contract ("svm data dir … is not a directory", exit
101), which the adapter reports as an "unsupported Solidity dialect" skip. The second
attempt at this run made exactly that mistake: Slither back, Aderyn on 0 of 143, aggregate
one false positive short of the reference. Before comparing two artifacts, check that
`.tools_used` lists the same tools and that `.provenance.solc.binaries` shows installed
versions in both; a missing tool is a different experiment, not a better number.

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
