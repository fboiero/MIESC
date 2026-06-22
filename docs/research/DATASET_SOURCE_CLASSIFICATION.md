# Ground-Truth Dataset Sources — Classification & Rationale

> **Scope.** This document records how and why we classified public smart-contract
> vulnerability datasets for use as **ground truth** in the recall-safe benign-context
> verifier evaluation (`scripts/wild_benign_context_eval.py`, `src/ml/benign_context_verifier.py`,
> the `--verify-fp` flag). It is additive tool R&D; it does not touch any frozen paper
> evidence. Local copies of the **usable** sources are fetched by
> `benchmarks/build_datasets.py` (gitignored — never committed).
>
> Every fact below was verified against the actual dataset files (label schemas parsed
> directly), not abstracts. Where a figure is author-reported but not independently
> re-counted, it is flagged.

## 1. Why we need ground truth at all

The verifier's job is to drop **benign-context false positives** without ever dropping a
**real** vulnerability (recall-safety is the cardinal invariant). To measure that honestly
we need, per finding, a trustworthy answer to "is this a real vuln here, or not?" — i.e.
ground truth. The quality of that ground truth *is* the quality of the measurement.

## 2. The two hard filters (and one deliberate non-criterion)

A source is **usable** only if it passes BOTH:

- **F1 — Localized labels (line or function level).** The anchor matches a finding to an
  annotated vuln by **category + line**. Contract-level ("this contract has reentrancy
  somewhere") cannot confirm or refute a *specific* finding, so it cannot anchor recall.

- **F2 — Non-circular labels (human or deterministic, NOT tool-voted).** If the labels were
  produced by the same class of static/symbolic tools the verifier filters
  (Slither/Mythril/Oyente/…), then "agreeing with the labels" just means "agreeing with the
  tools" — circular. Trustworthy labels come from **human auditors** or from
  **deterministic construction** (bug injection with exact logs).

**Deliberate non-criterion: license.** Out of scope for this classification pass (we are
selecting on scientific usability). Licensing must be resolved before any redistribution;
that is why local copies are fetched, not vendored. Real-vs-synthetic is recorded as
context, not a filter — both are useful (synthetic = controlled, real = field).

**Decision rule:** `usable ⇔ F1 ∧ F2`.

## 3. Usable sources (integrated)

All four are converted to one normalized format — SmartBugs-style
`[{path, vulnerabilities:[{category, lines}], clean?}]` — by `scripts/dataset_adapters.py`,
then consumed via `wild_benign_context_eval.py collect --ground-truth`.

| Source | Real? | Labels | Granularity | Size | Why it passes |
|--------|-------|--------|-------------|------|---------------|
| **SmartBugs-curated** | real + crafted | **human** inline + `vulnerabilities.json` | **line** | 143 contracts / 208 vulns | F1 ✓ (line) · F2 ✓ (manual). DASP taxonomy. The canonical core. |
| **fsalzano** (arXiv 2505.15756) | **real** | **human, tool-free** (3 validators) | **line** | 2,182 contracts (1,578 vuln + **604 clean**), 3,425 line instances¹ | F1 ✓ · F2 ✓. Taxonomy already matches ours; ships inline source + a true-negative set. **Highest value.** |
| **SolidiFI-benchmark** | injected | **deterministic** injection logs | **line range** (`loc`,`length`) | ~350 contracts / 9,369 bugs² | F1 ✓ · F2 ✓ (no tools in the loop). 7 types. solc 0.4–0.5. |
| **DAppSCAN** | **real** | **human** auditor reports → SWC | **line** (`lineNumber`) | 21,457 `.sol` / 1,646 weaknesses | F1 ✓ · F2 ✓ (professional audits). SWC taxonomy → mapped. |

¹ Paper states 3,381; our parse of the released file counts 3,425 (minor dedup difference).
² 9,369 bugs is README-reported; contract count not independently re-summed.

**Processing per source** (`scripts/dataset_adapters.py`):
- **SmartBugs-curated** — native format; consumed directly (`--ground-truth vulnerabilities.json`).
- **fsalzano** — `fsalzano` adapter: parse `tag` (`"529: time_manipulation; 563: …"`) into
  `{category, lines}`; materialize `.sol` from the inline `contract_code` column; emit the
  604 `no` rows as `clean:true` (anchored as **FP**, human-verified, no LLM).
- **SolidiFI** — `solidifi` adapter: `BugLog_N.csv` `loc`/`length` → line range
  `[loc, loc+length-1]`; label taken from the **folder** (the CSV `bug type` value is
  UTF-7-mangled for Re-entrancy); contracts flattened to unique names.
- **DAppSCAN** — `dappscan` adapter: walk SWC label JSONs (`{category, function, lineNumber}`);
  parse `lineNumber` (`L74`, `L45-47`); map SWC number → our category; unmapped SWCs kept
  as `swc-<n>` (inert — never falsely anchor).

## 4. Usable via scraper

**Code4rena — IMPLEMENTED** (`scripts/code4rena_scraper.py`). Best quality of all: competitive
human audits with exact `# Lines of code` permalinks. The key simplification that made it
feasible: we do **not** clone the audited repos — each permalink is `blob/<sha>/<path>`, so
we fetch only the referenced file via `raw.githubusercontent.com/<org>/<repo>/<sha>/<path>`
at the pinned SHA (single files, not clones). Three phases: `contests` (list 376 findings
repos) → `scrape` (pull issues, keep High/Med by label, parse permalinks) → `build` (fetch
files @SHA → flat corpus + `vulnerabilities.json`). Verified live on `2023-01-numoen`:
92 High/Med findings → 22 contracts fetched, 0 unreachable.

> **Category caveat.** Code4rena has no SWC/DASP tag — titles are free text. Category is
> keyword-mapped (noisy); unmapped findings get `other` and will NOT anchor (recall-safe:
> under-credit, never inflate). Severity (high/med) comes from issue labels. F1 ✓ (line) ·
> F2 ✓ (human auditors).

**Sherlock — IMPLEMENTED** (`scripts/sherlock_scraper.py`). Real human audits. Findings are
markdown files in `sherlock-audit/<contest>-judging` repos under severity folders (`<n>-H/`,
`<n>-M/`) — severity comes from the folder (authoritative), the `<id>-best.md` is the chosen
canonical write-up (dedupes warden duplicates). Reuses Code4rena's shared machinery (permalink
parsing, title→category, raw fetch, the identical `build` phase). Verified live on
`2023-02-gmx`: 72 High/Med findings → 38 contracts fetched. Same category caveat. F1 ✓ · F2 ✓.

> Sherlock permalinks often pin to `main` (a branch) rather than a commit SHA (the permalink
> regex accepts both); the judging repo is a frozen snapshot, but the fetched source reflects
> `main` at fetch time — record the run date for reproducibility.

## 5. Rejected (with the failing filter)

| Source | Verdict | Failing filter / reason (verified) |
|--------|---------|-----------------------------------|
| **DIVE** (Nature, 22,330) | ✗ | F1 ✗ contract-level **and** F2 ✗ tool-voted (6-tool MultiTagging). The biggest — and the clearest reject. |
| **ScrawlD** (6,780) | ✗ | F2 ✗ — labels are a **5-tool majority vote** (Slither, Smartcheck, Mythril, Oyente, Osiris). Circular. |
| **slither-audited** (HF) | ✗ | F2 ✗ — labeled **by Slither**. Maximally circular for a tool-finding verifier. |
| **Web3Bugs** (492) | ✗ | F1 ✗ — project/contest-level; only bug title + external URL, no file/line. |
| **Bastet** (Kaggle, 4,402) | ✗ | F1 ✗ — expert-labeled but **semantic/finding-level** (46 tags / 77 subtags), no source line. |
| **tintinweb/smart-contract-vulndb** (~39k) | ✗ | F1 ✗ — prose `body` + severity only; no structured location. |
| **HuangGai / JiuZhou** | ✗ | F1 ✗ contract/bug-type level; injection/literature-derived. |
| **Messi-Q/Smart-Contract-Dataset** (40k+) | ✗ | F1 ✗ granularity unconfirmed/contract-level; pattern/tool labels. |
| **VeriSmart-benchmarks** (616) | ✗ | F1 ✗ — contract-level (CVE/paper-derived). |
| **Zenodo 7744053** (4,364) | ✗ | F1 ✗ contract-level; also access-gated. |
| **SC-Bench** | ✗ | mostly AST-**injected** ERC-compliance, not vuln line-level. |
| **EVuLLM** | ✗ | F2 ~ — function-level but label provenance partly LLM/tool. |
| **HF darkknight25** | ✗ | F1 ✗ — synthetic, snippet-level, no line anchors into real source. |
| **HF seyyedaliayati** (270) | ✗ | F1 ✗ file-level **and** F2 ✗ explanations LLM-generated. |

**Pattern:** every rejection collapses to one of three causes — *contract-level only*,
*tool/LLM-derived (circular)*, or *prose-only*. Volume never rescued a source. The largest
candidate (DIVE, 22,330) is rejected; the smallest core (SmartBugs-curated, 143) is kept.
**Rigor lives in the labels, not the row count.**

## 6. Taxonomy normalization

Each source speaks a different vocabulary; all are mapped to the verifier's categories
(`reentrancy, access_control, arithmetic, unchecked_low_level_calls, bad_randomness,
time_manipulation, front_running, denial_of_service, short_addresses`) — the same set the
Slither→category map in `wild_benign_context_eval.py` produces, so anchoring lines up:

- **DASP** (SmartBugs, fsalzano) — near-identity (`unchecked_low_calls→unchecked_low_level_calls`,
  `denial_service→denial_of_service`).
- **SolidiFI folders** — `Overflow-Underflow→arithmetic`, `Re-entrancy→reentrancy`,
  `TOD→front_running`, `Timestamp-Dependency→time_manipulation`,
  `Unchecked-Send`/`Unhandled-Exceptions→unchecked_low_level_calls`, `tx.origin→access_control`.
- **SWC** (DAppSCAN) — `107→reentrancy`, `101→arithmetic`, `104→unchecked_low_level_calls`,
  `105/106/100/108/112/115→access_control`, `120→bad_randomness`, `116→time_manipulation`,
  `114→front_running`, `113/128→denial_of_service`; others kept as `swc-<n>` (inert).

The mapping tables live in `scripts/dataset_adapters.py` (`SOLIDIFI_MAP`, `FSALZANO_MAP`,
`SWC_MAP`).

## 7. Local copies & reproducibility

```bash
python benchmarks/build_datasets.py --labeled    # fetch all four usable corpora locally
```

Clones land in `benchmarks/datasets/` (shallow, `--depth 1`) and are **gitignored** — they
are external data, kept out of the repo to avoid bloat, licensing entanglement, and the
paper freeze. SmartBugs-curated's `vulnerabilities.json` (labels) is fetched separately
because the repo here vendors only the `.sol` files. For a citable run, pin each source to a
commit SHA (none of the four ship release tags) and record it alongside the result artifact.

## 8. Sources

- [awesome-smart-contract-datasets](https://github.com/acorn421/awesome-smart-contract-datasets)
- [SmartBugs-curated](https://github.com/smartbugs/smartbugs-curated) ·
  [fsalzano replication pkg](https://github.com/fsalzano/Empirical-Analysis-of-Vulnerability-Detection-Tools-for-Solidity-Smart-Contracts)
  ([arXiv 2505.15756](https://arxiv.org/abs/2505.15756)) ·
  [SolidiFI-benchmark](https://github.com/DependableSystemsLab/SolidiFI-benchmark) ·
  [DAppSCAN](https://github.com/InPlusLab/DAppSCAN)
- [Code4rena](https://github.com/code-423n4) · [Sherlock](https://github.com/sherlock-audit)
- Rejected: [DIVE](https://www.nature.com/articles/s41597-026-07025-5) ·
  [ScrawlD](https://github.com/sujeetc/ScrawlD) ·
  [Web3Bugs](https://github.com/ZhangZhuoSJTU/Web3Bugs) ·
  [Bastet](https://arxiv.org/html/2606.03387v1) ·
  [tintinweb/smart-contract-vulndb](https://github.com/tintinweb/smart-contract-vulndb) ·
  [SC-Bench](https://github.com/charlesxsh/scbench) ·
  [EVuLLM](https://github.com/Datalab-AUTH/EVuLLM-dataset)
