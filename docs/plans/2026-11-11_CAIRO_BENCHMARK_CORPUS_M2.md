# Cairo detection benchmark — independent corpus (M2) scoping

**Date:** 2026-11-11 · **Status:** Scoping plan (additive, no corpus curated yet) ·
**Scope:** an independent, labeled Cairo/Starknet vulnerability corpus for a *credible* recall/
precision benchmark — the dataset the current Cairo evidence cannot provide.

## Why this is needed

MIESC's Cairo support is `experimental — recall/precision not benchmark-validated`. The blocker is
**not** the tooling; it is the **ground truth**. Every Cairo set we currently have fails the
independence test a detection benchmark requires:

| Set in repo | What it is | Why it cannot give a detection rate |
|---|---|---|
| `examples/contracts/cairo/caracal_poc/vulnerable/` | **Caracal's own detector test suite** (`NOTICE.md`) | Caracal recall on it is true by construction; `docs/guides/CAIRO.md` says *not* to cite detection rates. Good only for the pipeline-**conformance** check (`benchmarks/cairo_conformance.py`). |
| `examples/contracts/cairo/Modern2024Exploits.cairo` | One hand-authored fixture, 13 vuln types labeled by real incidents (zkLend, Braavos, Pragma…) | Independent of Caracal, but **N = 1 contract**, and the vuln types were added to detect these exact shapes (self-referential for the pattern adapter). `v5.1.6_benchmark_report.md` measured 9/13 types fired on it — a coverage smoke, not a benchmark. |
| `examples/contracts/cairo/VulnerableVault.cairo` | One hand-authored vulnerable vault | Same: N = 1, author-labeled. |

So a credible benchmark needs a **third-party-labeled corpus of many contracts**, drawn from real
incidents and independent authoritative sources — not from Caracal's tests and not from a single
MIESC fixture.

## What a credible corpus requires

1. **Independence.** Labels come from the *incident* or a third-party author (Trail of Bits, an
   auditor, a CTF), never from the tool under test.
2. **Provenance per entry.** Each contract records: vuln class, real incident + loss (if any), root
   cause, source URL, commit/hash, and **license**.
3. **Negatives.** Patched/safe counterparts (the fixed version of each exploited contract, or clean
   peers) so *precision* — not only recall — is measurable. This is the axis the Caracal set cannot
   give honestly.
4. **Size with honesty.** Report `k/n` with Wilson 95% CIs (reuse `benchmarks/evaluate_exploits.
   wilson_ci`); never a rate for a class with n = 1. Starknet is young, so N will be modest — say so.

## Sourcing map (verified 2026-11-11)

Primary index: **`github.com/amanusk/awesome-starknet-security`** (the list itself is CC0; **each
linked resource's license must be checked at its origin before ingestion**).

**A. Vulnerable-contract collections (strongest, third-party-labeled):**
- **Trail of Bits — `not-so-smart-contracts/cairo`** (`github.com/crytic/building-secure-contracts`):
  curated common Cairo vulnerabilities with explanations. The strongest candidate. Verify the
  `building-secure-contracts` license (historically AGPL-3.0 — MIESC-compatible) before use.
- `credence0x/cairo-damn-vulnerable-defi` (Capture-the-Ether-style); Starknet-Security-Challenges;
  Underhanded Cairo; Node Guardians. CTFs: Paradigm CTF 2022, StarknetCC-CTF (starknet-edu), with
  writeups (pscott, Ledger) to cross-check labels.

**B. Real-exploit reproductions / post-mortems:**
- **`amanusk/zklend_repro`** — zkLend hack reproduction (Starknet-Foundry). zkLend (Feb 2025, ~$9.57M)
  root cause: a rounding error in `mint()` via improper integer division, inflating the lending
  accumulator through a donation to an empty market. License not stated → check.
- SlowMist and BlockSec zkLend/EraLend post-mortems, Argent-X / Braavos account write-ups (analysis;
  pair with the on-chain/audited contracts).

**C. Audit-report collections (findings, to label real contracts):**
- Nethermind `PublicAuditReports` (Braavos Account, Pragma, Carmine, AVNU, ZKX…); Argent (Consensys
  Diligence); Opus (Code4rena); Unruggable.meme community audits; Empiric (Zellic). Reports, not
  contracts — use them to attach independent labels to the matching open-source contracts.

## Bounded first increment

Do **not** boil the ocean. A credible v1 is ~10–15 contracts with patched counterparts:
1. Ingest Trail of Bits `not-so-smart-contracts/cairo` (license-cleared) as the labeled core.
2. Add the zkLend reproduction (bad + fixed) as the flagship real-incident entry.
3. Add 2–3 CTF challenges with public solutions (label from the writeup).
4. Write `benchmarks/datasets/cairo/labels.json`: per contract `{file, vuln_class, incident, root_cause, source_url, commit, license, has_patched_peer}`.
5. Wire a harness that runs the real Cairo scan over the corpus and reports recall + precision with
   Wilson CIs (reuse `wilson_ci` + `evaluate.py::_compute_metrics`), honest about N. Here — unlike
   the Caracal set — the labels are independent, so the numbers are real.

## Design decisions to settle before curation

- **Reconstruction vs on-chain.** Reproductions (zklend_repro) and ToB examples are easier to license
  and label but are *shaped* like the real bug, not the deployed bytecode. On-chain audited contracts
  (zkLend, Braavos) are stronger evidence but heavier on provenance/licensing. Start with
  reconstructions + ToB; add on-chain where license-clear.
- **Licensing gate (hard requirement).** Nothing enters the corpus until its origin license is
  verified AGPL-compatible (or permissive) and attribution is preserved, exactly as
  `caracal_poc/NOTICE.md` did for the Caracal fixtures. This is a per-file review, and it gates
  everything downstream.
- **Labeling method.** One class per contract where possible; multi-vuln contracts get per-function
  labels. Cross-check each label against an independent writeup/audit, never against MIESC's or
  Caracal's output.

## What this document is and is not

This is the **plan**, not the corpus. No third-party code has been ingested — that step is gated on
the per-source license review above and is itself a multi-step effort. Shipping it records the
verified sourcing map and the honest constraints so the curation, when it happens, is de-risked and
provenance-clean rather than improvised.
