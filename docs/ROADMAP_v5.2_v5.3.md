# MIESC Roadmap — v5.2.0 → v5.3.0

**Date**: 2026-04-21
**Author**: Fernando Boiero
**Context**: After shipping v5.1.5 through v5.1.9 (5 releases, +581 tests,
intelligence engine with 15 capabilities, 77 multi-chain vuln types, 8 bugs
fixed), this roadmap defines the path to v5.2.0 (consolidation) and v5.3.0
(next major evolution).

---

## v5.2.0 — Consolidation + Benchmark (target: May 2026)

**Theme**: _Prove what we shipped works at scale._

Everything in v5.1.5–v5.1.9 was shipped incrementally. v5.2.0 consolidates it
into a measured, benchmarked, paper-ready release.

### v5.2.0 Deliverables

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| 1 | **Version bump + CHANGELOG** | 30min | Single comprehensive entry covering intelligence engine, multi-chain, fix-code, plugins, gas analyzer |
| 2 | **SmartBugs benchmark with intelligence** | 2h | Re-run the full 143-contract suite with the intelligence engine enabled. Measure: precision delta, noise reduction %, false-positive rate per category. Target: precision 22.7% → 30%+ |
| 3 | **Paper v2 with intelligence section** | 3h | New §Architecture subsection on the intelligence engine (Bayesian confidence, semantic dedup, context-aware FP, zero-recall patterns). Add benchmark numbers. Submit to arXiv as v2 update. |
| 4 | **Empirical confidence calibration** | 2h | Capture per-tool raw findings BEFORE intelligence merge. Compute empirical precision per tool on SmartBugs. Replace educated-guess weights with measured values. |
| 5 | **VS Code extension sync** | 1h | Update package.json to v5.2.0, add intelligence summary in editor gutter |
| 6 | **GitHub Action v2** | 2h | Publish action to Marketplace with intelligence engine. SARIF output includes confidence + canonical category. Example workflow in README. |
| 7 | **Pending submissions** | — | arXiv paper, Streamlit Cloud, DPGA certification, 3 grants (Starknet, EF ESP, NGI) |

### v5.2.0 Success criteria

- SmartBugs precision ≥ 30% (was 22.7%)
- Noise reduction ≥ 25% measured on full corpus
- Paper v2 on arXiv with intelligence section
- VS Code extension published at v5.2.0
- GitHub Action live on Marketplace
- ≥ 1 grant submitted

---

## v5.3.0 — From Detection to Remediation Pipeline (target: Aug 2026)

**Theme**: _MIESC finds the bug AND helps you fix it — provably._

The v5.1.x intelligence engine tells you WHAT's wrong, WHY it's wrong,
and gives you a code snippet. v5.3.0 closes the loop: it generates a
patched file, proves the fix works via formal verification, and packages
the result into a compliance artifact.

### Track 1: Automated Remediation (`miesc fix`)

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| 1.1 | **`miesc fix` command** | 1 week | Takes a scan/audit JSON + the source file. For each finding with `fix_code`, applies the patch to generate `Contract.fixed.sol`. Uses AST-level patching (not regex) via `solc --ast-json` for safety. |
| 1.2 | **Foundry test generation** | 3 days | From each `exploit_scenario`, generate a Foundry test (`test_exploit_*.sol`) that FAILS on the original and PASSES on the fixed version. Proves the vulnerability was real AND the fix resolves it. |
| 1.3 | **`miesc verify --before-after`** | 2 days | Runs `miesc verify` on both original and fixed contract. Reports: "Finding F-001: FAILED on original (vulnerable), PASSED on fixed (resolved)". Closes the find→fix→verify loop. |
| 1.4 | **Full pipeline command: `miesc audit --fix --verify`** | 2 days | One command does scan → intelligence → fix → verify → report. The dream workflow for pre-audit triage. |

### Track 2: Real-Time / CI Integration

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| 2.1 | **PR-level diff scanning** | 3 days | `miesc scan --diff HEAD~1` scans only changed `.sol` files. Intelligence engine runs on the diff context (new findings only, not inherited from unchanged code). |
| 2.2 | **GitHub Action with diff mode** | 1 day | Action uses `--diff` by default on PR events. Posts inline comments on findings via SARIF. |
| 2.3 | **Webhook notifications** | 2 days | `miesc notify --slack <url> --on HIGH` sends webhook on HIGH+ findings. Supports Slack, Discord, PagerDuty. |
| 2.4 | **Trend dashboard** | 1 week | `miesc trend ./history/` reads a directory of past audit JSONs and shows findings-over-time chart. Streamlit-based, embeddable. |

### Track 3: Multi-Chain Depth

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| 3.1 | **Cairo formal verification** | 1 week | Integrate Caracal as a first-class adapter. Generate Certora-Cairo specs from findings. Wire into `miesc verify` for Starknet. |
| 3.2 | **Soroban live-contract scan** | 3 days | `miesc analyze --chain stellar --address <contract_id>` fetches Soroban contract WASM + source from Stellar Horizon API. Runs StellarAnalyzer on fetched code. |
| 3.3 | **Solana Anchor IDL parsing** | 3 days | Parse Anchor IDL JSON for type constraints. Cross-reference with detected vulnerabilities (e.g., missing `has_one` constraint → TYPE_COSPLAY finding). |
| 3.4 | **Move shared-object analysis** | 3 days | Detect Sui shared-object concurrent access patterns. Flag functions that mutate shared objects without `&mut` reference. |
| 3.5 | **Cross-chain bridge patterns** | 1 week | Intelligence patterns for Wormhole VAA verification, LayerZero endpoint configuration, Axelar GMP. Informed by 2024-2026 bridge exploits ($1B+ losses). |

### Track 4: Collaborative Audit Platform

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| 4.1 | **Web-based findings review** | 2 weeks | Streamlit app where 2+ auditors can mark findings as TP/FP/NEEDS_REVIEW. Stores verdicts in a project-level SQLite DB. |
| 4.2 | **Auditor-labeled FP dataset v2** | ongoing | Findings labeled during 4.1 feed back into AuditorTrainedFPClassifier. Monthly re-training cycle. |
| 4.3 | **Confidence calibration v2** | 1 week | Use 4.2's labeled data to compute empirical per-tool precision. Replace educated-guess weights in intelligence.py with measured values. Publish the calibration dataset. |
| 4.4 | **Compliance artifact export** | 3 days | `miesc export --format compliance` generates a signed PDF report with: audit trail, finding verdicts, fix verification status, compliance mappings (ISO 27001, NIST CSF, MiCA Art.11). Suitable for regulatory filing. |

---

## Milestones

```
v5.1.9 (now)  → Intelligence engine shipped, 5913 tests, 87% coverage
     │
v5.2.0 (May)  → Benchmarked, paper v2, GitHub Action Marketplace, grants
     │
v5.2.x (Jun)  �� PR-diff scanning, webhook notifications, trend dashboard
     │
v5.3.0 (Aug)  → miesc fix + verify loop, Foundry test gen, bridge patterns
     │
v5.3.x (Sep)  → Collaborative audit platform, FP dataset v2, calibration
     │
v6.0.0 (Q4)   → Multi-language (beyond Solidity), hosted SaaS option
```

---

## Resource Requirements

| Track | Solo developer | With 1 contributor | With grant funding |
|-------|:-:|:-:|:-:|
| v5.2.0 | 2 weeks | 1 week | 1 week |
| Track 1 (fix) | 3 weeks | 2 weeks | 1.5 weeks |
| Track 2 (CI) | 2 weeks | 1 week | 1 week |
| Track 3 (multi-chain) | 4 weeks | 2 weeks | 2 weeks |
| Track 4 (collaborative) | 4 weeks | 2 weeks | 2 weeks |
| **Total to v5.3.0** | **15 weeks** | **8 weeks** | **7.5 weeks** |

With Starknet + EF ESP grants funded: **v5.3.0 is achievable by August 2026.**

---

## Priority order (if I can only do some)

1. **v5.2.0** (consolidation + paper) — MANDATORY before any v5.3 work
2. **Track 1.1-1.3** (`miesc fix` + verify) — biggest differentiation vs competitors
3. **Track 2.1-2.2** (PR-diff + Action) — drives adoption among CI users
4. **Track 3.5** (bridge patterns) — exploits are happening NOW
5. **Track 4.4** (compliance export) — enterprise unlock

---

## What this does NOT include (deferred to v6.0)

- Multi-language support beyond Solidity (Vyper is partially supported; Rust/Python/Go TBD)
- Hosted SaaS offering (MIESC-as-a-Service)
- Mobile app / Telegram bot
- Training/certification program
- IDE-level real-time scanning (beyond VS Code batch scan)

These are v6.0+ scope. MIESC must be excellent at smart-contract security
before branching into general code analysis.

---

## How to use this document

- **For grants**: reference specific Track items in applications
- **For paper**: v5.2.0 items 2-3 are the immediate paper targets
- **For contributors**: Tracks 1-4 are self-contained work packages
- **For users**: the CLI commands (`miesc fix`, `miesc trend`) are the user-facing deliverables
