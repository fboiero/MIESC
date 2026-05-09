# MIESC Roadmap — v5.2.0 → v5.3.1 (Completed) + v5.4.x Plan

**Last updated**: 2026-04-23
**Author**: Fernando Boiero

---

## ✅ v5.2.0 — Shipped 2026-04-21

**Theme**: _Intelligence Engine — prove what we shipped works at scale._

| # | Item | Status | Notes |
|---|------|:------:|-------|
| 1 | Version bump + CHANGELOG | ✅ | Comprehensive entry covering 15 intelligence capabilities |
| 2 | Intelligence engine (15 capabilities) | ✅ | `src/core/intelligence.py` — Bayesian confidence, semantic dedup, 15 zero-recall patterns, 6 FP rules, LLM↔static cross-val |
| 3 | Multi-chain +35 vuln types (total 77) | ✅ | Stellar/Soroban +7, Solana/Anchor +7, Move/Sui/Aptos +7, EVM 8→15 |
| 4 | Plugin system + gas analyzer | ✅ | 26 tests |
| 5 | 8 production bugs fixed | ✅ | Including CRITICAL stale-cache Slither bug |

**Metrics**: 5913 tests, 87% coverage, ~30% noise reduction measured.

---

## ✅ v5.3.0 — Shipped 2026-04-21

**Theme**: _From Detection to Remediation Pipeline._

### Track 1: Automated Remediation

| # | Item | Status | Notes |
|---|------|:------:|-------|
| 1.1 | `miesc fix` command | ✅ | Text-level patching: nonReentrant, onlyOwner, require(success), SafeMath |
| 1.2 | Foundry test generation | ⬜ | Deferred to v5.4.x |
| 1.3 | `miesc verify --before-after` | ⬜ | Deferred to v5.4.x |
| 1.4 | `miesc audit --fix --verify` | ⬜ | Deferred to v5.4.x |

### Track 2: CI Integration

| # | Item | Status | Notes |
|---|------|:------:|-------|
| 2.1 | PR-level diff scanning | ✅ | `miesc scan --diff HEAD~1` |
| 2.2 | GitHub Action with diff mode | ⬜ | Action exists but no `--diff` by default on PR |
| 2.3 | Webhook notifications | ⬜ | Deferred |
| 2.4 | Trend dashboard | ⬜ | Deferred |

### Track 3: Multi-Chain Depth

| # | Item | Status | Notes |
|---|------|:------:|-------|
| 3.1 | Cairo formal verification | ⬜ | Caracal not yet integrated |
| 3.2 | Soroban live-contract scan | ⬜ | Deferred |
| 3.3 | Solana Anchor IDL parsing | ⬜ | Deferred |
| 3.4 | Move shared-object analysis | ⬜ | Deferred |
| 3.5 | Cross-chain bridge patterns | ✅ | 7 patterns from real incidents ($1.7B+) |

### Track 4: Collaborative Audit

| # | Item | Status | Notes |
|---|------|:------:|-------|
| 4.1 | Web-based findings review | ⬜ | Streamlit app planned |
| 4.2 | Auditor-labeled FP dataset v2 | ⬜ | |
| 4.3 | Confidence calibration v2 | ⬜ | |
| 4.4 | Compliance artifact export | ✅ | `miesc compliance --standard mica` (12 standards) |

---

## ✅ v5.3.1 — Shipped 2026-04-22

**Theme**: _Packaging hotfix + UX polish._

| Item | Status |
|------|:------:|
| Templates bundled in PyPI wheel | ✅ |
| `--llm-enhance` wired to Ollama | ✅ |
| `miesc fix` hit rate 33% → 100% | ✅ |
| Pre-flight syntax check | ✅ |
| Config YAML wired (timeouts, max_workers) | ✅ |
| PDF fallback warning | ✅ |
| Watch command fixes (30s cap, logging) | ✅ |
| Docker CI scoped cache | ✅ |
| Premium report layer coverage | ✅ |
| Multi-chain output normalized | ✅ |
| +29 new tests (watch, e2e, llmbugscanner) | ✅ |

**Metrics**: 6031 tests, 88% coverage.

---

## 🔜 v5.4.x — Release Track

**Theme**: _Close the find→fix→verify loop + distribution._

### Priority 1: Scientific Publication

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| P1 | Paper v2 update | 3h | Update abstract/body with v5.3.x features (fix, compliance, intelligence engine). Update benchmark numbers with intelligence engine enabled. |
| P2 | arXiv submission | 1h | Submit `paper/miesc-arxiv.tar.gz` to arXiv cs.CR |
| P3 | Re-run SmartBugs benchmark | 2h | Full 143-contract suite with intelligence engine. Measure precision delta. |

### Priority 2: Ecosystem

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| E1 | Grant submissions | 2h | Submit Starknet Foundation ($25K), EF ESP ($40K), NGI Zero (€50K) |
| E2 | DPGA certification | 1h | Self-assessment at digitalpublicgoods.net |
| E3 | Streamlit Cloud deploy | 1h | Deploy web UI for non-CLI users |
| E4 | GitHub Action v2 on Marketplace | 2h | With intelligence + `--diff` + SARIF |

### Priority 3: Technical Depth

| # | Item | Effort | Description |
|---|------|:------:|-------------|
| T1 | `miesc fix` → Foundry test gen | 1 week | From `exploit_scenario`, generate test that FAILS on original, PASSES on fixed |
| T2 | `miesc verify --before-after` | 3 days | Scan original + fixed, diff findings |
| T3 | Empirical confidence calibration | 2h | Replace educated-guess weights with measured per-tool precision on SmartBugs |
| T4 | `audit full` layers 8-9 by default | 1 day | Exploit validation + consensus currently skipped unless `--layers 1-9` |
| T5 | VS Code extension sync to v5.3+ | 1 day | Update package.json, add intelligence gutter |

---

## Milestones (updated 2026-04-23)

```
v5.1.9 (Apr 21) ✅ Intelligence engine shipped
     │
v5.2.0 (Apr 21) ✅ Consolidation release
     │
v5.3.0 (Apr 21) ✅ Fix + compliance + bridge patterns
     │
v5.3.1 (Apr 22) ✅ Packaging hotfix + UX + 29 tests
     │
v5.4.x          → Paper v2 + grants + Foundry test gen
     │
v6.0.0 (Q4)     → Hosted SaaS, multi-language, collaborative audit
```

---

## What this does NOT include (deferred to v6.0)

- Multi-language support beyond Solidity (Vyper partially supported; Rust/Python/Go TBD)
- Hosted SaaS offering (MIESC-as-a-Service)
- Mobile app / Telegram bot
- Training/certification program
- IDE-level real-time scanning (beyond VS Code batch scan)
