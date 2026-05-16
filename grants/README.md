# Grant Applications — MIESC

This folder holds ready-to-submit drafts for three grant programs. Total
expected value from applying all three: **USD 15K–165K over 3–4 months**,
based on the probability estimates in the parent session notes.

## Submission order (highest ROI first)

| # | Program | File | Ask | Win prob. | Timeline |
|---|---|---|---|:---:|---|
| 1 | Starknet Foundation | `01_STARKNET_FOUNDATION.md` | USD 25 000 | 60–70% | 3–6 weeks |
| 2 | Ethereum Foundation ESP | `02_EF_ESP.md` | USD 40 000 | 30–40% | 6–12 weeks |
| 3 | NGI Zero (NLnet) | `03_NGI_ZERO.md` | EUR 50 000 | 40–50% | 8–12 weeks |

Plus: `04_CASE_STUDY_TEMPLATE.md` — fill with a real project you've
audited with MIESC. Attach to each grant application as supporting
material.

## Pre-flight checklist (do BEFORE submitting)

### ✅ Already done this session
- [x] v5.1.8 on PyPI + GitHub
- [x] Paper updated to reflect v5.1.6+v5.1.7 capabilities (Cairo,
      multi-LLM consensus, formal verify bridge)
- [x] arXiv submission bundle built (`paper/miesc-arxiv.tar.gz`)
- [x] Pre-release audit (`docs/PRE_RELEASE_AUDIT_v5.1.7.md`)
- [x] 5,332 passing tests, 0 regressions
- [x] CI green (after `68fcbb3`)

### 🔲 Blockers (do these THIS WEEK)

- [ ] **Submit paper to arXiv**
  - Log in to https://arxiv.org/submit
  - Upload `paper/miesc-arxiv.tar.gz`
  - Follow `paper/ARXIV_SUBMISSION.md`
  - Wait for arXiv ID (< 24 h)
  - **All three grants link to this ID — do it first.**

- [ ] **Publish a zero-install live demo**
  - Use the platform repository for hosted UI/demo deployment.
  - Keep this open-core repository focused on CLI, local REST API, MCP stdio,
    static reports, and reproducible evidence.
  - Grants reviewers WILL click this; zero-install evaluation dramatically
    improves win rate.

- [ ] **ORCID if you don't have one**
  - https://orcid.org/register — takes 2 minutes
  - Adds credibility to grant applications, required by many programs

### 🔲 Strongly recommended

- [ ] **DPGA certification**: submit the self-assessment at
  https://digitalpublicgoods.net/submission-form/. Approval ~ 4-6 weeks.
  NGI application becomes MUCH stronger with an approved DPGA entry.

- [ ] **One case study** (use `04_CASE_STUDY_TEMPLATE.md`)
  - Even a short one (a UTN thesis using MIESC, a friend's DeFi
    protocol, your own test project) beats pure theory.

- [ ] **Update CITATION.cff** with arXiv ID once assigned.

## Per-grant specifics

### Starknet (fastest win, submit first)

- Portal: https://www.starknet.io/grants (or via OnlyDust)
- Supporting materials to bundle:
  - `examples/contracts/cairo/Modern2024Exploits.cairo` — 13/13 coverage
  - `tests/test_cairo_analyzer.py` — 28 tests passing
  - `paper/miesc-paper.pdf` §Multi-Chain Support
  - `benchmarks/results/v5.1.7_gates_report.md` — real benchmark data
- Email lead: include the "2024-2026 Starknet exploits" angle in the
  subject line. zkLend is still raw in the ecosystem's memory.

### EF ESP

- Portal: https://esp.ethereum.foundation/applicants
- Review cycle: monthly-ish, but they respond to every submission
- Emphasis in the form: **orchestration, not re-implementation**. ESP
  funds builders, not people re-solving solved problems.
- Referees: list 2–3. Thesis director + an OSS contact you have.
- LinkedIn / GitHub profile links are required.

### NGI Zero (NLnet)

- Portal: https://nlnet.nl/propose
- Choose track:
  - **NGI Zero Entrust** for WP2 + WP3 (privacy + regulatory)
  - **NGI Zero Commons Fund** for WP1 + WP4 (DPGA + accessibility)
- Submission windows: quarterly. Check upcoming deadline before
  finalising.
- Strong signal in a NLnet application: a letter of intent from a
  European deployer. Even a small one. Any EU-based DeFi team that
  uses MIESC counts.

## After submitting

1. **Tweet / Farcaster announcement** when each submission goes in.
   "Just applied for [grant] to continue building MIESC — here's what
   we'd do with it ↓".
2. **Update this README** with submission date + reference number.
3. **Keep shipping**. Grant review boards check whether the repo shows
   signs of life. A weekly commit cadence during the review window
   helps enormously.
