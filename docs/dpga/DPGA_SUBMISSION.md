# MIESC — DPGA Submission Package

This document assembles, in one place, the material a Digital Public Goods
Alliance (DPGA) reviewer needs to assess MIESC against the nine DPG indicators.
It does not replace the detailed compliance statement in
[`../policies/DPG-COMPLIANCE.md`](../policies/DPG-COMPLIANCE.md); it is a
reviewer-facing index that maps each indicator to the evidence already present
in the repository, plus the impact and SDG narrative that the DPGA application
form asks for.

## Header

| Field | Value |
|-------|-------|
| **Project** | MIESC — Multi-layer Intelligent Evaluation for Smart Contracts |
| **What it is** | Open-source security-analysis framework for EVM smart contracts |
| **License** | AGPL-3.0-only (OSI-approved copyleft) — [`LICENSE`](../../LICENSE) |
| **Repository** | https://github.com/fboiero/MIESC |
| **Documentation** | https://fboiero.github.io/MIESC |
| **Owner / maintainer** | Fernando Boiero (fboiero@frvm.utn.edu.ar) |
| **DPGA application** | #13478 (app.digitalpublicgoods.net/a/13478) — **verify before filing** |
| **Global ID (GID)** | GID0092948 — **verify before filing** |
| **DPGA submission date** | 2025-12-05 |
| **DPGA review status** | Under review at the DPGA (self-assessment: 9/9 indicators met) |

> **Honesty note on status.** "9/9 indicators met" is MIESC's own assessment of
> its conformance with the DPG Standard v1.1.6, backed by the evidence in the
> table below. The DPGA's independent review of application #13478 was still
> open at the time this document was written. This package is what supports that
> review; it does not assert that the DPGA has already granted recognition.
> The application id and GID are carried forward from earlier records
> (`docs/policies/DPG-COMPLIANCE.md`, README) and should be re-confirmed in the
> DPGA portal before the package is filed — see the submission checklist.

## The nine DPGA indicators

Standard: [DPG Standard v1.1.6](https://github.com/DPGAlliance/DPG-Standard).
Full narrative per indicator lives in
[`../policies/DPG-COMPLIANCE.md`](../policies/DPG-COMPLIANCE.md); the anchors
below point into that document. Paths are relative to this file
(`docs/dpga/`); GitHub URLs are given where a reviewer will more naturally open
the repository view.

| # | Indicator | Status | Evidence (in-repo / URL) |
|---|-----------|--------|--------------------------|
| 1 | SDG relevance | PASS | [`../policies/SDG_RELEVANCE.md`](../policies/SDG_RELEVANCE.md); [`../policies/DPG-COMPLIANCE.md` §Indicator 1](../policies/DPG-COMPLIANCE.md#indicator-1-sdg-relevance). SDG 9, 16, 17 with UN targets. |
| 2 | Open licensing | PASS | AGPL-3.0-only: [`LICENSE`](../../LICENSE) / https://github.com/fboiero/MIESC/blob/main/LICENSE. OSI-approved. |
| 3 | Clear ownership | PASS | Fernando Boiero; [`../policies/DPG-COMPLIANCE.md` §Indicator 3](../policies/DPG-COMPLIANCE.md#indicator-3-clear-ownership); [`CONTRIBUTORS.md`](../CONTRIBUTORS.md). Copyright 2024–2026, no patents, right to redistribute confirmed. |
| 4 | Platform independence | PASS | Pluggable tool adapters, graceful degradation, no closed components: [`../policies/DPG-COMPLIANCE.md` §Indicator 4](../policies/DPG-COMPLIANCE.md#indicator-4-platform-independence); [`../ARCHITECTURE.md`](../ARCHITECTURE.md). Local-first (Ollama) — no mandatory cloud/proprietary dependency. |
| 5 | Documentation | PASS | Hosted docs https://fboiero.github.io/MIESC; [`README.md`](../../README.md) + [`README_ES.md`](../../README_ES.md) (EN/ES); [`CONTRIBUTING.md`](../../CONTRIBUTING.md); [`../openapi.yaml`](../openapi.yaml). |
| 6 | Data extraction / portability | PASS | Open export formats JSON, SARIF 2.1, CSV, Markdown, HTML, PDF: [`../policies/DPG-COMPLIANCE.md` §Indicator 6](../policies/DPG-COMPLIANCE.md#indicator-6-data-extraction). No proprietary lock-in. |
| 7 | Privacy & applicable laws | PASS | Local processing, no telemetry: [`../policies/PRIVACY.md`](../policies/PRIVACY.md). GDPR / CCPA / Argentina Law 25.326 / LGPD noted in the application responses. |
| 8 | Standards & best practices | PASS | Open standards (SARIF, OpenAPI 3.0, MCP, SemVer, SWC, CWE) and Principles for Digital Development: [`../policies/DPG-COMPLIANCE.md` §Indicator 8](../policies/DPG-COMPLIANCE.md#indicator-8-standards--best-practices); [`../../CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md). |
| 9 | Do no harm by design | PASS | [`../policies/DO_NO_HARM.md`](../policies/DO_NO_HARM.md), [`../policies/RESPONSIBLE_USE.md`](../policies/RESPONSIBLE_USE.md); dual-use discussion in [`../policies/DPG-COMPLIANCE.md` §Indicator 9](../policies/DPG-COMPLIANCE.md#indicator-9-do-no-harm); Contributor Covenant CoC for community interactions. |

The DPGA form splits indicator 9 into sub-parts (9A data privacy / PII, 9B
content, 9C harassment). MIESC collects no PII and hosts no user content; the
only interaction surface is the project's own contribution channels, governed by
the Code of Conduct. Those answers are recorded in
[`../policies/DPGA_Application_Responses.csv`](../policies/DPGA_Application_Responses.csv).

## SDG relevance statement

MIESC advances **SDG 9 (Industry, Innovation and Infrastructure)** as its
primary goal. Blockchain systems increasingly carry financial, supply-chain and
governance workloads, and a single unremediated smart-contract vulnerability can
compromise all of it. MIESC strengthens that infrastructure by detecting
vulnerabilities before deployment through a defense-in-depth pipeline, and by
making that capability open-source it puts enterprise-grade analysis within
reach of teams that could never afford a commercial audit — the substance of
Target 9.b (support for domestic technology, research and innovation).

MIESC also advances **SDG 16 (Peace, Justice and Strong Institutions)** and
**SDG 17 (Partnerships for the Goals)**. Transparent, reproducible security
verification of the contracts behind financial and governance systems reduces
opportunities for fraud and supports accountable institutions (Targets 16.5 and
16.6). As an AGPL-3.0 project with bilingual (English/Spanish) documentation and
a local-first architecture that runs without paid cloud APIs, it lowers the
barrier to participation for developers in the Global South and enables
cross-border collaboration on blockchain-security research (Targets 17.6 and
17.8). Secondary alignment with SDG 8 (financial inclusion via safer DeFi) and
SDG 10 (secure blockchain remittance rails) is documented in
[`../policies/SDG_RELEVANCE.md`](../policies/SDG_RELEVANCE.md).

## Impact narrative

MIESC is a digital public good because it turns a capability that used to be a
paid, specialist service — a professional smart-contract security audit, priced
at roughly USD 20K–60K per engagement — into free, open, reproducible software
that any team can run on its own machine. It integrates roughly 50 analysis
tools across nine defense layers (static analysis, dynamic testing, symbolic
execution, formal verification, AI/LLM analysis, pattern detection,
DeFi-specific analysis, exploit validation, and consensus) behind a single
command line and API, with multi-provider LLM support that includes a fully
local option (Ollama) so no source code has to leave the user's environment.

**Who benefits.** Independent and small-team developers who cannot afford a
commercial audit; enterprises that want a repeatable pre-audit triage gate in
CI; public-sector and NGO blockchain projects that need transparent,
evidence-backed security verification; and researchers who need a reproducible
analysis baseline. Bilingual documentation and Docker packaging (`pip install
miesc`, `ghcr.io/fboiero/miesc`) keep the on-ramp short, and the local-first
design keeps it usable in low-connectivity or data-sensitive settings.

**Real-world use and validated capability.** MIESC is not a demonstrator. Its
performance is measured on public benchmarks — for example 95.8% recall on the
SmartBugs-curated corpus (137/143 contracts) and 81.8% recall on eleven
confirmed real-world DeFi exploits — with the exact evidence artifacts cited in
[`../policies/SDG_RELEVANCE.md`](../policies/SDG_RELEVANCE.md) and the paper
claims matrices. Beyond detection numbers, the capability that most directly
lowers the adoption barrier for resource-constrained teams is the **T1.1 finding
baseline and suppression engine** (validated on `main`, commit `929157e8`; see
[`../roadmap/V6_VALIDATED_CAPABILITIES.md`](../roadmap/V6_VALIDATED_CAPABILITIES.md)).
The single biggest reason teams abandon a static analyzer is the first-run flood
of pre-existing findings that turns the pipeline red on day one. The baseline
engine lets a team acknowledge existing findings once and then fail CI only when
a *new* issue is introduced, with content-hash fingerprints that stay stable as
unrelated edits shift line numbers. That means MIESC meets teams where their
code already is — the state of nearly every enterprise and public-sector
codebase — instead of assuming a greenfield project. Adoption friction drops to
almost zero for exactly the users who were previously hardest to onboard.

**Why this is a public good and not just a free tool.** The economics of
security are asymmetric: attackers are well-resourced and audits are expensive,
so under-funded teams ship under-reviewed contracts. Driving the cost of
competent defensive analysis toward zero shifts that asymmetry back toward
defenders. The copyleft license keeps the framework and its derivatives open, so
the benefit compounds across the ecosystem rather than being captured privately.

## Do no harm / responsible use

MIESC is a vulnerability-analysis tool, and vulnerability information is
inherently dual-use. The project addresses this directly rather than ignoring
it: MIESC is oriented toward *pre-deployment triage of the user's own
contracts*, it performs no mass or offensive scanning of third-party deployed
contracts, its proof-of-concept generation is bounded to confirming and then
closing a vulnerability, and every pattern it detects is already public
knowledge (SWC Registry, CWE, peer-reviewed literature, post-mortems). It
collects no personal data, hosts no user content, and does not modify user code
— it reports findings with remediation guidance.

Full detail:

- Risk assessment and dual-use analysis:
  [`../policies/DO_NO_HARM.md`](../policies/DO_NO_HARM.md)
- Responsible-use guidelines:
  [`../policies/RESPONSIBLE_USE.md`](../policies/RESPONSIBLE_USE.md)
- Indicator 9 narrative:
  [`../policies/DPG-COMPLIANCE.md` §Indicator 9](../policies/DPG-COMPLIANCE.md#indicator-9-do-no-harm)

## Submission checklist

Practical items to complete before (or while) filing with the DPGA:

- [ ] **Confirm the application id and GID.** Re-open the DPGA portal and verify
      that application **#13478** and **GID0092948** are current and refer to
      this submission. Both are carried from earlier records and are flagged
      "verify" in the header above. Correct them here if they have changed.
- [ ] **Confirm review status.** Check whether the DPGA review is still open,
      has returned reviewer questions, or has been decided, and update the
      status line accordingly.
- [ ] **Verify every evidence link resolves** on the default branch, including
      the anchors into `DPG-COMPLIANCE.md`. (Note: the root `README.md` links
      `RESPONSIBLE_USE.md` / `DO_NO_HARM.md` at the repository root, but the
      canonical files live under `docs/policies/`. This package links the
      canonical `docs/policies/` locations; reconcile the README paths
      separately if desired — outside the scope of this scaffold.)
- [ ] **Attach the application-response answers.** The filled form answers are
      in [`../policies/DPGA_Application_Responses.csv`](../policies/DPGA_Application_Responses.csv);
      make sure the version pasted into the portal matches the current release
      (project version, Docker tag, metrics).
- [ ] **Sync metrics to the current release.** Tool count, chain count, KB
      pattern count, standards count and benchmark figures appear in several
      docs; confirm they match the release being submitted before filing.
- [ ] **Provide the DPGA contact / evangelist thread** reference if the review
      is being shepherded (historically Bolaji Ayodeji, per
      `DPG-COMPLIANCE.md`).
- [ ] **Confirm license SPDX** is expressed as `AGPL-3.0-only` consistently
      across `LICENSE`, package metadata and the application form.

---

*This is additive submission-support documentation. It references existing
repository evidence and does not modify any frozen paper, benchmark, or claims
artifact.*
