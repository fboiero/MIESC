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

## Submission readiness verdict

Evidence-verification pass performed against the repository at release **v6.0.0**
(the release being submitted). Every in-repo path and relative link cited in this
package and in `DPG-COMPLIANCE.md` was resolved on the default branch; the DPG
Standard version cited (v1.1.6) is current (published 2024-09-04).

| # | Indicator | Verdict | Notes |
|---|-----------|---------|-------|
| 1 | SDG relevance | Evidence VERIFIED ✓ | `SDG_RELEVANCE.md` + `DPG-COMPLIANCE.md` §1 present; SDG 9.b / 16.5 / 16.6 with targets. SDG-9 target now consistent (`9.b`) across all four DPGA-facing docs. |
| 2 | Open licensing | Evidence VERIFIED ✓ | Full AGPL-3.0 text in `LICENSE`; `pyproject.toml` SPDX `AGPL-3.0-only`; OSI-approved. Consistent everywhere it matters. |
| 3 | Clear ownership | Evidence VERIFIED ✓ | `DPG-COMPLIANCE.md` §3 + `docs/CONTRIBUTORS.md`; copyright 2024–2026; no patents; UNDEF→UTN-FRVM lineage now consistent in ownership and contact tables. |
| 4 | Platform independence | Evidence VERIFIED ✓ | `DPG-COMPLIANCE.md` §4 + `ARCHITECTURE.md`; local-first (Ollama), pluggable adapters, graceful degradation. |
| 5 | Documentation | Evidence VERIFIED ✓ | README EN/ES, `CONTRIBUTING.md`, `openapi.yaml` all resolve. Reconfirm the hosted site (`fboiero.github.io/MIESC`) renders live before filing — it could not be checked from the repo. |
| 6 | Data extraction / portability | Evidence VERIFIED ✓ | Open export formats (JSON, SARIF 2.1, CSV, Markdown, HTML, PDF) documented in `DPG-COMPLIANCE.md` §6. |
| 7 | Privacy & applicable laws | Evidence VERIFIED ✓ | `PRIVACY.md` present; local processing, no telemetry; GDPR/CCPA/Argentina Law 25.326 noted. |
| 8 | Standards & best practices | Evidence VERIFIED ✓ | SARIF/OpenAPI/MCP/SWC/CWE + 12 standards + Contributor Covenant CoC. Security-scanner list corrected to match `ci.yml` (Bandit, pip-audit, safety, Trivy, CodeQL — Semgrep/Snyk were not actually wired in). The point-in-time test count in §8 should be re-run and refreshed against v6.0.0 before it is quoted to a reviewer. |
| 9 | Do no harm by design | Evidence VERIFIED ✓ | `DO_NO_HARM.md` + `RESPONSIBLE_USE.md` + dual-use narrative; 9A/9B/9C answers in the responses CSV (no PII, no hosted content, CoC governs interactions). |

**Bottom line.** All nine indicators resolve to real, current in-repo evidence;
no broken links remain in this package or in `DPG-COMPLIANCE.md` (EN/ES). The
verdict is a self-assessment supporting the DPGA's open review of application
#13478 — it does not assert the DPGA has granted recognition. Two residual items
are reviewer-facing rather than blocking: confirm the hosted docs site is live
(indicator 5) and refresh the test count against v6.0.0 (indicator 8).

**Flagged in frozen files (not editable in this pass — for Fernando's attention).**
The root `README.md` (a frozen paper artifact) states the project "is fully
compliant with all 9 DPGA indicators." That reads stronger than the honest
"self-assessed 9/9, under review" framing used throughout this package. Consider
softening it to "self-assesses as meeting all 9 DPGA indicators (application
#13478 under review)" the next time the README baseline is intentionally
refreshed — do not edit it ad hoc while it is frozen.

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
- [ ] **Confirm the SDG-9 target.** This package and the responses CSV were
      reconciled to **Target 9.b** (the choice used across `DPG-COMPLIANCE.md`,
      `SDG_RELEVANCE.md` and this file). If you prefer 9.5 in the portal, change
      it in one place and re-align the others.
- [ ] **Refresh the CI/test evidence.** The security-scanner row in
      `DPG-COMPLIANCE.md` §8 now matches `ci.yml` (Bandit, pip-audit, safety,
      Trivy, CodeQL). Re-run the suite and update the test-count line to the
      v6.0.0 figure before quoting it.
- [ ] **Confirm the hosted docs site** (`fboiero.github.io/MIESC`) renders live;
      it is cited as indicator-5 evidence but was not verifiable from the repo.

---

*This is additive submission-support documentation. It references existing
repository evidence and does not modify any frozen paper, benchmark, or claims
artifact.*
