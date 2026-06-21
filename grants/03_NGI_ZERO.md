# NGI Zero (NLnet) — MIESC Sovereign Smart-Contract Auditing

**Applicant**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Repository**: https://github.com/fboiero/MIESC
**License**: AGPL-3.0

> Intended NLnet track: **NGI Zero Entrust** (privacy/security) or
> **NGI Zero Commons Fund** (open-source commons)

---

## Project summary (250 words)

MIESC (Multi-layer Intelligent Evaluation for Smart Contracts) is a
**sovereign, local-first** security framework for smart-contract
auditing. Unlike commercial auditing services and SaaS scanners that
require uploading your code to third-party cloud infrastructure, MIESC
runs **100% on the developer's machine**: no telemetry, no remote calls,
no cloud dependency for the core analysis pipeline. Optional large
language model (LLM) integration is local-first via Ollama, with
explicit cloud-provider opt-in only if the user configures it.

MIESC orchestrates **35 analysis modules** — 13 external security tools
(Slither, Mythril, Echidna, Halmos, Certora Prover, ...) and 22
internal modules — across 9 complementary analysis layers with per-layer
timing instrumentation. It unifies their heterogeneous outputs into a
single finding schema, filters false positives using a RAG-enhanced ML
pipeline (59 curated vulnerability patterns), and maps findings to 12
international security standards (ISO 27001, NIST CSF, OWASP, SWC, CWE,
MITRE ATT&CK). v5.4.0 adds a scientific evaluation framework (`miesc
evaluate` with corpus evaluation, ablation studies, experiment cards), a
plugin system for third-party detectors via PyPI entry points, and JSONL
export for ML pipelines.

Evaluated on SmartBugs-curated, MIESC achieves **95.8% recall**
(static+intelligence layers, 137/143), 97.9% with a local Ollama follow-up. On EVMBench:
**92.5% ensemble recall** (#1, beating Cecuro at 87.7%). On 11 confirmed
DeFi exploits totalling $3.3B in losses: 81.8% recall, Cohen's
κ = 0.77. The automated fix pipeline achieves 87% applied, 63% compile,
84% vulnerability eliminated, 0% regression.

The tool is published under **AGPL-3.0** on PyPI (`pip install miesc`,
v5.4.0) and GHCR. Two academic papers document the methodology (Paper 1:
multi-layer evaluation, Paper 2: remediation pipeline). It is currently
aligned with the **Digital Public Goods Alliance (DPGA)** standard
(certification in progress). This grant funds four sovereign-tech
hardening work packages below.

---

## Fit with NGI Zero priorities

| NGI criterion | How MIESC fits |
|---|---|
| **Sovereignty** | 100% local execution, no telemetry, no cloud dependency |
| **Privacy** | Contract code never leaves the developer's machine unless they explicitly opt in to cloud LLMs |
| **Open source** | AGPL-3.0 (copyleft, cannot be appropriated) |
| **European relevance** | Significant DeFi deployment in EU (Aave, Morpho, Gnosis Chain, ...); regulatory pressure from MiCA requires verifiable security analysis |
| **Reusable** | Published on PyPI (v5.4.0), packaged in Docker, integrated with Foundry/Hardhat/Remix, extensible via plugin system |
| **No vendor lock-in** | LLM layer is pluggable: Ollama (local), Anthropic, OpenAI — all optional |

MIESC is not a Web3 marketing vehicle. It is **security infrastructure
that happens to operate in the smart-contract domain**. The same
orchestration + RAG-filtering architecture would generalise to any
code-analysis pipeline, which is an explicit v6 goal.

---

## Work packages

### WP1 — DPGA certification completion (month 1, €5 000)

MIESC already aligns with the 9 DPGA indicators (OSS license, clear
ownership, platform independence, SDG contribution, data privacy, no
harm, adherence to privacy laws, accessibility). The formal
certification process requires evidence packaging, governance
documentation, and third-party review.

**Deliverable**: DPGA-registered entry in the UN registry. Increases
credibility for public-sector use (EU ministries, regulators).

### WP2 — Privacy-by-design audit + fix pack (months 1–3, €15 000)

Despite MIESC's local-first design, third-party tools it invokes
(Slither, Aderyn) read source code and write output files. A full
privacy review needs to:

- Audit every `subprocess.run` call for potential data exfiltration
  vectors (already done this session — 0 shell-injection, list-args
  everywhere — but needs formal documentation).
- Add **tmpfs-only output paths** so analysis never writes source code
  or findings to disk outside an explicit user directory.
- Document every network call (LLM, RAG) with an opt-in flag.
- Produce a sworn declaration (sandbox reviewer or independent audit).

**Deliverable**: signed privacy-by-design assessment + a hardened
release with tmpfs output paths, explicit network-flag boundaries, and
a tested offline mode.

### WP3 — EU regulatory alignment — MiCA / DORA (months 3–6, €20 000)

MiCA (Markets in Crypto-Assets) and DORA (Digital Operational
Resilience Act) require crypto service providers to document
security-analysis processes. Most existing toolchains are US-centric.

**Deliverable**:
- Compliance-report templates that map MIESC findings to specific MiCA
  Art. 11 (security policies) and DORA Art. 9 (ICT risk) requirements.
- A deterministic report mode (same contract + same tool versions →
  byte-identical PDF) so regulators can reproduce audit artifacts
  years after the fact.
- Reference integration with an EU-based DeFi protocol willing to
  document their use of MIESC for MiCA preparedness (letter of intent
  provided separately).

### WP4 — Accessibility + internationalisation (months 5–6, €10 000)

MIESC's documentation is currently English + Spanish. For EU reach:

- French, German, Italian, Portuguese translations of the core
  documentation and CLI messages.
- WCAG 2.2 AA compliance for the static HTML reports and hosted
  platform dashboard.
- Screen-reader-friendly reports (semantic HTML, not just PDF tables).

**Deliverable**: 5-language docs, accessible reports, and an accessible
platform demo deployed on a European-hosted URL (e.g. Hetzner-hosted
`miesc.eu`).

---

## Total ask

**€50 000** over 6 months, milestone-based. Breakdown:

| WP | Amount | Month |
|----|---:|---:|
| WP1 DPGA certification | €5 000 | 1 |
| WP2 Privacy-by-design audit | €15 000 | 1–3 |
| WP3 MiCA/DORA alignment | €20 000 | 3–6 |
| WP4 Accessibility + i18n | €10 000 | 5–6 |

If NLnet prefers smaller grants, we can scope down to WP1+WP2 (€20 000
for 3 months).

---

## Team

**Fernando Boiero** — sole developer.
- 12+ years engineering, MSc Cybersecurity at UNDEF (in progress).
- Teaching at UTN–FRVM (Universidad Tecnológica Nacional, Argentina).

Partner for WP4 (accessibility): need to identify a European NGO or
university lab with WCAG expertise. Open to NLnet recommendations.

---

## Post-grant sustainability

MIESC is already published (PyPI, GHCR, GitHub Action). The AGPL-3.0
license and DPGA registration make it impossible to enclose. Ongoing
maintenance funding sources:

- Parallel grant applications (Ethereum Foundation ESP, Starknet
  Foundation — see this folder)
- University teaching appointment covers half of my maintainer time
- Consulting (pre-audit triage + MIESC training) for teams that want
  hands-on support

No VC money. No proprietary fork. Ever.

---

## Supporting materials

- **Paper 1** (multi-layer evaluation): `paper/miesc-paper.pdf`
- **Paper 2** (remediation pipeline, 7 pages): `paper/miesc-paper2.pdf`
- **Research Guide**: `docs/guides/RESEARCH.md`
- **Plugin Guide**: `docs/guides/PLUGINS.md`
- **License**: `LICENSE` (AGPL-3.0 verbatim)
- **Privacy statement**: in `CLAUDE.md` and `docs/policies/SBOM.md`
- **DPGA self-assessment** (already passes 8/9 indicators): available
  on request
