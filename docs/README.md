# MIESC Documentation

**Last Updated:** 2026-05-09

This directory contains the MIESC documentation set, split between current
project documentation and historical archive material.

> Current research claims are the Paper 1/Paper 2 PDFs,
> `paper/PAPER*_REPRODUCIBILITY.md`, and
> `benchmarks/results/paper*_claims_matrix.json`.
>
> Historical material in `docs/tesis`, `docs/evidence`, older release notes, and
> older roadmap files is preserved for traceability. It can contain v4.x/v5.1
> metrics, 7-layer wording, or version-specific statements that are not current
> claims.

---

## Documentation Structure

```
docs/
├── README.md                     # This file - documentation index
├── guides/                       # Current user, researcher, and maintainer guides
├── architecture/                 # Current architecture docs
├── policies/                     # Current governance, security, privacy, DPG docs
├── adr/                          # Architecture decision records
├── roadmap/                      # Current and historical planning notes
├── evidence/                     # Historical post-thesis OSS evidence archive
├── tesis/                        # Historical thesis archive (v4.0.0)
│   ├── README.md                 # Thesis structure guide
│   ├── INDICE_TESIS.md          # Complete thesis index
│   ├── PORTADA_TESIS.md         # Cover page
│   ├── CAPITULO_*.md            # Thesis chapters (1-8)
│   ├── APENDICE_*.md            # Appendices
│   └── figures/                  # Thesis figures
├── DEFENSA_TESIS_SLIDES.md      # Defense presentation (Marp)
├── figures/                      # General diagrams
├── openapi.yaml                  # API spec (post-thesis)
├── index.md                      # GitHub Pages - English
├── index_es.md                   # GitHub Pages - Spanish
├── thesis.md                     # Thesis summary EN
├── thesis_es.md                  # Thesis summary ES
└── _config.yml                   # Jekyll configuration
```

---

## Key Documents

### Current Research and Platform Claims

| Document | Location | Description |
|----------|----------|-------------|
| Paper index | `../paper/README.md` | Current paper artifacts and reproducibility map |
| Paper 1 reproducibility | `../paper/PAPER1_REPRODUCIBILITY.md` | Detection evidence and commands |
| Paper 2 reproducibility | `../paper/PAPER2_REPRODUCIBILITY.md` | Remediation evidence and commands |
| Paper/platform alignment | `roadmap/PAPER_LEARNINGS_PLATFORM_ALIGNMENT.md` | How paper evidence maps to CLI/API/MCP/RAG |
| Technical debt plan | `roadmap/TECHNICAL_DEBT_REMEDIATION_PLAN.md` | Completed and remaining cleanup work |

### Current Project Maintenance

| Document | Location | Description |
|----------|----------|-------------|
| Repository Hygiene | `guides/REPOSITORY_HYGIENE.md` | What belongs in Git, what is generated/local, and how evidence is curated |
| Researcher Packaging | `guides/RESEARCHER_PACKAGING.md` | How researchers should install and run the full toolchain |
| Testing Guide | `guides/TESTING.md` | Test strategy and validation commands |
| RAG Source Policy | `guides/RAG_SOURCE_POLICY.md` | Source selection and weighting criteria |
| Remediation API/MCP | `guides/REMEDIATION_API_MCP.md` | Evidence-producing remediation workflows |

### Current User Documentation

| Document | Location | Description |
|----------|----------|-------------|
| Quickstart | `guides/QUICKSTART.md` | Fast path for users |
| Installation | `guides/INSTALL.md` | Local installation and dependencies |
| Research workflow | `guides/RESEARCH.md` | Benchmark and paper-oriented workflows |
| Reports | `guides/REPORTS.md` | Report generation and templates |
| Architecture | `ARCHITECTURE.md` | High-level architecture |
| Tools | `TOOLS.md` | Tool inventory |

### Historical Thesis Archive

| Document | Location | Description |
|----------|----------|-------------|
| Thesis Index | `tesis/INDICE_TESIS.md` | Complete chapter structure |
| Cover Page | `tesis/PORTADA_TESIS.md` | Institutional cover |
| Introduction | `tesis/CAPITULO_INTRODUCCION.md` | Context, objectives, hypothesis |
| Theoretical Framework | `tesis/CAPITULO_MARCO_TEORICO.md` | Foundations |
| State of the Art | `tesis/CAPITULO_ESTADO_DEL_ARTE.md` | Tool review |
| Development | `tesis/CAPITULO_DESARROLLO.md` | 7-layer architecture |
| Results | `tesis/CAPITULO_RESULTADOS.md` | Experimental validation |
| AI/LLM Justification | `tesis/CAPITULO_JUSTIFICACION_IA_LLM_SOBERANO.md` | Sovereign AI |
| MCP Justification | `tesis/CAPITULO_JUSTIFICACION_MCP.md` | Protocol integration |
| Future Work | `tesis/CAPITULO_TRABAJOS_FUTUROS.md` | Proposed lines |
| Separation Document | `evidence/THESIS_VS_POSTWORK_SEPARATION.md` | Thesis vs post-thesis work |

### Historical OSS Handoff Archive

| Document | Location | Description |
|----------|----------|-------------|
| Handoff Report | `evidence/HANDOFF_REPORT_OSS.md` | Complete project overview |
| OpenAPI Spec | `openapi.yaml` | API documentation (2,273 lines) |
| Exporters Demo | `evidence/demo_exporters.py` | SARIF, SonarQube, etc. |
| Metrics Demo | `evidence/demo_metrics.py` | Prometheus metrics |
| WebSocket Demo | `evidence/demo_websocket.py` | Real-time events |
| OpenAPI Demo | `evidence/demo_openapi.py` | API exploration |

---

## Historical Timeline

| Date | Event | Version |
|------|-------|---------|
| **23 Oct 2025** | Thesis submitted to tribunal | v4.0.0 |
| Oct-Nov 2025 | Post-thesis: WebSocket, Layers 8-9 | v4.1.0 |
| Nov-Dec 2025 | Post-thesis: Exporters, Metrics, DPGA | v4.2.0 |
| **18 Dec 2025** | Thesis defense | - |

---

## Thesis Scope (v4.0.0)

**What is defended:**
- 7-layer defense-in-depth architecture
- 25 integrated security tools
- SWC/CWE/OWASP normalization
- Sovereign LLM with Ollama
- MCP Server integration
- Results: 100% recall, +40.8% improvement, $0 cost

**What is NOT defended (post-thesis):**
- Layers 8-9 (DeFi/Dependencies)
- WebSocket real-time API
- Multi-format exporters
- Prometheus metrics
- GitHub Actions CI/CD
- DPGA application

---

## Quick Links

- **Main README**: `/README.md`
- **Spanish README**: `/README_ES.md`
- **Contributing**: `/CONTRIBUTING.md`
- **License**: `/LICENSE` (AGPL-3.0)
- **Changelog**: `/CHANGELOG.md`

---

*MIESC documentation index - current project docs plus historical thesis/archive material*
