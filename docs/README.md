# MIESC Documentation

**Last Updated:** 2025-12-13

This directory contains all documentation for the MIESC project, organized by purpose and timeline.

---

## Documentation Structure

```
docs/
├── README.md                     # This file - documentation index
├── tesis/                        # THESIS (v4.0.0 - 23 Oct 2025)
│   ├── README.md                 # Thesis structure guide
│   ├── INDICE_TESIS.md          # Complete thesis index
│   ├── PORTADA_TESIS.md         # Cover page
│   ├── CAPITULO_*.md            # Thesis chapters (1-8)
│   ├── APENDICE_*.md            # Appendices
│   └── figures/                  # Thesis figures
├── evidence/                     # POST-THESIS for OSS Team (v4.1.0+)
│   ├── README.md                 # Evidence guide
│   ├── THESIS_VS_POSTWORK_SEPARATION.md  # Key separation document
│   ├── HANDOFF_REPORT_OSS.md    # OSS team handoff (DPGA compliance)
│   ├── demo_*.py                 # Component demos
│   └── output_*.*                # Demo outputs
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

### For Thesis Defense (Dec 18, 2025)

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
| **Separation Document** | `evidence/THESIS_VS_POSTWORK_SEPARATION.md` | Thesis vs Post-thesis |

### For OSS Team Handoff

| Document | Location | Description |
|----------|----------|-------------|
| Handoff Report | `evidence/HANDOFF_REPORT_OSS.md` | Complete project overview |
| OpenAPI Spec | `openapi.yaml` | API documentation (2,273 lines) |
| Exporters Demo | `evidence/demo_exporters.py` | SARIF, SonarQube, etc. |
| Metrics Demo | `evidence/demo_metrics.py` | Prometheus metrics |
| WebSocket Demo | `evidence/demo_websocket.py` | Real-time events |
| OpenAPI Demo | `evidence/demo_openapi.py` | API exploration |

---

## Timeline

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
- **License**: `/LICENSE` (GPL-3.0)
- **Changelog**: `/CHANGELOG.md`

---

*MIESC v4.2.0 "Fortress" - Maestria en Ciberdefensa, UNDEF/IUA*
