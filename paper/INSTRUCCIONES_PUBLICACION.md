# Instrucciones para publicar el paper MIESC

## Archivos

| Archivo | Path absoluto |
|---------|---------------|
| Tarball arXiv | `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-arxiv.tar.gz` |
| PDF compilado | `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-paper.pdf` |
| Source LaTeX | `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-paper.tex` |
| Bibliografía | `/Users/fboiero/Documents/GitHub/MIESC/paper/references.bib` |

---

## PASO 1: Revisar el PDF

Abrir `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-paper.pdf` y verificar:

- [ ] Afiliación: "Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María"
- [ ] Email: fboiero@frvm.utn.edu.ar
- [ ] 5 tablas sin texto flotando fuera de lugar
- [ ] 14 referencias en bibliografía
- [ ] Números: 13 ext + 22 int = 35 modules, 60 RAG patterns
- [ ] Recall: 54.6% (static), 80% (all layers), 81.8% (exploits)
- [ ] Cohen's κ = 0.773
- [ ] Modelo LLM especificado: qwen2.5-coder:14b
- [ ] Comando de reproducibilidad visible (no vacío)
- [ ] Acknowledgment: UNDEF (tesis) + UTN-FRVM (actual)
- [ ] Data Availability con link a GitHub

---

## PASO 2: Subir a TechRxiv (HACER PRIMERO — sin endorsement, genera DOI)

1. Ir a **https://www.techrxiv.org**
2. Crear cuenta con `fboiero@frvm.utn.edu.ar`
3. Click **"Submit a Preprint"**
4. Subir PDF: `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-paper.pdf`
5. Completar:

```
Title:       MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
Authors:     Fernando Boiero (Universidad Tecnológica Nacional, Facultad Regional Villa María)
Keywords:    smart contracts, blockchain security, vulnerability detection, static analysis, LLM, RAG
License:     CC BY 4.0
```

6. Abstract (copiar tal cual):

```
Automated security analysis tools for smart contracts each capture only a
fraction of existing vulnerabilities, and their high false positive rates
limit practical adoption. We present MIESC (Multi-layer Intelligent Evaluation
for Smart Contracts), an open-source framework that orchestrates 13 external
security tools and 22 internal analysis modules across 9 complementary defense
layers to provide comprehensive pre-audit triage. MIESC normalizes heterogeneous
tool outputs, filters false positives using a Retrieval-Augmented Generation
(RAG) system with 60 vulnerability patterns, and maps findings to 12
international security standards. Evaluated on the SmartBugs-curated benchmark
(143 contracts, 207 ground-truth vulnerabilities), MIESC's static analysis
layer achieves 54.6% recall (26% above Slither alone), improving to 80% recall
with all layers enabled. On 11 confirmed DeFi exploits totaling $3.3 billion
in losses, MIESC achieves 81.8% recall with Cohen's kappa = 0.77. For critical
vulnerability classes, recall reaches 100% on both reentrancy and access
control. MIESC is freely available under AGPL-3.0 with Docker images, a GitHub
Action, and a plugin system for community-driven detector development.
```

7. Submit — genera DOI en minutos

---

## PASO 3: Subir a arXiv (necesita endorsement)

1. Ir a **https://arxiv.org/submit**
2. Login con `fboiero@frvm.utn.edu.ar`
3. Intentar con categoría **`cs.SE`** (Software Engineering) primero — puede no necesitar endorsement
4. Si pide endorsement, probar `cs.DC` (Distributed Computing)
5. Si funciona sin endorsement, completar:

```
Primary Category:    cs.SE
Cross-list:          cs.CR
Title:               MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
Authors:             Fernando Boiero
Comments:            5 pages, 5 tables, 14 references
License:             CC BY 4.0
```

6. Upload: `/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-arxiv.tar.gz`
7. Mismo abstract que el paso anterior
8. Submit

---

## PASO 4: Enviar emails de endorsement para arXiv

Si arXiv pide endorsement en todas las categorías, hay que contactar autores que puedan endorsar.

**Código de endorsement de Fernando:** `AORK7R`

**Cómo verificar quién puede endorsar:** En cada paper de arXiv, abajo del abstract hay un link "Which of the authors of this article can endorse?" — click ahí para confirmar.

### Enviar desde el webmail de la UTN

URL del webmail: https://roundcube.frvm.utn.edu.ar

**En TODOS los emails adjuntar el PDF:**
`/Users/fboiero/Documents/GitHub/MIESC/paper/miesc-paper.pdf`

---

### Email 1 — Thomas Durieux (SmartBugs, TU Delft) ⭐ PRIORIDAD MÁXIMA

**Para:** thomas@durieux.me

**Asunto:** arXiv endorsement request — smart contract security framework (cs.CR)

**Cuerpo:**

```
Dear Dr. Durieux,

I am Fernando Boiero, a researcher at Universidad Tecnológica Nacional
(UTN-FRVM), Argentina. I am writing to request your endorsement to
submit a paper to arXiv in the cs.CR category.

The paper presents MIESC, an open-source framework for automated smart
contract security evaluation that orchestrates 35 analysis modules
across 9 defense layers. We evaluated it on the SmartBugs-curated
benchmark — your dataset — achieving 80% recall with all layers enabled
(85% improvement over Slither alone). We also validated against 11
real-world DeFi exploits totaling $3.3B in losses, with 81.8% recall
(Cohen's κ = 0.77).

Your work on SmartBugs (ICSE 2020, ASE 2023) was foundational to our
evaluation methodology, and we cite both papers.

The framework is publicly available at: https://github.com/fboiero/MIESC

My arXiv endorsement code is: AORK7R

I attach the paper PDF for your review. I would be very grateful for
your endorsement.

Best regards,
Fernando Boiero
Universidad Tecnológica Nacional — Facultad Regional Villa María
fboiero@frvm.utn.edu.ar
```

---

### Email 2 — Josselin Feist (Slither)

**Para:** josselin@seceureka.com

**Asunto:** arXiv endorsement request — multi-tool smart contract security framework

**Cuerpo:**

```
Dear Josselin,

I am Fernando Boiero, a researcher at Universidad Tecnológica Nacional
(UTN-FRVM), Argentina. I am writing to request your endorsement to
submit a paper to arXiv in the cs.CR category.

The paper presents MIESC, an open-source framework that orchestrates
multiple security tools — including Slither as a core component of
Layer 1 — across 9 defense layers. On the SmartBugs-curated benchmark,
MIESC achieves 80% recall, and on 11 real-world DeFi exploits ($3.3B
losses), 81.8% recall with 100% on reentrancy and access control.

Your work on Slither is central to our framework and evaluation, and
we cite it prominently.

Tool: https://github.com/fboiero/MIESC
My arXiv endorsement code: AORK7R

I attach the paper for your review.

Best regards,
Fernando Boiero
Universidad Tecnológica Nacional — Facultad Regional Villa María
fboiero@frvm.utn.edu.ar
```

---

### Email 3 — Yuqiang Sun (GPTScan, ICSE 2024)

**Para:** Buscar en https://arxiv.org/abs/2308.03314 → click "view email" junto al nombre. Probablemente yuqiang.sun@ntu.edu.sg (NTU Singapore)

**Asunto:** arXiv endorsement request — LLM-enhanced smart contract security

**Cuerpo:**

```
Dear Dr. Sun,

I am Fernando Boiero, a researcher at Universidad Tecnológica Nacional
(UTN-FRVM), Argentina. I am writing to request your endorsement to
submit a paper to arXiv in the cs.CR category.

The paper presents MIESC, a framework that integrates LLM-based
semantic analysis (similar in spirit to your GPTScan work) within a
multi-layer defense-in-depth architecture. A key finding is that LLM
layers contribute +25 percentage points of recall beyond what static
and symbolic analysis achieve alone.

We cite GPTScan (ICSE 2024) as a foundational reference for
AI-enhanced security analysis.

Tool: https://github.com/fboiero/MIESC
My arXiv endorsement code: AORK7R

I attach the paper for your review.

Best regards,
Fernando Boiero
Universidad Tecnológica Nacional — Facultad Regional Villa María
fboiero@frvm.utn.edu.ar
```

---

### Email 4 — Gustavo Grieco (Echidna, Trail of Bits)

**Para:** Buscar en GitHub (github.com/ggrieco-tob) o LinkedIn. Alternativa: contactar via Twitter @ggrieco

**Asunto:** arXiv endorsement request — smart contract security framework using Echidna

**Cuerpo:**

```
Dear Dr. Grieco,

I am Fernando Boiero, a researcher at Universidad Tecnológica Nacional
(UTN-FRVM), Argentina. I am writing to request your endorsement to
submit a paper to arXiv in the cs.CR category.

The paper presents MIESC, a multi-layer framework for smart contract
security that integrates Echidna as part of its dynamic testing layer
(Layer 2). We evaluated it on SmartBugs-curated (80% recall) and
11 real-world DeFi exploits totaling $3.3B (81.8% recall).

Your work on Echidna (ISSTA 2020) is cited in our paper as a key
dynamic testing technique.

Tool: https://github.com/fboiero/MIESC
My arXiv endorsement code: AORK7R

I attach the paper for your review.

Best regards,
Fernando Boiero
Universidad Tecnológica Nacional — Facultad Regional Villa María
fboiero@frvm.utn.edu.ar
```

---

## RESUMEN DE PRIORIDADES

| # | Acción | Estado |
|---|--------|--------|
| 1 | Revisar PDF | Pendiente |
| 2 | Subir a TechRxiv (inmediato, DOI) | Pendiente |
| 3 | Intentar arXiv con cs.SE | Pendiente |
| 4 | Enviar email a Thomas Durieux (PRIORIDAD) | Pendiente |
| 5 | Enviar email a Josselin Feist | Pendiente |
| 6 | Enviar email a Yuqiang Sun | Pendiente |
| 7 | Enviar email a Gustavo Grieco | Pendiente |

**NOTA:** TechRxiv y arXiv son compatibles — se puede estar en ambos sin conflicto. Ambos son preprint servers, no journals.
