# arXiv Submission — Two MIESC Papers

Two ready-to-submit bundles. Submit as separate arXiv preprints — they cross-reference each other.

---

## Paper 1: Detection (miesc-arxiv.tar.gz)

### Title
```
MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
```

### Authors
```
Fernando Boiero
Sebastian Norberto Mussetta
Norberto Gaspar Cena
```

- **Affiliation**: Universidad Tecnologica Nacional (UTN), Facultad Regional Villa Maria
- **Emails**: fboiero@frvm.utn.edu.ar, smussetta@frvm.utn.edu.ar, ngcena@frvm.utn.edu.ar
- **ORCID**: Fernando Boiero — 0009-0005-7935-2758; Sebastian Norberto Mussetta — 0009-0007-8025-9846; Norberto Gaspar Cena — not provided

### Abstract
*(copy verbatim from `miesc-paper.tex`)*

### Subjects
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments
```
8 pages, 1 figure, 7 tables. Editorial v3 over the v2 evidence baseline: EVMBench local high-severity extraction 111/120 detections (92.5% recall); SmartBugs primary reproducible profile 137/143 (95.8% recall), with a secondary local Ollama follow-up artifact reporting 140/143 (97.9%). Framework: https://github.com/fboiero/MIESC (AGPL-3.0, PyPI: pip install miesc). Reproducibility artifacts included.
```

### License
**CC BY 4.0**

### Key results

| Benchmark | Result | Context |
|-----------|--------|---------|
| SmartBugs (143 contracts) | 95.8% primary; 97.9% secondary | Latest full-corpus reproducible local profile; v2 local Ollama follow-up artifact records 140/143 |
| Real exploits ($1.59B) | 81.8% recall, kappa=0.77 | 11 confirmed DeFi exploits |
| EVMBench local extraction (40 audits, 120 findings) | **111/120 = 92.5% ensemble** | Static-only baseline: 22/120 = 18.3%; union artifact generated from provider JSONs |
| Cost | ~$7/audit full ensemble, $0 local | vs $20K-60K manual audit |

---

## Paper 2: Verifiable Remediation Artifacts (paper2-arxiv.tar.gz)

### Title
```
From Findings to Verifiable Remediation Artifacts: A Smart Contract Security Pipeline
```

### Authors
```
Fernando Boiero
Sebastian Norberto Mussetta
Norberto Gaspar Cena
```

- **Affiliation**: Universidad Tecnologica Nacional (UTN), Facultad Regional Villa Maria
- **Emails**: fboiero@frvm.utn.edu.ar, smussetta@frvm.utn.edu.ar, ngcena@frvm.utn.edu.ar
- **ORCID**: Fernando Boiero — 0009-0005-7935-2758; Sebastian Norberto Mussetta — 0009-0007-8025-9846; Norberto Gaspar Cena — not provided

### Abstract
*(copy verbatim from `paper2-remediation.tex`)*

### Subjects
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments
```
8 pages, 3 code listings, 5 tables. Editorial v3 over the v2 external-validation baseline: 123/143 current-scan fix application, 123/123 standalone compilation, 86/123 vulnerability elimination by MIESC re-scan, 121/123 bounded no-regression criterion, and 58/123 clean-HIGH results under external Slither validation. Companion paper to [Paper 1 arXiv ID]. Framework: https://github.com/fboiero/MIESC (AGPL-3.0).
```

### License
**CC BY 4.0**

### Key results

| Metric | Result |
|--------|--------|
| Fix application rate | 86% (123/143 contracts, current scan) |
| Compilation (standalone) | 100% (123/123 patched contracts) |
| Vulnerability eliminated | 70% (86/123 patched contracts, MIESC re-scan) |
| No-regression criterion | 98% (121/123 patched contracts) |
| External Slither clean-HIGH | 47% (58/123 patched contracts) |
| Exploit tests generated | 6/6 compile, all confirm vuln |
| Comparison | Only evaluated tool with tests + specs + compliance |

---

## Submission Workflow

### Step 1: Submit Paper 1 first

1. Go to https://arxiv.org/submit
2. Log in (UTN email accepted as institutional)
3. **Start new submission**, category `cs.CR`
4. Upload `paper/miesc-arxiv.tar.gz`
5. arXiv compiles the PDF — verify it matches `paper/miesc-paper.pdf`
6. Fill metadata from Paper 1 section above
7. Submit. Preprint lands within 24 hours.
8. Note the arXiv ID: `arXiv:2604.XXXXX`

### Step 2: Submit Paper 2

1. Start new submission at https://arxiv.org/submit
2. Upload `paper/paper2-arxiv.tar.gz`
3. In **Comments**, replace `[Paper 1 arXiv ID]` with the actual ID from Step 1
4. Fill metadata from Paper 2 section above
5. Submit.

### Step 3: Cross-reference

Once both IDs are assigned:
1. Update Paper 1 on arXiv (new version) to add Paper 2's arXiv ID in the companion paper reference
2. Update `references.bib` entry `boiero2025miesc` with the arXiv ID

---

## Post-submission checklist

Once arXiv IDs are assigned:

- [ ] Update `CITATION.cff` with arXiv IDs
- [ ] Add badges to README:
  ```markdown
  [![Paper 1](https://img.shields.io/badge/arXiv-2604.XXXXX-b31b1b.svg)](https://arxiv.org/abs/2604.XXXXX)
  [![Paper 2](https://img.shields.io/badge/arXiv-2604.YYYYY-b31b1b.svg)](https://arxiv.org/abs/2604.YYYYY)
  ```
- [ ] Update grant applications with arXiv links (Starknet, EF ESP, NGI Zero)
- [ ] Announce: Twitter/X, r/ethereum, r/ethdev, Hacker News (`Show HN`), Farcaster
- [ ] Submit to peer-reviewed venues:
  - **IEEE S&P Workshop on DeFi Security** (deadline ~Sep)
  - **ACM CCS Workshop on Blockchain** (deadline ~Jun)
  - **USENIX Security** (rolling)
