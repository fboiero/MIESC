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
```

- **Affiliation**: Universidad Tecnologica Nacional (UTN), Facultad Regional Villa Maria
- **Email**: fboiero@frvm.utn.edu.ar

### Abstract
*(copy verbatim from `miesc-paper.tex`)*

### Subjects
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments
```
7 pages, 1 figure, 7 tables. Multi-provider ensemble achieves 92.5% recall on EVMBench (120 business-logic vulns), surpassing Cecuro (87.7%). SmartBugs: 96.5% recall (143 contracts). Framework: https://github.com/fboiero/MIESC (AGPL-3.0, PyPI: pip install miesc). Reproducible benchmarks included.
```

### License
**CC BY 4.0**

### Key results

| Benchmark | Result | Context |
|-----------|--------|---------|
| SmartBugs (143 contracts) | 96.5% recall | Static+intelligence; ~98.6% with LLM |
| Real exploits ($3.3B) | 81.8% recall, kappa=0.77 | 11 confirmed DeFi exploits |
| EVMBench (40 audits, 120 vulns) | **92.5% ensemble** | Cecuro: 87.7%, Claude standalone: 45.9% |
| Cost | $0.18/audit (API), $0 local | vs $20K-60K manual audit |

---

## Paper 2: Remediation (paper2-arxiv.tar.gz)

### Title
```
From Detection to Remediation: An Automated Pipeline for Smart Contract Security
```

### Authors
```
Fernando Boiero
```

- **Affiliation**: Universidad Tecnologica Nacional (UTN), Facultad Regional Villa Maria
- **Email**: fboiero@frvm.utn.edu.ar

### Abstract
*(copy verbatim from `paper2-remediation.tex`)*

### Subjects
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments
```
7 pages, 3 code listings, 5 tables. Automated find-fix-prove pipeline evaluated on 143 SmartBugs contracts: 87% fix rate, 84% vuln elimination, 0% regression. Companion paper to [Paper 1 arXiv ID]. Framework: https://github.com/fboiero/MIESC (AGPL-3.0).
```

### License
**CC BY 4.0**

### Key results

| Metric | Result |
|--------|--------|
| Fix application rate | 87% (125/143 contracts) |
| Compilation (standalone) | 63% (88% on self-contained) |
| Vulnerability eliminated | 84% |
| No regression | 100% |
| Exploit tests generated | 6/6 compile, all confirm vuln |
| Comparison | Only tool with tests + specs + compliance |

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
