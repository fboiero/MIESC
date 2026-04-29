# arXiv Submission — MIESC Paper

Ready-to-submit bundle at `paper/miesc-arxiv.tar.gz`.

## Metadata

### Title
```
MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
```

### Authors
```
Fernando Boiero
```

- **Affiliation**: Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María
- **Email**: fboiero@frvm.utn.edu.ar
- **ORCID**: (add yours if you have one)

### Abstract
*(copy verbatim from `miesc-paper.tex` — fits arXiv's limit)*

### Subjects
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments
```
7 pages, 7 tables. Multi-provider ensemble achieves 92.5% recall on EVMBench (120 business-logic vulns), surpassing Cecuro (87.7%). Framework: https://github.com/fboiero/MIESC (AGPL-3.0, PyPI: miesc). Reproducible benchmarks included.
```

### License
**CC BY 4.0**

---

## Key results to highlight in submission

| Benchmark | Result | Context |
|-----------|--------|---------|
| SmartBugs (143 contracts) | 80% recall | Slither alone: 43% |
| Real exploits ($3.3B) | 81.8% recall, κ=0.77 | 11 confirmed DeFi exploits |
| EVMBench (40 audits, 120 vulns) | **92.5% ensemble** | Cecuro: 87.7%, Claude standalone: 45.9% |
| EVMBench single provider | 82.5% (Claude) | GPT-5: 77.5%, Ollama local: 59.2% |
| Cost | $0.18/audit (ensemble) | vs $20K-60K manual audit |

## Submission workflow

1. Go to https://arxiv.org/submit
2. Log in (UTN email accepted as institutional)
3. **Start new submission**, category `cs.CR`
4. Upload `paper/miesc-arxiv.tar.gz`
5. arXiv compiles the PDF — verify it matches `paper/miesc-paper.pdf`
6. Fill metadata from above
7. Submit. Preprint lands within 24 hours.

---

## Post-submission

Once arXiv ID is assigned (e.g., `arXiv:2604.XXXXX`):

1. Update `CITATION.cff` with arXiv ID + DOI
2. Add badge to README:
   ```markdown
   [![arXiv](https://img.shields.io/badge/arXiv-2604.XXXXX-b31b1b.svg)](https://arxiv.org/abs/2604.XXXXX)
   ```
3. Cite in grant applications (Starknet, EF ESP, NGI)
4. Announce:
   - Twitter/X thread: "MIESC achieves 92.5% on EVMBench — #1, surpassing Cecuro (87.7%). Open-source, multi-provider ensemble. Paper + code:"
   - r/ethereum, r/ethdev, Hacker News (`Show HN`)
   - Farcaster `/security` channel
5. Submit v2 to peer-reviewed venue:
   - **IEEE S&P Workshop on DeFi Security** (deadline ~Sep)
   - **ACM CCS Workshop on Blockchain** (deadline ~Jun)
   - **USENIX Security** (rolling)

---

## What makes this paper publishable

1. **State-of-the-art result**: 92.5% on EVMBench > Cecuro (87.7%)
2. **Novel finding**: multi-provider ensemble > any single LLM (each finds different vulns)
3. **Practical**: $0.18/audit, open-source, works with free local models
4. **Reproducible**: all benchmarks, configs, and results in the repo
5. **Three benchmarks**: SmartBugs (patterns) + real exploits ($3.3B) + EVMBench (business logic)
