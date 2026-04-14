# arXiv Submission — MIESC Paper

Ready-to-submit bundle at `paper/miesc-arxiv.tar.gz` (16 KB, contains
`miesc-paper.tex`, `references.bib`, `miesc-paper.bbl`).

## Metadata to enter on the arXiv form

### Title
```
MIESC: A Multi-layer Framework for Automated Smart Contract Security Evaluation
```

### Authors
```
Fernando Boiero
```

Author metadata:
- **Affiliation**: Universidad Tecnológica Nacional (UTN), Facultad Regional Villa María
- **Email**: fboiero@frvm.utn.edu.ar
- **ORCID**: (add yours if you have one)

### Abstract
*(copy verbatim from `miesc-paper.tex` line 46; ~1800 chars, fits arXiv's limit)*

### Subjects / primary category
- `cs.CR` — Cryptography and Security (PRIMARY)
- `cs.SE` — Software Engineering (SECONDARY)

### Comments (optional)
```
7 pages, 6 tables. Framework published under AGPL-3.0 at https://github.com/fboiero/MIESC, PyPI package `miesc`. Reproducible benchmarks included.
```

### License
Recommended: **CC BY 4.0** (allows reuse + citation with attribution)

---

## Submission workflow

1. Go to https://arxiv.org/submit
2. Log in (create account if needed — UTN email is accepted as institutional)
3. **Start new submission**, category `cs.CR`
4. Upload `paper/miesc-arxiv.tar.gz`
5. arXiv's LaTeX compiler builds the PDF. If errors:
   - Check that `miesc-paper.bbl` is included (it is — embedded bibliography)
   - `IEEEtran.cls` ships with arXiv's TeX Live; no action needed
6. Fill metadata from the block above
7. Preview the PDF — it should be identical to `paper/miesc-paper.pdf`
8. Submit. Preprint lands on arXiv within 24 hours.

---

## Why arXiv first (before conference / journal)

- **Free preprint DOI** → citable from your grant applications (Starknet, EF ESP, NGI)
- **Does NOT block later journal submission** (IEEE, ACM, Springer all accept prior arXiv)
- **Establishes priority date** if anyone else works on similar ideas
- **Measurable reach** — arXiv tracks downloads per paper

---

## Post-submission actions

Once the arXiv ID is assigned (e.g., `arXiv:2604.12345`):

1. Update `CITATION.cff` with the arXiv ID + DOI
2. Add arXiv badge to README:
   ```markdown
   [![arXiv](https://img.shields.io/badge/arXiv-2604.12345-b31b1b.svg)](https://arxiv.org/abs/2604.12345)
   ```
3. Cite in all three grant applications (Starknet, EF ESP, NGI)
4. Announce on:
   - Twitter/X thread
   - Farcaster (`/developers` or `/security` channels)
   - r/ethereum, r/ethdev
   - Hacker News (`Show HN: MIESC`)
5. Submit v2 to a peer-reviewed venue:
   - **ICSE 2027** (Software Engineering, deadline ~August 2026)
   - **USENIX Security 2027** (summer 2026 deadline)
   - **S&P 2027** / **IEEE EuroS&P**
   - Journal track: IEEE TSE, ACM TOSEM, ESE (Empirical Software Engineering)

---

## Known limitations to disclose in v2 / journal version

From `docs/PRE_RELEASE_AUDIT_v5.1.7.md` and the v5.1.7 benchmark report:

1. **Non-EVM chains**: Cairo has 13 vuln types with real exploit coverage;
   Move and Solana are scaffolded only. To be expanded before journal
   submission.
2. **`AuditorTrainedFPClassifier` needs real auditor labels**: the current
   bootstrap dataset (934 samples, 67 TPs) is derived heuristically.
3. **11-exploit Rekt evaluation is small**. Target: expand to 100+
   contracts before the journal version.
4. **Multi-LLM consensus ran with 2 models on 11 contracts**; scaling to
   more models (GPT-4, Claude, Gemini) is future work.
