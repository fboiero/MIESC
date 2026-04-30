# Ethereum Foundation ESP — Small Grant Application (MIESC)

**Project**: MIESC — Multi-layer Intelligent Evaluation for Smart Contracts
**Applicant**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Repository**: https://github.com/fboiero/MIESC
**License**: AGPL-3.0

---

## Project summary (≤ 3 sentences)

MIESC is an open-source pre-audit triage framework that orchestrates 35
analysis modules — 13 external security tools (Slither, Aderyn, Mythril,
Echidna, Halmos, Certora Prover, Scribble, SMTChecker, ...) and 22
internal modules — across 9 complementary defense layers with per-layer
timing instrumentation. It normalizes heterogeneous tool outputs into a
unified finding schema, reduces false positives with RAG-enhanced
filtering (59 vulnerability patterns), and closes the loop from
detection to proof via `miesc specs` + `miesc verify`. v5.4.0 adds a
scientific evaluation framework (`miesc evaluate`), a plugin system for
third-party detectors via PyPI entry points, JSONL export for ML
pipelines, and two academic papers. Evaluated on SmartBugs-curated
(96.5% recall static+intelligence, ~98.6% with LLM), EVMBench (92.5%
ensemble recall, #1), and 11 confirmed $3.3B DeFi exploits (81.8%
recall, κ = 0.77). Published as open source at
https://github.com/fboiero/MIESC.

---

## Why ESP (fit)

MIESC is squarely inside ESP's "Developer Tooling / Security" wheelhouse:

1. **Public good, AGPL-3.0**: no freemium trickery, no "community
   edition" asterisk. What you see on GitHub is what users get.
2. **Non-duplicative**: MIESC is an **orchestrator**. It wraps tools
   ESP has already funded (Slither, Scribble, Echidna) and adds the
   missing layer — consistent schema, RAG-backed FP filter, formal-
   verification bridge.
3. **Evidence, not promises**: the tool ships today
   (`pip install miesc`, v5.4.0 on PyPI), 5,300+ passing tests, honest
   benchmark numbers in two academic papers (no inflated precision).
4. **Runs locally**: no telemetry, no cloud dependency. Ollama is
   optional; everything works with local Python.

---

## The specific deliverables this grant funds

### Deliverable A — Labelled false-positive corpus (months 1–2)

**Problem**: MIESC ships `AuditorTrainedFPClassifier` (sklearn-based
trainable FP filter) but the seed dataset is bootstrapped heuristically
(934 samples, 67 TPs). For the classifier to actually lower FP rate in
production, we need real auditor-labelled findings.

**Plan**: Partner with 2–3 professional auditing firms that agree to
label findings they already adjudicate. Build a pipeline that ingests
their judgements (TP / FP / mitigated) and re-trains the classifier.

**Output**: public anonymised corpus of 2 000+ labelled findings + a
retrained classifier that further improves the FP rate beyond the
current precision baseline on SmartBugs-curated.

### Deliverable B — Victim-side exploit corpus (months 2–3)

**Problem**: MIESC's Rekt benchmark (11 contracts, 81.8% recall,
κ = 0.77) uses attacker-harness contracts rather than the original
victim code. We explicitly flagged this in our paper's limitations
section.

**Plan**: Source the pre-exploit victim contracts for Euler, Ronin,
Curve, Beanstalk, Platypus, Compound Governance, BonqDAO, Rari Capital,
Level Finance, Yearn v1, bZx. Label the specific function + line that
contained the exploitable pattern. Publish as
`benchmarks/datasets/rekt-victim-corpus/`.

**Output**: a reproducible, expanding corpus that every smart-contract
static analyzer can benchmark against. Target: 30+ contracts.

### Deliverable C — Multi-LLM consensus at scale (months 3–4)

**Problem**: MIESC's multi-LLM consensus mechanism (v5.4.0) currently
uses two local Ollama models. Scaling to hosted frontier models
(GPT-4-class, Claude Sonnet, Gemini Pro) was deferred because no
labelled dataset existed to measure precision delta.

**Plan**: Once Deliverable A is shipping, run the consensus across 4+
models on the Rekt corpus + SmartBugs. Quantify the precision-recall
curve and the cost curve (tokens x pricing). Publish as a measured
improvement in Paper 2 (remediation pipeline).

**Output**: an empirical answer to "does a second LLM meaningfully
reduce false positives, and at what cost" — something currently
missing from the literature.

### Deliverable D — GitHub Action + Foundry plugin (months 4–6)

**Problem**: the MIESC GitHub Action exists (`action.yml`) but is
unpublished on the Marketplace. Foundry integration is CLI-only
(`forge ... && miesc scan`).

**Plan**: polish and submit the Action to the Marketplace with the
standard five tiers of example workflows. Build a native
`foundry_plugin` so `forge script` can dispatch MIESC.

**Output**: frictionless CI/CD integration for any Ethereum project
using Foundry or Hardhat.

---

## Budget

**USD 40 000** total, milestone-based (all payments on delivery):

| Milestone | Deliverable | USD |
|----|----|---:|
| M1 | Labelled FP corpus, 2000+ findings | 10 000 |
| M2 | Victim-side exploit corpus, 30+ contracts | 8 000 |
| M3 | Multi-LLM consensus benchmark + v2 paper update | 10 000 |
| M4 | Marketplace GitHub Action + Foundry plugin | 8 000 |
| M5 | Documentation, tutorial, video demo | 4 000 |

If the EF prefers smaller tranches, any subset (e.g. M1+M2 for
$18 000) is also achievable in 3 months.

---

## Success metrics (12 months post-grant)

- **PyPI downloads**: 5 000/month (from current 611/month)
- **GitHub stars**: 200+ (from current 3)
- **External contributors**: ≥ 5
- **External citations**: paper cited in 3+ subsequent papers
- **Production use**: ≥ 10 public Ethereum projects document MIESC in
  their security sections (README / audit log)
- **New vulnerability-class contributions**: ≥ 10 patterns submitted by
  external contributors to our RAG registry

---

## Who I am

Fernando Boiero — sole developer. 12+ years of engineering; MSc in
Cybersecurity at UNDEF, teaching appointment at UTN–FRVM. MIESC is both
my thesis artifact and a framework I maintain full-time.

Past work, public code:
- (link your prior OSS projects here)
- UTN faculty page: (link)

References: my thesis director at UNDEF, plus colleagues at UTN-FRVM
who have reviewed MIESC internally.

---

## Why I'm asking now, not later

MIESC today has: benchmarks, a published package (v5.4.0 on PyPI), two
academic papers (evaluation methodology + remediation pipeline), a
scientific evaluation framework, a plugin system for third-party
detectors, and 5,300+ passing tests. It does not have: the funding
runway to work on it full-time for 12 months. With an ESP grant I
finish the thesis, the papers, and the v6 release cycle as a unit
rather than in snatches between teaching commitments. Without it I keep shipping, just slower.

Either way, MIESC ships. The grant is about speed + evidence depth
(real labelled datasets require someone to actually sit with auditors
and tag findings — that takes weeks of labour).

---

## Supporting materials

- `paper/miesc-paper.pdf` — Paper 1: multi-layer evaluation methodology
- `paper/miesc-paper2.pdf` — Paper 2: remediation pipeline (7 pages)
- `docs/guides/RESEARCH.md` — Research guide with evaluation framework
- `docs/guides/PLUGINS.md` — Plugin development guide
- `https://github.com/fboiero/MIESC/releases/tag/v5.4.0` — latest release
