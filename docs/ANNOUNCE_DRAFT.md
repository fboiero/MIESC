# Announcement Drafts

## Show HN (Hacker News)

**Title:** Show HN: MIESC – Open-source smart contract security with 95% recall (35 tools, 9 layers)

**Text:**
Hi HN, I'm Fernando from Argentina. I built MIESC, an open-source framework that orchestrates 35 analysis modules across 9 defense layers for smart contract security.

Key results:
- 95.1% recall on SmartBugs-curated (143 contracts) — vs Slither alone at 43%
- 92.5% recall on EVMBench (120 business-logic vulnerabilities) — #1, beating Cecuro (87.7%)
- Works with local models (Ollama, $0) or frontier APIs (Claude/GPT, ~$7/audit)
- Full pipeline: detect → fix → test-gen → verify → compliance report

The main insight: no single tool catches everything, but orchestrating static analysis + ML + multi-LLM ensemble achieves recall that none can reach alone.

Try it: `pip install miesc && miesc scan contract.sol`

Docker: `docker run ghcr.io/fboiero/miesc:5.4.1 scan /contracts/Token.sol`

GitHub: https://github.com/fboiero/MIESC
PyPI: https://pypi.org/project/miesc/
Paper: [SSRN DOI here]

---

## r/ethereum + r/ethdev

**Title:** Open-source tool achieves 95% vulnerability detection on SmartBugs and 92.5% on EVMBench (beats Cecuro's 87.7%)

**Body:**
I've been building MIESC — a multi-layer smart contract security framework. Just published two academic papers on it and wanted to share with the community.

**What it does:**
- Orchestrates 35 analysis modules (Slither, Mythril, Aderyn, Halmos, + 22 internal modules including multi-LLM audit)
- Runs locally with Ollama ($0) or frontier APIs
- Full pipeline: scan → auto-patch → generate exploit tests → formal verify → compliance report

**Numbers:**
- SmartBugs (143 contracts): 95.1% recall
- EVMBench (120 biz-logic vulns): 92.5% ensemble recall
- Real exploits ($3.3B): 81.8% recall (κ=0.77)
- Automated patching: 99% applied, 64% compile standalone

**For researchers:**
- `miesc evaluate corpus` — ground-truth evaluation with precision/recall
- `miesc evaluate ablation` — per-layer contribution study
- Plugin system via PyPI entry points
- JSONL export for ML pipelines

**Quick start:**
```bash
pip install miesc
miesc scan MyContract.sol
miesc scan MyContract.sol --model claude  # with frontier LLM
miesc fix results.json -c MyContract.sol  # auto-patch
```

AGPL-3.0 | GitHub: https://github.com/fboiero/MIESC | Paper: [DOI]

---

## Twitter/X Thread

1/ Releasing MIESC v5.4.1 — open-source smart contract security that achieves 95.1% recall on SmartBugs and 92.5% on EVMBench (#1, beating Cecuro's 87.7%).

35 analysis modules. 9 defense layers. Works with local models ($0) or frontier APIs.

🧵 Thread:

2/ The key insight: no single tool catches everything.
- Slither alone: 43% recall
- Mythril alone: 27%
- Best single LLM: 82.5%
- All together: 95.1%

Multi-layer orchestration > any individual tool.

3/ Full pipeline in one command:
```
miesc scan contract.sol → detect
miesc fix → auto-patch
miesc test-gen → exploit tests
miesc verify → formal proofs
miesc report → PDF audit
```

4/ For researchers:
- `miesc evaluate corpus` — benchmark harness with ground truth
- `miesc evaluate ablation` — isolate each layer's contribution
- Plugin system — publish your detector on PyPI, MIESC discovers it
- JSONL export for ML pipelines

5/ Numbers that matter:
- $0 with local Ollama (59% recall)
- $7/audit with 4-provider ensemble (92.5% recall)
- vs $20K-60K manual audit

Paper: [DOI]
GitHub: github.com/fboiero/MIESC
PyPI: pip install miesc

---

## Farcaster /security

MIESC v5.4.1 — open-source smart contract security framework

95.1% recall on SmartBugs, 92.5% on EVMBench (#1)
35 modules, 9 layers, works with local models

detect → fix → test-gen → verify → report

pip install miesc
github.com/fboiero/MIESC
