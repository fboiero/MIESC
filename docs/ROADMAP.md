# MIESC Roadmap

Development roadmap for MIESC. The authoritative history of shipped changes lives in
[`CHANGELOG.md`](../CHANGELOG.md); this file looks forward.

---

## Current Version: 6.0.0 (released 2026-07-13)

MIESC is feature-complete and in active maintenance. Highlights of the 5.x line:

- **Detection**: 9 defense layers, 50 integrated tools; SmartBugs-curated recall **95.8%**
  (Paper 1 reproducible profile; v-next 99.3% pending baseline, see Near-term);
  EVMBench 92.5% with a multi-provider ensemble.
- **Remediation** (`miesc fix`): self-contained find→fix→verify pipeline (Paper 2).
- **RAG** false-positive filtering, cross-tool Bayesian confidence, agentic deep-audit.
- **Formal bridge** (`miesc verify`): Certora/Scribble/SMTChecker spec generation.
- **Multi-chain**: EVM + Cardano/Plutus-Aiken, Algorand/TEAL, Stellar/Soroban, Starknet/Cairo.
- **Research**: `miesc evaluate` framework, plugin system, two academic papers.

> Versions 5.2.0 → 6.0.0 are **shipped** (see CHANGELOG). An earlier version of this
> roadmap listed them as future work; corrected 2026-06.

---

## Near-term — Papers v-next + hardening

- **Paper 1 v-next baseline**: detection recall 95.8%→**99.3%** (deterministic
  detectors close 5 of 6 prior misses). Evidence ready; baseline pending final PDF build
  and freeze re-tag.
- **Paper 2 v-next**: raise the external-validation clean rate (v2 baseline: 70/123
  standalone-Slither clean of HIGH, 88/123 eliminate on re-scan) and lean further on
  independent verification (Slither/SMTChecker/Foundry on patched contracts) to remove
  re-scan circularity. Standalone compilation is already 123/123 in v2.
- **Reproducibility**: the benchmark harness reports external-tool crash counts per run;
  document the unloaded-machine measurement protocol.
- **Quality**: 81% line coverage, 75% mutation score on core v6 modules, and a
  deterministic order-independent suite; ongoing robustness hardening toward higher coverage.

## Medium-term

- Promote additional chain analyzers (Solana, Move/CosmWasm) from experimental to beta.
- Expand the RAG knowledge base and per-detector calibration.
- Deeper LLM-ensemble consensus and confidence calibration.

## Longer-term

The v6.0 platform-enablement work — CI-native finding baseline & suppression, SARIF
inline PR annotations, editor-agnostic code-action + LSP diagnostics contracts, unified
formal-verification report (Scribble/Kontrol), versioned plugin API + conformance suite +
reference plugins, and a webhook/Slack notifier — **shipped in 6.0.0** (see Completed).
Beyond the medium-term items above:

- Deepen formal verification (more provers; counterexample→PoC linkage).
- Grow the community plugin ecosystem on the versioned plugin API + conformance suite.
- Editor and SaaS product surfaces consume these stable core contracts; those UIs are
  built separately from this open-source core.

---

## Completed milestones (summary)

Full detail in [`CHANGELOG.md`](../CHANGELOG.md). Historical version-specific plans are
archived under [`docs/archive/`](archive/).

- **6.0.0** — CI-native adoption (finding baseline & suppression, fail-only-on-new), SARIF
  inline PR annotations, editor-agnostic code-action output + `miesc lsp` diagnostics server,
  unified formal-verification report (Scribble/Kontrol), versioned plugin API + conformance
  suite + reference plugins, webhook/Slack notifier. 81% coverage, 75% mutation, DPGA 9/9
  (self-assessed, application under review).
- **5.4.x** — remediation pipeline (Paper 2), research evaluation framework, multi-chain
  analyzers (Cardano/Algorand/Stellar), PyPI + multi-arch Docker.
- **5.1–5.3.x** — RAG (59→ patterns) with caching, CLI refactor, plugin system,
  multi-chain alpha→beta.
- **4.x (2025)** — 9 defense layers, MCP support, ML-based false-positive reduction.

---

## How to influence the roadmap

Open a [GitHub Discussion](https://github.com/fboiero/MIESC/discussions) or a
[feature request](https://github.com/fboiero/MIESC/issues/new?template=feature_request.yml).
See [`GOVERNANCE.md`](../.github/GOVERNANCE.md) for the decision process.
