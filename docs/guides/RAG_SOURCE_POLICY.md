# RAG Source Policy

This policy defines how MIESC selects, ranks, and uses sources in the
vulnerability RAG layer. Its purpose is to keep RAG context useful for security
analysis while preserving reproducibility and avoiding unsupported research
claims.

## Source Tiers

MIESC ranks RAG documents by source tier. Higher tiers should dominate final
technical conclusions; lower tiers may add context but should not override
standards, official documentation, or reproducible artifacts.

| Tier | Weight | Role | Examples |
|------|:------:|------|----------|
| `standard` | 1.00 | Normative or quasi-normative security guidance | EEA EthTrust, OWASP SCSVS, CWE |
| `official_docs` | 0.95 | Authoritative implementation guidance | Solidity docs, OpenZeppelin docs, Chainlink docs, Uniswap docs |
| `benchmark` | 0.90 | Reproducible evaluation evidence | SmartBugs, EVMBench, local MIESC paper artifacts |
| `incident` | 0.85 | Real-world exploit context and impact | DeFiHackLabs, Immunefi reports, SlowMist incident archive |
| `audit_guide` | 0.80 | Practitioner audit guidance | Reputable audit checklists and public security guides |
| `tool_docs` | 0.78 | Tool-specific interpretation support | Slither, Aderyn, Foundry, Echidna, Halmos documentation |
| `curated` | 0.70 | Locally curated vulnerability examples | MIESC-maintained vulnerability patterns |
| `legacy_taxonomy` | 0.65 | Historical taxonomy mapping | SWC Registry and older mappings |

The current implementation exposes these weights in
`miesc.llm.embedding_rag.SOURCE_TIER_WEIGHTS`.

## Selection Criteria

A source may be added to the RAG corpus when it satisfies at least one of these
criteria:

- It defines a security requirement, weakness class, or best practice used by
  auditors.
- It documents a library, compiler, protocol, or tool that MIESC analyzes or
  recommends.
- It is part of a reproducible benchmark or local experiment artifact.
- It describes a real exploit with enough technical detail to help assess
  exploitability, impact, or attack path.
- It supports remediation by showing safe implementation patterns or known
  unsafe alternatives.

Sources should include stable references whenever available. For local
artifacts, use repository paths such as `benchmarks/results/...` or
`paper/PAPER*_REPRODUCIBILITY.md`.

## Use Rules

RAG context may support:

- finding enrichment;
- severity calibration;
- exploit scenario explanation;
- remediation recommendation;
- false-positive review;
- source-backed report text.

RAG context must not create new benchmark claims by itself. Quantitative claims
for the current papers must come from:

- `paper/PAPER1_REPRODUCIBILITY.md`;
- `paper/PAPER2_REPRODUCIBILITY.md`;
- `benchmarks/results/paper1_claims_matrix.json`;
- `benchmarks/results/paper2_claims_matrix.json`.

Incident sources may explain why a vulnerability matters, but they do not prove
that MIESC detects or remediates a class unless backed by benchmark or local run
artifacts.

Legacy taxonomies such as SWC may be used for compatibility and mapping, but
newer standards, official docs, and current benchmark artifacts take precedence
when terminology or severity differs.

## OpenZeppelin Sources

OpenZeppelin documentation is included as `official_docs` because MIESC often
recommends OpenZeppelin patterns for access control, reentrancy protection,
proxy upgradeability, governance, token standards, and safe transfer helpers.

When RAG suggests OpenZeppelin-based remediation, it should distinguish between:

- importing a library in a project environment where dependencies are available;
- using an inline standalone patch for benchmark reproducibility;
- recommending a manual migration when the safe fix changes architecture.

This distinction matters for Paper 2 because standalone compilation intentionally
measures whether patched artifacts compile without restoring external project
dependencies.

## Review Checklist

Before adding or changing RAG sources, verify:

- The source tier is explicit.
- References are stable enough for review.
- The document has a clear security purpose.
- The source does not contradict current paper claims.
- Quantitative statements are tied to reproducible artifacts.
- The retrieval text explains how the source should and should not be used.

