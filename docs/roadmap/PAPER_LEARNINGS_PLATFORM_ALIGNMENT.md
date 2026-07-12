# Paper Learnings and Platform Alignment

This note maps what the two current MIESC papers established experimentally to
what the product, CLI, API, MCP surface, and reproducibility layer should expose
as a consistent platform contract.

## Scope

Paper 1 establishes the detection and evidence baseline:

- SmartBugs-curated full-corpus reproducible profile: 143 contracts, 95.8%
  recall, 22.2% precision, 36.0% F1.
- Paper 1 also reports a local Ollama follow-up over residual SmartBugs misses
  that raises the editorial reading to 97.9% recall; platform metrics should
  continue to treat 95.8% as the primary machine-readable corpus artifact until
  a dedicated lift artifact is published.
- Real DeFi exploits: 11 incidents, 81.8% recall.
- EVMBench local high-severity extraction: 111/120 findings detected by the
  reproducible four-provider ensemble.
- The 9-layer run is integration evidence, not a full-corpus SmartBugs claim.

Paper 2 starts after detection and measures remediation artifacts:

- 141/143 fixes applied.
- 90/141 patched contracts compile standalone.
- 93/141 eliminate the original finding by re-scan.
- 91/141 pass bounded no-regression.
- Compile failures are not noise; they are a measured failure mode dominated by
  undefined symbols in low-level-call remediation.

## Current Platform State

The CLI already exposes the right primitives:

- `miesc scan` for quick detection plus intelligence enrichment.
- `miesc fix` for patch artifact generation from findings with `fix_code`.
- `miesc verify` for SMTChecker, Halmos, and Certora execution.
- `miesc report` for human-facing audit artifacts.
- `miesc audit deep` for agentic multi-step analysis with optional RAG and LLM.

The API and MCP surfaces expose detection, correlation, false-positive
filtering, reporting, compliance mapping, and remediation enrichment. They do
not yet expose the same end-to-end remediation evidence contract that Paper 2
uses in benchmarks.

The RAG layer has moved in the right direction: it includes source tiers,
official documentation, standards, benchmark artifacts, incident context, and
OpenZeppelin-specific documents. The selection criterion should remain explicit:
standards and official docs rank highest, benchmark artifacts ground measurable
claims, incidents explain risk and exploitability, and legacy taxonomies are
supporting context only.

## Product Contract to Standardize

Every platform surface should converge on the same artifact states:

1. `detected`: finding produced by one or more tools.
2. `enriched`: finding normalized, deduplicated, severity-calibrated, and
   optionally RAG-backed.
3. `patch_candidate`: concrete remediation artifact generated or attached.
4. `patch_applied`: patched Solidity file emitted.
5. `compile_checked`: patched file compiled with selected solc.
6. `rescan_checked`: original finding eliminated or still present.
7. `regression_checked`: new-finding delta measured under an explicit bound.
8. `evidence_bundle`: JSON report with tool versions, solc version, input hash,
   model metadata when LLMs are used, and timestamps.

This contract should be shared by CLI, API, MCP, and benchmark scripts.

## Main Gaps

The old `miesc.core.orchestrator` still documents a 7-layer, 25-tool architecture
and hardcodes version `4.0.0`. It should either be deprecated from the public
surface or updated to the current 9-layer model. The current public narrative is
9 layers, 35 modules, and current package version from `miesc.__version__`.

`miesc fix` applies the patch artifact, but it does not yet produce the full
Paper 2 evidence bundle in normal user workflows. The benchmark script has that
logic; product users should not need to run a benchmark to get compile,
re-scan, and no-regression evidence.

`miesc verify` runs formal tools, but it is separate from fix application and
does not yet consume Paper 2-style remediation metadata. It should become one
stage in a larger `fix --verify` or `remediate` workflow.

The API currently exposes detection and analysis endpoints, but not an explicit
`/remediate` or `/validate-remediation` endpoint with the Paper 2 state model.

The MCP server exposes `miesc_remediate`, but this enriches findings with
recommendations rather than generating and validating patched Solidity
artifacts.

## Recommended Implementation Plan

Priority 1: create one internal remediation pipeline module.

The module should own the Paper 2 state machine and be used by CLI, API, MCP,
and benchmark scripts. It should accept an original contract plus findings and
return patched source, compile result, re-scan result, no-regression result, and
an evidence bundle.

Implementation status: initial module added in `src.security.remediation_pipeline`.
It provides the shared evidence dataclasses, Paper 2 compile-failure taxonomy,
standalone compile checks, re-scan/no-regression fields, and a reusable
`remediate_contract` entry point.

Priority 2: add a user-facing command.

Recommended CLI:

```bash
miesc remediate results.json -c Contract.sol -o out/ --compile --rescan --no-regression-bound 2
```

This should not replace `miesc fix`; `fix` can remain the lightweight patch
writer. `remediate` should be the full evidence-producing pipeline.

Implementation status: initial CLI command added as `miesc remediate`. It keeps
`miesc fix` intact and writes both the patched Solidity artifact and evidence
JSON. Optional `--compile` and `--rescan` flags activate the heavier checks.

Priority 3: expose the same flow in API and MCP.

API endpoints:

- `POST /api/v1/remediate/`
- `POST /api/v1/validate-remediation/`

MCP tools:

- `miesc_apply_fix`
- `miesc_validate_remediation`
- `miesc_remediation_evidence_bundle`

Implementation status: REST endpoints added as `POST /api/v1/remediate/` and
`POST /api/v1/validate-remediation/`. MCP tools added as `miesc_apply_fix` and
`miesc_validate_remediation`; the existing `miesc_remediate` remains available
for recommendation enrichment.

Priority 4: align docs and legacy modules.

- Update or deprecate `miesc.core.orchestrator`.
- Keep README claims canonical and avoid historical benchmark drift.
- Link Paper 1 and Paper 2 claims matrices from developer docs.
- Add a “historical docs may contain old metrics” note in docs index or release
  notes.

Priority 5: make RAG source governance visible.

Status: implemented as `docs/guides/RAG_SOURCE_POLICY.md`.

The source-policy document explains tiering:

- `standard`: EEA EthTrust, OWASP SCSVS, CWE.
- `official_docs`: Solidity, OpenZeppelin, Chainlink, Uniswap docs.
- `benchmark`: SmartBugs, EVMBench, local reproducibility artifacts.
- `incident`: reproducible exploit writeups, DeFiHackLabs, Immunefi, SlowMist.
- `audit_guide` and `tool_docs`: practitioner and tool-specific support.
- `legacy_taxonomy`: SWC and older mappings as historical context.

## Acceptance Criteria

The platform is aligned with the papers when these checks pass:

- A user can run detection, remediation, compile check, re-scan, and bounded
  no-regression without invoking benchmark scripts.
- The CLI, API, and MCP outputs use the same remediation evidence schema.
- Every evidence bundle includes source contract hash, patched contract hash,
  solc version, tool versions where available, model metadata where applicable,
  and no-regression threshold.
- Paper 1 detection claims and Paper 2 remediation claims are reachable from
  README and are not contradicted by current docs.
- `pytest --collect-only` works without coverage false negatives.
