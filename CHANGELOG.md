# Changelog

All notable changes to MIESC will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.1.8] - 2026-04-13

### Fixed — Critical regression in v5.1.7

- **`pip install miesc` produced a broken CLI.** The 5.1.7 install missed
  `rich` (which was in the `[cli]` optional extra), so any command that
  printed via `console.print(...)` crashed with
  `AttributeError: 'NoneType' object has no attribute 'print'`. Affected
  commands include `analyze`, `report`, `audit`, `verify`, and several
  others — totalling **137 console.print sites across miesc/cli/commands/**.

  Fix has two parts:
  1. **`rich>=13.0.0` is now a hard dependency** in `pyproject.toml`
     (moved out of the `[cli]` optional extra).
  2. **Defensive `_PlainConsole` fallback** in `miesc/cli/utils.py`:
     even if `rich` is missing for any reason, `console.print(...)` calls
     fall back to plain `print()` with markup stripped.

  Discovered during the v5.1.7 post-release smoke test (fresh
  `pip install miesc==5.1.7` in a clean venv → ran the README's Quick
  Start commands → `miesc analyze` crashed). v5.1.7 is left on PyPI for
  reproducibility but **users should upgrade to 5.1.8 immediately**.

## [5.1.7] - 2026-04-13

### Added — v5.1.7 Gates (closing the v5.1.6 benchmark report's three open items)

- **Gate 2: Taxonomy normalization** (`src/core/finding_taxonomy.py`).
  New `CanonicalCategory` enum (16 categories) + 70+ direct mappings
  from tool-specific detector names (Slither's `arbitrary-send-eth`,
  Aderyn's `unprotected-upgrade`, Mythril's `integer-overflow`, etc.)
  to canonical categories. DeepAuditAgent's Phase-3 branches now route
  via canonical category instead of substring matching, so follow-up
  analysis fires on real-world tool output. Rekt benchmark:
  `defi_confirmed` 0 → 19.

- **Gate 1: Victim-side corpus + balanced FP dataset**.
  Pulled the missing five SmartBugs-curated categories
  (`access_control`, `bad_randomness`, `denial_of_service`, `reentrancy`,
  `unchecked_low_level_calls`), bringing the in-repo corpus to the full
  143 contracts. Reworked `scripts/bootstrap_fp_dataset.py` to use the
  canonical taxonomy. Result: FP dataset grew 122 → 934 samples
  (3 → 67 TPs), `AuditorTrainedFPClassifier` now produces non-degenerate
  metrics.

- **Gate 3: LLM-path benchmark with multi-LLM consensus**
  (`benchmarks/deep_audit_rekt_llm.py`). Forces two distinct Ollama
  models for the `code_analysis` vs `verification` use cases so the
  consensus mechanism actually fires. Phase-3 consensus gate widened
  from `severity == "critical"` to `("critical", "high")`. Full run on
  11 Rekt exploits: **80 HIGH+CRITICAL findings → 4 needs_manual_review**
  (5% triage queue density, 26 agree_rejected, 12 single_opinion).
  BonqDAO oracle exploit produced 4/4 disagreements — exactly the case
  multi-LLM consensus is designed to surface for human review.

### Added — Test infrastructure (+321 tests vs. v5.1.6)

- **`tests/test_security_regressions.py`** (22 tests):
  command injection resistance, path traversal, prompt injection
  sanitization, pickle safety, ReDoS resistance, LLM output validation,
  secret redaction.
- **`tests/test_scalability.py`** (12 tests):
  large-contract scanning bounds, SpecRunner timeout enforcement,
  RAG O(1) lookup, taxonomy throughput, concurrent agent safety.
- **`tests/test_functionality_regressions.py`** (12 tests):
  FP classifier persistence, multi-chain dispatcher, CanonicalCategory
  contract, phase ordering, VulnerabilityExample fields, specs↔verify
  shape.
- **`tests/test_deep_audit_regressions.py`** (16 tests):
  one regression per bug fixed (DeFi API, Phase-3 report block, consensus
  gate, canonical routing, _start_time timeout).
- **`tests/test_bootstrap_fp.py`** (22 tests): FP labeling heuristic.
- **`tests/test_verify_command.py`** (11 tests): CLI contract.
- **`tests/test_load_adapters.py`** (8 tests): shim regression.
- **`tests/test_llm_location_coercion.py`** (18 tests): location field
  coercion regression.
- **`tests/test_finding_taxonomy.py`** (32 tests): taxonomy module.
- **`tests/test_adapter_contracts.py`** (162 parametrized tests):
  contract-level checks across the full ADAPTER_MAP — import clean,
  is_available never raises, analyze on missing file returns error.

### Fixed — Real bugs surfaced by the new test infrastructure

- **LLM output validator rejected non-dict locations** (`src/security/
  llm_output_validator.py`). SmartLLM was returning 0 findings on
  every Rekt contract because Pydantic strictly required
  `Optional[CodeLocation]` and the LLMs return `"function:line"`,
  bare integers, plain function names, etc. Added
  `@field_validator("location", mode="before")` that coerces common
  shapes into a `CodeLocation` dict.

- **`load_adapters` shim missing** (`miesc/cli/utils.py`). DeepAuditAgent
  imported it on every `analyze()` call, the import failed, the warning
  spammed logs, AND Phase-3 dynamic tool triggering silently degraded.
  Added a 48-LOC shim that walks `ADAPTER_MAP`, imports each module,
  instantiates the class, and caches the result. 50 adapters load
  successfully in our local environment.

- **Slither / Aderyn / Mythril stale-cache bug**
  (`src/adapters/{slither,aderyn,mythril}_adapter.py`). When given a
  nonexistent contract path, these adapters' subprocess calls failed —
  but the post-processing then read `/tmp/{tool}_output.json`, a stale
  file from a previous successful run on a DIFFERENT contract. Result:
  findings for the wrong contract were returned. Discovered by
  `tests/test_adapter_contracts.py` and fixed with explicit existence
  checks at the top of each `analyze()`.

- **`SecureFormatter` env-var redaction gap**
  (`src/security/secure_logging.py`). Only matched 48-character
  `sk-` keys and `api_key=`-style assignments. Missed the
  `OPENAI_API_KEY=sk-...` env-var pattern (most common shape in real
  logs). Added redaction for `_KEY=`, `_TOKEN=`, `_SECRET=` env-var
  suffixes and shorter `sk-` keys.

- **Peculiar adapter fallback warning spam**
  (`src/adapters/peculiar_adapter.py`). Logged `WARNING: No GNN model
  found...` on every `is_available()` check (called by every audit).
  Now logged once per process at info level.

### Improved — Code quality

- Lint cleanup: 42 → 12 ruff issues (71% reduction). Remaining 12
  are stylistic-only (`B905` zip-without-strict, `E402` intentional
  sys.path manipulation, `I001` import order in conditional block).
- Docker workflow now triggers on `v*.*.*` tag pushes and emits
  semver Docker tags (`{{version}}`, `{{major}}.{{minor}}`) — future
  releases auto-publish to GHCR.

### Documentation

- `docs/PRE_RELEASE_AUDIT_v5.1.7.md` — comprehensive audit covering
  code quality, security, OSS compliance, and project alignment.
  Includes prioritized action plan and bug-fix summary.
- `benchmarks/results/v5.1.7_gates_report.md` — full per-contract
  breakdown of the LLM consensus run on the Rekt corpus.
- `paper/miesc-paper.tex` updated to reflect v5.1.6+v5.1.7 capabilities
  (Cairo 1.1.0 with 13 vuln types, multi-LLM consensus mechanism,
  formal-verification bridge, attack_steps + detection_heuristic in
  the RAG knowledge base).

### Tests

5,306 passed, 5 skipped, 0 regressions across the ~25-commit
pre-release sweep (was 4,985 in v5.1.6, +321 tests).

## [5.1.6] - 2026-04-12

### Added — Bloque 3 (DeepAuditAgent deep investigation)

- **Finding-driven tool triggering** now actually invokes the follow-up analyzers
  instead of only setting labels:
  - Oracle / price findings → `_targeted_defi_scan()` runs `DeFiPatternDetector`
    scoped to the vulnerable function and attaches concrete pattern matches.
  - Access-control findings → `_targeted_property_for_function()` generates a
    Certora CVL rule targeting the function (pipes directly into `miesc verify`).
- **Multi-LLM consensus** on CRITICAL findings (replaces the single second-opinion
  path). Queries the primary code-analysis model AND the verification-use-case
  model; reconciles into `agree_confirmed` / `agree_rejected` / `disagreement`
  / `single_opinion` and applies bounded confidence adjustments (+0.20 on
  agreement, -0.30 on joint rejection, -0.10 + `needs_manual_review=True` on
  disagreement). Legacy `_get_llm_second_opinion()` is preserved as a shim.
- Phase 3 result exposes new aggregate fields: `needs_manual_review_count`,
  `properties_generated`, `defi_confirmed_count`.

### Added — Bloque 4 (RAG knowledge base depth)

- `VulnerabilityExample` dataclass extended with `attack_steps: List[str]` and
  `detection_heuristic: Optional[str]`.
- Enriched the 6 most common SWC patterns (SWC-107, -105, -106, -104, -115, -101)
  and the two most impactful 2023 exploit case studies (Euler, Curve/Vyper) with
  concrete step-by-step attack procedures and grep-level detection heuristics.
- `VulnerabilityRAG.enhance_finding()` now surfaces `attack_steps` and
  `detection_heuristic` in the LLM context block when the match provides them.

### Fixes — Post-v5.1.5 polish

- **Halmos verification fixed end-to-end**: CLI now walks up to `foundry.toml`
  before invoking halmos. `SpecRunner.run_halmos()` returns `status="no_tests"`
  when halmos finds no symbolic tests (previously misreported as `failed`).
  Parser now strips ANSI color codes from counterexamples.
- **GPTScan RAG placeholder bug**: `%RAG_CONTEXT%` stayed literal in the final
  prompt because the RAG injection replaced a different string. Renamed to
  `%RAG_CONTEXT_PLACEHOLDER%` with an explicit single-site replacement.
- Added few-shot real-exploit references (Cream/Euler/BNB in GPTScan,
  Curve/Euler/Wormhole in SmartLLM, Parity/Nomad/Audius in LLMSmartAudit).

### Tests

- `tests/test_deep_audit_agent.py`: +13 tests across 4 new classes
  (TestTargetedDefiScan, TestTargetedPropertyGeneration, TestLLMConsensus,
  TestPhase3FindingDrivenIntegration).
- `tests/test_vulnerability_rag.py`: +16 tests covering the new dataclass
  fields, attack_steps / detection_heuristic presence on top patterns, and
  real_exploit coverage across all 60 registry entries.
- `tests/test_gptscan_prompt.py` (new): 6 tests on prompt integrity + RAG
  placeholder behavior.
- `tests/test_spec_runner.py`: +2 tests (ANSI stripping, `no_tests` status).
- Full suite: 4985 passed, 5 skipped, 0 regressions.

## [5.1.5] - 2026-04-12

### Added

- **Auditor-trained False Positive classifier**
  (`src/ml/fp_ml_classifier.py`, `AuditorTrainedFPClassifier`)
  - scikit-learn `GradientBoostingClassifier` trained on JSONL-labeled
    findings — lets teams improve precision over time with their own
    validated data.
  - Graceful heuristic fallback when sklearn isn't installed or the
    model isn't trained yet.
  - Features: severity, tool one-hot, vuln-type hash, confidence, code
    context length, known-library detection, Solidity 0.8+ detection.
  - `create_sample_dataset()` produces a 20-row synthetic dataset for
    quick demos / tests.

- **Formal verification RUNNER**
  (`src/formal/spec_runner.py`, `SpecRunner`)
  - Executes the specs generated by `miesc specs` against real provers:
    Certora Prover (`certoraRun`), Halmos, and SMTChecker (`solc`).
  - Normalizes outputs into `VerificationResult` (pass/fail/timeout/error +
    counterexamples + elapsed seconds).
  - `run_all_available()` convenience runner that skips missing tools.

- **New CLI command: `miesc verify`**
  - `miesc verify contract.sol --tool smtchecker`
  - `miesc verify contract.sol --spec rules.spec --tool certora`
  - Closes the loop: **finding → spec → actually run the prover**.

- **Expanded Cairo/Starknet patterns** (13 vuln types, up from 8)
  New patterns informed by real 2024-2026 exploits:
  - `PRAGMA_ORACLE_STALE` — zkLend (Feb 2025, $9.6M)
  - `UNCHECKED_U256` — Cairo 1.0 u256 unchecked arithmetic
  - `UPGRADE_NO_INIT_GUARD` — Braavos account reinitialization (2023)
  - `UNCHECKED_SYSCALL_RESULT` — dropped `SyscallResult` from
    `call_contract_syscall` / `library_call_syscall`
  - `SIGNATURE_REPLAY` — account abstraction without nonce/chain_id binding

- **Streamlit Cloud deployment guide**
  (`docs/guides/STREAMLIT_CLOUD_DEPLOYMENT.md`)
  - Step-by-step `share.streamlit.io` deploy, secrets setup, troubleshooting.
  - `webapp/app.py` version now reads dynamically from `miesc.__version__`
    (no more manual bumps on the dashboard).

### Changed

- `CairoAnalyzer.version` bumped to `1.1.0` (13 vuln types).
- `src/formal/__init__.py` now exports `SpecRunner`, `VerificationResult`,
  `run_all_available` alongside the existing spec-generation API.

### Tests

40+ new tests:
- `tests/test_fp_ml_classifier.py` — 23 tests for feature extraction,
  heuristic fallback, and sklearn training/persistence.
- `tests/test_spec_runner.py` — 14 tests for prover availability, output
  parsers, graceful degradation, and a real-solc SMTChecker integration test.
- `tests/test_cairo_analyzer.py` — 6 new tests for the 2024-2026 exploit
  patterns (zkLend / Braavos / syscall / replay).

## [5.1.4] - 2026-04-12

### Added
- **Multi-chain support via `miesc analyze` command**
  - Auto-detects chain from file extension
  - Supports: Ethereum/EVM (.sol, .vy), Starknet (.cairo), Move (.move), Solana (.rs)
- **New Cairo/Starknet analyzer** (`src/adapters/cairo_adapter.py`)
  - 8 vulnerability types: felt overflow, L1/L2 message validation,
    caller spoofing, storage collisions, proxy upgrade, reentrancy,
    access control, arithmetic
  - Detects issues in VulnerableVault.cairo demo contract
- Example Cairo contract: `examples/contracts/cairo/VulnerableVault.cairo`

### Usage
```bash
miesc analyze Token.sol           # Auto-detects EVM
miesc analyze Vault.cairo         # Auto-detects Starknet
miesc analyze MyModule.move       # Move (Sui/Aptos)
miesc analyze program.rs --chain solana
```

### Tests
13 new tests for Cairo analyzer. Total 4925 tests, 80.13% coverage.

## [5.1.3] - 2026-04-12

### Added
- **Formal verification spec auto-generator** (`src/formal/spec_generator.py`)
  - Generates Certora CVL rules from MIESC findings
  - Generates Scribble annotations
  - Generates SMTChecker assertions
- **New CLI command: `miesc specs`**
  - `miesc specs results.json -f cvl -o my.spec`
  - `miesc specs results.json -f scribble`
  - `miesc specs results.json -f smtchecker`
- Maps 7 vulnerability types to spec templates:
  reentrancy, access-control, overflow, underflow, unchecked-call,
  timestamp, weak-randomness

### Use case
Bridge between automated detection (MIESC) and formal verification
(Certora Prover, Scribble, solc SMTChecker) — previously a gap.

Workflow:
  1. `miesc scan contract.sol -o results.json`
  2. `miesc specs results.json -f cvl -o my.spec`
  3. `certoraRun contract.sol --verify MyContract:my.spec`

### Tests
18 new tests for spec generation. Total 4912 tests, 82.38% coverage.

## [5.1.2] - 2026-04-12

### Added
- **Tunable FP filter via `--fp-strictness` flag** (off/low/medium/high)
  - `off`: report everything (threshold=1.1)
  - `low`: permissive (0.70)
  - `medium`: balanced, default (0.60)
  - `high`: aggressive for CI (0.40)
  - EtherStore.sol: off=14, low=14, medium=11, high=9 findings
- **`--llm-enhance` flag** for opt-in AI insights (adds ~40s)
- **Head-to-head competitor comparison** (`benchmarks/competitor_comparison.py`)
  - Compares MIESC vs Slither, Aderyn, Solhint, Echidna on 5 contracts
- **Honest comparison doc** (`docs/COMPARISON.md`) with pros/cons
- **New strictness presets API** in `FalsePositiveFilter`

### Changed
- **60x speedup on scan**: 529s → 8.5s on 5-contract benchmark
  - LLM enhancement now opt-in across 11 adapters (was auto-running)
  - Parallelized QUICK_TOOLS with ThreadPoolExecutor
  - Removed Mythril from QUICK_TOOLS (too slow, opt-in via `audit full`)
- **Cross-tool dedup improved**: 40+ new aliases in `TYPE_ALIASES`
  - Slither `suicidal` + Aderyn `selfdestruct-identifier` → 1 finding
  - Slither `weak-prng` + Aderyn `weak-randomness` → 1 finding
  - Slither `controlled-delegatecall` + Aderyn `delegate-call-unchecked-address` → 1 finding
- **Quieter CLI output**: 8 init logs moved from INFO → DEBUG
- **Ollama HTTP API** instead of CLI subprocess (cleaner LLM output)
- **Slither path discovery**: added `/opt/homebrew/bin` for macOS Homebrew users

### Fixed
- Slither adapter: honor `--solc` path directly (works around bad-interpreter issue in solc-select wrapper)
- ANSI escape codes garbled `llm_insights` field in JSON output
- GPTScan model priority list (was returning `:7b` when `:32b` was available)

### Performance
- `miesc scan contract.sol`: **1.4s** (was 1:22 / 82s in v5.1.1)
- Multi-contract benchmark (5 vulnerable contracts): **7.3s** (was 529s)
- Still 2.15x more findings than Slither alone (97 vs 45), at 6x the time cost

### OSS Quality
- Root directory cleanup: **48 → 31 visible items**
- Moved governance files (`CODE_OF_CONDUCT`, `CONTRIBUTING`, etc.) to `.github/`
- Moved policy files (`PRIVACY`, `RESPONSIBLE_USE`) to `docs/policies/`
- Removed 19 `.coverage*` snapshot files from git
- Added comprehensive Troubleshooting section to README

## [5.1.1] - 2026-02-12

### Added
- **RAG Knowledge Base Expansion**: 59 vulnerability patterns (up from 39)
  - New categories: MEV (4), Bridge (3), ZK (2), NFT (2), DeFi (2)
  - Real exploits: Curve/Vyper ($70M), Euler ($197M), Wormhole ($320M)
- **RAG Performance Optimizations**:
  - O(1) document lookup via dictionary index (was O(n) linear search)
  - Query caching with 5-min TTL, 256-entry LRU cache
  - `batch_search()` for multiple queries in single ChromaDB call
  - `batch_get_context_for_findings()` groups findings by type (50-75% faster)
- **Context Window Optimization**:
  - `_truncate_code_smart()` prioritizes security-critical functions
  - `_extract_rag_query()` for semantic queries instead of raw code
  - Dynamic context allocation based on contract size
  - Prompt template reduced from ~2500 to ~500 chars
- **RAG-Enhanced False Positive Filter**:
  - Validates findings against 59-pattern knowledge base
  - Detects fix patterns present in code (nonReentrant, SafeMath, etc.)
  - Identifies severity mismatches between reported and expected
- **Documentation**:
  - `docs/guides/RAG_API.md` - Comprehensive RAG API documentation
  - `scripts/benchmark_rag.py` - Performance benchmark script

### Changed
- SmartLLM verificator now pre-fetches all RAG context at once
- FalsePositiveFilter now accepts `use_rag` parameter (default True)

---

## [5.1.0] - 2026-02-11

### Changed
- **CLI Refactoring**: main.py reduced from 6,710 to 126 lines (98.1% reduction)
- Extracted 8 command modules to `miesc/cli/commands/`:
  - `audit.py` - 7 subcommands (quick, full, layer, smart, profile, single, batch)
  - `report.py` - Report generation with 7 templates and LLM interpretation
  - `benchmark.py` - Security posture tracking over time
  - `scan.py` - Quick vulnerability scan
  - `detect.py` - Framework auto-detection (Foundry/Hardhat/Truffle/Brownie)
  - `doctor.py` - System health check
  - `export.py` - Export to SARIF/Markdown/CSV/HTML
  - `watch.py` - Real-time file watching with auto-scan
- All commands now registered via `cli.add_command()` pattern
- Removed unused imports from main.py

### Added
- `miesc/cli/commands/` package with 15 command modules
- Modular CLI architecture for easier maintenance and testing

---

## [5.0.3] - 2026-02-02

### Fixed
- Docker build: package stubs for editable install in multi-stage build
- CI/CD: override entrypoint for Docker image test
- CI/CD: disable coverage threshold in integration tests (only 2 test files)
- Removed unused `setuptools_scm` from build-requires

### Changed
- Black formatting applied to scripts, examples and webapp (13 files)
- Cleaned up 177 Finder duplicate files

---

## [5.0.2] - 2026-02-01

### Fixed
- CLI help text updated to reflect 50 tools / 9 defense layers
- REST API VERSION now imports from package (no more hardcoded value)
- 849 ruff linting errors resolved (0 remaining)
- 242 files reformatted with black
- 27 bare-except clauses replaced with specific exception types
- 31 raise-without-from-inside-except fixed with proper exception chaining

### Changed
- Docker base image optimized: Mythril/Manticore moved to Dockerfile.full only
- Docker build parallelized: aderyn + foundry builder stages run concurrently
- Docker layer reordering: code changes no longer invalidate pip cache
- BuildKit cache mounts for pip and cargo across all Docker images
- Duplicate Foundry install removed from runtime stage
- Medusa removed from builder (was always failing)
- Pre-commit hooks updated to latest versions (ruff v0.14.14, black 26.1.0, etc.)
- Pre-commit Python version updated from 3.9 to 3.12
- Test warnings reduced from 242 to 198

---

## [5.0.1] - 2026-02-01

### Fixed
- Version sync across Docker files, README, docker-compose.yml
- REST API VERSION constant updated from stale 4.3.2 to package version
- CI/CD: Linting, formatting, and security checks now block PRs (removed continue-on-error)
- Layer 5 AI adapters use centralized OLLAMA_HOST config instead of hardcoded localhost

### Added
- MCP server test suite (test_mcp_server.py, 13 tests)
- v5.0.0 adapter test suite (test_v500_adapters.py, 51 tests)
- ML model requirements documentation (docs/models/README.md)
- MCP dependency in Docker image
- Graceful degradation logging for ML adapters (peculiar, dagnn, smartbugs_ml)

### Changed
- Coverage threshold raised from 50% to 55%
- CI Python version updated from 3.11 to 3.12
- REST API ADAPTER_MAP expanded to 50 entries (was 32)

---

## [5.0.0] - 2026-01-31

### Added
- **9 Defense Layers with 35 Analysis Modules**: Expanded from 7 layers/32 tools to 9 layers/50 tools
- **17 new adapters**: fouranalyzer, oyente, pakala, scribble, solcmc, gptlens, llamaaudit, iaudit, peculiar, upgradability_checker, bridge_monitor, l2_validator, circom_analyzer, audit_consensus, exploit_synthesizer, vuln_verifier, remediation_validator
- **MCP Server**: stdio-based FastMCP server for Claude Desktop integration with 18 tools
- **Cross-Validation v3**: Bayesian scoring with intra/inter-layer confidence and Layer 9 meta-analysis
- **`miesc-mcp` entry point**: Run MCP server via `miesc-mcp` CLI command

### Changed
- Architecture expanded from 7 to 9 defense layers
- False positive filter v2.3 with FP rates for all new adapters
- Tool weights updated for 50 tools in config/miesc.yaml

---

## [4.5.3] - 2026-01-30

### Fixed
- **Batch audit PoC names**: PoC exploit templates now use the correct per-contract name instead of "Unknown" when generating reports from batch audits (`audit batch`).

---

## [4.5.2] - 2026-01-29

### Added
- **PoC exploit generation in PDF reports**: Professional/premium reports now auto-generate Foundry test templates for Critical/High findings, including exploit code, prerequisites, and expected outcomes.

### Fixed
- **ML-enhanced findings in reports**: Reports now use ML-adjusted severities instead of raw findings, ensuring deployment recommendations reflect the full ML pipeline (FP filtering, severity adjustments).

---

## [4.5.1] - 2026-01-29

### Fixed
- **Deployment recommendation override**: LLM can no longer override a stricter deployment recommendation (NO-GO) with a more permissive one (GO/CONDITIONAL). This prevents critical findings from being incorrectly marked as safe for deployment.

### Links
- **PyPI**: https://pypi.org/project/miesc/4.5.1/
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.5.1`

---

## [4.5.0] - 2026-01-29

### Added

#### Comprehensive Integration Tests
- **Full test suite**: 2700+ tests with 71% coverage
- **Integration test files**: Pipeline, reports, multichain, and benchmark integration tests
- **CLI testing**: End-to-end audit command testing with Click's CliRunner

#### Enhanced Report Generation
- **Smart audit format support**: Reports now correctly parse `tools_run`, `tools_success`, `tools_failed` arrays
- **Effort vs Impact Matrix**: Prioritization matrix with finding counts per cell (DO FIRST, Quick Win, Priority, Schedule, etc.)
- **Tool execution details**: Tools Utilized, Layer Coverage Analysis, and Appendix sections now populate correctly
- **Report documentation**: Comprehensive `docs/guides/REPORTS.md` guide

#### Optional Dependencies
- **Graceful degradation**: `openai` and `python-dotenv` are now optional imports
- **Cleaner installs**: Base installation works without LLM dependencies

### Fixed
- **PDF generation**: Fixed Jinja2 template rendering by adding to core dependencies
- **Smart audit reports**: Contract name, findings, and tool data now correctly extracted
- **Test mock**: Fixed `audit smart` test to use correct `analyze` method

### Links
- **PyPI**: https://pypi.org/project/miesc/4.5.0/
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.5.0`

---

## [4.4.0] - 2026-01-25

### Changed
- **Repository reorganization**: Restructured project layout for better maintainability
- **CI/CD improvements**: Enhanced GitHub Actions workflows

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.4.0

---

## [4.3.7] - 2025-01-20

### Added

#### Premium Audit Reports
- **Premium report template** (`-t profesional`): Trail of Bits / OpenZeppelin style professional audit reports
- **CVSS-like scoring**: Automatic vulnerability scoring with attack vectors (AV, AC, PR, UI, C/I/A)
- **Risk matrix**: Visual Impact vs Likelihood matrix with finding distribution
- **Deployment recommendation**: GO / NO-GO / CONDITIONAL with justification
- **Attack scenarios**: AI-generated step-by-step attack scenarios for critical findings
- **Code remediation**: AI-generated fix suggestions with git-style diffs
- **Remediation roadmap**: Prioritized timeline for addressing vulnerabilities

#### Docker LLM Distribution
- **Dual-model support**: docker-compose now downloads both `deepseek-coder:6.7b` and `mistral:latest`
- **Production config**: New `docker-compose.prod-llm.yml` with health checks, resource limits, and GPU support
- **Setup wizard**: Interactive `scripts/docker-setup.sh` for easy deployment
- **Health check**: New `deploy/health-check.sh` to verify Ollama and model availability

#### PDF Report Generation
- **WeasyPrint integration**: Native PDF generation with professional styling in Docker
- **Premium CSS**: Professional CSS optimized for PDF output with A4 page setup
- **CLI support**: `miesc report results.json -f pdf -o report.pdf` now works in Docker
- **Auto-fallback**: Falls back to pandoc/wkhtmltopdf if weasyprint unavailable

#### New Files
- `docs/templates/reports/profesional.md` - Premium report template
- `docs/templates/reports/profesional.css` - Professional PDF styling
- `src/reports/risk_calculator.py` - CVSS scoring and risk matrix generator
- `docker-compose.prod-llm.yml` - Production Docker config with LLM
- `scripts/docker-setup.sh` - Interactive setup wizard
- `deploy/health-check.sh` - Service health verification

### Changed
- `miesc report` now supports `--template profesional` option
- `llm_interpreter.py` enhanced with attack scenario and code remediation generation
- `config/miesc.yaml` includes profesional report configuration section

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.7
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.3.7`

---

## [4.3.5] - 2025-01-19

### Fixed
- **Slither ARM64 compatibility**: Auto-creates minimal Foundry project for standalone `.sol` files when solc-select binaries don't work on ARM64 architecture
- **crytic-compile detection**: Prevents `AssertionError` when forge is installed but no `foundry.toml` exists

### Changed
- Slither adapter now intelligently detects platform and chooses compilation method
- Added `_setup_foundry_project()` and `_cleanup_foundry_project()` for temporary Foundry configuration

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.5
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.3.5`

---

## [4.3.4] - 2025-01-15

### Added
- **PyPI plugin search**: `miesc plugins search <query>` to discover plugins on PyPI
- **Local plugins directory**: `~/.miesc/plugins/` for development and local plugins
- **Version compatibility validation**: Checks plugin compatibility with MIESC version
- **New CLI options**: `--force` and `--no-check` for `miesc plugins install`
- **Plugin path command**: `miesc plugins path [--create]` to manage local plugins directory

### Changed
- `miesc plugins list` now shows compatibility status column
- `miesc plugins info` displays version requirements and compatibility details

### Fixed
- SyntaxWarning in `detector_api.py` docstrings (escaped regex patterns)

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.4/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.4
- **Docker**: `docker pull ghcr.io/fboiero/miesc:latest`

---

## [4.3.3] - 2025-01-14

### Added

#### Plugin System
- **Full plugin management CLI**: `miesc plugins list/install/uninstall/enable/disable/create`
- **Plugin scaffolding**: `miesc plugins create my-detector` generates complete plugin project
- **PyPI integration**: Install detector plugins directly from PyPI
- **Plugin configuration**: Enable/disable plugins via `~/.miesc/plugins.yaml`

#### Custom Detectors
- **15 built-in detectors** available out of the box:
  - `flash-loan-attack` - Flash loan attack patterns
  - `reentrancy-patterns` - Reentrancy vulnerabilities
  - `access-control` - Missing access controls
  - `tx-origin` - tx.origin authentication issues
  - `unchecked-return` - Unchecked return values
  - `slippage-protection` - Missing slippage protection
  - `rug-pull-patterns` - Token rug pull patterns
  - `mev-vulnerability` - MEV extraction vulnerabilities
  - `delegatecall-danger` - Dangerous delegatecall patterns
  - `selfdestruct-usage` - Selfdestruct usage detection
  - `weak-randomness` - Weak randomness sources
  - `timestamp-dependence` - Block.timestamp reliance
  - `approval-race` - ERC20 approval race conditions
  - `unbounded-loop` - DoS via unbounded loops
  - `hardcoded-address` - Hardcoded addresses

#### Sample Plugin
- **Example plugin** in `examples/sample-plugin/` demonstrating:
  - Complete plugin structure with `pyproject.toml`
  - Custom detector implementation (`DangerousDelegatecallDetector`)
  - Test suite for the detector
  - Vulnerable test contract (`VulnerableProxy.sol`)

#### Docker ARM64 Support
- **Multi-arch Docker images**: `ghcr.io/fboiero/miesc:latest` now supports both AMD64 and ARM64
- Native support for Apple Silicon (M1/M2/M3/M4) Macs
- Fixed `latest` tag to include ARM64 manifest

### Changed
- Docker workflow builds `latest` tag only from multi-arch job
- Plugin entry points now use string category instead of enum for flexibility

### Documentation
- Added sample plugin documentation in `examples/sample-plugin/README.md`
- Updated plugin system documentation in README.md

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.3/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.3
- **Docker**: `docker pull ghcr.io/fboiero/miesc:latest`

---

## [4.3.2] - 2025-01-09

### Added

#### PyPI Publication
- **MIESC is now available on PyPI**: `pip install miesc`
- Installation options: `miesc`, `miesc[cli]`, `miesc[web]`, `miesc[full]`
- Package includes all 31 adapters and 9 defense layers

#### New CLI Commands
- **`miesc scan`** - Simplified quick vulnerability scan
  - `miesc scan contract.sol` - Quick 4-tool scan
  - `miesc scan contract.sol --ci` - CI mode (exit 1 on critical/high issues)
  - `miesc scan contract.sol -o report.json` - JSON output

#### Module Execution
- Support for `python -m miesc` execution
- Added `miesc/__main__.py` for module entry point

### Fixed
- **Optional dependency imports** - WebSocket/FastAPI type annotations no longer fail when packages not installed
- Added `from __future__ import annotations` for deferred type evaluation
- Fallback `None` assignments for optional imports (FastAPI, uvicorn, WebSocket)

### Changed
- Web frameworks (FastAPI, Flask, Streamlit, Django) are now optional dependencies
- Minimal core dependencies: click, pydantic, pyyaml, slither-analyzer
- Package structure updated to include `src.*` modules in distribution

### Documentation
- Added `QUICKSTART.md` with CLI usage and 9-layer architecture guide
- Updated README badges (PyPI, version 4.3.2)
- Updated README_ES.md with same badges

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.2/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.2

---

## [4.2.1] - 2024-12-23

### Added

#### Scientific Benchmark Validation (SmartBugs Curated)
- **Comprehensive multi-tool benchmark** against SmartBugs Curated dataset (143 contracts)
- Benchmark runner script (`benchmarks/run_benchmark.py`) for reproducible validation
- Detailed results in `benchmarks/results/` JSON format

#### Benchmark Results Summary
| Tool | Layer | Recall | F1-Score | Notes |
|------|-------|--------|----------|-------|
| Slither | 1 | 84.3% | 80.0% | +27.3% vs SmartBugs 2020 paper |
| SmartBugsDetector | 2 | 100% | - | Pattern-based, no compilation |
| Mythril | 3 | - | - | 6 findings with SWC codes |

#### Per-Category Detection Rates (Slither)
- Unchecked low-level calls: 100%
- Front running: 100%
- Arithmetic overflow: 93.3%
- Bad randomness: 87.5%
- Access control: 86.7%
- Reentrancy: 73.3%
- Time manipulation: 60.0%
- Denial of service: 50.0%

#### New Adapters
- **SmartGuard Adapter** - ML-based vulnerability prediction
- **LLMBugScanner Adapter** - GPT-4o powered vulnerability detection
- **ZK Circuit Adapter** - Zero-knowledge proof circuit validation
- **CrossChain Adapter** - Bridge and cross-chain security analysis

#### Slither Adapter Improvements
- Legacy Solidity support (0.4.x - 0.5.x) with `--compile-force-framework solc`
- Automatic solc-select integration for version management
- Improved IR generation handling for complex legacy patterns

### Changed
- Updated version to 4.2.1
- Enhanced adapter error handling for legacy contracts
- Improved benchmark reproducibility with JSON result export

### Documentation
- Added benchmark methodology documentation
- Scientific comparison with literature (SmartBugs 2020, Empirical Review 2020)
- Multi-tool strategy recommendations

---

## [4.1.0] - 2024-12-09

### Added

#### New Security Layers (post-thesis extension)
- **Layer 8: DeFi Security Analysis** - First open-source DeFi vulnerability detectors
  - Flash loan attack detection (callback validation, repayment verification)
  - Oracle manipulation detection (spot price vs TWAP)
  - Sandwich attack detection (zero slippage, missing deadlines)
  - MEV exposure analysis (liquidation front-running)
  - Price manipulation detection (reserve ratio vulnerabilities)

- **Layer 9: Dependency Security Analysis** - Supply chain security
  - OpenZeppelin CVE database integration (CVE-2022-35961, etc.)
  - Vulnerable version detection with semantic versioning
  - Dangerous pattern detection (tx.origin, selfdestruct, delegatecall, ecrecover)
  - Third-party library vulnerability scanning (Uniswap, Compound)

#### API Enhancements
- SSE (Server-Sent Events) streaming endpoint `/mcp/stream/audit`
- DeFi-specific analysis endpoint `/mcp/defi/analyze`
- Real-time layer-by-layer progress updates

#### Scientific Validation
- **SmartBugs benchmark integration** (143 contracts, 207 vulnerabilities)
  - 50.22% recall (outperforms individual tools)
  - 87.5% recall on reentrancy vulnerabilities
  - 89.3% recall on unchecked low-level calls
- Automated evaluation script with metrics calculation
- Scientific report generation for thesis

#### Performance Benchmarks
- Scalability benchmarks demonstrating 346 contracts/minute
- 3.53x parallel speedup with 4 workers
- Memory-efficient analysis (< 5 MB per contract)

### Changed
- Updated MCP REST API to version 4.1.0
- Improved Solidity version auto-detection for legacy contracts (0.4.x - 0.8.x)
- Enhanced error handling in tool adapters
- Architecture extended from 7 to 9 layers (Layers 8-9 are post-thesis work)

### Fixed
- Foundry.toml interference with Slither analysis on SmartBugs dataset
- Solc version selection for legacy contracts

---

## [Unreleased]

### Added
- **DPGA Application Submitted** (December 5, 2025)
  - Application ID: GID0092948
  - Status: Under Review
  - Contact: Bolaji Ayodeji (DPG Evangelist)
  - Expected review period: 4-8 weeks
- Complete DPG compliance documentation package
- DPGA Application Responses CSV for reference

## [4.0.0] - 2025-01-14

### Added
- **PropertyGPT** (Layer 4 - Formal Verification): Automated CVL property generation
  - 80% recall on ground-truth Certora properties
  - Increases formal verification adoption from 5% to 40% (+700%)
  - Based on NDSS 2025 paper (arXiv:2405.02580)
- **DA-GNN** (Layer 6 - ML Detection): Graph Neural Network-based vulnerability detection
  - 95.7% accuracy with 4.3% false positive rate
  - Control-flow + data-flow graph representation
  - Based on Computer Networks (ScienceDirect, Feb 2024)
- **SmartLLM RAG + Verificator** (Layer 5 - AI Analysis): Enhanced AI-powered analysis
  - Retrieval-Augmented Generation with ERC-20/721/1155 knowledge base
  - Multi-stage pipeline: Generator → Verificator → Consensus
  - Precision improved from 75% to 88% (+17%), FP rate reduced by 52%
  - Based on arXiv:2502.13167 (Feb 2025)
- **DogeFuzz** (Layer 2 - Dynamic Testing): Coverage-guided fuzzer with hybrid execution
  - AFL-style power scheduling algorithm
  - 85% code coverage, 3x faster than Echidna
  - Parallel execution with 4 workers
  - Based on arXiv:2409.01788 (Sep 2024)
- Certora adapter (formal verification integration)
- Halmos adapter (symbolic testing for Foundry)
- DAG-NN adapter (graph neural network detection)

### Changed
- Increased tool count from 22 to 25 adapters (+13.6%)
- Precision: 89.47% → 94.5% (+5.03pp)
- Recall: 86.2% → 92.8% (+6.6pp)
- False Positive Rate: 10.53% → 5.5% (-48%)
- Detection Coverage: 85% → 96% (+11pp)
- Restructured repository to UNIX/OSS conventions
- Updated README with comprehensive "What's New in v4.0" section
- Improved scientific rigor in documentation

### Research Papers Integrated
- NDSS Symposium 2025: PropertyGPT for automated property generation
- Computer Networks 2024: DA-GNN for graph-based vulnerability detection
- arXiv 2025: SmartLLM with RAG and Verificator enhancements
- arXiv 2024: DogeFuzz coverage-guided fuzzing

## [3.5.0] - 2025-01-13

### Added
- OpenLLaMA local LLM integration for AI-assisted analysis
- Aderyn adapter (Rust-based static analyzer)
- Medusa adapter (coverage-guided fuzzer)
- AI enhancement for Layers 3-4 (symbolic execution, formal verification)
- SmartLLM, GPTScan, LLM-SmartAudit adapters
- SMTChecker adapter (built-in Solidity verification)
- Wake adapter (Python development framework)
- 117 unit and integration tests
- CI/CD workflow with automated tool installation
- Complete adapter documentation

### Changed
- Increased tool count from 15 to 17
- Improved test coverage to 87.5%
- Enhanced DPGA compliance (100% maintained)

## [3.4.0] - 2025-11-08

### Added
- Aderyn and Medusa adapters
- 17 security tool integrations

### Changed
- Test suite expanded to 117 tests

## [2.2.0] - 2024-10-XX

### Added
- 15 security tool integrations
- AI-assisted triage (GPT-4, Llama)
- PolicyAgent v2.2 (12 compliance standards)
- Model Context Protocol (MCP) architecture
- 30 regression tests
- Comprehensive documentation

## [2.1.0] - 2024-09-XX

### Added
- Multi-agent architecture
- Initial MCP integration
- Compliance mapping framework

## [2.0.0] - 2024-08-XX

### Added
- Complete framework rewrite
- 7-layer defense architecture
- Initial tool adapters (10)

## [1.0.0] - 2024-06-XX

### Added
- Initial proof-of-concept
- Basic Slither and Mythril integration

---

[Unreleased]: https://github.com/fboiero/MIESC/compare/v4.3.4...HEAD
[4.3.4]: https://github.com/fboiero/MIESC/compare/v4.3.3...v4.3.4
[4.3.3]: https://github.com/fboiero/MIESC/compare/v4.3.2...v4.3.3
[4.3.2]: https://github.com/fboiero/MIESC/compare/v4.2.1...v4.3.2
[4.2.1]: https://github.com/fboiero/MIESC/compare/v4.1.0...v4.2.1
[4.1.0]: https://github.com/fboiero/MIESC/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/fboiero/MIESC/compare/v3.5.0...v4.0.0
[3.5.0]: https://github.com/fboiero/MIESC/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/fboiero/MIESC/compare/v2.2.0...v3.4.0
[2.2.0]: https://github.com/fboiero/MIESC/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/fboiero/MIESC/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/fboiero/MIESC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/fboiero/MIESC/releases/tag/v1.0.0
