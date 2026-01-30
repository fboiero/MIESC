# Changelog

All notable changes to MIESC will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
