# Changelog

All notable changes to MIESC will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.5.0] - 2026-01-26

### Added

#### Multi-Chain Support (Alpha/Experimental)

MIESC now supports security analysis across **7 blockchain platforms**:

| Chain | Status | Languages | Key Features |
|-------|--------|-----------|--------------|
| **EVM** | Production | Solidity, Vyper | 31 tools, 9 layers |
| **Solana** | Alpha | Rust/Anchor | Pattern detection |
| **NEAR** | Alpha | Rust | Pattern detection |
| **Move** (Sui/Aptos) | Alpha | Move | Pattern detection |
| **Stellar/Soroban** | Alpha | Rust | Pattern detection |
| **Algorand** | Alpha | TEAL, PyTeal | Pattern detection |
| **Cardano** | Alpha | Plutus, Aiken | Pattern detection |

#### New Chain Adapters

- **SolanaAnalyzer** (`src/adapters/solana_adapter.py`)
  - Anchor framework support
  - Detects: missing signer checks, PDA issues, account data vulnerabilities
  - 450+ lines of analysis logic

- **NEARAnalyzer** (`src/adapters/near_adapter.py`)
  - near-sdk support
  - Detects: callback reentrancy, promise result handling, storage issues
  - 400+ lines of analysis logic

- **MoveAnalyzer** (`src/adapters/move_adapter.py`)
  - Sui and Aptos support
  - Detects: object ownership, capability leaks, flash loan vulnerabilities
  - 550+ lines of analysis logic

- **StellarAnalyzer** (`src/adapters/stellar_adapter.py`)
  - Soroban SDK support
  - Detects: authorization issues, TTL problems, cross-contract risks
  - 680+ lines of analysis logic

- **AlgorandAnalyzer** (`src/adapters/algorand_adapter.py`)
  - TEAL and PyTeal support
  - Detects: rekey attacks, inner txn safety, group validation
  - 720+ lines of analysis logic

- **CardanoAnalyzer** (`src/adapters/cardano_adapter.py`)
  - Plutus (Haskell) and Aiken support
  - Detects: double satisfaction, datum hijacking, eUTXO vulnerabilities
  - 950+ lines of analysis logic

#### Chain Abstraction Layer

- **ChainType enum** expanded: SOLANA, NEAR, SUI, APTOS, STELLAR, ALGORAND, CARDANO
- **ContractLanguage enum** expanded: ANCHOR, MOVE, TEAL, PYTEAL, PLUTUS, AIKEN
- **AbstractChainAnalyzer** base class for consistent multi-chain API
- **VulnerabilityMapping** for cross-chain finding normalization

#### Enhanced Detection (v4.4.0 Patterns)

- **DeFi Patterns**: 20 vulnerability categories (up from 12)
  - Read-only reentrancy
  - ERC4626 inflation attacks
  - Arbitrary external calls
  - Precision loss / rounding errors
  - Cross-function reentrancy
  - Signature replay attacks
  - First depositor attacks
  - Storage collision (proxy)

- **RAG Knowledge Base**: 32+ SWC entries with code examples
  - SWC-100 through SWC-136 covered
  - Real-world exploit references (2023-2025)
  - Attack scenarios and remediations

#### Documentation

- **Multi-Chain Documentation** (`docs/MULTICHAIN.md`)
  - Support levels (Production vs Alpha)
  - Per-chain vulnerability categories
  - Usage examples for each chain
  - Limitations and recommendations

### Changed

- Updated README with multi-chain badge and support table
- Updated version badge to 4.5.0
- Added chain support status to Features section

### Testing

- **117 multi-chain tests** (all passing)
  - TestSolanaAnalyzer: 12 tests
  - TestNEARAnalyzer: 10 tests
  - TestMoveAnalyzer: 12 tests
  - TestStellarAnalyzer: 11 tests
  - TestAlgorandAnalyzer: 11 tests
  - TestCardanoAnalyzer: 17 tests
  - Cross-chain integration: 8 tests

### Important Notes

> **Non-EVM chain support is experimental/alpha.** These analyzers use pattern-based detection without the full 9-layer analysis available for EVM. Production audits should use EVM analysis for comprehensive coverage.

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

[Unreleased]: https://github.com/fboiero/MIESC/compare/v4.2.1...HEAD
[4.2.1]: https://github.com/fboiero/MIESC/compare/v4.1.0...v4.2.1
[4.1.0]: https://github.com/fboiero/MIESC/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/fboiero/MIESC/compare/v3.5.0...v4.0.0
[3.5.0]: https://github.com/fboiero/MIESC/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/fboiero/MIESC/compare/v2.2.0...v3.4.0
[2.2.0]: https://github.com/fboiero/MIESC/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/fboiero/MIESC/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/fboiero/MIESC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/fboiero/MIESC/releases/tag/v1.0.0
