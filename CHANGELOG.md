# Changelog

All notable changes to MIESC will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Restructured repository to UNIX/OSS conventions
- Updated README to distinguish implemented features from pending validation
- Improved scientific rigor in documentation

## [3.5.0] - 2025-11-13

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

[Unreleased]: https://github.com/fboiero/MIESC/compare/v3.5.0...HEAD
[3.5.0]: https://github.com/fboiero/MIESC/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/fboiero/MIESC/compare/v2.2.0...v3.4.0
[2.2.0]: https://github.com/fboiero/MIESC/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/fboiero/MIESC/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/fboiero/MIESC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/fboiero/MIESC/releases/tag/v1.0.0
