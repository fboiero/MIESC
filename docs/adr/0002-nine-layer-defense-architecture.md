# ADR-0002: Nine-Layer Defense Architecture

## Status

Accepted

## Context

Smart contract security analysis can be approached with many different techniques:
- Static analysis (pattern matching, AST analysis)
- Dynamic testing (fuzzing, property testing)
- Symbolic execution (path exploration)
- Formal verification (mathematical proofs)
- AI/ML-based detection

Each technique has strengths and weaknesses. No single tool catches all vulnerabilities. We needed a systematic approach to combine multiple techniques for comprehensive coverage.

## Decision

Organize tools into **9 defense layers**, each targeting different vulnerability classes:

| Layer | Category | Tools | Focus |
|-------|----------|-------|-------|
| 1 | Static Analysis | Slither, Aderyn, Solhint | Code patterns, AST |
| 2 | Dynamic Testing | Echidna, Medusa, Foundry, DogeFuzz | Fuzzing, runtime |
| 3 | Symbolic Execution | Mythril, Manticore, Halmos | Path exploration |
| 4 | Formal Verification | Certora, SMTChecker, Wake | Proofs |
| 5 | AI Analysis | SmartLLM, GPTScan, LLMSmartAudit, GPTLens, LlamaAudit, iAudit | LLM detection |
| 6 | ML Detection | DA-GNN, SmartBugs-ML, SmartBugs-Detector, SmartGuard, Peculiar | ML models |
| 7 | Specialized Analysis | Threat Model, Gas Analyzer, MEV Detector, Clone Detector, DeFi, Advanced Detector, Upgradability Checker | Domain-specific |
| 8 | Cross-Chain & ZK Security | Cross-Chain, ZK Circuit, Bridge Monitor, L2 Validator, Circom Analyzer | Bridge & ZK circuits |
| 9 | Advanced AI Ensemble | LLMBugScanner, Audit Consensus, Exploit Synthesizer, Vuln Verifier, Remediation Validator | Multi-LLM consensus |

Layers 8–9 (Cross-Chain & ZK Security, Advanced AI Ensemble) are experimental modules on the multi-chain roadmap; the EVM core is Layers 1–7.

Analysis profiles select which layers to use:
- **quick**: Layer 1 only
- **standard**: Layers 1-3
- **thorough**: Layers 1-6
- **paranoid**: All layers

## Consequences

### Positive

- **Defense in depth**: Multiple techniques catch different bugs
- **Flexibility**: Users choose depth vs. speed trade-off
- **Completeness**: 35.9% F1-score (95.8% recall / 22.1% precision) on SmartBugs-curated (143 contracts)
- **Organization**: Clear mental model for tool categorization

### Negative

- **Complexity**: 9 layers with 50 tools is a lot to manage
- **Resource usage**: Full scans can be slow and resource-intensive
- **Overlap**: Some findings may be duplicated across layers

### Neutral

- Need ML aggregation to deduplicate and correlate findings
- Documentation overhead to explain all layers

## References

- [OWASP Defense in Depth](https://owasp.org/www-community/Defense_in_depth)
- [docs/ARCHITECTURE_PATTERNS.md](../ARCHITECTURE_PATTERNS.md)
