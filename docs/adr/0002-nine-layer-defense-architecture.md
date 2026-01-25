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
| 5 | Property Testing | PropertyGPT, Vertigo | Invariants |
| 6 | AI/LLM Analysis | SmartLLM, GPTScan, LLMSmartAudit | NLP detection |
| 7 | ML Pattern Recognition | DAGNN, SmartGuard, SmartBugsML | ML models |
| 8 | DeFi Security | DeFiAnalyzer, MEVDetector, GasAnalyzer | Protocol risks |
| 9 | Advanced Detection | AdvancedDetector, ThreatModel, ZKCircuit | Specialized |

Analysis profiles select which layers to use:
- **quick**: Layer 1 only
- **standard**: Layers 1-3
- **thorough**: Layers 1-6
- **paranoid**: All layers

## Consequences

### Positive

- **Defense in depth**: Multiple techniques catch different bugs
- **Flexibility**: Users choose depth vs. speed trade-off
- **Completeness**: 82.35% F1-score on SmartBugs benchmark
- **Organization**: Clear mental model for tool categorization

### Negative

- **Complexity**: 9 layers with 31 tools is a lot to manage
- **Resource usage**: Full scans can be slow and resource-intensive
- **Overlap**: Some findings may be duplicated across layers

### Neutral

- Need ML aggregation to deduplicate and correlate findings
- Documentation overhead to explain all layers

## References

- [OWASP Defense in Depth](https://owasp.org/www-community/Defense_in_depth)
- [docs/ARCHITECTURE_PATTERNS.md](../ARCHITECTURE_PATTERNS.md)
