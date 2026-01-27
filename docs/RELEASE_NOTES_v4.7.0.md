# MIESC v4.7.0 Release Notes

**Release Date:** January 2026
**Author:** Fernando Boiero <fboiero@frvm.utn.edu.ar>

## Overview

Version 4.7.0 focuses on improving detection precision through cross-validation with external static analysis tools (Slither) and symbolic execution (Mythril). This release introduces intelligent confidence adjustment based on tool confirmation.

## Key Metrics

| Metric | v4.6.0 | v4.7.0 | Change |
|--------|--------|--------|--------|
| **Precision** | 26.7% | 35.9% | **+9.2%** |
| **Recall** | 85.7% | 81.2% | -4.5% |
| **F1 Score** | 40.7% | 49.7% | **+9.0%** |

*Measured on SolidiFI benchmark (70 contracts) with `--slither --min-confidence 0.5`*

## New Features

### Slither Cross-Validation
- Real-time cross-validation with Slither static analysis
- Automatic Solidity version detection and solc-select integration
- Selective confidence penalties by vulnerability type
- CLI flags: `--slither`, `--slither-timeout`

```bash
# Run benchmark with Slither cross-validation
python benchmarks/solidifi_benchmark.py --slither --min-confidence 0.5
```

### ML-Based False Positive Classifier
- Rule-based feature extraction for code context
- 19 features including: guards, modifiers, Solidity version
- Conservative weights to preserve recall
- CLI flags: `--fp-filter`, `--fp-threshold`

### Mythril Symbolic Execution
- Cross-validation with Mythril for path reachability
- SWC-based vulnerability type mapping
- CLI flags: `--mythril`, `--mythril-timeout`
- Note: Very slow (~2+ min/contract), best for targeted analysis

## Technical Improvements

### SlitherValidator Enhancements
- Auto-detection of `address payable` syntax → uses Solidity 0.5+
- Version mapping for pragma compatibility
- Support for solc-select installed versions

### Benchmark Enhancements
- Cross-validation functions for Slither and Mythril
- Selective penalty application (only for Slither-detectable types)
- Confidence boosting for confirmed findings (+0.25)
- Confidence reduction for unconfirmed findings (-0.20)

## Requirements

### New Dependencies
```bash
# Slither with multiple Solidity versions
pip install solc-select
solc-select install 0.4.26 0.5.17 0.6.12 0.7.6 0.8.20

# Mythril (optional, for symbolic execution)
pip install mythril
```

## Configuration

### Recommended Settings
```bash
# Best F1 score (precision/recall balance)
python benchmarks/solidifi_benchmark.py --slither --min-confidence 0.5

# Maximum recall (security-focused)
python benchmarks/solidifi_benchmark.py --slither --min-confidence 0.4

# Fast mode (no cross-validation)
python benchmarks/solidifi_benchmark.py --quick
```

## Known Limitations

1. **Slither Coverage**: Doesn't detect overflow/underflow or TOD effectively
2. **Mythril Speed**: 2+ minutes per contract, impractical for large benchmarks
3. **FP Classifier**: Limited effectiveness on intentionally vulnerable contracts (no guards)
4. **Precision Goal**: 60% target not achievable without sacrificing >50% recall

## Files Changed

- `config/miesc.yaml` - Version bump to 4.7.0
- `benchmarks/solidifi_benchmark.py` - Slither/Mythril cross-validation
- `src/ml/slither_validator.py` - Solidity version auto-detection
- `src/ml/fp_classifier.py` - New ML-based false positive classifier
- `docs/PLAN_v4.7.0.md` - Implementation plan and results

## Upgrade Notes

No breaking changes from v4.6.0. All new features are opt-in via CLI flags.

## Next Steps

For future versions:
1. Improve Slither type mapping for better confirmation rates
2. Explore ensemble methods combining multiple validators
3. Consider training ML classifier on labeled production data
4. Investigate Echidna fuzzing for additional validation
