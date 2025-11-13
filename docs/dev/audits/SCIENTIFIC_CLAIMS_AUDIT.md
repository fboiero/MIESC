# Scientific Claims Audit - MIESC v3.5.0

**Date**: 2025-11-13
**Auditor**: Repository refactoring process
**Purpose**: Verify scientific claims match empirical evidence

## Executive Summary

**Status**: CRITICAL - Multiple unsubstantiated claims found in README.md

**Action Required**: Update README to reflect actual experimental status and remove claims not yet validated.

---

## Claims Analysis

### CLAIM 1: "5,127 real-world contracts" dataset

**Status**: ❌ NOT VALIDATED

**Evidence searched**:
- `benchmark_results/` contains only 5 contracts analyzed
- No large dataset files found (all JSON/CSV < 10KB)
- `docs/thesis/data/` contains config files, not contract datasets
- No SmartBugs, Etherscan, or DeFi datasets present

**Reality**: Framework has been tested on ~5-10 test contracts, not 5,127

**Recommendation**: Update README to state:
- "Framework architecture designed to scale to large datasets"
- "Validated on test suite of vulnerable contracts"
- "Large-scale empirical validation pending (planned for thesis defense Q4 2025)"

---

### CLAIM 2: "89.47% precision, 86.2% recall"

**Status**: ❌ NOT VALIDATED

**Evidence searched**:
- `benchmark_results/benchmark_latest.json` shows only 5 contracts, 39 total findings
- No precision/recall calculations found in results files
- No ground truth labels for validation
- No expert annotations found

**Reality**: No precision/recall measurements have been performed

**Recommendation**: Remove specific metrics OR clearly state:
- "Projected performance based on tool vendor specifications"
- "Empirical validation in progress"

---

### CLAIM 3: "Cohen's Kappa 0.847 with 3 expert auditors"

**Status**: ❌ NOT VALIDATED

**Evidence searched**:
- No expert annotations found
- No inter-rater agreement calculations
- No auditor data files

**Reality**: No expert validation study has been conducted

**Recommendation**: Remove this claim entirely OR state as future work

---

### CLAIM 4: "43% false positive reduction"

**Status**: ❌ NOT VALIDATED

**Evidence searched**:
- No comparative analysis files
- No tool-by-tool FP measurements
- No AI triage validation data

**Reality**: No comparative FP study performed

**Recommendation**: State as "theoretical estimate" OR remove

---

### CLAIM 5: "90% time reduction (32-50h → 3-5h)"

**Status**: ⚠️ ESTIMATED (not measured)

**Evidence**: Based on tool execution times in benchmarks, not actual auditor time studies

**Reality**: Theoretical estimate from tool speeds, not empirical user study

**Recommendation**: Clarify as "estimated based on tool execution time"

---

## Claims with VALID support

### ✅ CLAIM: Multi-tool integration

**Status**: VALIDATED

**Evidence**:
- 17 adapters implemented in `src/adapters/`
- All inherit from `ToolAdapter` protocol
- Integration tests exist

---

### ✅ CLAIM: MCP implementation

**Status**: VALIDATED

**Evidence**:
- `src/mcp/` directory contains implementation
- Server and protocol files present
- Documentation exists

---

### ✅ CLAIM: References to Durieux et al., Atzei et al., Saltzer & Schroeder

**Status**: VALIDATED

**Evidence**:
- `docs/compliance/REFERENCES.md` contains proper citations
- DOIs and URLs provided
- Relevant to design decisions

---

## Recommended Actions

### IMMEDIATE (before any commit/publication):

1. **Update README.md** - Remove all unvalidated quantitative claims
2. **Add LIMITATIONS.md** - Document current validation status
3. **Update thesis references** - Change `thesis/results/` to `docs/thesis/`
4. **Clarify development status** - Mark empirical validation as "in progress"

### MEDIUM-TERM (before thesis defense):

1. **Conduct actual empirical study** on representative dataset
2. **Measure precision/recall** with ground truth labels
3. **Document methodology** for reproducibility
4. **Run expert validation** study if claiming inter-rater agreement

### Framework for honest claims:

```markdown
## Current Status

**Implementation**: Complete (17 tools, 7 layers, MCP integration)
**Testing**: Unit and integration tests passing (117 tests)
**Empirical Validation**: In progress (planned Q4 2025)

**Validated claims**:
- Multi-tool orchestration implemented
- MCP protocol integration functional
- Compliance mapping to 12 standards implemented

**Pending validation** (thesis work):
- Large-scale precision/recall measurements
- Expert inter-rater agreement study
- False positive reduction quantification
- Time savings empirical study
```

---

## Scientific Integrity Assessment

**Current state**: README contains aspirational claims presented as completed work

**Risk**:
- Loss of credibility if claims cannot be substantiated
- Incompatible with mature open-source project standards
- Potential academic integrity issues for thesis

**Recommendation**: Adopt conservative, evidence-based claims following established OSS norms (Linux, Git, GCC style)

---

**Conclusion**: Major revision needed to align claims with evidence.
