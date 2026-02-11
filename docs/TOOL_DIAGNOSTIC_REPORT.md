# MIESC Tool Diagnostic Report

**Date**: 2026-02-06
**Version**: 5.1.0
**Images Tested**: `miesc:latest` (standard), `miesc:full`

---

## Executive Summary

| Image | Pass Rate | Available | Failed | Config Error |
|-------|-----------|-----------|--------|--------------|
| **Standard** | 54% | 27/50 | 21 | 2 |
| **Full** | 64% | 32/50 | 16 | 2 |

The "full" image gains 5 additional tools over standard, primarily Halmos and AI tools (when Ollama is connected).

---

## Critical Failures

### 1. Mythril - NOT INSTALLED (Dockerfile.full bug)

**Error**: Permission denied during pip cache mount
```
PermissionError: [Errno 13] Permission denied: '/home/miesc/.cache/puccinialin'
```

**Root Cause**: The `--mount=type=cache` in Dockerfile.full causes puccinialin (Mythril dependency) to fail creating cache directory.

**Fix Options**:
1. Remove cache mount for Mythril installation
2. Pre-create `.cache/puccinialin` with correct permissions
3. Use `pip install --no-cache-dir mythril`

### 2. Manticore - NOT INSTALLED (Python 3.12 incompatible)

**Error**: pysha3 compilation failure
```
fatal error: pystrhex.h: No such file or directory
```

**Root Cause**: `pysha3` library has C code incompatible with Python 3.12 (header removed).

**Fix Options**:
1. **RECOMMENDED**: Deprecate Manticore (maintenance-only upstream)
2. Use Python 3.11 image (breaking change)
3. Fork pysha3 and patch (high effort)

### 3. Echidna & Medusa - NOT IN DOCKERFILE

**Status**: Never included in Docker images.

**Fix**: Add to Dockerfile:
```dockerfile
# Echidna (from GitHub releases)
RUN curl -L https://github.com/crytic/echidna/releases/download/v2.2.7/echidna-2.2.7-Linux-x86_64.tar.gz | tar xz -C /usr/local/bin/

# Medusa (from GitHub releases)
RUN curl -L https://github.com/crytic/medusa/releases/download/v1.3.1/medusa-linux-x64.tar.gz | tar xz -C /usr/local/bin/
```

---

## Layer-by-Layer Analysis

### Layer 1: Static Analysis (4/6 in Full)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| slither | ✅ | ✅ | - |
| aderyn | ✅ | ✅ | - |
| solhint | ✅ | ✅ | - |
| semgrep | ❌ | ⚠️ CONFIG | Config issue in full |
| wake | ❌ | ❌ | Not installed |
| fouranalyzer | ✅ | ✅ | Internal impl |

**Recommendation**: Fix semgrep config, consider removing wake (low value).

### Layer 2: Dynamic Testing (4/6 in Full)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| echidna | ❌ | ❌ | **NOT IN DOCKERFILE** |
| medusa | ❌ | ❌ | **NOT IN DOCKERFILE** |
| foundry | ✅ | ✅ | - |
| dogefuzz | ✅ | ✅ | Internal impl |
| hardhat | ⚠️ | ✅ | Works in full |
| vertigo | ✅ | ✅ | Internal impl |

**Critical**: Echidna is essential for fuzzing. Must add to Dockerfile.

### Layer 3: Symbolic Execution (3/5 in Full)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| mythril | ❌ | ❌ | **PIP CACHE PERMISSION BUG** |
| manticore | ❌ | ❌ | **PYTHON 3.12 INCOMPATIBLE** |
| halmos | ❌ | ✅ | Works in full |
| oyente | ✅ | ✅ | Internal impl (deprecated) |
| pakala | ✅ | ✅ | Internal impl |

**Critical**: Mythril bug must be fixed. Manticore should be deprecated.

### Layer 4: Formal Verification (1/5 in Full)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| certora | ❌ | ❌ | Requires commercial API key |
| smtchecker | ⚠️ | ⚠️ | solc version check failing |
| propertygpt | ❌ | ❌ | Needs Ollama |
| scribble | ✅ | ✅ | Internal impl |
| solcmc | ❌ | ❌ | Needs solc SMT config |

**Note**: Certora is intentionally disabled (commercial). Fix SMTChecker.

### Layer 5: AI Analysis (3/6 in Full with Ollama)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| smartllm | ❌ | ❌ | Adapter check issue |
| gptscan | ❌ | ❌ | Adapter check issue |
| llmsmartaudit | ❌ | ❌ | Adapter check issue |
| gptlens | ❌ | ✅ | Works with Ollama |
| llamaaudit | ❌ | ✅ | Works with Ollama |
| iaudit | ❌ | ✅ | Works with Ollama |

**Issue**: smartllm/gptscan/llmsmartaudit adapters have different availability checks than gptlens/llamaaudit/iaudit.

### Layer 6: ML Detection (2/5 in Full)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| dagnn | ❌ | ❌ | Needs PyTorch + model files |
| smartguard | ❌ | ❌ | Needs model files |
| smartbugs_ml | ❌ | ❌ | Needs model files |
| smartbugs_detector | ✅ | ✅ | Internal impl |
| peculiar | ✅ | ✅ | Fallback mode (no GNN) |

**Note**: PyTorch IS installed in full image. Issue is missing model files.

### Layer 7: Specialized (7/7)

All tools pass - these are internal implementations.

### Layer 8: Cross-Chain & ZK (4/5)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| crosschain | ✅ | ✅ | Internal impl |
| zk_circuit | ❌ | ❌ | Needs snarkjs/circom |
| bridge_monitor | ✅ | ✅ | Internal impl |
| l2_validator | ✅ | ✅ | Internal impl |
| circom_analyzer | ✅ | ✅ | Internal impl |

### Layer 9: Advanced Ensemble (4/5)

| Tool | Standard | Full | Issue |
|------|----------|------|-------|
| llmbugscanner | ❌ | ❌ | Adapter check issue |
| audit_consensus | ✅ | ✅ | - |
| exploit_synthesizer | ✅ | ✅ | Uses forge |
| vuln_verifier | ✅ | ✅ | Uses z3 |
| remediation_validator | ✅ | ✅ | Internal impl |

---

## Priority Fixes

### P0 - Critical (Week 1)

1. **Fix Mythril installation** in Dockerfile.full
   - Change: `pip install --no-cache-dir mythril`
   - Or: Pre-create cache directory with correct permissions

2. **Add Echidna** to Dockerfile.full
   ```dockerfile
   RUN curl -L https://github.com/crytic/echidna/releases/download/v2.2.7/echidna-2.2.7-Linux-x86_64.tar.gz | tar xz -C /usr/local/bin/
   ```

3. **Fix SMTChecker** adapter - solc version detection

### P1 - High (Week 2)

4. **Add Medusa** to Dockerfile.full (fuzzing redundancy)

5. **Fix L5 AI adapters** (smartllm, gptscan, llmsmartaudit)
   - Unify Ollama availability check with gptlens/iaudit

6. **Fix Semgrep** config error in full image

### P2 - Medium (Week 3-4)

7. **Deprecate Manticore** officially (Python 3.12 incompatible)

8. **Add ML model files** or document where to download them
   - dagnn, smartguard, smartbugs_ml need pretrained models

9. **Consider removing** low-value tools:
   - oyente (deprecated)
   - pakala (experimental)
   - wake (low adoption)

---

## Recommended Target State

After fixes, target pass rates:

| Image | Current | Target |
|-------|---------|--------|
| Standard | 54% | 65% |
| Full | 64% | 85% |

This achieves the "25-30 curated tools" strategy from the roadmap.

---

## Test Commands

```bash
# Standard image diagnostic
docker run --rm --entrypoint python \
  -v $(pwd)/scripts:/scripts:ro \
  ghcr.io/fboiero/miesc:latest \
  /scripts/diagnose-direct.py

# Full image diagnostic (with Ollama)
docker run --rm --entrypoint python \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/scripts:/scripts:ro \
  ghcr.io/fboiero/miesc:full \
  /scripts/diagnose-direct.py
```

---

*Report generated by MIESC diagnostic tool v5.1.0*
