# MIESC vs Competitors — Honest Head-to-Head

This document presents an honest comparison of MIESC against the most popular smart contract security tools. We measure findings count, execution time, and severity distribution on the same 5 vulnerable contracts.

**Reproducibility:** `python benchmarks/competitor_comparison.py`

## Test Setup

- **Contracts:** 5 intentionally vulnerable (EtherStore, VulnerableDeFi, AccessControlFlaws, ReentrancyDAO, FlashLoanAttack)
- **Environment:** macOS ARM64 (Apple Silicon M5 Pro), 48GB RAM, Python 3.12
- **Tool versions:** Slither 0.11.3, Aderyn 0.6.x, Solhint 5.x, Echidna 2.3, MIESC 5.3.0
- **MIESC mode:** `miesc scan` (Layer 1 + intelligence engine)

## Quantitative Results (April 2026, v5.3.0)

| Tool | Raw findings | After intelligence | Time | Notes |
|------|------------:|-------------------:|------|-------|
| Slither alone | 45 | — | 1.2s | Fast baseline, 100 detectors |
| Aderyn alone | 38 | — | 3.1s | Rust-based, Solidity 0.8+ only |
| **MIESC** (multi-tool) | 107 | **93** | **7.2s** | Intelligence engine: ~13% noise reduction |
| Solhint | 0* | — | 3.7s | * Needs custom `.solhint.json` |
| Echidna | 0* | — | 0.6s | * Needs property contracts |

**Key insight:** MIESC's intelligence engine (v5.2.0+) takes 107 raw findings from Slither + Aderyn and produces **93 deduplicated, confidence-scored findings** — each with a Bayesian confidence score, canonical category, and (for 34%) a copy-pasteable Solidity fix. The ~13% noise reduction comes from semantic deduplication (same vuln detected by both tools → 1 finding with higher confidence) and context-aware FP suppression.

### Tunable strictness (v5.1.2+)

```bash
miesc scan contract.sol --fp-strictness off     # Report everything
miesc scan contract.sol --fp-strictness low     # Permissive
miesc scan contract.sol --fp-strictness medium  # Default, balanced
miesc scan contract.sol --fp-strictness high    # Aggressive for CI
```

EtherStore.sol by strictness: off=14, low=14, medium=11, high=9 findings.

## Where MIESC is BETTER

### 1. Cross-tool validation
MIESC runs multiple tools and cross-validates findings. A reentrancy detected by both Slither and Aderyn has higher confidence than either tool alone.

### 2. Normalized output schema
All findings have unified format: `{type, severity, location, swc_id, recommendation}`. Slither/Aderyn each have their own JSON format that requires custom parsing.

### 3. AI insights per finding
Each finding includes plain-English `llm_insights` explaining business impact (when Ollama is running). No competitor offers this out-of-the-box.

### 4. Multiple report formats
- JSON (for tooling)
- Markdown (for PRs)
- PDF (for clients) — competitor tools don't have this
- SARIF (for GitHub Security)
- CSV (for spreadsheets)

### 5. Real-world exploit recall
On 11 historical DeFi exploits ($1.59B in combined losses), MIESC achieves **81.8% recall** (95% Wilson CI [52%, 95%]) — higher than any single tool measured in [Durieux et al. ICSE 2020](https://doi.org/10.1145/3377811.3380364) (best single tool: Slither 43.2%). On SmartBugs-curated (143 contracts), static + intelligence engine achieves **95.8% recall** (137/143; reproducible Paper 1 profile), with a local Ollama follow-up reported at 97.9% (140/143) as a secondary claim.

### 6. Defense-in-depth
9 complementary layers (static, symbolic, fuzzing, formal verification, AI/LLM, pattern detection, DeFi-specific, exploit validation, consensus). No single competitor covers all of these.

### 7. Production-ready integrations
- GitHub Action with SARIF upload
- Docker images (multi-arch)
- Pre-built reports with CVSS, risk matrix, remediation roadmap
- MCP server (Model Context Protocol) for Claude Desktop integration

## Where MIESC is WORSE

### 1. Speed: 5.6x slower than Slither alone (was 200x in v5.1.0)
**MIESC: 8.5s vs Slither: 1.5s** for 5 contracts.

What we improved (v5.1.2):
- Made LLM enhancement opt-in per adapter (was auto-running 5 calls × 8s = 40s overhead)
- Parallelized QUICK_TOOLS in scan command (ThreadPoolExecutor)
- Removed Mythril from quick scan (90s/contract, opt-in via `audit full`)

What's left:
- Lazy-load LLM/RAG/ChromaDB only when --llm-interpret is used
- Reduce remaining adapter import overhead

For sub-second feedback, use Slither directly. Use MIESC when you need cross-tool consensus, normalized output, or AI-enhanced reports.

### 2. Aggressive false positive filtering
Slither raw output: 14 findings on VulnerableDeFi.sol. MIESC reports 4 (after FP filter).

The FP filter removes informational findings (e.g., `solc-version`, naming conventions) but may also drop real findings. **Addressed in v5.1.2+** with `--fp-strictness {off,low,medium,high}` flag.

### 3. Fewer detectors than Slither alone
- **Slither:** 100+ built-in detectors
- **Aderyn:** 50+ detectors
- **MIESC:** uses Slither + Aderyn + 22 internal modules, but the internal modules don't cover the full Slither detector set

### 4. Heavier dependencies
MIESC requires:
- Python 3.12+
- Multiple analysis tools (Slither, Aderyn, optionally Mythril)
- Ollama for LLM features (~10-20GB models)
- WeasyPrint for PDF generation (system libraries)

Slither: just `pip install slither-analyzer`.

### 5. No formal verification
- **Certora Prover:** Mathematical proofs (gold standard)
- **Halmos / Foundry symbolic:** Symbolic property testing
- **MIESC:** Has SMTChecker integration but doesn't generate property specs

## Where MIESC is EQUAL

### 1. Open-source license
MIESC: AGPL-3.0. Same as Slither, Echidna, Halmos, Manticore.

### 2. Single-chain focus
MIESC: Solidity + experimental support for Vyper, Move, Solana, NEAR.
Most competitors: Solidity-only.
Certora: Best multi-chain (EVM + Solana + Stellar).

### 3. False positive rate
All static analysis tools have FP rates of 80-90%+ (recall-focused). MIESC's RAG-enhanced filter brings this down for known-safe patterns but is far from perfect.

## When to Use What

| Use case | Recommended tool |
|----------|------------------|
| Quick PR check (under 5s) | **Slither** alone |
| Pre-deploy comprehensive audit | **MIESC `audit full`** |
| Fuzzing with properties | **Echidna** or **Medusa** |
| Symbolic execution on bytecode | **Mythril** |
| Symbolic property verification | **Halmos** |
| Mathematical proofs | **Certora** (commercial) |
| Multi-tool report for clients | **MIESC** with PDF output |
| CI/CD integration | **MIESC GitHub Action** or Slither |
| Real-world exploit detection | **MIESC** (81.8% recall) |

## Iterative Improvements (Shipped + Roadmap)

**Shipped in v5.1.2–v5.3.1:**
1. ✅ **FP filter tuning:** `--fp-strictness {off,low,medium,high}` flag
2. ✅ **Multi-chain:** Native support for Move, Cairo, Solana (77 vuln types)
3. ✅ **Formal verification:** `miesc specs` generates CVL/Scribble/SMTChecker
4. ✅ **Intelligence engine:** ~30% noise reduction, semantic dedup, fix-code generation
5. ✅ **Automated remediation:** `miesc fix` (Paper 2 on SmartBugs-curated: 123/143 fixes applied, 123/123 compile standalone, 86/123 eliminate the finding on re-scan, 121/123 no-regression)

**Remaining after v5.4.x:**
1. **Speed:** Lazy-load LLM/RAG/ChromaDB (currently imported on every command)
2. **Foundry test gen:** Auto-generate failing tests from exploit_scenario
3. **Empirical calibration:** Replace educated-guess tool weights with measured precision

## Sources

- Tool benchmarks: `benchmarks/results/competitor_comparison_*.json`
- SmartBugs evaluation: `benchmarks/results/SMARTBUGS_SCIENTIFIC_REPORT.md`
- Real exploit evaluation: `benchmarks/evaluate_exploits.py`
- Academic baseline: [Durieux et al., ICSE 2020](https://doi.org/10.1145/3377811.3380364)

---

*Last updated: April 23, 2026 | Run `python benchmarks/competitor_comparison.py` to reproduce.*
