# MIESC vs Competitors — Honest Head-to-Head

This document presents an honest comparison of MIESC against the most popular smart contract security tools. We measure findings count, execution time, and severity distribution on the same 5 vulnerable contracts.

**Reproducibility:** `python benchmarks/competitor_comparison.py`

## Test Setup

- **Contracts:** 5 intentionally vulnerable (EtherStore, VulnerableDeFi, AccessControlFlaws, ReentrancyDAO, FlashLoanAttack)
- **Environment:** macOS ARM64 (Apple Silicon M5 Pro), 48GB RAM, Python 3.12
- **Tool versions:** Slither 0.11.3, Aderyn 0.6.x, Solhint 5.x, Echidna 2.3, MIESC 5.1.1
- **MIESC mode:** `miesc scan` (Layer 1 only — Slither + Aderyn + Solhint + Mythril)

## Quantitative Results (April 2026)

| Tool | Total findings | Total time | Speed (findings/s) |
|------|---------------|------------|---------------------|
| **Slither alone** | **45** | **2.8s** | **16.1** ⚡ |
| Aderyn alone | 38 | 5.6s | 6.8 |
| **MIESC** (multi-tool) | **45** | 529s | 0.085 |
| Solhint | 0* | 5.1s | — |
| Echidna | 0* | 1.3s | — |

\* Solhint requires custom config; Echidna requires property contracts

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
On 11 historical DeFi exploits ($3.3B in losses), MIESC achieves **81.8% recall** — higher than any single tool measured in [Durieux et al. ICSE 2020](https://doi.org/10.1145/3377811.3380364) (best single tool: Slither 43.2%).

### 6. Defense-in-depth
9 complementary layers (static, symbolic, fuzzing, formal verification, AI/LLM, pattern detection, DeFi-specific, exploit validation, consensus). No single competitor covers all of these.

### 7. Production-ready integrations
- GitHub Action with SARIF upload
- Docker images (multi-arch)
- Pre-built reports with CVSS, risk matrix, remediation roadmap
- MCP server (Model Context Protocol) for Claude Desktop integration

## Where MIESC is WORSE

### 1. Speed: ~80s startup overhead per scan
**MIESC: 1:22 (with 0.6s actual analysis) vs Slither: 2.8s** total.

The overhead comes from:
- **Adapter loader imports ~80s** (LLM clients, RAG, ChromaDB, sentence-transformers)
- Tool execution itself is fast (slither: 0.6s, aderyn: 0.8s) and parallelized
- This is a known issue tracked for v5.2: lazy imports for optional features

**Workaround for speed-critical users:**
```bash
# Use Slither directly for sub-second feedback
slither contract.sol

# Use MIESC when you need cross-validation, normalized output, or AI insights
miesc scan contract.sol
```

**v5.2 plan:** Lazy-load LLM/RAG dependencies only when `--llm-interpret` is used.

### 2. Aggressive false positive filtering
Slither raw output: 14 findings on VulnerableDeFi.sol. MIESC reports 4 (after FP filter).

The FP filter removes informational findings (e.g., `solc-version`, naming conventions) but may also drop real findings. **This is a known limitation** that we're addressing in v5.2 with a tunable filtering level.

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

## Iterative Improvements (Roadmap)

Based on this honest comparison, MIESC v5.2 will focus on:

1. **Speed:** Parallelize tool execution at the layer level (target: 30s for full audit)
2. **FP filter tuning:** Add `--fp-strictness {low,medium,high}` flag
3. **More detectors:** Wrap missing Slither detectors in MIESC's normalized output
4. **Multi-chain:** Native support for Move, Cairo, Solana programs
5. **Formal verification:** Auto-generate Certora specs from MIESC findings

## Sources

- Tool benchmarks: `benchmarks/results/competitor_comparison_*.json`
- SmartBugs evaluation: `benchmarks/results/SMARTBUGS_SCIENTIFIC_REPORT.md`
- Real exploit evaluation: `benchmarks/evaluate_exploits.py`
- Academic baseline: [Durieux et al., ICSE 2020](https://doi.org/10.1145/3377811.3380364)

---

*Last updated: April 12, 2026 | Run `python benchmarks/competitor_comparison.py` to reproduce.*
