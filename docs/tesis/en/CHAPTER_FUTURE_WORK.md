# Chapter 8: Conclusions and Future Work

## MIESC: Final Reflections and Research Lines

---

## 8.1 Conclusions

### 8.1.1 Synthesis of the Work Performed

This thesis has presented MIESC (Multi-layer Integration for Ethereum Smart Contract Security), an open-source framework that implements a defense-in-depth architecture for automated smart contract auditing. The development of MIESC represents a significant contribution to the field of smart contract security, addressing the gaps identified in the state of the art.

### 8.1.2 Objectives Achieved

**Table 8.1.** Assessment of the specific objectives (Chapter 1 wording)

| Specific objective | Indicator | Result | Status |
|--------------------|-----------|--------|--------|
| SO1 — Tool integration (≥20) | Operational tools | 25/25 available in the evaluation environment (Table 5.3) | Achieved |
| SO2 — Output normalization | SWC/CWE/OWASP mapping and deduplication | Mapping precision 97.1% on the verified sample (Table 5.10); deduplication 68% (385→123) | Achieved |
| SO3 — Defense-in-Depth architecture (7 layers) | Layers implemented and evaluated | 7 layers implemented; detection was measured on layers 1/6/7 (Table 5.6); complementarity among static tools was not confirmed (§5.3.3), the LLM layer's was | Achieved with caveats |
| SO4 — Data sovereignty (Ollama backend) | Analysis without external transmission | Local backend operational at $0/audit; the best *type-aware* result (72%) required a frontier model via API (`--deep`); the local model reached 44% | Achieved; lower local capability (§6.2.4) |
| SO5 — Conversational interface (MCP) | Operational MCP server | Implemented; the server and tools run locally, the main client (Claude) is a cloud service (§7.7.1) | Achieved with the caveat of §7.7.1 |
| H1/RQ2 — Improve *type-aware* detection | Beat the best single tool | Combined static 48% < Slither 58%; 72% with a frontier LLM layer; 86% with a multi-model ensemble | Partial (§8.1.4) |

### 8.1.3 Main Contributions

1. **7-Layer Architecture:** As far as the Chapter 3 review reaches, first documented implementation of defense-in-depth applied specifically to smart contract auditing, combining static, dynamic, symbolic, formal, and AI analysis.

2. **ToolAdapter Protocol:** Unified interface that allows integration of heterogeneous tools without core modification, following SOLID principles and the Adapter pattern.

3. **Triple Normalization System:** Automatic mapping of findings to SWC, CWE, and OWASP taxonomies with 97.1% accuracy.

4. **Migration to Local Backend:** Elimination of commercial API dependencies through Ollama integration, meeting DPGA requirements.

5. **MCP Server:** As far as the Chapter 3 review reaches, first smart contract auditing tool with native Model Context Protocol support, enabling integration with Claude and other AI assistants.

6. **Legacy Tool Rescue:** Documented patches for Manticore (Python 3.11) and Oyente (Docker image), preserving analysis capabilities.

7. **Sovereignty as a requirement, empirically validated:** the thesis that control over the tool — open weights, auditable execution — is a first-order requirement of security analysis and not a preference, grounded doctrinally, scientifically, epistemically and philosophically (Ch. 6, §6.6.3). Its empirical counterpart is that, in the EVMBench comparison and under the lenient matcher, an open-weight model records the highest precision (88.5%) and F1 (78.7%) of the comparison at about USD 0.08 per audit (15–69× less). This is an optimistic estimate, whose provider ranking under the official judge is deferred to future work, but sufficient to indicate that the sovereign choice no longer requires sacrificing capability.

### 8.1.4 Hypothesis Validation

The three hypotheses are assessed with the wording of section 1.5.

**H1** (*a framework integrating multiple tools through the Adapter pattern can reach a detection rate higher than any single tool*): **partially supported, with qualifications.** Combining static and pattern tools did not beat Slither alone (48% vs. 58% *type-aware* detection, with equivalent coverage —100% vs. 96%— and about six times more false positives). Beating the best single tool was achieved only by adding semantic reasoning: 72% with a frontier LLM layer (`--deep`) and 86% with a multi-model ensemble (§5.3.3–5.3.4). Effective complementarity therefore requires semantic analysis, not the mere accumulation of static tools. Note also that the 72% is MIESC's figure with a single frontier model as the layer-7 detector (§5.3.4, Table 5.8), so the additional gain attributable to the architecture over that single detector is only observed in the ensemble configuration (86%, union of seven models and Slither; 83% without Slither), a difference that with n=29 does not reach statistical significance (§5.6.4). The hypothesis holds as a consistent trend, not as a statistically established result.

**H2** (*normalization to standard taxonomies significantly reduces duplicates without information loss*): **supported in its first part; the second was not demonstrated.** Deduplication reached 68% (385→123) with 97.1% mapping precision on the verified sample (Table 5.10). The absence of information loss was not measured as such: Table 5.9 records three "false duplicates" (distinct findings merged), indicating a bounded but non-zero loss.

**H3** (*running local LLMs via Ollama provides semantic-analysis capability comparable to commercial services, at near-zero operating cost*): **not supported as formulated.** On the corpus, the local model (qwen2.5-coder:14b) reached 44% *type-aware* detection vs. 72% for the frontier model; on EVMBench, the local 32B model reached 59.2% recall vs. 73.7–82.5% for the frontier models, always under the lenient matcher. The near-zero cost does hold. The formulation the evidence does support is Chapter 6's: **open-weight** models are viable —the hosted open-weight model records the highest precision and F1 of the comparison under the lenient matcher— and **fully local** execution has a measured, not assumed, recall cost. This reformulation is adopted as a conclusion (§8.5); the provider comparison under the official judge is left as future work (§8.3.1).

---

## 8.2 Work Limitations

### 8.2.1 Technical Limitations

1. **Scalability:** Analysis of very large contracts (>1000 LOC) may require times exceeding 5 minutes, particularly in the symbolic execution layer (Mythril, Manticore).

2. **LLM Model Dependency:** Layer 7 analysis quality depends on the available Ollama model. Smaller models may produce more false positives.

3. **Emerging Vulnerability Coverage:** Specific business logic vulnerabilities (flash loans, oracle manipulation, MEV) require external context not available in static analysis.

4. **Cross-Chain Compatibility:** MIESC is optimized for Ethereum and EVM-compatible chains. Other blockchains (Solana, Cosmos) would require specific adapters.

### 8.2.2 Methodological Limitations

1. **Limited Test Corpus:** Validation was performed with 4 contracts (614 LOC) and 29 documented vulnerabilities. According to Durieux et al. (2020), this may overestimate effectiveness.

2. **Absence of Production Validation:** No validation was performed with mainnet-deployed contracts with unknown vulnerabilities.

3. **Subjective AI Metrics:** Some Layer 7 outputs (ThreatModel, BestPractices) produce qualitative recommendations that are difficult to quantify.

---

## 8.3 Future Work

Several of the lines outlined in this section **were already started and published
after the defense**, in the papers derived from this thesis. Those advances are
summarized first, then the lines that remain open.

### 8.3.1 Derived publications and lines already started (post-defense)

This thesis gave rise to two papers presented at the IV International Symposium on
Blockchain and Cybersecurity (RIBCi–CYTED 2026, IEEE, double-blind review):

- **Paper 1 — Detection** (Boiero et al., 2026a): consolidates the detection
  evaluation and contributes evidence that was not part of the defended corpus:
  - **Real-world exploits:** 9/11 detected (81.8% recall; 95% Wilson CI [52%, 95%]) over
    USD 1.59B in evaluated losses — a first step of Line 1.
  - **LLM-free ablation:** static 82.5% → +own detectors 93.0% → +intelligence 97.9%
    over the 143 SmartBugs contracts (each stage gains contracts without losing any;
    significance by McNemar's test) — quantifying the contribution of Line 2.
  - **Honest EVMBench (triple):** a single run measured under three protocols — lenient
    matcher (92.5% union / 88.3% single run), null control, and EVMBench's official
    judge with GPT-5 (27.4%) — showing that every EVMBench score must report the
    protocol and judge used.
  - **False-positive filter:** removes 207 of 1,263 FPs (16%) without losing true
    positives, raising finding-level precision from 13.3% to 15.5%.
- **Paper 2 — Remediation** (Boiero et al., 2026b): applies and verifies
  automated repairs (123/143 contracts patched, 123/123 compile, 88/123 eliminate the
  HIGH/CRITICAL finding, 121/123 with no regression) — a realization of Line 5
  (development-ecosystem integration). It does not claim semantic equivalence or
  corpus-wide formal proof: both remain open (Line 4).

The lines that remain open are detailed below. In particular, the **provider ranking
under the official judge** of EVMBench (not concluded with the lenient matcher; see
Chapter 6) and an **agentic detection loop** for business-logic vulnerabilities are the
two priorities Paper 1 flags as immediate future work.

---

### 8.3.2 Line 1: Vulnerability Coverage Extension

**Objective:** Expand detection to emerging vulnerabilities in the DeFi ecosystem.

**Proposed tasks:**

| Task | Description | Complexity | Impact |
|------|-------------|------------|--------|
| FW-1.1 | Flash loan vulnerability detection | High | High |
| FW-1.2 | Oracle dependency analysis | Medium | High |
| FW-1.3 | MEV (Maximal Extractable Value) detection | High | Medium |
| FW-1.4 | DeFi composability analysis | High | High |
| FW-1.5 | Token rug pull detection | Medium | High |

**Rationale:** Qin et al. (2021) document losses exceeding $1B from flash loan vulnerabilities not detectable by traditional tools.

**Technical approach:**
- Integrate historical transaction analysis to detect exploitation patterns
- Develop adapter for Forta Network (real-time detection)
- Implement flash loan attack simulation with Foundry

---

### 8.3.3 Line 2: AI Model Improvement

**Objective:** Increase Layer 7 precision through fine-tuning specialized models.

**Proposed tasks:**

| Task | Description | Complexity | Impact |
|------|-------------|------------|--------|
| FW-2.1 | CodeLlama fine-tuning for Solidity | High | Very High |
| FW-2.2 | Annotated vulnerabilities dataset | Medium | High |
| FW-2.3 | LLM benchmark for auditing (partially achieved: EVMBench, 40 audits, frontier vs open-weight vs local; remaining scope is official-leaderboard submission) | Medium | High |
| FW-2.4 | False positive reduction with RAG | Medium | High |
| FW-2.5 | AI decision explainability | High | Medium |

**Rationale:** Table 5.8 shows that the model used largely determines detection; the gap between the local and the frontier configuration (44% vs. 72%) is what an open model fine-tuned for Solidity should close.

**Technical approach:**
```python
# Proposed fine-tuning pipeline example
class SoliditySecurityFineTuner:
    def __init__(self, base_model="codellama:7b"):
        self.base_model = base_model
        self.dataset = VulnerabilityDataset()

    def prepare_training_data(self):
        """
        Format: (vulnerable_code, vulnerability, explanation, fix)
        Sources: SWC Registry, Immunefi, Code4rena
        """
        pass

    def fine_tune(self, epochs=3, learning_rate=2e-5):
        """Fine-tuning with LoRA for efficiency"""
        pass
```

---

### 8.3.4 Line 3: Multi-Chain Support

**Objective:** Extend MIESC to other blockchains with smart contracts.

**Proposed tasks:**

| Task | Description | Blockchain | Complexity |
|------|-------------|------------|------------|
| FW-3.1 | Adapters for Solana (Rust/Anchor) | Solana | High |
| FW-3.2 | Adapters for Move (Aptos/Sui) | Aptos/Sui | High |
| FW-3.3 | CosmWasm support | Cosmos | Medium |
| FW-3.4 | Cairo contract analysis (StarkNet) | StarkNet | High |
| FW-3.5 | Cross-chain vulnerability mapping | All | Medium |

**Rationale:** The multi-chain ecosystem represents >40% of TVL in 2024 (DeFiLlama, 2024). Vulnerabilities in these ecosystems lack mature automated tools.

**Proposed architecture:**

**Figure 8.1.** Proposed Multi-Chain Architecture for MIESC

![Figure 8.1 - Multi-Chain Architecture Proposed for MIESC](../figures/Figura%2028%20Multichain%20arquitectura%20propuesta..svg)

---

### 8.3.5 Line 4: Advanced Formal Verification

**Objective:** Deepen formal verification capabilities with automatic specifications.

**Proposed tasks:**

| Task | Description | Complexity | Impact |
|------|-------------|------------|--------|
| FW-4.1 | Automatic CVL specification generation | High | Very High |
| FW-4.2 | Integration with Certora Gambit | Medium | High |
| FW-4.3 | Invariant synthesis with AI | High | Very High |
| FW-4.4 | Upgradeability pattern verification | Medium | High |
| FW-4.5 | Pre/post upgrade equivalence tests | High | High |

**Rationale:** Formal verification can prove properties about contract state exhaustively within the scope of the specification (Certora, 2024), but requires costly manual specifications.

**Invariant synthesis proposal:**

**Figure 8.2.** Proposal for AI-based Invariant Synthesis

![Figure 8.2 - Proposal for AI-based Invariant Synthesis](../figures/Figura%2029%20Propuesta%20de%20síntesis%20de%20invariantes.svg)

---

### 8.3.6 Line 5: Development Ecosystem Integration

**Objective:** Integrate MIESC into the smart contract development lifecycle.

**Proposed tasks:**

| Task | Description | Complexity | Impact |
|------|-------------|------------|--------|
| FW-5.1 | VS Code / Remix IDE plugin | Medium | Very High |
| FW-5.2 | GitHub App for automatic PRs | Medium | High |
| FW-5.3 | Tenderly integration (simulation) | Medium | High |
| FW-5.4 | Security metrics dashboard | Medium | Medium |
| FW-5.5 | Dependency vulnerability notifications | Low | High |

**GitHub App proposal:**
```yaml
# .github/workflows/miesc-pr-review.yml
name: MIESC Security Review
on: [pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: miesc/action@v1
        with:
          layers: [1, 2, 3, 7]
          fail_on: high
          comment_on_pr: true
          suggest_fixes: true
```

---

### 8.3.7 Line 6: Continuous Production Auditing

**Objective:** Extend MIESC for post-deployment monitoring.

**Proposed tasks:**

| Task | Description | Complexity | Impact |
|------|-------------|------------|--------|
| FW-6.1 | Forta integration for alerts | Medium | Very High |
| FW-6.2 | Real-time transaction analysis | High | High |
| FW-6.3 | Anomalous behavior detection | High | High |
| FW-6.4 | Automatic response system | High | Very High |
| FW-6.5 | Contract monitoring dashboard | Medium | Medium |

**Proposed architecture:**

**Figure 8.3.** Continuous Production Auditing Architecture

![Figure 8.3 - Continuous Production Auditing Architecture](../figures/Figura%2030%20Auditoría%20Continua%20en%20Producción.svg)

---

## 8.4 Expected Impact

### 8.4.1 Academic Impact

1. **Derived publications (realized):**
   - **RIBCi–CYTED 2026 (IEEE, double-blind)** — Paper 1 (detection) and Paper 2
     (remediation), direct derivatives of this thesis (Boiero et al., 2026a,
     2026b).
   - Future dissemination lines: a journal with the extended empirical evaluation
     (e.g. TSE/TOSEM) and DeFi security workshops.

2. **Contribution to knowledge:**
   - Empirical —qualified— validation of technique complementarity: the gain comes from semantic reasoning, not from accumulating static tools
   - Reproducible framework for research
   - Normalized vulnerability dataset

### 8.4.2 Industrial Impact

1. **Expected adoption:**
   - Independent developers: access to free auditing
   - Startups: substantial reduction in the cost of a first security review (not quantified in this thesis)
   - Companies: integration with existing pipelines

2. **Loss reduction:**
   - Early detection: prevention of post-deployment exploits
   - Magnitude of avoidable losses not quantified in this thesis

### 8.4.3 Social Impact

1. **Security democratization:**
   - Free and open-source tool
   - No API key or cost barriers
   - Documentation in Spanish and English

2. **Contribution to Digital Public Goods:**
   - DPGA standards compliance
   - AGPL-3.0 license (open-source copyleft, OSI-approved)
   - Portability through multi-architecture Docker images

---

## 8.5 Final Reflections

The development of MIESC represents a significant step towards democratizing smart contract security. In an ecosystem where vulnerability losses exceed billions of dollars annually, the availability of accessible and effective auditing tools is fundamental.

The evaluation of the defense-in-depth architecture yielded a more instructive result than expected: merely combining static tools did not beat the best of them, and the measured gain came from LLM reasoning and from combining reasoners in an ensemble (§5.3.3–5.3.4). This finding has implications beyond the smart contract domain, suggesting that multi-technique approaches should be the norm in software security analysis.

The integration with the Model Context Protocol (MCP) represents a vision of the future where AI assistants can directly access specialized security tools, amplifying both human and automated capabilities. MIESC is not just an auditing tool, but a platform that can evolve with the AI-assisted development ecosystem.

The proposed future work establishes an ambitious but achievable roadmap, with significant potential impact on blockchain ecosystem security. The open-source nature of MIESC invites the community to contribute and extend these capabilities.

> "Security is not a product, it's a process" - Bruce Schneier (2000)

MIESC embodies this philosophy, providing not just a tool, but an extensible framework for continuous improvement of smart contract security.

---

## 8.6 Chapter References

Boiero, F., Mussetta, S. N., & Cena, N. G. (2026a). MIESC: A multi-layer framework for automated smart contract security evaluation. In *Livros de Atas — IV International Symposium on Blockchain and Cybersecurity (RIBCi–CYTED 2026)*.

Boiero, F., Mussetta, S. N., & Cena, N. G. (2026b). From findings to verifiable remediation artifacts: A smart contract security pipeline. In *Livros de Atas — IV International Symposium on Blockchain and Cybersecurity (RIBCi–CYTED 2026)*.

DeFiLlama. (2024). *DeFi TVL by Chain*. https://defillama.com/chains

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *ICSE 2020*, 530-541.


Qin, K., Zhou, L., Livshits, B., & Gervais, A. (2021). Attacking the DeFi ecosystem with flash loans. *FC 2021*, 3-32.

Schneier, B. (2000). *Secrets and lies: Digital security in a networked world*. Wiley.

Sun, Y., et al. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *ICSE 2024*, 1-12.

---

*Note: References follow APA 7th edition format.*
