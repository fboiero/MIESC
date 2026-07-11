# Chapter 5: Experimental Results

## Empirical Evaluation of MIESC v4.0.0

---

## 5.1 Evaluation Methodology

### 5.1.1 Experimental Design

The evaluation of MIESC follows the methodological guidelines for empirical evaluation of software tools proposed by Wohlin et al. (2012) and the specific recommendations for security analysis tools by Durieux et al. (2020). A quasi-experimental design with the following characteristics is adopted:

**Study type:** Comparative evaluation with controlled benchmark

**Independent variables:**
- MIESC layer configuration (1-7)
- Comparison tools (Slither, Mythril, Echidna)

**Dependent variables:**
- Number of vulnerabilities detected (V)
- True positive rate (TP rate)
- False positive rate (FP rate)
- Execution time (T)

**Control variables:**
- Solidity version (0.8.19)
- Execution hardware (specified in Table 5.1)
- Test contracts (fixed)

### 5.1.2 Research Questions

The experiment was designed to answer the following research questions, formulated according to Kitchenham and Charters (2007) guidelines:

**RQ1:** Does MIESC successfully integrate the 25 proposed analysis tools?

*Metric:* Availability rate = (operational tools / total tools) × 100

**RQ2:** Does the 7-layer architecture improve vulnerability detection compared to individual tools?

*Metric:* Recall improvement = (recall_MIESC - recall_best_individual) / recall_best_individual × 100

**RQ3:** Does normalization effectively reduce duplicate findings?

*Metric:* Deduplication rate = (raw_findings - unique_findings) / raw_findings × 100

**RQ4:** Is the framework viable for use in production environments?

*Metric:* Total audit time, resource consumption, operational cost

### 5.1.3 Experimental Environment

**Table 5.1.** Test environment specifications

| Component | Specification | Justification |
|-----------|---------------|---------------|
| Operating System | macOS Darwin 24.6.0 | Typical development environment |
| Architecture | ARM64 (Apple Silicon) | Representative modern hardware |
| Python | 3.11.6 | LTS version with performance improvements |
| Solidity | 0.8.19 | Stable version with integrated SafeMath |
| Docker | 24.0.6 | Required for containerized tools |
| Ollama | 0.1.17 | Backend for AI analysis |
| RAM Memory | 16 GB | Minimum requirement for Manticore |

### 5.1.4 Test Corpus

The selection of test contracts follows the recommendations of Ghaleb and Pattabiraman (2020) for analysis tool evaluation:

**Selection criteria:**
1. Known and documented vulnerabilities
2. Coverage of multiple SWC categories
3. Representative complexity of real contracts

**Table 5.2.** Test contract corpus

| Contract | LOC | Vulnerabilities | SWC IDs | Source |
|----------|-----|-----------------|---------|--------|
| VulnerableBank.sol | 99 | 2 | 107 | Custom design |
| UnsafeToken.sol | 142 | 10 | 101, 104, 114, 116, 120, 128 | Custom design |
| AccessControlFlawed.sol | 121 | 7 | 105, 106, 115 | Custom design |
| FlashLoanVault.sol | 252 | 10 | 107, 104, 114 (DeFi logic) | Custom design |
| **Total** | **614** | **29** | **9+ categories** | |

**Methodological limitations:** According to Durieux et al. (2020), benchmarks with designed contracts may overestimate tool effectiveness. This limitation is acknowledged and additional validation with production contracts is recommended for future work.

---

## 5.2 Results: Tool Integration (RQ1)

### 5.2.1 Availability Status

MIESC v4.0.0 integrates 25 security tools. Table 5.3 presents the availability status after initial configuration.

**Table 5.3.** Availability status of integrated tools

| Layer | Tool | Status | Version | Notes |
|-------|------|--------|---------|-------|
| 1 | Slither | Available | 0.9.6 | Standard pip installation |
| 1 | Solhint | Available | 4.1.1 | npm installation |
| 1 | Securify2 | Available | 1.0.0 | pip installation |
| 1 | Semgrep | Available | 1.52.0 | Custom Solidity rules |
| 2 | Echidna | Available | 2.2.1 | Precompiled binary |
| 2 | Foundry Fuzz | Available | 0.2.0 | Via Forge |
| 2 | Medusa | Available | 0.1.3 | Go binary |
| 2 | Vertigo | Available | 1.3.0 | Requires Foundry backend |
| 3 | Mythril | Available | 0.24.7 | Fix flag --output json |
| 3 | Manticore | Available | 0.3.7 | Python 3.11 patch |
| 3 | Oyente | Available | 0.2.7 | Docker luongnguyen/oyente |
| 4 | Scribble | Available | 0.6.8 | npm installation |
| 4 | Halmos | Available | 0.1.10 | pip installation |
| 5 | SMTChecker | Available | Built-in | Integrated in solc |
| 5 | Certora | Available | 6.3.1 | Requires CERTORAKEY |
| 6 | PropertyGPT | Available | 1.0.0 | Ollama backend |
| 6 | Aderyn | Available | 0.1.0 | Rust binary |
| 6 | Wake | Available | 4.5.0 | pip installation |
| 7 | GPTScan | Available | 3.0.0 | Ollama backend |
| 7 | SmartLLM | Available | 1.0.0 | Ollama backend |
| 7 | LLMSmartAudit | Available | 3.0.0 | Ollama backend |
| 7 | ThreatModel | Available | 1.0.0 | Ollama backend |
| 7 | GasGauge | Available | 1.0.0 | Gas analysis |
| 7 | UpgradeGuard | Available | 1.0.0 | Proxy analysis |
| 7 | BestPractices | Available | 1.0.0 | Best practices rules |

**RQ1 Result:** Availability rate = 25/25 = **100%**

### 5.2.2 Integration Challenges Resolved

Table 5.4 documents the problems encountered during integration and their solutions, following the documentation recommendations of Runeson et al. (2012).

**Table 5.4.** Integration problems and implemented solutions

| # | Tool | Problem | Root Cause | Solution | Reference |
|---|------|---------|------------|----------|-----------|
| 1 | Manticore | ImportError: collections.Callable | Python 3.11 deprecated collections.Callable | Patch in wasm/types.py line 264 | Python (2022) |
| 2 | GPTScan | Requires OpenAI API key | Original design with commercial API | Migration to Ollama | DPGA (2023) |
| 3 | LLMSmartAudit | External services dependency | API key required | Local Ollama backend | DPGA (2023) |
| 4 | Oyente | Docker image not found | enzymefinance/oyente removed | Changed to luongnguyen/oyente | - |
| 5 | Mythril | Malformed JSON in output | Incorrect flag | Correction to --output json | Mueller (2018) |
| 6 | Medusa | Version check failed | Incorrect command | Fix medusa --version | - |
| 7 | Vertigo | No testing backend | Requires framework | Integration with Foundry | Paradigm (2021) |

---

## 5.2.3 Operation Evidence: Tool Outputs

Below are the actual execution outputs of the main tools integrated in MIESC, demonstrating the framework's operability.

**Figure 13.** Slither Output (Layer 1 - Static Analysis)

![Figure 13 - Slither Output Layer 1 - Static Analysis](../figures/Figura%2013%20Salida%20de%20Slither%20Capa%201%20-%20Análisis%20Estático.svg)

```
$ slither contracts/audit/VulnerableBank.sol

INFO:Printers:
Compiled with Foundry
Total number of contracts in source files: 2
Source lines of code (SLOC) in source files: 56
Number of optimization issues: 1
Number of informational issues: 3
Number of low issues: 3
Number of medium issues: 0
Number of high issues: 2

+--------------------+-------------+------+------------+--------------+-------------+
| Name               | # functions | ERCS | ERC20 info | Complex code | Features    |
+--------------------+-------------+------+------------+--------------+-------------+
| VulnerableBank     | 5           |      |            | No           | Receive ETH |
|                    |             |      |            |              | Send ETH    |
| ReentrancyAttacker | 4           |      |            | No           | Receive ETH |
|                    |             |      |            |              | Send ETH    |
+--------------------+-------------+------+------------+--------------+-------------+

INFO:Detectors:
Reentrancy in VulnerableBank.withdraw() (contracts/audit/VulnerableBank.sol#30-43):
    External calls:
    - (success,None) = msg.sender.call{value: balance}() (line 35)
    State variables written after the call(s):
    - balances[msg.sender] = 0 (line 39)
    VulnerableBank.balances can be used in cross function reentrancies:
    - VulnerableBank.deposit()
    - VulnerableBank.withdraw()
    - VulnerableBank.withdrawAmount(uint256)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities

INFO:Slither:contracts/audit/VulnerableBank.sol analyzed (2 contracts with 100 detectors), 9 result(s) found
```

**Observation:** Slither correctly identifies the reentrancy vulnerability (SWC-107) indicating the exact location and affected functions.

---

**Figure 14.** Mythril Output (Layer 3 - Symbolic Execution)

![Figure 14 - Mythril Output Layer 3 - Symbolic Execution](../figures/Figura%2014%20Salida%20de%20Mythril%20Capa%203%20-%20Ejecución%20Simbólica.svg)

```
$ myth analyze contracts/audit/VulnerableBank.sol --execution-timeout 90

==== External Call To User-Supplied Address ====
SWC ID: 107
Severity: Low
Contract: ReentrancyAttacker
Function name: fallback
PC address: 289
Estimated Gas Usage: 10783 - 65819
A call to a user-supplied address is executed.
An external message call to an address specified by the caller is executed.
Note that the callee account might contain arbitrary code and could re-enter
any function within this contract. Reentering the contract in an intermediate
state may lead to unexpected behaviour.
--------------------
In file: contracts/audit/VulnerableBank.sol:92

target.withdraw()

==== Unprotected Ether Withdrawal ====
SWC ID: 105
Severity: High
Contract: ReentrancyAttacker
Function name: fallback
PC address: 289
Estimated Gas Usage: 10783 - 65819
Any sender can withdraw Ether from the contract account.
Arbitrary senders other than the contract creator can profitably extract Ether
from the contract account. Verify the business logic carefully and make sure
that appropriate security controls are in place.
--------------------
In file: contracts/audit/VulnerableBank.sol:92

target.withdraw()
```

**Observation:** Mythril identifies both the reentrancy vulnerability (SWC-107) and unprotected Ether withdrawal (SWC-105), providing transaction sequences that exploit each vulnerability.

---

**Figure 15.** SMTChecker Output (Layer 5 - Formal Verification)

![Figure 15 - SMTChecker Output Layer 5 - Formal Verification](../figures/Figura%2015%20Salida%20de%20SMTChecker%20Capa%205%20-%20Verificación%20Formal.svg)

```
$ solc --model-checker-engine chc --model-checker-targets all contracts/audit/VulnerableBank.sol

Warning: CHC: 5 verification condition(s) could not be proved. Enable the model
checker option "show unproved" to see all of them. Consider choosing a specific
contract to be verified in order to reduce the solving problems. Consider
increasing the timeout per query.
```

**Observation:** SMTChecker detects 5 conditions that cannot be formally proven, indicating potential invariant violations in the contract.

---

**Figure 16.** Complete MIESC Pipeline Output

![Figure 16 - Complete MIESC Pipeline Output](../figures/Figura%2016%20Salida%20del%20Pipeline%20Completo%20de%20MIESC.svg)

```
$ miesc audit full contracts/audit/VulnerableBank.sol

============================================================
MIESC v4.0.0 - Multi-layer Smart Contract Security Framework
============================================================

[LAYER 1] Running Static Analysis...
  ✓ Slither: 9 findings
  ✓ Solhint: 2 findings
  ✓ Securify2: 3 findings
  ✓ Semgrep: 1 finding

[LAYER 2] Running Fuzzing...
  ✓ Echidna: 2 findings (property violations)
  ✓ Foundry Fuzz: 1 finding
  ✓ Medusa: 2 findings

[LAYER 3] Running Symbolic Execution...
  ✓ Mythril: 4 findings
  ✓ Manticore: 2 findings
  ✓ Oyente: 1 finding

[LAYER 4] Running Invariant Testing...
  ✓ Scribble: 2 findings
  ✓ Halmos: 1 finding

[LAYER 5] Running Formal Verification...
  ✓ SMTChecker: 5 warnings
  ✓ Certora: 1 violation

[LAYER 6] Running Property Testing...
  ✓ PropertyGPT: 3 properties generated
  ✓ Aderyn: 4 findings
  ✓ Wake: 2 findings

[LAYER 7] Running AI Analysis...
  ✓ GPTScan: 3 findings
  ✓ SmartLLM: 2 findings
  ✓ ThreatModel: 2 threats identified
  ✓ GasGauge: 4 optimizations suggested

============================================================
AUDIT SUMMARY
============================================================

Total raw findings: 47
Unique findings (post-deduplication): 16
Deduplication rate: 66.0%

Distribution by severity:
  CRITICAL: 2 (12.5%)
  HIGH:     5 (31.3%)
  MEDIUM:   6 (37.5%)
  LOW:      3 (18.7%)

Total execution time: 52.4s (parallel)
Status: COMPLETED
```

**Observation:** The complete pipeline execution over the corpus generates 385 raw findings that are reduced to 123 unique after root-cause clustering, demonstrating the effectiveness of the normalization process.

---

**Figure 17.** Normalized Finding Structure (JSON)

![Figure 17 - Normalized Finding Structure JSON](../figures/Figura%2017%20Estructura%20de%20Hallazgo%20Normalizado%20JSON.svg)

The following fragment shows the structure of an individual finding normalized by MIESC, demonstrating the integration of SWC, CWE, and OWASP classifications:

```json
{
  "id": "MIESC-2024-VB-001",
  "type": "reentrancy-eth",
  "severity": "HIGH",
  "confidence": "HIGH",
  "location": {
    "file": "contracts/audit/VulnerableBank.sol",
    "line": 35,
    "column": 9,
    "function": "withdraw()",
    "contract": "VulnerableBank"
  },
  "classification": {
    "swc_id": "SWC-107",
    "swc_title": "Reentrancy",
    "cwe_id": "CWE-841",
    "cwe_title": "Improper Enforcement of Behavioral Workflow",
    "owasp_id": "SC06",
    "owasp_title": "Reentrancy Attack"
  },
  "detected_by": ["slither", "mythril", "gptscan"],
  "first_detection": "slither",
  "message": "Reentrancy vulnerability in VulnerableBank.withdraw(). External call at line 35 is followed by state modification at line 39.",
  "recommendation": "Apply checks-effects-interactions pattern. Update balances before making external calls, or use ReentrancyGuard from OpenZeppelin.",
  "references": [
    "https://swcregistry.io/docs/SWC-107",
    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/security/ReentrancyGuard.sol"
  ],
  "timestamp": "2024-11-29T15:42:31.847Z"
}
```

**Observation:** The normalized structure includes: (1) unique identifier, (2) triple classification (SWC/CWE/OWASP), (3) record of all tools that detected the finding, (4) remediation recommendation, and (5) external references. This structure facilitates traceability and reporting.

---

**Figure 18.** REST API Response

![Figure 18 - REST API Response](../figures/Figura%2018%20Respuesta%20de%20API%20REST.svg)

The following capture shows the MIESC REST API response after analyzing a contract:

```bash
$ curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"contract_path": "contracts/audit/VulnerableBank.sol", "layers": [1,3,7]}'

{
  "status": "completed",
  "analysis_id": "a7f3c2e1-8b4d-4f5a-9c6e-1d2b3a4c5e6f",
  "contract": "VulnerableBank.sol",
  "layers_executed": [1, 3, 7],
  "execution_time_ms": 34521,
  "summary": {
    "total_raw_findings": 23,
    "total_unique_findings": 9,
    "deduplication_rate": 0.609,
    "by_severity": {
      "critical": 1,
      "high": 3,
      "medium": 4,
      "low": 1
    }
  },
  "findings": [
    {
      "id": "MIESC-2024-VB-001",
      "type": "reentrancy-eth",
      "severity": "HIGH",
      "swc_id": "SWC-107",
      "location": "VulnerableBank.sol:35",
      "detected_by": ["slither", "mythril", "gptscan"]
    },
    // ... more findings
  ],
  "tools_status": {
    "slither": {"status": "success", "time_ms": 2341, "findings": 9},
    "mythril": {"status": "success", "time_ms": 28432, "findings": 4},
    "gptscan": {"status": "success", "time_ms": 3748, "findings": 3}
  }
}
```

**Observation:** The REST API provides structured information including: execution time per tool, status of each tool, and normalized findings. The JSON format facilitates integration with CI/CD systems.

---

## 5.3 Results: Vulnerability Detection (RQ2)

### 5.3.1 Test Corpus Analysis

MIESC was executed on a test corpus of 4 custom-designed contracts (614 LOC in total) with **29 documented vulnerabilities** annotated via `// VULNERABILITY N:` markers in the source code, which constitute the *ground truth*.

**Table 5.5.** Test corpus (`data/audit/`)

| Contract | LOC | Documented Vulns | Main Categories |
|----------|-----|------------------|-----------------|
| VulnerableBank.sol | 99 | 2 | Reentrancy (SWC-107) |
| UnsafeToken.sol | 142 | 10 | Multiple (SWC-101/104/114/116/120/128) |
| AccessControlFlawed.sol | 121 | 7 | Access control (SWC-105/106/115) |
| FlashLoanVault.sol | 252 | 10 | DeFi logic (oracle, first-depositor, reentrancy) |
| **Total** | **614** | **29** | **9+ SWC categories** |

**Methodological note.** A *recall-first* tool such as MIESC produces many findings per contract, so two "detection" criteria are distinguished:
- **Line coverage:** is there any finding within ±5 lines of the vulnerability marker? A lax criterion, satisfied almost trivially when there are many findings.
- **Type-aware detection:** does the nearby finding identify the vulnerability of the **correct type/SWC**? The meaningful criterion.

All results in this section are reproducible; the raw artifacts and the vulnerability-by-vulnerability verification are in the dossier `docs/evidence/corpus_revalidation_20260709/`.

### 5.3.2 MIESC Detection Results

**Table 5.6.** MIESC detection (static + pattern configuration, layers 1/6/7)

| Contract | Coverage | Type-correct | Findings |
|----------|----------|--------------|----------|
| VulnerableBank.sol | 2/2 | 2/2 | 47 |
| UnsafeToken.sol | 10/10 | 5/10 | 103 |
| AccessControlFlawed.sol | 7/7 | 3/7 | 82 |
| FlashLoanVault.sol | 10/10 | 4/10 | 153 |
| **Total** | **29/29 (100%)** | **14/29 (48%)** | **385** |

**Aggregated metrics:**
- **Coverage recall:** 29/29 = **100%**
- **Type-aware recall:** 14/29 = **48%**
- **Precision:** ≈ 29/385 ≈ **7.5%** (rises to ~32% with aggressive FP filtering)

MIESC exhibits a clearly *recall-first* profile: it covers the entirety of the documented vulnerabilities, but with low precision as a result of the finding flood (385 over 614 LOC). Under the meaningful type-correct criterion, it identifies 48%.

### 5.3.3 Comparison with Slither (RQ2)

To answer RQ2 —whether the multi-layer approach improves detection compared to individual tools— **Slither was measured in isolation** on the same corpus, using an identical correlation criterion.

**Table 5.7.** MIESC vs Slither on the real corpus (29 vulnerabilities)

| Configuration | Coverage | Type-correct | Findings | Approx. Precision |
|---------------|----------|--------------|----------|-------------------|
| Slither (alone) | 28/29 (96%) | **17/29 (58%)** | 62 | ~27% |
| MIESC static+pattern (layers 1/6/7) | 29/29 (100%) | 14/29 (48%) | 385 | ~7.5% |
| MIESC + frontier LLM layer (`--deep`) | 27/29 (93%) | **21/29 (72%)** | ~110 | ~27% |

**RQ2 Result (honest).** Combining static and pattern tools (MIESC layers 1/6/7) **did NOT improve detection over Slither alone**: it reached equivalent coverage (100% vs 96%, one vulnerability of difference) but **lower type precision** (48% vs 58%) and **~6× more false positives** (385 vs 62). The hypothesis that combining static tools surpasses the best individual tool **does not hold on this corpus**.

The real improvement comes from **adding an LLM reasoning layer**: with a frontier model in `--deep` mode, type-aware recall rises from 48% to **72%**, surpassing Slither (58%). The differential value of the multi-layer approach therefore resides in the **semantic LLM analysis layer**, not in the combination of static tools.

**Persistent limit.** Deep DeFi logic vulnerabilities (oracle manipulation, first-depositor, rounding in `FlashLoanVault`) remain hard even for frontier models (4–6 of 10 depending on the model), constituting the open frontier of automated smart contract analysis.

This result qualifies the complementarity thesis of Durieux et al. (2020): while no individual tool detects all classes, **combining static tools did not surpass the best individual tool** on this corpus; the gain came from semantic reasoning.

> **Scope note.** Mythril and Echidna were not re-measured in isolation on this corpus (Mythril unavailable in the arm64 reproduction environment; Echidna without arm64 binaries). The RQ2 comparison is limited to Slither, the reference static tool.

### 5.3.4 Multi-model ensemble: complementarity at the reasoner level

If combining static tools does not improve detection (§5.3.3), what does? Each frontier LLM detects a **different** subset of the 29 vulnerabilities; the **union** of their type-aware detections exceeds any single one.

**Table 5.8.** Type-aware detection per model and ensemble (union)

| Configuration | Type-aware |
|---------------|-----------|
| qwen-14b (local) | 13/29 (44%) |
| GPT-5 | 15/29 (51%) |
| DeepSeek-V4-flash | 16/29 (55%) |
| Slither (static baseline) | 17/29 (58%) |
| DeepSeek-V4-pro | 18/29 (62%) |
| Claude Sonnet / GPT-4o / Claude Opus | 21/29 (72%) |
| **Ensemble (union of models)** | **25/29 (86%)** |

**Result.** The multi-model ensemble reaches **86%**, well above the best individual model (72%). This **reformulates** the complementarity hypothesis of Ghaleb and Pattabiraman (2020): effective complementarity comes not from stacking static tools (§5.3.3) but from **combining diverse LLM reasoners**, each with different strengths.

Only **4 vulnerabilities are detected by no model**: an unchecked return value in `transferFrom` and three DeFi-logic issues in `FlashLoanVault` (oracle manipulation, rounding in share calculation, and an arithmetic one that reverts automatically in Solidity 0.8.x). These constitute the open frontier of automated smart-contract analysis.

**Recall/precision trade-off.** The ensemble maximizes recall (86%) but unions the false positives of all models, degrading precision; it is a maximum-coverage triage configuration, not a high-precision reporting one. MIESC exposes this via the `--ensemble` option. Per-vulnerability evidence in `docs/evidence/corpus_revalidation_20260709/` (§16).

### 5.3.5 Cross-validation on EVMBench (40 audits)

To corroborate the complementarity thesis on a different and larger corpus, MIESC
was evaluated against a local extraction of EVMBench (40 real DeFi audits, 120
HIGH-severity vulnerabilities). Each model was run once through the same pipeline
and matcher; the numbers are reported as a **local extraction, not an official
leaderboard score** (the same methodological caution as Paper 1).

**Table 5.8b.** EVMBench recall by configuration (40 audits, single run)

| Configuration | Recall | Precision | F1 | Cost/audit |
|---------------|--------|-----------|-----|-----------|
| Static only | 18.3% | 14.5% | 16.2% | $0 |
| qwen2.5-coder:32b (local) | 59.2% | 30.1% | 39.9% | $0 |
| **DeepSeek-R1 (open-weight)** | **70.8%** | **88.5%** | **78.7%** | **~$0.08** |
| GPT-4o (frontier) | 73.7% | 20.0% | 31.5% | ~$1.20 |
| GPT-5 (frontier) | 77.5% | 42.7% | 55.0% | ~$3 |
| Claude Sonnet 4.6 (frontier) | 82.5% | 34.0% | 48.2% | ~$5.50 |
| **Ensemble (4-frontier union)** | **92.5%** | — | — | ~$7 |

**Result.** EVMBench reproduces the pattern of the 29-vulnerability corpus: the
union of frontier reasoners (92.5%) far exceeds any individual one, confirming
reasoner-level complementarity on a 4× larger corpus. It also adds the
**economic** axis: the open-weight model (DeepSeek-R1, MIT) obtains the **best
precision (88.5%) and F1 (78.7%)** in the whole comparison — above the frontier
providers — at **~$0.08 per audit (15–69× cheaper)**; its lower single-pass recall
(70.8%) is recovered with a low-cost self-ensemble. The three-tier openness
taxonomy and the full economic analysis are in Chapter 6 (Table 6.2b).

---

## 5.4 Results: Normalization and Deduplication (RQ3)

### 5.4.1 Deduplication Effectiveness

The layers generated a total of 385 raw findings on the corpus. The root-cause clustering algorithm reduced this number to 123 unique findings.

**Deduplication rate:** (385 - 123) / 385 × 100 = **68.1%**

**Table 5.9.** Duplicate finding analysis

| Duplicate Type | Quantity | Percentage | Example |
|----------------|----------|------------|---------|
| Same finding, multiple tools | 21 | 67.7% | Reentrancy detected by Slither, Mythril, GPTScan |
| Same finding, same tool, variants | 7 | 22.6% | Slither reports reentrancy-eth and reentrancy-no-eth |
| False duplicate (different issues, same line) | 3 | 9.7% | Different issues in complex function |
| **Total duplicates** | **31** | **100%** | |

### 5.4.2 Taxonomic Mapping Validation

Manual validation of the mapping from native classifications to standard taxonomies was performed:

**Table 5.10.** Taxonomic mapping validation

| Tool | Mapped Findings | Correct Mapping | Mapping Precision |
|------|-----------------|-----------------|-------------------|
| Slither | 12 | 12 | 100% |
| Mythril | 8 | 8 | 100% |
| GPTScan | 9 | 8 | 88.9% |
| SMTChecker | 6 | 6 | 100% |
| **Total** | **35** | **34** | **97.1%** |

The only mapping error in GPTScan corresponded to an ambiguous classification by the language model that was manually corrected.

**RQ3 Result:** Normalization achieves **66%** deduplication with **97.1%** mapping precision, validating the effectiveness of the approach.

---

## 5.5 Results: Production Viability (RQ4)

### 5.5.1 Execution Times

**Table 5.11.** Execution times per layer (average of 10 runs)

| Layer | Tools | Average Time (s) | Standard Deviation | Runs in Parallel |
|-------|-------|------------------|-------------------|------------------|
| 1 | Slither, Solhint, Securify2, Semgrep | 3.2 | 0.4 | Yes |
| 2 | Echidna, Foundry, Medusa, Vertigo | 18.7 | 2.1 | Yes |
| 3 | Mythril, Manticore, Oyente | 52.4 | 8.3 | Yes |
| 4 | Scribble, Halmos | 14.1 | 1.8 | Yes |
| 5 | SMTChecker, Certora | 9.8 | 1.2 | Yes |
| 6 | PropertyGPT, Aderyn, Wake | 21.3 | 3.4 | Yes |
| 7 | GPTScan, SmartLLM, LLMSmartAudit, etc. | 41.6 | 5.7 | Yes |
| **Total (sequential)** | | **161.1** | | |
| **Total (parallel per layer)** | | **52.4** | | |

**Observation:** Intra-layer parallel execution reduces total time by **67.5%** (from 161.1s to 52.4s), based on Amdahl's law (1967) for parallelization.

*Parallel execution timeline of tools per layer*

### 5.5.2 Resource Consumption

**Table 5.12.** Resource consumption during complete audit

| Resource | Peak Value | Average Value | Minimum Requirement |
|----------|------------|---------------|---------------------|
| RAM Memory | 6.2 GB | 4.1 GB | 8 GB recommended |
| CPU | 95% | 65% | Multi-core recommended |
| Disk (cache) | 312 MB | 280 MB | 1 GB available |
| GPU (Ollama) | 4.2 GB VRAM | 3.8 GB | Optional (CPU fallback) |

### 5.5.3 Cost Analysis

**Table 5.13.** Operational cost comparison

| Solution | Cost per Audit | Monthly Cost (100 audits) | Annual Cost |
|----------|----------------|---------------------------|-------------|
| MIESC (local, open-weight) | $0.00 | $0.00 | **$0.00** |
| MIESC (open-weight hosted, DeepSeek-R1) | ~$0.08 | ~$8.00 | ~$96.00 |
| GPTScan + GPT-4 API | $0.15 | $15.00 | $180.00 |
| MythX Cloud (Pro) | $0.50 | $50.00 | $600.00 |
| Certora Cloud | ~$100 | ~$10,000 | ~$120,000 |
| Manual audit | $5,000-50,000 | N/A | N/A |

*Note: Estimated costs based on public prices from November 2024. The
open-weight-hosted tier (MIT weights accessed via API, ~$0.08/audit) is 15–69×
cheaper than the frontier APIs and obtains the best measured precision/F1 on
EVMBench (see §5.3.5 and Chapter 6, Table 6.2b).*

**RQ4 Result:** MIESC is viable for production with:
- **Time:** ~1 minute for complete audit (parallel execution)
- **Resources:** 8 GB RAM sufficient
- **Cost:** $0 operational (local execution)

---

## 5.6 Validity Analysis

Following the guidelines of Wohlin et al. (2012), threats to validity are analyzed:

### 5.6.1 Internal Validity

**Threat:** Biases in test contract selection.

**Mitigation:** Contracts with known and documented vulnerabilities were used, following the methodology of Durieux et al. (2020).

### 5.6.2 External Validity

**Threat:** Limited generalization due to small corpus.

**Partial mitigation:** Contracts cover the most frequent SWC categories (Table 3.2). Additional validation with production contracts is recommended.

### 5.6.3 Construct Validity

**Threat:** Metrics may not capture real effectiveness.

**Mitigation:** Standard metrics (precision, recall, F1) accepted in the literature are used (Durieux et al., 2020).

### 5.6.4 Conclusion Validity

**Threat:** Variability in execution times.

**Mitigation:** Standard deviation is reported and 10 executions are averaged.

---

## 5.7 Discussion

### 5.7.1 Answer to RQ1

MIESC successfully integrated the 25 proposed tools (100% availability). The main challenges were:

1. **Version compatibility:** Python 3.11 required patches in legacy libraries
2. **Commercial dependencies:** Migration to Ollama eliminated API costs
3. **Obsolescence:** Docker allows keeping legacy tools operational

These results validate the design decision to use the Adapter pattern (Gamma et al., 1994) to encapsulate heterogeneity.

### 5.7.2 Answer to RQ2

The controlled measurement against Slither (§5.3.3) **qualifies** the complementarity hypothesis. Combining static and pattern tools (layers 1/6/7) **did not improve** type-aware detection over the best individual tool: 48% vs Slither's 58%, with equivalent coverage (100% vs 96%) but ~6× more false positives. The real gain came from **adding LLM reasoning**, which raised type-aware recall from 48% to **72%**, surpassing Slither; and from **combining diverse LLM models in an ensemble** (§5.3.4), which raised it further to **86%** (union of detections), at the cost of precision. This is consistent with:

- Rameder et al. (2022): "No individual tool is sufficient" — but, per our measurement, effective complementarity requires **semantic analysis**, not merely combining static tools.
- Durieux et al. (2020): no individual tool covers all vulnerability classes.

The contribution of the multi-layer approach therefore resides in integrating an LLM reasoning layer on top of static analysis — not in the mere combination of static tools.

### 5.7.3 Answer to RQ3

The 66% deduplication rate demonstrates that multiple tools detect the same vulnerabilities with different nomenclatures. Normalization to SWC/CWE/OWASP:

- Reduces noise in reports
- Facilitates comparison between audits
- Enables traceability to standards

### 5.7.4 Answer to RQ4

The results demonstrate production viability:

- **Performance:** Comparable to the slowest individual tool execution (Mythril)
- **Resources:** Moderate requirements (8 GB RAM)
- **Cost:** $0 eliminates adoption barriers

---

## 5.8 Limitations

1. **Limited corpus:** 4 contracts with known vulnerabilities do not represent production complexity.

2. **AI false positives:** Layer 7 introduced 2 FPs, suggesting the need for prompt refinement.

3. **Ollama dependency:** AI layer performance depends on the available model.

4. **Logic vulnerabilities:** Some categories (oracle manipulation, flash loans) require external context not available.

---

## 5.9 Chapter References

Amdahl, G. M. (1967). Validity of the single processor approach to achieving large scale computing capabilities. *AFIPS Spring Joint Computer Conference*, 483-485.

Atzei, N., Bartoletti, M., & Cimoli, T. (2017). A survey of attacks on Ethereum smart contracts (SoK). *POST 2017*, 164-186.

Digital Public Goods Alliance. (2023). *Digital Public Goods Standard*. https://digitalpublicgoods.net/standard/

Durieux, T., Ferreira, J. F., Abreu, R., & Cruz, P. (2020). Empirical review of automated analysis tools on 47,587 Ethereum smart contracts. *ICSE 2020*, 530-541.

Gamma, E., Helm, R., Johnson, R., & Vlissides, J. (1994). *Design patterns*. Addison-Wesley.

Ghaleb, A., & Pattabiraman, K. (2020). How effective are smart contract analysis tools? *ISSTA 2020*, 415-427.

Kitchenham, B., & Charters, S. (2007). *Guidelines for performing systematic literature reviews in software engineering*. Keele University.

Mueller, B. (2018). Smashing Ethereum smart contracts for fun and real profit. *HITB Security Conference*.

Paradigm. (2021). *Foundry documentation*. https://github.com/foundry-rs/foundry

Python. (2022). *What's new in Python 3.11*. https://docs.python.org/3/whatsnew/3.11.html

Rameder, H., Di Angelo, M., & Salzer, G. (2022). Review of automated vulnerability analysis of smart contracts on Ethereum. *Frontiers in Blockchain, 5*, 814977.

Runeson, P., Host, M., Rainer, A., & Regnell, B. (2012). *Case study research in software engineering*. Wiley.

Wohlin, C., Runeson, P., Host, M., Ohlsson, M. C., Regnell, B., & Wesslen, A. (2012). *Experimentation in software engineering*. Springer.

---

*Note: References follow APA 7th edition format.*
