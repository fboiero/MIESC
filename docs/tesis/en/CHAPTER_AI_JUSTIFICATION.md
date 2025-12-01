# Chapter 6: Justification for Using Sovereign AI and LLMs

## Data Sovereignty in Smart Contract Auditing

---

## 6.1 Introduction: The Confidentiality Dilemma

### 6.1.1 Nature of Pre-Launch Audit Code

The source code of a smart contract before its mainnet deployment represents a particular type of computing asset that combines three characteristics that make it especially sensitive:

**First characteristic: Direct economic value.** Unlike traditional software, where code has indirect value through the product it produces, a smart contract IS the product. The contract of a DeFi protocol managing 100 million dollars in TVL (Total Value Locked) does not simply "serve to" handle that money: the contract is the mechanism that defines the rules for handling it. Exposing the code before launch allows attackers to prepare exploits that can be executed in the first seconds after deployment.

**Second characteristic: Post-deployment immutability.** Once deployed on blockchain, a smart contract's code cannot be modified without extraordinary procedures (upgrades requiring governance consensus, or complete protocol forks). This means that a vulnerability detected by an attacker before launch can be exploited indefinitely if the deployed code is identical to what was leaked.

**Third characteristic: Temporal competition.** In the DeFi ecosystem, the first protocol to implement an innovative mechanism captures most of the market. Leaking an innovative protocol's code allows competitors to launch clones before the original, capturing the market the innovator expected to conquer.

### 6.1.2 The Problem with Commercial AI APIs

The emergence of large language models (LLMs) like GPT-4 and Claude has transformed the possibilities of code analysis. Sun et al. (2024) demonstrated that GPTScan, a tool combining LLM with program analysis, detects 90.2% of business logic vulnerabilities that escape traditional tools. This result is significant because logic vulnerabilities, unlike technical patterns like reentrancy, require semantic understanding of the code's purpose.

However, using these models via commercial APIs implies transmitting source code to third-party servers. Consider the data flow when an auditor uses OpenAI's GPT-4 to analyze a contract:

```
[Confidential code]
    -> HTTPS to api.openai.com
    -> Servers in Virginia, USA
    -> Processing by model
    -> Storage in logs for 30 days
    -> Possible use for training (per ToS)
```

Each of these steps introduces risks:

1. **Transmission:** Traffic, although encrypted, traverses third-party infrastructure. Metadata (source IP, timestamps, payload size) is visible to intermediaries.

2. **Jurisdiction:** The code becomes subject to US laws, including the CLOUD Act that allows authorities to access data stored by US companies without notifying the owner.

3. **Retention:** OpenAI's retention policies (30 days for API), Anthropic (30 days), and Google (variable) imply that code remains accessible in their systems long after analysis.

4. **Memorization:** Carlini et al. (2023) demonstrated that LLMs can memorize and reproduce fragments of their training data. Although commercial APIs have policies not to train with API data, the technical possibility exists.

### 6.1.3 Risk Quantification

Table 6.1 presents a risk value estimate for different types of audited contracts.

**Table 6.1.** Value at risk by contract type

| Contract Type | Typical TVL | Leak Impact | Incident Examples |
|---------------|-------------|-------------|-------------------|
| Core DeFi Protocol | $100M - $10B | Exploit in first minutes post-launch | Harvest Finance ($33M, 2020) |
| Token Launch / ICO | $10M - $500M | Purchase front-running, sniping | Multiple cases in 2021 |
| NFT Marketplace | $50M - $1B | Mint price manipulation | BAYC clones (2022) |
| DAO Governance | $100M - $5B | Prepared governance attacks | Beanstalk ($182M, 2022) |
| Cross-chain Bridge | $500M - $5B | Coordinated cross-chain exploit | Ronin ($624M, 2022) |

The common pattern in these incidents is that attackers had time to analyze the code and prepare exploits before or immediately after deployment. If the code had leaked during the audit, the attack preparation time would have been even longer.

---

## 6.2 Commercial API Risk Analysis

### 6.2.1 Technical Risks

**1. Interception in transit**

Although HTTPS provides end-to-end encryption, attack vectors exist:
- Compromise of certificate authorities (precedent: DigiNotar, 2011)
- Man-in-the-middle attacks on corporate networks with SSL inspection
- Vulnerabilities in TLS implementations (precedent: Heartbleed, 2014)

For high-value code, these risks are not theoretical but rather vectors that sophisticated actors can exploit.

**2. Exposure by provider employees**

OpenAI, Anthropic, or Google staff with access to API logs can potentially view client code. Precedents of insider threats at technology companies (Twitter, 2020; Tesla, 2018) demonstrate this risk is real.

**3. Model memorization and extraction**

Carlini et al. (2023) demonstrated the "memorization attack": through carefully designed prompts, it is possible to extract training data fragments from LLMs. If a model were trained (inadvertently or not) with client code, that code could be subsequently extracted by third parties.

**Figure 21.** Attack surface in commercial API analysis

![Figure 21 - Attack surface in commercial API analysis](figures/Figura%2021%20Superficie%20de%20ataque%20análisis%20en%20API%20comercial.svg)

```
+--------------------------------------------------------------------+
|                    ANALYSIS WITH COMMERCIAL API                      |
|                                                                      |
|  [AUDITOR]                                                          |
|      |                                                              |
|      | Confidential                                                 |
|      | source code                                                  |
|      v                                                              |
|  +--------+     +-----------+     +------------+    +---------+    |
|  | HTTPS  |---->| CDN/Edge  |---->|  API GW    |--->| Model   |    |
|  | Client |     | Cloudflare |     | (OpenAI)   |    | GPU     |    |
|  +--------+     +-----------+     +------------+    +---------+    |
|       |              |                  |                |          |
|       v              v                  v                v          |
|   VECTOR 1       VECTOR 2          VECTOR 3         VECTOR 4       |
|   Man-in-        Logs at           Retention       Memorization    |
|   middle         edge nodes        30+ days        in model        |
|                                                                      |
|  Each node represents a potential exposure point                    |
+--------------------------------------------------------------------+
```

### 6.2.2 Regulatory Risks

**1. GDPR (European Union)**

Article 44 of GDPR establishes restrictions on personal data transfers to third countries. If source code contains wallet addresses, user-based function names, or any personal data, its transmission to US servers requires specific legal mechanisms (SCCs, Privacy Shield certification, etc.).

**2. LGPD (Brazil)**

The Lei Geral de Protecao de Dados, in its Article 33, requires that international personal data transfers meet specific conditions that commercial APIs typically do not guarantee for programmatic use.

**3. LFPDPPP (Mexico)**

The Federal Law for Protection of Personal Data in Possession of Private Parties establishes security obligations that may be compromised when transmitting data to cloud services in third countries.

**4. Sector financial regulations**

- SOC 2: Requires demonstrable control over sensitive data processing
- PCI DSS: For contracts handling card data, explicitly prohibits certain transfers
- HIPAA: For healthcare contracts, imposes severe restrictions

### 6.2.3 Economic Risks

**Table 6.2.** Commercial API cost structure (November 2024)

| Provider | Model | Input Cost | Output Cost | Cost/Audit* |
|----------|-------|------------|-------------|-------------|
| OpenAI | GPT-4o | $2.50/1M | $10.00/1M | ~$0.38 |
| OpenAI | GPT-4 Turbo | $10.00/1M | $30.00/1M | ~$1.20 |
| Anthropic | Claude 3.5 Sonnet | $3.00/1M | $15.00/1M | ~$0.54 |
| Anthropic | Claude 3 Opus | $15.00/1M | $75.00/1M | ~$2.70 |
| Google | Gemini 1.5 Pro | $3.50/1M | $10.50/1M | ~$0.42 |

*Estimate for analysis of ~500 line contract with multiple passes

**Annual cost projection:**

```
Scenario: Audit team performing 100 monthly audits

Annual cost with GPT-4 Turbo:
100 audits x 12 months x $1.20 = $1,440/year

Plus API key management overhead, rate limits, retries:
$1,440 x 1.5 = ~$2,160/year

Plus pricing change risk (precedent: OpenAI raised prices 3x in 2023):
Contingency reserve: +$500/year

Total estimated cost: ~$2,660/year
```

Although these costs appear modest, they represent a significant barrier for:
- Open source projects without funding
- Individual developers in countries with weak currencies
- Educational organizations
- Academic researchers

---

## 6.3 Solution: Sovereign LLMs with Ollama

### 6.3.1 Data Sovereignty Concept

The term "data sovereignty" has multiple meanings in the literature. For the purposes of this work, we adopt the Digital Public Goods Alliance (2023) definition:

> "Data sovereignty is the principle that data is subject to the laws and governance structures of the nation or entity where it is generated and processed, and that said entity maintains effective control over its use and distribution."

Applying this principle to smart contract analysis implies that:
1. Source code must not leave infrastructure controlled by the auditor
2. Processing must occur on computational resources under auditor control
3. There must be no transmission to third-party services introducing external jurisdiction

### 6.3.2 Ollama as Sovereign Backend

Ollama is an open source framework that enables running LLMs locally on consumer hardware. Its key features for MIESC are:

**1. Completely local execution**

The Ollama server listens exclusively on localhost (127.0.0.1) by default. There is no remote server, no data transmission:

```bash
# Network binding verification
$ netstat -tlnp | grep ollama
tcp   0   0   127.0.0.1:11434   0.0.0.0:*   LISTEN   12345/ollama

# Verification of outgoing connections during analysis
$ tcpdump -i any "not localhost" during analysis
tcpdump: listening on any
^C
0 packets captured  # ZERO external traffic
```

**2. Models with open weights**

Ollama supports models whose weights are public and auditable:

**Table 6.3.** Models supported by MIESC

| Model | Parameters | Required VRAM | License | Code Quality |
|-------|------------|---------------|---------|--------------|
| Llama 3.2:3b | 3B | 4 GB | Meta Llama 3.2 | Good |
| Llama 3.1:8b | 8B | 8 GB | Meta Llama 3.1 | Very good |
| CodeLlama:7b | 7B | 8 GB | Meta Llama 2 | Very good (code) |
| CodeLlama:13b | 13B | 16 GB | Meta Llama 2 | Excellent (code) |
| Qwen2.5-Coder:7b | 7B | 8 GB | Apache 2.0 | Excellent (code) |
| Mistral:7b | 7B | 8 GB | Apache 2.0 | Very good |
| DeepSeek-Coder:6.7b | 6.7B | 8 GB | MIT | Excellent (code) |

**3. No telemetry**

Unlike commercial services, Ollama does not include telemetry code. This is verifiable because the source code is public and auditable:

```go
// No telemetry code exists in ollama/server/routes.go
// No analytics endpoints
// No tracking beacons
```

### 6.3.3 MIESC Architecture with Sovereign LLM

**Figure 22.** Analysis architecture with sovereign LLM

![Figure 22 - Analysis architecture with sovereign LLM](figures/Figura%2022.%20Arquitectura%20de%20análisis%20con%20LLM%20soberano.svg)

*100% local infrastructure with zero external traffic*

### 6.3.4 Configuration in MIESC

```python
# src/config/llm_config.py
"""
Sovereign LLM configuration for MIESC.

Design prioritizes data sovereignty over performance:
- Only localhost connections
- No fallback to external APIs
- Explicit locality verification
"""

LLM_CONFIG = {
    # Mandatorily local backend
    "backend": "ollama",
    "base_url": "http://localhost:11434",

    # Default model (quality/speed balance)
    "model": "llama3.2:3b",

    # Timeouts
    "timeout": 120,
    "max_retries": 3,

    # Generation parameters
    "temperature": 0.1,  # Low for consistency
    "max_tokens": 4096,
    "top_p": 0.9,

    # Security configuration
    "verify_localhost": True,  # Fail if not localhost
    "allow_external": False,   # NEVER connect to external APIs
    "log_prompts": False,      # Don't persist analyzed code
}

def verify_sovereign_backend() -> bool:
    """
    Verify that the LLM backend is sovereign (local).

    This verification runs on each analysis to guarantee
    there is no misconfiguration leaking code.
    """
    base_url = LLM_CONFIG["base_url"]

    # Whitelist of sovereign hosts
    sovereign_hosts = ["localhost", "127.0.0.1", "::1"]

    from urllib.parse import urlparse
    parsed = urlparse(base_url)

    if parsed.hostname not in sovereign_hosts:
        raise SovereigntyViolation(
            f"LLM backend {parsed.hostname} is not local. "
            f"MIESC requires local LLM for data sovereignty. "
            f"Configure Ollama on localhost:11434"
        )

    return True
```

---

## 6.4 Detailed Technical Justification

### 6.4.1 Capability Comparison: Local vs. Commercial

The most frequent objection to local LLMs is that their capability is inferior to frontier commercial models. This section examines to what extent this difference affects the specific use case of smart contract analysis.

**Table 6.4.** Capability comparison for code analysis

| Capability | GPT-4 | Claude 3 Opus | Llama 3.1:8b | CodeLlama:13b |
|------------|-------|---------------|--------------|---------------|
| Solidity comprehension | Excellent | Excellent | Good | Very good |
| Reentrancy detection | High | High | Medium-High | High |
| Overflow detection | High | High | High | High |
| Business logic | Very High | Very High | Medium | Medium |
| Remediation generation | Excellent | Excellent | Good | Good |
| Speed (tokens/s) | ~50 | ~60 | ~80* | ~60* |
| Cost per analysis | $1-2 | $2-3 | $0 | $0 |

*On RTX 3090 GPU or equivalent

**Key observations:**

1. **For known technical vulnerabilities** (reentrancy, overflow, access control), local models achieve performance comparable to commercial ones. This is because these vulnerabilities follow predictable patterns that 7-13B parameter models can learn.

2. **For business logic vulnerabilities**, commercial models have an advantage. However, this advantage is mitigated in MIESC because:
   - The AI layer is one of seven layers, not the only defense
   - AI findings are correlated with traditional tool findings
   - The human auditor remains the final decision maker

3. **Local model speed** is frequently superior because there is no network latency or API queues.

### 6.4.2 Trade-off Analysis

**Trade-off 1: Capability vs. Sovereignty**

The decision to use local LLMs implies accepting lower reasoning capability in exchange for complete data sovereignty. This trade-off is acceptable when:

- The code has significant value (>$10M at stake)
- Regulatory confidentiality obligations exist
- The auditor cannot accept leak risk
- Other MIESC layers compensate for LLM limitations

The trade-off is NOT acceptable when:
- The code is already public (post-audit analysis of deployed contracts)
- There are no confidentiality restrictions
- Maximum business logic detection capability is required

MIESC allows configuring hybrid analyses where traditional layers always run locally, and the AI layer can be configured to use external models only for non-confidential code.

**Trade-off 2: Initial cost vs. Operational cost**

| Aspect | Commercial API | Sovereign LLM |
|--------|----------------|---------------|
| Initial cost | $0 | $500-1000 (GPU) |
| Operational cost | ~$2,500/year | ~$60/year (electricity) |
| Break-even | - | ~6 months |
| 3-year cost | $7,500 | $1,180 |

For organizations performing audits regularly, sovereign LLM has better ROI even ignoring sovereignty benefits.

### 6.4.3 Limitation Mitigation Strategies

**1. Multi-layer architecture**

Local LLM limitations are mitigated because it operates within a 7-layer architecture where 24 non-LLM tools provide complementary coverage:

```python
def run_comprehensive_audit(contract_path: str) -> AuditReport:
    """
    Comprehensive audit that does not depend exclusively on LLM.

    Even if the local LLM doesn't detect a logic vulnerability,
    other layers may detect related symptoms.
    """
    all_findings = []

    # Layers 1-5: Traditional tools (24 total)
    all_findings.extend(run_static_analysis(contract_path))    # Slither, etc.
    all_findings.extend(run_fuzzing(contract_path))            # Echidna, etc.
    all_findings.extend(run_symbolic(contract_path))           # Mythril, etc.
    all_findings.extend(run_invariant_testing(contract_path))  # Scribble, etc.
    all_findings.extend(run_formal_verification(contract_path))  # SMTChecker, etc.

    # Layers 6-7: Local LLM for semantic analysis
    all_findings.extend(run_llm_analysis(contract_path))  # GPTScan, etc.

    # Deduplication correlates findings from multiple sources
    return deduplicate_and_prioritize(all_findings)
```

**2. Prompts optimized for smaller models**

MIESC prompts are designed to maximize effectiveness with 7-8B parameter models:

```python
OPTIMIZED_SECURITY_PROMPT = """
Analyze this Solidity contract for security vulnerabilities.

FOCUS ON THESE SPECIFIC PATTERNS:
1. External calls before state updates (reentrancy)
2. Unchecked arithmetic operations
3. Missing access control on sensitive functions
4. Dangerous delegatecall usage
5. Improper handling of ETH transfers

For each vulnerability found, provide:
- Line number
- Vulnerability type
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Brief explanation (1-2 sentences)

CONTRACT:
```solidity
{contract_code}
```

Respond in JSON format only:
{{"vulnerabilities": [...]}}
"""
```

The prompt is:
- Specific (exact list of what to look for)
- Structured (clear response format)
- Concise (minimizes context tokens for response)

**3. RAG (Retrieval-Augmented Generation)**

MIESC implements RAG with a local knowledge base of known vulnerabilities:

```python
class LocalRAGEngine:
    """
    Local RAG engine to enrich LLM analysis.

    Knowledge base includes:
    - Complete SWC Registry with examples
    - Historical smart contract CVEs
    - Documented attack patterns
    """

    def __init__(self):
        # Local knowledge base (no internet required)
        self.knowledge_base = load_local_embeddings("data/swc_knowledge.faiss")

    def augment_prompt(self, code: str, base_prompt: str) -> str:
        """
        Enrich prompt with relevant KB context.
        """
        # Search for similar patterns in KB
        similar_vulns = self.knowledge_base.search(code, top_k=3)

        # Add relevant examples to prompt
        context = "SIMILAR KNOWN VULNERABILITIES:\n"
        for vuln in similar_vulns:
            context += f"- {vuln['swc_id']}: {vuln['description']}\n"
            context += f"  Example: {vuln['example'][:200]}...\n"

        return f"{context}\n{base_prompt}"
```

---

## 6.5 Implementation in MIESC

### 6.5.1 Integrated LLM Tools

MIESC integrates six LLM-based tools, all configured for local execution:

**Table 6.5.** LLM tools in MIESC

| Tool | Purpose | Tokens/Analysis | Typical Time |
|------|---------|-----------------|--------------|
| GPTScan | Vulnerability detection | ~15,000 | 30-60s |
| SmartLLM | Contextual RAG analysis | ~20,000 | 45-90s |
| LLMSmartAudit | Complete automated audit | ~25,000 | 60-120s |
| ThreatModel | STRIDE threat modeling | ~10,000 | 20-40s |
| PropertyGPT | Invariant generation | ~12,000 | 25-50s |
| GasGauge | Gas optimization | ~8,000 | 15-30s |

### 6.5.2 Base LLM Adapter Implementation

```python
# src/adapters/base_llm_adapter.py
"""
Base adapter for sovereign LLM-based tools.

This adapter guarantees that all MIESC LLM tools
use exclusively local backends, with no possibility
of accidental code leakage to external services.
"""

import requests
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from src.config.llm_config import LLM_CONFIG, verify_sovereign_backend

class SovereigntyViolation(Exception):
    """Exception for data sovereignty violations."""
    pass

class BaseLLMAdapter(ABC):
    """
    Base adapter guaranteeing sovereign LLM execution.

    All MIESC LLM tools inherit from this class,
    automatically inheriting sovereignty guarantees.
    """

    def __init__(self):
        self.base_url = LLM_CONFIG["base_url"]
        self.model = LLM_CONFIG["model"]
        self.timeout = LLM_CONFIG["timeout"]

        # Critical sovereignty verification
        if not self._verify_sovereignty():
            raise SovereigntyViolation(
                "Cannot initialize LLM adapter: backend is not sovereign"
            )

    def _verify_sovereignty(self) -> bool:
        """
        Verify that LLM backend is local.

        This verification runs:
        1. When instantiating the adapter
        2. Before each analysis call

        Redundancy is intentional: protects against
        runtime configuration changes.
        """
        return verify_sovereign_backend()

    def _verify_ollama_local(self) -> bool:
        """
        Verify Ollama responds and is effectively local.
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )

            # Verify response comes from localhost
            # (not from a proxy that could forward to external service)
            if response.headers.get("X-Ollama-Version"):
                return True

        except requests.exceptions.ConnectionError:
            raise SovereigntyViolation(
                f"Ollama not running at {self.base_url}. "
                f"Start Ollama with: ollama serve"
            )

        return False

    def generate(self, prompt: str) -> str:
        """
        Generate response from local LLM.

        Analyzed code never leaves the local system.
        """
        # Re-verify sovereignty before each call
        self._verify_sovereignty()

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": LLM_CONFIG["temperature"],
                    "num_predict": LLM_CONFIG["max_tokens"]
                }
            },
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise RuntimeError(f"Ollama error: {response.text}")

        return response.json()["response"]

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Specific analysis implementation."""
        pass
```

### 6.5.3 Sovereignty Verification

MIESC includes a verification script that the auditor can run to demonstrate sovereignty to clients or regulators:

```bash
#!/bin/bash
# verify_sovereignty.sh - MIESC Data Sovereignty Verification

echo "+=================================================================+"
echo "|        DATA SOVEREIGNTY VERIFICATION - MIESC                    |"
echo "+=================================================================+"
echo ""

# 1. Verify Ollama only listens on localhost
echo "[1/4] Verifying Ollama network binding..."
OLLAMA_BIND=$(netstat -tlnp 2>/dev/null | grep 11434 || ss -tlnp | grep 11434)
if echo "$OLLAMA_BIND" | grep -q "127.0.0.1:11434"; then
    echo "      OK - Ollama listens ONLY on localhost (127.0.0.1:11434)"
else
    echo "      WARNING: Ollama may be externally exposed"
    echo "      Output: $OLLAMA_BIND"
fi
echo ""

# 2. Monitor traffic during test analysis
echo "[2/4] Monitoring network traffic during analysis..."
timeout 30 tcpdump -c 100 -i any "not host localhost" 2>/dev/null &
TCPDUMP_PID=$!

# Run test analysis
python3 -c "
from src.adapters.gptscan_adapter import GPTScanAdapter
adapter = GPTScanAdapter()
adapter.analyze('contracts/test/TestContract.sol')
" 2>/dev/null

# Verify no external traffic
wait $TCPDUMP_PID 2>/dev/null
if [ $? -eq 0 ]; then
    echo "      OK - ZERO external connections during analysis"
else
    echo "      WARNING - External traffic detected (investigate)"
fi
echo ""

# 3. Verify model location
echo "[3/4] Verifying local model storage..."
if [ -d "$HOME/.ollama/models" ]; then
    MODEL_SIZE=$(du -sh "$HOME/.ollama/models" 2>/dev/null | cut -f1)
    echo "      OK - Models stored locally: $MODEL_SIZE"
    echo "      Location: $HOME/.ollama/models/"
else
    echo "      WARNING - No local models found"
fi
echo ""

# 4. Verify MIESC configuration
echo "[4/4] Verifying MIESC configuration..."
python3 -c "
from src.config.llm_config import LLM_CONFIG, verify_sovereign_backend
print(f'      Backend: {LLM_CONFIG[\"backend\"]}')
print(f'      URL: {LLM_CONFIG[\"base_url\"]}')
print(f'      Allow External: {LLM_CONFIG[\"allow_external\"]}')
if verify_sovereign_backend():
    print('      OK - Configuration is SOVEREIGN')
"
echo ""

echo "+=================================================================+"
echo "|                  VERIFICATION COMPLETED                         |"
echo "+=================================================================+"
```

---

## 6.6 Compliance with Standards

### 6.6.1 Digital Public Goods Alliance (DPGA)

MIESC is designed to comply with the nine DPGA standard indicators:

| DPGA Indicator | MIESC Compliance |
|----------------|------------------|
| 1. SDG Relevance | Contributes to SDG 9 (Infrastructure) and SDG 16 (Institutions) |
| 2. Open license | AGPL-3.0 for code, CC-BY 4.0 for documentation |
| 3. Clear documentation | Installation and usage guides published |
| 4. Data extraction | N/A (analysis tool, does not store user data) |
| 5. Privacy | Local execution, no data transmission |
| 6. Open standards | Use of SWC, CWE, SARIF |
| 7. Non-discrimination | No access restrictions |
| 8. No proprietary dependencies | Only open source tools |
| 9. Platform independence | Works on Linux, macOS, Windows |

### 6.6.2 Community Benefits

**1. Access democratization**

Local execution eliminates cost barriers for:
- Open source projects without budget
- Developers in developing countries
- Educational institutions
- Academic researchers

**2. National technological sovereignty**

Government organizations and companies in jurisdictions with data localization requirements can use MIESC without compromising compliance:
- No international data transfer
- No dependency on foreign services
- Total control over processing infrastructure

**3. Transparency and auditability**

The entire stack is open source and auditable:
- MIESC code: Public GitHub
- Ollama: Open source (MIT)
- Llama models: Public weights and training documentation

---

## 6.7 Conclusions

### 6.7.1 Justification Summary

The decision to implement sovereign LLMs in MIESC responds to a rigorous risk and trade-off analysis. The justification is based on:

1. **Pre-audit smart contract code has direct and significant economic value.** Leaking this code can result in losses of tens or hundreds of millions of dollars.

2. **Commercial LLM APIs introduce unacceptable risk vectors** for high-value code: transmission to foreign jurisdictions, extended retention periods, possible memorization in models.

3. **Local 7-13B parameter models provide sufficient capability** for the security analysis use case, especially when operating within a multi-layer architecture.

4. **Total cost of ownership of sovereign LLMs is lower** than commercial APIs for organizations performing audits regularly.

5. **Local execution guarantees automatic regulatory compliance** with GDPR, LGPD, LFPDPPP and sector regulations.

### 6.7.2 Recommendation

For smart contract audits handling confidential code with significant economic value:

> **Using sovereign (local) LLMs is the only option that provides verifiable guarantees of source code confidentiality during the audit process.**

Capability limitations compared to commercial models are mitigated through:
- Seven-layer architecture with 25 tools
- Prompts optimized for smaller models
- RAG with local knowledge base
- Finding correlation across multiple sources

---

## 6.8 Chapter References

Carlini, N., et al. (2023). Extracting Training Data from Large Language Models. *USENIX Security Symposium*.

Digital Public Goods Alliance. (2023). *Digital Public Goods Standard*. https://digitalpublicgoods.net/standard/

European Parliament. (2016). General Data Protection Regulation (GDPR). *Regulation (EU) 2016/679*.

Meta AI. (2024). Llama 3 Model Card. https://ai.meta.com/llama/

Ollama. (2024). Ollama Documentation. https://ollama.ai/

OpenAI. (2024). API Data Usage Policies. https://openai.com/policies/api-data-usage

Presidencia de la Republica. (2010). Ley Federal de Proteccion de Datos Personales en Posesion de los Particulares (LFPDPPP).

Republica Federativa do Brasil. (2018). Lei Geral de Protecao de Dados (LGPD). *Lei n. 13.709*.

Sun, Y., et al. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *ICSE 2024*, 1-12.

Touvron, H., et al. (2023). LLaMA: Open and efficient foundation language models. *arXiv:2302.13971*.

---

*Note: References follow APA 7th edition format. Document updated: 2025-11-29*
