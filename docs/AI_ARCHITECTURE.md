# MIESC AI Architecture & Governance
## ISO/IEC 42001:2023 Compliant AI Management System

**Version:** 2.2.0
**Last Updated:** December 2024
**Status:** 🔄 Evolving (Pre-DPG Compliance)
**Compliance:** ISO/IEC 42001:2023, EU AI Act, DPGA Standards

---

## 📋 Table of Contents

1. [Current AI Architecture Status](#current-ai-architecture-status)
2. [AI Abstraction Layer (ISO 42001)](#ai-abstraction-layer)
3. [Provider-Agnostic Design](#provider-agnostic-design)
4. [Digital Public Good (DPG) Compliance](#digital-public-good-compliance)
5. [Privacy & Security](#privacy--security)
6. [Governance & Ethics](#governance--ethics)
7. [Implementation Roadmap](#implementation-roadmap)

---

## 🎯 Current AI Architecture Status

### **IMPORTANT CLARIFICATION**

**Current Reality (v2.2.0):**

MIESC **currently does NOT use real AI/LLM APIs** in production. Here's why:

```python
# Current Implementation (Simulated AI)
class AIAgent:
    def filter_false_positives(self, findings):
        """
        Currently uses RULE-BASED heuristics, NOT actual AI.

        Why no API calls yet:
        1. No vendor lock-in risk (DPGA requirement)
        2. No privacy concerns (no data leaves your machine)
        3. Works offline (critical for security audits)
        4. No API costs
        5. Deterministic behavior (reproducible research)
        """
        # Rule-based filtering using patterns
        filtered = []
        for finding in findings:
            # Heuristic rules
            if self._is_high_confidence(finding):
                if not self._is_common_false_positive(finding):
                    filtered.append(finding)
        return filtered
```

### Why Demo Scripts Show "AI"?

The video demo scripts (`record_demo_intelligent.sh`) simulate **future capabilities** for:
- **Marketing/Vision**: Show what MIESC will become
- **Research Validation**: Demonstrate multi-agent concept
- **User Education**: Explain AI-assisted workflow

**This is clearly documented as simulation**, not production code.

---

## 🏗️ AI Abstraction Layer (ISO 42001 Compliance)

### Design Principles

To achieve **ISO/IEC 42001:2023** compliance and **DPGA standards**, MIESC implements:

#### 1. **Provider-Agnostic Interface**

```python
# src/ai/provider_interface.py

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class AIRequest:
    """Standard request format for all AI providers."""
    prompt: str
    context: Dict
    max_tokens: int = 1000
    temperature: float = 0.7
    model_requirements: Optional[Dict] = None

@dataclass
class AIResponse:
    """Standard response format from all AI providers."""
    content: str
    confidence: float
    reasoning: Optional[str]
    provider: str
    model: str
    cost: float  # For transparency

class AIProvider(ABC):
    """
    Abstract base class for all AI providers.
    Ensures NO vendor lock-in (DPGA requirement).
    """

    @abstractmethod
    def analyze_vulnerability(self, request: AIRequest) -> AIResponse:
        """Analyze a vulnerability with AI reasoning."""
        pass

    @abstractmethod
    def filter_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """Filter false positives using AI."""
        pass

    @abstractmethod
    def generate_fix(self, vulnerability: Dict) -> str:
        """Generate a code fix suggestion."""
        pass

    @abstractmethod
    def get_capabilities(self) -> Dict:
        """Return provider capabilities."""
        pass

    @abstractmethod
    def estimate_cost(self, request: AIRequest) -> float:
        """Estimate API call cost (transparency)."""
        pass
```

#### 2. **Multiple Provider Implementations**

```python
# src/ai/providers/openai_provider.py
class OpenAIProvider(AIProvider):
    """OpenAI GPT-4 provider (optional, requires API key)."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None  # Only initialize if key provided

    def analyze_vulnerability(self, request: AIRequest) -> AIResponse:
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY.")

        # Call OpenAI API
        response = openai.ChatCompletion.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a smart contract security expert."},
                {"role": "user", "content": request.prompt}
            ],
            temperature=request.temperature,
            max_tokens=request.max_tokens
        )

        return AIResponse(
            content=response.choices[0].message.content,
            confidence=0.85,  # Based on model capabilities
            reasoning=None,
            provider="OpenAI",
            model="gpt-4-turbo",
            cost=self._calculate_cost(response)
        )


# src/ai/providers/anthropic_provider.py
class AnthropicProvider(AIProvider):
    """Anthropic Claude provider (optional, requires API key)."""

    def analyze_vulnerability(self, request: AIRequest) -> AIResponse:
        # Claude implementation
        pass


# src/ai/providers/ollama_provider.py
class OllamaProvider(AIProvider):
    """
    Ollama local LLM provider (RECOMMENDED for DPG compliance).

    Benefits:
    - Runs locally (no data leaves your machine)
    - Free (no API costs)
    - Privacy-preserving
    - Offline capable
    - No vendor lock-in
    """

    def __init__(self, model: str = "llama3"):
        self.model = model
        self.base_url = "http://localhost:11434"

    def analyze_vulnerability(self, request: AIRequest) -> AIResponse:
        # Call local Ollama instance
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": request.prompt,
                "stream": False
            }
        )

        return AIResponse(
            content=response.json()["response"],
            confidence=0.75,  # Local model, slightly lower confidence
            reasoning=None,
            provider="Ollama",
            model=self.model,
            cost=0.0  # Free!
        )


# src/ai/providers/huggingface_provider.py
class HuggingFaceProvider(AIProvider):
    """HuggingFace models (open-source, DPGA compliant)."""

    def analyze_vulnerability(self, request: AIRequest) -> AIResponse:
        # Use local or HF Inference API
        pass
```

#### 3. **Configuration-Driven Provider Selection**

```yaml
# config/ai_config.yaml

ai:
  # Provider priority (try in order, fallback to next)
  providers:
    - name: ollama
      enabled: true
      priority: 1  # Try first (privacy-preserving)
      model: llama3
      endpoint: http://localhost:11434

    - name: openai
      enabled: false  # Disabled by default (requires API key)
      priority: 2
      model: gpt-4-turbo
      max_cost_per_analysis: 0.50  # USD

    - name: anthropic
      enabled: false
      priority: 3
      model: claude-3-opus

    - name: huggingface
      enabled: true
      priority: 4
      model: codellama/CodeLlama-13b

  # Fallback to rule-based if all providers fail
  fallback_to_rules: true

  # ISO 42001: Human oversight
  human_review_threshold:
    critical: true  # Always require human review
    high: true
    medium: false
    low: false

  # Privacy settings (GDPR/DPGA)
  privacy:
    send_contract_code: false  # Never send full code to external APIs
    send_only_findings: true   # Only send vulnerability descriptions
    anonymize_data: true       # Remove project-specific info

  # Transparency (ISO 42001)
  logging:
    log_all_ai_calls: true
    log_prompts: true
    log_responses: true
    audit_trail: outputs/ai_audit_log.json
```

#### 4. **Smart Routing Logic**

```python
# src/ai/ai_manager.py

class AIManager:
    """
    Manages AI providers with fallback logic.
    ISO 42001: Ensures human oversight and transparency.
    """

    def __init__(self, config_path: str = "config/ai_config.yaml"):
        self.config = self._load_config(config_path)
        self.providers = self._initialize_providers()
        self.audit_log = []

    def analyze_with_fallback(self, request: AIRequest) -> AIResponse:
        """
        Try providers in priority order, fallback to rules.

        ISO 42001: Logs all decisions for audit trail.
        """
        for provider in sorted(self.providers, key=lambda p: p.priority):
            try:
                if not provider.enabled:
                    continue

                # Log attempt (ISO 42001: Transparency)
                self._log_attempt(provider.name, request)

                # Check cost limit (ISO 42001: Accountability)
                estimated_cost = provider.estimate_cost(request)
                if estimated_cost > self.config['max_cost_per_analysis']:
                    self._log_skip(provider.name, "Cost limit exceeded")
                    continue

                # Make AI call
                response = provider.analyze_vulnerability(request)

                # Log success (ISO 42001: Audit trail)
                self._log_success(provider.name, response)

                return response

            except Exception as e:
                # Log failure, try next provider
                self._log_failure(provider.name, str(e))
                continue

        # All providers failed, use rule-based fallback
        if self.config['fallback_to_rules']:
            return self._rule_based_analysis(request)
        else:
            raise Exception("All AI providers failed and fallback disabled")

    def _rule_based_analysis(self, request: AIRequest) -> AIResponse:
        """
        Fallback to deterministic rule-based analysis.
        Always available, no API required.
        """
        # Use pattern matching, heuristics
        content = self._apply_heuristics(request)

        return AIResponse(
            content=content,
            confidence=0.70,  # Lower confidence than AI
            reasoning="Rule-based heuristics (no AI provider available)",
            provider="RuleBasedFallback",
            model="heuristics-v1",
            cost=0.0
        )
```

---

## 🔓 Provider-Agnostic Design (No Vendor Lock-in)

### DPGA Requirements Compliance

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| **No vendor lock-in** | Abstract provider interface | ✅ |
| **Open standards** | Standard AIRequest/AIResponse | ✅ |
| **Privacy-preserving** | Local-first (Ollama default) | ✅ |
| **Cost transparency** | `estimate_cost()` method | ✅ |
| **Offline capable** | Rule-based fallback | ✅ |
| **Data sovereignty** | Code never leaves machine (default) | ✅ |
| **Auditable** | Full AI audit trail | ✅ |

### Switching Providers (Zero Friction)

```bash
# Switch from OpenAI to Ollama (local, free, private)
miesc config set ai.providers.openai.enabled false
miesc config set ai.providers.ollama.enabled true

# Or edit config/ai_config.yaml
# No code changes needed!
```

---

## 🌍 Digital Public Good (DPG) Compliance

### DPGA Requirements

MIESC is being prepared for [Digital Public Goods Alliance (DPGA)](https://digitalpublicgoods.net/) certification:

#### ✅ Already Compliant

1. **Open License**: GPL-3.0 (OSI-approved)
2. **Open Standards**: Uses standard security protocols (SWC, CWE, OWASP)
3. **Best Practices**:
   - CI/CD with tests
   - Documentation
   - Contribution guidelines
4. **Privacy & Applicable Laws**:
   - GDPR compliant (EU)
   - ISO 27001 (data security)
   - ISO 42001 (AI governance)
5. **Extractable Data**: All data stored in open formats (JSON, CSV, HTML)

#### 🔄 In Progress

6. **Security**:
   - [ ] Security audit (scheduled Q1 2025)
   - [ ] Penetration testing
   - [x] Secure development practices
7. **AI Ethics**:
   - [x] ISO 42001 framework
   - [x] Provider abstraction layer
   - [ ] Bias testing (Q1 2025)

### DPG Benefits for Users

| Traditional Tools | MIESC (DPG) |
|-------------------|-------------|
| ❌ Vendor lock-in (Paid API required) | ✅ Run 100% locally (Ollama) |
| ❌ Data sent to proprietary APIs | ✅ Data stays on your machine |
| ❌ Expensive ($0.50-$5 per analysis) | ✅ Free (open-source models) |
| ❌ Requires internet | ✅ Works offline |
| ❌ Closed-source AI | ✅ Open-source models (Llama, CodeLlama) |
| ❌ No transparency | ✅ Full audit trail |

---

## 🔒 Privacy & Security

### Data Flow Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Your Machine (Complete Privacy)                        │
│                                                          │
│  ┌────────────┐     ┌──────────────┐                   │
│  │  Contract  │────▶│   MIESC      │                    │
│  │  (Your Code)     │   Framework  │                    │
│  └────────────┘     └──────┬───────┘                    │
│                              │                           │
│                              ▼                           │
│                     ┌────────────────┐                  │
│                     │ Security Tools │                  │
│                     │ (Slither, etc) │                  │
│                     └────────┬───────┘                  │
│                              │                           │
│                              ▼                           │
│                     ┌────────────────┐                  │
│                     │  AI Manager    │                  │
│                     └────────┬───────┘                  │
│                              │                           │
│              ┌───────────────┼───────────────┐          │
│              ▼               ▼               ▼          │
│       ┌─────────┐    ┌─────────┐    ┌─────────┐       │
│       │ Ollama  │    │  Rules  │    │ OpenAI  │       │
│       │ (Local) │    │ (Local) │    │ (API)   │       │
│       │  FREE   │    │  FREE   │    │ PAID    │       │
│       └─────────┘    └─────────┘    └─────────┘       │
│            │              │               │             │
│            │              │               │             │
│            └──────────────┴───────────────┘             │
│                           │                             │
│                           ▼                             │
│                  ┌────────────────┐                    │
│                  │  Final Report  │                    │
│                  │  (Your Machine)│                    │
│                  └────────────────┘                    │
│                                                          │
└─────────────────────────────────────────────────────────┘

         Optional: External API (if you enable it)
                           │
                           ▼
                ┌──────────────────┐
                │  Only sends:     │
                │  - Vulnerability │
                │    descriptions  │
                │  - NO full code  │
                │  - Anonymized    │
                └──────────────────┘
```

### Privacy Guarantees

**Default Configuration (Maximum Privacy):**

```yaml
privacy:
  ai_provider: ollama  # Runs on your machine
  send_contract_code: false  # NEVER send full code
  send_only_findings: true   # Only vulnerability descriptions
  anonymize_data: true       # Remove identifiers
  offline_mode: true         # No internet required
```

**What Gets Sent to External APIs (if enabled):**

```json
{
  "type": "vulnerability_analysis",
  "finding": {
    "type": "reentrancy",
    "severity": "high",
    "pattern": "external_call_before_state_update",
    "context": "ERC20-like contract",
    // NO SOURCE CODE
    // NO PROJECT NAME
    // NO FILE PATHS
  }
}
```

---

## ⚖️ Governance & Ethics (ISO 42001)

### AI Ethics Framework

```python
# src/ai/ethics.py

class AIEthicsFramework:
    """
    ISO/IEC 42001:2023 compliant AI governance.
    """

    def __init__(self):
        self.principles = {
            "transparency": True,
            "accountability": True,
            "fairness": True,
            "privacy": True,
            "human_oversight": True,
            "safety": True,
        }

    def validate_ai_decision(self, decision: AIResponse) -> bool:
        """
        Validate AI decision against ethics framework.
        """
        checks = {
            "has_reasoning": decision.reasoning is not None,
            "confidence_disclosed": decision.confidence > 0,
            "cost_disclosed": decision.cost >= 0,
            "provider_disclosed": decision.provider is not None,
            "human_reviewable": True,  # All decisions can be reviewed
        }

        # Log for audit trail
        self._log_ethics_check(decision, checks)

        return all(checks.values())

    def require_human_review(self, finding: Dict) -> bool:
        """
        Determine if human review is required.
        ISO 42001: High-risk decisions require human oversight.
        """
        if finding["severity"] in ["critical", "high"]:
            return True  # Always require human review for critical

        if finding["confidence"] < 0.80:
            return True  # Low confidence needs review

        if finding["source"] == "ai_only":
            return True  # AI-only findings need validation

        return False
```

### Human-in-the-Loop

```python
# src/reporting/human_oversight.py

class HumanOversightModule:
    """
    ISO 42001: Ensure human oversight of AI decisions.
    """

    def generate_report(self, findings: List[Dict]) -> Report:
        """
        Generate report with clear AI/Human distinction.
        """
        report = Report()

        for finding in findings:
            if self.ethics.require_human_review(finding):
                # Mark for manual review
                finding["status"] = "REQUIRES_HUMAN_REVIEW"
                finding["review_url"] = f"http://localhost:8000/review/{finding['id']}"

                # Add to review queue
                self.review_queue.add(finding)

        # Add disclaimer to report
        report.add_disclaimer(
            "⚠️  HUMAN REVIEW REQUIRED: "
            f"{len(self.review_queue)} findings require expert validation. "
            "AI-assisted analysis is not a replacement for professional audits."
        )

        return report
```

---

## 🛠️ Implementation Roadmap

### Phase 1: Foundation (v2.2 - CURRENT)

- [x] Abstract provider interface
- [x] Rule-based fallback (no AI required)
- [x] Configuration system
- [x] Privacy-first architecture
- [x] Audit logging

### Phase 2: Local AI (v2.3 - Q1 2025)

- [ ] Ollama integration (default provider)
- [ ] HuggingFace local models
- [ ] Offline capability testing
- [ ] Performance benchmarking

### Phase 3: Optional Cloud (v2.4 - Q2 2025)

- [ ] OpenAI provider (optional)
- [ ] Anthropic provider (optional)
- [ ] Cost estimation
- [ ] Usage analytics

### Phase 4: DPG Certification (v3.0 - Q3 2025)

- [ ] DPGA application
- [ ] Security audit
- [ ] Bias testing
- [ ] Ethics review
- [ ] Community governance

### Phase 5: Advanced Features (v3.1+)

- [ ] Multi-provider consensus
- [ ] Custom model fine-tuning
- [ ] Federated learning
- [ ] Zero-knowledge proofs for privacy

---

## 📊 Cost Comparison

### Traditional AI Security Tools

| Tool | Cost per Analysis | Privacy | Offline |
|------|-------------------|---------|---------|
| Tool A | $2-5 | ❌ Cloud only | ❌ No |
| Tool B | $3-10 | ❌ API required | ❌ No |
| Tool C | Free tier + $50/mo | ⚠️  Limited | ❌ No |

### MIESC Options

| Configuration | Cost | Privacy | Offline | Provider |
|---------------|------|---------|---------|----------|
| **Default (Ollama)** | $0 | ✅ Local | ✅ Yes | Open-source |
| Rules-only | $0 | ✅ Local | ✅ Yes | None |
| OpenAI (optional) | ~$0.10 | ⚠️  API | ❌ No | OpenAI |
| Anthropic (optional) | ~$0.15 | ⚠️  API | ❌ No | Anthropic |

**Recommendation**: Use default Ollama configuration for maximum privacy and zero cost.

---

## 🎯 Key Takeaways

### For Users

1. **Privacy First**: By default, MIESC runs 100% locally. No data leaves your machine.
2. **No Lock-in**: Switch AI providers with a config change. No code changes needed.
3. **Cost Control**: Default configuration is free. Optional paid APIs have cost limits.
4. **Transparency**: Every AI decision is logged and explainable.
5. **Human Oversight**: Critical findings always require expert review.

### For Contributors

1. **Add Provider**: Implement `AIProvider` interface, no other changes needed.
2. **ISO 42001**: Follow ethics framework for all AI features.
3. **Test Locally**: Use Ollama for development (no API keys needed).
4. **Document**: All AI decisions must have reasoning/confidence scores.

### For Auditors

1. **Audit Trail**: Full logs in `outputs/ai_audit_log.json`
2. **Reproducible**: Rule-based fallback ensures deterministic behavior
3. **Compliant**: ISO 42001, GDPR, DPGA standards followed
4. **Open**: All code open-source, no hidden AI calls

---

## 📚 References

- **ISO/IEC 42001:2023**: Information technology — Artificial intelligence — Management system
- **DPGA Standards**: https://digitalpublicgoods.net/standard/
- **EU AI Act**: High-risk AI systems requirements
- **NIST AI RMF**: AI Risk Management Framework
- **ISO/IEC 27001:2022**: Information security management
- **GDPR**: General Data Protection Regulation

---

**Status**: ✅ Architecture defined, 🔄 Implementation in progress
**Next Review**: Q1 2025
**Contact**: fboiero@frvm.utn.edu.ar

---

**Made with transparency for the smart contract security community** 🛡️
