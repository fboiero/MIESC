# Master's Thesis

<div align="center">

![Thesis](https://img.shields.io/badge/Thesis-Master's%20Degree-blue?style=for-the-badge)
![Year](https://img.shields.io/badge/Year-2024--2025-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In%20Progress-orange?style=for-the-badge)

**Integrated Security Assessment Framework for Smart Contracts:**
**A Defense-in-Depth Approach to Cyberdefense**

*Master's Degree in Cyberdefense*

**English** | [Espanol](thesis_es.md)

[Back to Home](index.md)

</div>

---

## Thesis Information

| Field | Value |
|-------|-------|
| **Title** | Integrated Security Assessment Framework for Smart Contracts: A Defense-in-Depth Approach to Cyberdefense |
| **Author** | Fernando Boiero |
| **Advisor** | M.Sc. Eduardo Casanovas |
| **Institution** | Universidad de la Defensa Nacional (UNDEF) - IUA Cordoba |
| **Program** | Master's Degree in Cyberdefense |
| **Expected Defense** | Q4 2025 |

---

## Abstract

This thesis presents **MIESC (Multi-layer Intelligent Evaluation for Smart Contracts)**, a production-grade security framework that implements a **7-layer Defense-in-Depth architecture** for comprehensive smart contract vulnerability detection.

The framework integrates **25 specialized security tools** with **AI-powered correlation** using sovereign LLMs (Ollama) and **ML-based detection** (DA-GNN Graph Neural Networks), achieving **94.5% precision**, **92.8% recall**, and an **F1-score of 0.93**.

Key innovations include:
- Triple normalization system (SWC/CWE/OWASP) with 97.1% accuracy
- MCP Protocol integration for AI assistant interoperability
- Sovereign AI backend ensuring data never leaves the user's machine
- Legacy tool rescue for deprecated but valuable security tools

---

## Chapters

### Part I: Foundations

| Chapter | Title | Description |
|---------|-------|-------------|
| 1 | [Introduction](tesis/en/CHAPTER_INTRODUCTION.md) | Problem statement, objectives, and thesis structure |
| 2 | [Theoretical Framework](tesis/en/CHAPTER_THEORETICAL_FRAMEWORK.md) | Blockchain, smart contracts, and security fundamentals |
| 3 | [State of the Art](tesis/en/CHAPTER_STATE_OF_THE_ART.md) | Existing tools, frameworks, and research |

### Part II: Implementation

| Chapter | Title | Description |
|---------|-------|-------------|
| 4 | [Development](tesis/en/CHAPTER_DEVELOPMENT.md) | MIESC architecture, agents, and implementation details |
| 5 | [Experimental Results](tesis/en/CHAPTER_RESULTS.md) | Benchmarks, metrics, and comparative analysis |

### Part III: Justification

| Chapter | Title | Description |
|---------|-------|-------------|
| 6 | [AI and Sovereign LLM Justification](tesis/en/CHAPTER_AI_JUSTIFICATION.md) | Data sovereignty, Ollama integration, DPGA compliance |
| 7 | [MCP Protocol Justification](tesis/en/CHAPTER_MCP_JUSTIFICATION.md) | Model Context Protocol, tool handlers, interoperability |

### Part IV: Conclusions

| Chapter | Title | Description |
|---------|-------|-------------|
| 8 | [Future Work](tesis/en/CHAPTER_FUTURE_WORK.md) | Research directions, planned enhancements |

---

## Key Metrics

### Framework Performance (v4.0.0)

| Metric | Value |
|--------|-------|
| **Precision** | 94.5% |
| **Recall** | 92.8% |
| **F1-Score** | 0.93 |
| **False Positive Rate** | 5.5% |
| **Detection Coverage** | 96% |
| **Integrated Tools** | 25 |
| **Defense Layers** | 7 |
| **Compliance Index** | 91.4% |

### ML Detection (DA-GNN)

| Metric | Value |
|--------|-------|
| **Accuracy** | 95.7% |
| **False Positive Rate** | 4.3% |
| **Graph Representation** | CFG + DFG |

---

## Research Contributions

1. **7-Layer Defense-in-Depth Architecture** - Novel multi-layer approach combining static, dynamic, symbolic, formal, AI, ML, and audit layers

2. **25 Tool Integration** - Unified ToolAdapter protocol for seamless tool interoperability

3. **Triple Normalization System** - SWC/CWE/OWASP mapping with 97.1% accuracy

4. **Sovereign AI Backend** - Ollama integration ensuring data sovereignty and $0 operational cost

5. **MCP Server** - Model Context Protocol for AI assistant integration

6. **Legacy Tool Rescue** - Manticore Python 3.11 compatibility, Oyente Docker containerization

---

## Citation

```bibtex
@mastersthesis{boiero2025miesc,
  author = {Boiero, Fernando},
  title = {{MIESC}: Multi-layer Intelligent Evaluation for Smart Contracts},
  school = {Universidad de la Defensa Nacional (UNDEF)},
  year = {2025},
  type = {Master's Thesis},
  address = {Cordoba, Argentina},
  note = {Master's Degree in Cyberdefense}
}
```

---

<div align="center">

[View Full Documentation](index.md) | [GitHub Repository](https://github.com/fboiero/MIESC)

---

**MIESC v4.0.0** | Master's Thesis in Cyberdefense | UNDEF - IUA Cordoba

2024-2025 Fernando Boiero

</div>
