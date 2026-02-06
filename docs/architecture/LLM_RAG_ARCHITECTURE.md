# MIESC LLM & RAG Architecture

This document describes the LLM (Large Language Model) and RAG (Retrieval-Augmented Generation) architecture used in MIESC for AI-powered smart contract security analysis.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Diagrams](#component-diagrams)
3. [Data Flow](#data-flow)
4. [RAG Systems](#rag-systems)
5. [LLM Adapters](#llm-adapters)
6. [Metrics Framework](#metrics-framework)
7. [Expansion Roadmap](#expansion-roadmap)

---

## Architecture Overview

MIESC uses a multi-layered LLM architecture with optional RAG enrichment for vulnerability detection:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MIESC LLM Architecture                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌─────────────────────────────────────────────────┐    │
│  │  Contract   │───▶│              LLM ADAPTER LAYER                  │    │
│  │   (.sol)    │    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌───────┐  │    │
│  └─────────────┘    │  │SmartLLM │ │GPTLens  │ │BugScan  │ │GPTScan│  │    │
│                     │  │(Multi-  │ │(Auditor/│ │(Ensemble│ │(Single│  │    │
│                     │  │ stage)  │ │ Critic) │ │ Voting) │ │ pass) │  │    │
│                     │  └────┬────┘ └────┬────┘ └────┬────┘ └───┬───┘  │    │
│                     └───────┼──────────┼──────────┼──────────┼───────┘    │
│                             │          │          │          │            │
│                             ▼          ▼          ▼          ▼            │
│                     ┌─────────────────────────────────────────────────┐    │
│                     │              RAG ENRICHMENT LAYER               │    │
│                     │  ┌─────────────────┐  ┌────────────────────┐   │    │
│                     │  │  EmbeddingRAG   │  │  Keyword RAG       │   │    │
│                     │  │  (ChromaDB +    │  │  (BM25 fallback)   │   │    │
│                     │  │  Transformers)  │  │                    │   │    │
│                     │  └────────┬────────┘  └─────────┬──────────┘   │    │
│                     └───────────┼─────────────────────┼──────────────┘    │
│                                 │                     │                   │
│                                 ▼                     ▼                   │
│                     ┌─────────────────────────────────────────────────┐    │
│                     │           KNOWLEDGE BASE LAYER                  │    │
│                     │  ┌──────────┐ ┌──────────┐ ┌─────────────────┐  │    │
│                     │  │   SWC    │ │  CWE     │ │  Real-world     │  │    │
│                     │  │ Registry │ │ Database │ │  Exploits       │  │    │
│                     │  │ (30+)    │ │ (mapped) │ │  (DeFi hacks)   │  │    │
│                     │  └──────────┘ └──────────┘ └─────────────────┘  │    │
│                     └─────────────────────────────────────────────────┘    │
│                                                                             │
│                     ┌─────────────────────────────────────────────────┐    │
│                     │              LLM BACKEND LAYER                  │    │
│                     │  ┌─────────────┐ ┌─────────┐ ┌───────────────┐  │    │
│                     │  │   Ollama    │ │ OpenAI  │ │  Anthropic    │  │    │
│                     │  │  (local)    │ │ (cloud) │ │   (cloud)     │  │    │
│                     │  │ deepseek    │ │ gpt-4   │ │  claude-3.5   │  │    │
│                     │  │ codellama   │ │ gpt-4o  │ │  claude-3     │  │    │
│                     │  └─────────────┘ └─────────┘ └───────────────┘  │    │
│                     └─────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Diagrams

### 1. EmbeddingRAG System (ChromaDB)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         EmbeddingRAG Architecture                        │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────┐        ┌──────────────────────────────────────┐   │
│   │   Input Query   │        │        Vulnerability Knowledge       │   │
│   │  (contract code │        │              Base (30+)              │   │
│   │   or finding)   │        │  ┌────────────────────────────────┐  │   │
│   └────────┬────────┘        │  │ SWC-107: Reentrancy (4 types)  │  │   │
│            │                 │  │ SWC-105: Unprotected Withdraw  │  │   │
│            ▼                 │  │ SWC-115: tx.origin Auth        │  │   │
│   ┌─────────────────┐        │  │ SWC-104: Unchecked Return      │  │   │
│   │  Sentence       │        │  │ SWC-101: Integer Overflow      │  │   │
│   │  Transformer    │        │  │ Flash Loan Attack              │  │   │
│   │  (all-MiniLM-   │        │  │ Oracle Manipulation            │  │   │
│   │   L6-v2)        │        │  │ Sandwich Attack                │  │   │
│   │  384-dim embed  │        │  │ Price Manipulation             │  │   │
│   └────────┬────────┘        │  │ ERC-777 Hooks                  │  │   │
│            │                 │  │ Proxy Storage Collision        │  │   │
│            ▼                 │  │ + 19 more patterns...          │  │   │
│   ┌─────────────────┐        │  └────────────────────────────────┘  │   │
│   │    ChromaDB     │◀───────┤                                      │   │
│   │   Vector Store  │        │  Each pattern contains:              │   │
│   │  (cosine sim.)  │        │  • SWC/CWE identifiers               │   │
│   │                 │        │  • Title & description               │   │
│   │  ~/.miesc/      │        │  • Vulnerable code example           │   │
│   │  chromadb/      │        │  • Fixed code example                │   │
│   └────────┬────────┘        │  • Attack scenario                   │   │
│            │                 │  • Severity (CRITICAL→LOW)           │   │
│            ▼                 │  • Real exploit references           │   │
│   ┌─────────────────┐        │  • Semantic tags                     │   │
│   │  Search Results │        └──────────────────────────────────────┘   │
│   │  (top-k, with   │                                                   │
│   │   similarity    │                                                   │
│   │   scores)       │                                                   │
│   └─────────────────┘                                                   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2. HybridRAG System (Embedding + BM25)

```
┌────────────────────────────────────────────────────────────────────────┐
│                          HybridRAG Architecture                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│                        ┌─────────────────┐                             │
│                        │   Input Query   │                             │
│                        └────────┬────────┘                             │
│                                 │                                      │
│                    ┌────────────┴────────────┐                         │
│                    ▼                         ▼                         │
│           ┌────────────────┐        ┌────────────────┐                 │
│           │  EmbeddingRAG  │        │    BM25Okapi   │                 │
│           │   (ChromaDB)   │        │  (rank-bm25)   │                 │
│           │                │        │                │                 │
│           │ Semantic match │        │ Lexical match  │                 │
│           │ (meaning)      │        │ (keywords)     │                 │
│           └───────┬────────┘        └───────┬────────┘                 │
│                   │                         │                          │
│                   │   ┌─────────────────┐   │                          │
│                   └──▶│  Score Fusion   │◀──┘                          │
│                       │                 │                              │
│                       │  final_score =  │                              │
│                       │  0.7 × embed +  │                              │
│                       │  0.3 × bm25     │                              │
│                       └────────┬────────┘                              │
│                                │                                       │
│                                ▼                                       │
│                       ┌─────────────────┐                              │
│                       │ Ranked Results  │                              │
│                       │ (best of both)  │                              │
│                       └─────────────────┘                              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 3. SmartLLM Multi-Stage Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                    SmartLLM Adapter Architecture                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────┐                                                   │
│  │  Contract Code  │                                                   │
│  └────────┬────────┘                                                   │
│           │                                                            │
│           ▼                                                            │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    STAGE 1: GENERATOR                          │   │
│  │  ┌──────────────────┐                                          │   │
│  │  │ LLM (deepseek-   │  Prompt: Analyze for vulnerabilities     │   │
│  │  │ coder:6.7b)      │  Temperature: 0.2 (deterministic)        │   │
│  │  │                  │  Output: Raw findings JSON               │   │
│  │  └────────┬─────────┘                                          │   │
│  └───────────┼────────────────────────────────────────────────────┘   │
│              │                                                         │
│              ▼                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    RAG CONTEXT INJECTION                       │   │
│  │                                                                │   │
│  │  ┌────────────────┐        ┌─────────────────────┐             │   │
│  │  │ EmbeddingRAG   │───────▶│ Vulnerability       │             │   │
│  │  │ search()       │        │ context for each    │             │   │
│  │  └────────────────┘        │ finding             │             │   │
│  │                            │ - Similar SWCs      │             │   │
│  │  ┌────────────────┐        │ - Attack scenarios  │             │   │
│  │  │ smartllm_rag_  │───────▶│ - Code examples     │             │   │
│  │  │ knowledge      │        │ - ERC standards     │             │   │
│  │  └────────────────┘        └──────────┬──────────┘             │   │
│  └───────────────────────────────────────┼────────────────────────┘   │
│                                          │                            │
│                                          ▼                            │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    STAGE 2: VERIFICATOR                        │   │
│  │  ┌──────────────────┐                                          │   │
│  │  │ LLM (codellama:  │  Prompt: Validate findings with context  │   │
│  │  │ 7b)              │  Temperature: 0.1 (critical/strict)      │   │
│  │  │                  │  Output: Validated findings + confidence │   │
│  │  └────────┬─────────┘                                          │   │
│  └───────────┼────────────────────────────────────────────────────┘   │
│              │                                                         │
│              ▼                                                         │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    STAGE 3: CONSENSUS                          │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │ Cross-validation:                                        │  │   │
│  │  │ • Compare Generator vs Verificator findings              │  │   │
│  │  │ • Adjust confidence based on agreement                   │  │   │
│  │  │ • Filter false positives                                 │  │   │
│  │  │ • Merge duplicate findings                               │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│              │                                                         │
│              ▼                                                         │
│  ┌─────────────────┐                                                   │
│  │ Final Findings  │  High-confidence, validated vulnerabilities       │
│  └─────────────────┘                                                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 4. LLMBugScanner Ensemble Voting

```
┌────────────────────────────────────────────────────────────────────────┐
│                   LLMBugScanner Ensemble Architecture                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────┐                                                   │
│  │  Contract Code  │                                                   │
│  └────────┬────────┘                                                   │
│           │                                                            │
│           ▼                                                            │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                    PARALLEL LLM INFERENCE                       │   │
│  │                                                                 │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │   │
│  │  │   Model 1      │  │   Model 2      │  │   Model 3      │    │   │
│  │  │  deepseek-     │  │  codellama:    │  │  mistral:      │    │   │
│  │  │  coder:6.7b    │  │  7b            │  │  7b            │    │   │
│  │  │                │  │                │  │                │    │   │
│  │  │  Weight: 45%   │  │  Weight: 35%   │  │  Weight: 20%   │    │   │
│  │  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘    │   │
│  │          │                   │                   │              │   │
│  │          ▼                   ▼                   ▼              │   │
│  │     [Findings A]        [Findings B]        [Findings C]        │   │
│  └──────────┼───────────────────┼───────────────────┼──────────────┘   │
│             │                   │                   │                  │
│             └───────────────────┼───────────────────┘                  │
│                                 ▼                                      │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                      VOTING ENGINE                              │   │
│  │                                                                 │   │
│  │  For each unique finding:                                       │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │ votes = sum(model_weights where model detected finding)  │  │   │
│  │  │                                                          │  │   │
│  │  │ if votes >= threshold (50%):                             │  │   │
│  │  │     finding.status = CONFIRMED                           │  │   │
│  │  │     finding.confidence = votes / total_weight            │  │   │
│  │  │ else:                                                    │  │   │
│  │  │     finding.status = REJECTED                            │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └────────────────────────────────────────────────────────────────┘   │
│                                 │                                      │
│                                 ▼                                      │
│  ┌─────────────────┐                                                   │
│  │ Consensus       │  Only findings with ≥50% weighted agreement       │
│  │ Findings        │                                                   │
│  └─────────────────┘                                                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 5. GPTLens Dual-Role Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                     GPTLens Adapter Architecture                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌─────────────────┐                                                   │
│  │  Contract Code  │                                                   │
│  └────────┬────────┘                                                   │
│           │                                                            │
│           ▼                                                            │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                       AUDITOR ROLE                              │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │ LLM: deepseek-coder:6.7b                                 │  │   │
│  │  │                                                          │  │   │
│  │  │ Prompt: "As a security auditor, analyze this contract    │  │   │
│  │  │         for vulnerabilities. Be thorough and report      │  │   │
│  │  │         all potential issues."                           │  │   │
│  │  │                                                          │  │   │
│  │  │ Output: Comprehensive findings list (may include FPs)    │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────┬────────────────────────────────┘   │
│                                  │                                     │
│                                  ▼                                     │
│  ┌────────────────────────────────────────────────────────────────┐   │
│  │                        CRITIC ROLE                              │   │
│  │  ┌──────────────────────────────────────────────────────────┐  │   │
│  │  │ LLM: codellama:7b                                        │  │   │
│  │  │                                                          │  │   │
│  │  │ Prompt: "As a security critic, review these findings     │  │   │
│  │  │         and determine which are valid. Remove false      │  │   │
│  │  │         positives and assess real risk."                 │  │   │
│  │  │                                                          │  │   │
│  │  │ Input: Auditor findings + original contract              │  │   │
│  │  │ Output: Filtered findings with validation reasoning      │  │   │
│  │  └──────────────────────────────────────────────────────────┘  │   │
│  └───────────────────────────────┬────────────────────────────────┘   │
│                                  │                                     │
│                                  ▼                                     │
│  ┌─────────────────┐                                                   │
│  │ Validated       │  Critic-approved findings only                    │
│  │ Findings        │                                                   │
│  └─────────────────┘                                                   │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### Complete Analysis Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        MIESC Analysis Data Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  INPUT                                                                      │
│  ┌─────────────┐                                                            │
│  │ Contract.sol│                                                            │
│  └──────┬──────┘                                                            │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ ADAPTER SELECTION                                                    │  │
│  │ (based on audit profile: quick, standard, full)                      │  │
│  └───────────────────────────────────┬──────────────────────────────────┘  │
│                                      │                                      │
│         ┌────────────────────────────┼────────────────────────────┐        │
│         │                            │                            │        │
│         ▼                            ▼                            ▼        │
│  ┌─────────────┐            ┌─────────────┐             ┌─────────────┐    │
│  │ Static      │            │ LLM         │             │ Formal      │    │
│  │ Analyzers   │            │ Adapters    │             │ Verifiers   │    │
│  │ (slither,   │            │ (smartllm,  │             │ (halmos,    │    │
│  │  mythril)   │            │  gptlens)   │             │  certora)   │    │
│  └──────┬──────┘            └──────┬──────┘             └──────┬──────┘    │
│         │                          │                           │           │
│         │                          ▼                           │           │
│         │           ┌───────────────────────────────┐          │           │
│         │           │ RAG ENRICHMENT                │          │           │
│         │           │ ┌─────────────────────────┐   │          │           │
│         │           │ │ EmbeddingRAG.search()   │   │          │           │
│         │           │ │ - Query: contract code  │   │          │           │
│         │           │ │ - Retrieve: SWC patterns│   │          │           │
│         │           │ │ - Enrich: LLM prompts   │   │          │           │
│         │           │ └─────────────────────────┘   │          │           │
│         │           └───────────────┬───────────────┘          │           │
│         │                           │                          │           │
│         │                           ▼                          │           │
│         │           ┌───────────────────────────────┐          │           │
│         │           │ LLM BACKEND (Ollama/OpenAI)   │          │           │
│         │           │ - Generate analysis           │          │           │
│         │           │ - Parse JSON response         │          │           │
│         │           └───────────────┬───────────────┘          │           │
│         │                           │                          │           │
│         └────────────────┬──────────┴──────────┬───────────────┘           │
│                          │                     │                            │
│                          ▼                     ▼                            │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ FINDING AGGREGATION                                                  │  │
│  │ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐  │  │
│  │ │ Normalize    │ │ Deduplicate  │ │ Map SWC/CWE  │ │ Score        │  │  │
│  │ │ format       │ │ findings     │ │ identifiers  │ │ confidence   │  │  │
│  │ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘  │  │
│  └───────────────────────────────────┬──────────────────────────────────┘  │
│                                      │                                      │
│                                      ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │ POST-PROCESSING (Optional)                                           │  │
│  │ ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐   │  │
│  │ │ Finding Validator │ │ Remediation Gen   │ │ OpenLLaMA Helper  │   │  │
│  │ │ (LLM validation)  │ │ (code fixes)      │ │ (enhancements)    │   │  │
│  │ └───────────────────┘ └───────────────────┘ └───────────────────┘   │  │
│  └───────────────────────────────────┬──────────────────────────────────┘  │
│                                      │                                      │
│  OUTPUT                              ▼                                      │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ FINAL REPORT                                                       │    │
│  │ • Findings with SWC/CWE mapping                                    │    │
│  │ • Confidence scores                                                │    │
│  │ • Remediation recommendations                                      │    │
│  │ • CVSS scores                                                      │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## RAG Systems

### Comparison Table

| Feature | EmbeddingRAG | HybridRAG | Keyword RAG |
|---------|--------------|-----------|-------------|
| **Search Method** | Cosine similarity | Embedding + BM25 | BM25 only |
| **Storage** | ChromaDB (persistent) | ChromaDB + memory | In-memory |
| **Embedding Model** | all-MiniLM-L6-v2 | all-MiniLM-L6-v2 | N/A |
| **Dimensions** | 384 | 384 | N/A |
| **Dependencies** | chromadb, sentence-transformers | + rank-bm25 | rank-bm25 |
| **Semantic Understanding** | High | High | Low |
| **Keyword Matching** | Weak | Strong | Strong |
| **Speed** | Fast | Medium | Fastest |
| **Use Case** | Semantic similarity | Best of both worlds | Fallback |

### Knowledge Base Content

The RAG knowledge base contains **30+ vulnerability patterns**:

#### SWC Registry Patterns
- SWC-107: Reentrancy (4 variants: single, cross-function, cross-contract, read-only)
- SWC-105: Unprotected Ether Withdrawal
- SWC-115: Authorization through tx.origin
- SWC-104: Unchecked Call Return Value
- SWC-101: Integer Overflow/Underflow
- SWC-112: Delegatecall to Untrusted Callee
- SWC-106: Unprotected SELFDESTRUCT
- SWC-116: Block Values as Time Proxy
- SWC-120: Weak Sources of Randomness

#### DeFi-Specific Patterns
- Flash Loan Attack
- Oracle Manipulation
- Sandwich Attack
- Price Manipulation
- Front-running
- MEV Exploitation

#### Advanced Patterns
- ERC-777 Hooks Attack
- Proxy Storage Collision
- UUPS Upgrade Vulnerability
- Fee-on-Transfer Token Issues
- Rebasing Token Issues

---

## LLM Adapters

### Adapter Comparison Matrix

| Adapter | Architecture | Models | RAG Type | Strengths | Weaknesses |
|---------|-------------|--------|----------|-----------|------------|
| **SmartLLM** | Multi-stage | deepseek + codellama | EmbeddingRAG + Keyword | Low false positives, thorough | Slower |
| **GPTLens** | Dual-role | deepseek + codellama | Pattern-based | Critic filtering reduces FPs | Two LLM calls |
| **LLMBugScanner** | Ensemble | 3 models | EmbeddingRAG | Consensus voting | Highest latency |
| **GPTScan** | Single-pass | codellama | EmbeddingRAG | Fast, semantic | May miss complex issues |
| **LlamaAudit** | Single-pass | codellama | SWC mapping | Simple, reliable | Less thorough |
| **LLMSmartAudit** | Single-pass | codellama | EmbeddingRAG | Balanced | Average performance |

### RAG Integration Status

```
┌─────────────────────────────────────────────────────────────────┐
│                    RAG Integration Status                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Adapter          │ EmbeddingRAG │ Keyword RAG │ No RAG        │
│  ─────────────────┼──────────────┼─────────────┼───────────────│
│  SmartLLM         │     ✓        │      ✓      │               │
│  GPTScan          │     ✓        │             │               │
│  LLMSmartAudit    │     ✓        │             │               │
│  LLMBugScanner    │     ✓        │             │               │
│  PropertyGPT      │     ✓        │             │               │
│  GPTLens          │              │             │      ✓        │
│  LlamaAudit       │              │      ✓      │               │
│                                                                 │
│  Legend:                                                        │
│  ✓ = Integrated and active                                     │
│  (empty) = Not integrated                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Metrics Framework

### Key Performance Indicators (KPIs)

To measure RAG effectiveness, implement these metrics:

#### 1. Retrieval Quality Metrics

```python
# Precision@K: How many retrieved docs are relevant?
precision_at_k = relevant_retrieved / k

# Recall@K: How many relevant docs were retrieved?
recall_at_k = relevant_retrieved / total_relevant

# Mean Reciprocal Rank: Position of first relevant result
mrr = 1 / rank_of_first_relevant

# Normalized Discounted Cumulative Gain
ndcg = dcg / ideal_dcg
```

#### 2. Detection Quality Metrics

```python
# True Positive Rate (Sensitivity)
tpr = true_positives / (true_positives + false_negatives)

# False Positive Rate
fpr = false_positives / (false_positives + true_negatives)

# Precision
precision = true_positives / (true_positives + false_positives)

# F1 Score
f1 = 2 * (precision * recall) / (precision + recall)
```

#### 3. RAG Impact Metrics

```python
# RAG Improvement Score
rag_improvement = (f1_with_rag - f1_without_rag) / f1_without_rag

# Context Relevance Score (0-1)
# Measured by LLM judging if retrieved context helped
context_relevance = helpful_contexts / total_contexts

# Hallucination Reduction Rate
hallucination_reduction = (hallucinations_baseline - hallucinations_rag) / hallucinations_baseline
```

### Proposed Evaluation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RAG Evaluation Pipeline                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │ Ground Truth    │  Dataset of contracts with known vulnerabilities       │
│  │ Dataset         │  (labeled with SWC IDs, locations, severity)           │
│  └────────┬────────┘                                                        │
│           │                                                                 │
│           ▼                                                                 │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ A/B TESTING                                                        │    │
│  │                                                                    │    │
│  │  ┌─────────────────────┐      ┌─────────────────────┐              │    │
│  │  │ Control Group       │      │ Treatment Group     │              │    │
│  │  │ (RAG disabled)      │      │ (RAG enabled)       │              │    │
│  │  │                     │      │                     │              │    │
│  │  │ LLM Adapter         │      │ LLM Adapter         │              │    │
│  │  │ - No RAG context    │      │ - EmbeddingRAG      │              │    │
│  │  │ - Baseline prompt   │      │ - Enriched prompt   │              │    │
│  │  └──────────┬──────────┘      └──────────┬──────────┘              │    │
│  │             │                            │                         │    │
│  │             ▼                            ▼                         │    │
│  │     [Findings A]                  [Findings B]                     │    │
│  └─────────────┼────────────────────────────┼─────────────────────────┘    │
│                │                            │                              │
│                └────────────┬───────────────┘                              │
│                             ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ METRIC COMPUTATION                                                 │    │
│  │                                                                    │    │
│  │  For each group, compute:                                          │    │
│  │  • True positives (correct detections)                             │    │
│  │  • False positives (incorrect detections)                          │    │
│  │  • False negatives (missed vulnerabilities)                        │    │
│  │  • Precision, Recall, F1                                           │    │
│  │  • Average inference time                                          │    │
│  │  • Token usage                                                     │    │
│  └───────────────────────────────┬────────────────────────────────────┘    │
│                                  │                                         │
│                                  ▼                                         │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │ RESULTS DASHBOARD                                                  │    │
│  │                                                                    │    │
│  │  ┌─────────────────────────────────────────────────────────────┐  │    │
│  │  │ Metric          │ Without RAG │ With RAG  │ Improvement    │  │    │
│  │  │ ────────────────┼─────────────┼───────────┼────────────────│  │    │
│  │  │ Precision       │   0.65      │   0.78    │   +20%         │  │    │
│  │  │ Recall          │   0.72      │   0.85    │   +18%         │  │    │
│  │  │ F1 Score        │   0.68      │   0.81    │   +19%         │  │    │
│  │  │ Avg Latency     │   2.3s      │   2.8s    │   +22%         │  │    │
│  │  │ False Positives │   35        │   22      │   -37%         │  │    │
│  │  └─────────────────────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Expansion Roadmap

### Phase 1: Measurement Foundation (Current)

- [x] Implement EmbeddingRAG with ChromaDB
- [x] Integrate RAG into 5/6 LLM adapters
- [ ] Create ground truth dataset (50+ labeled contracts)
- [ ] Implement A/B testing framework
- [ ] Add metrics collection to adapters

### Phase 2: Knowledge Base Expansion

- [ ] Expand from 30 to 100+ vulnerability patterns
- [ ] Add protocol-specific patterns (Aave, Compound, Uniswap)
- [ ] Include historical exploit data (rekt.news integration)
- [ ] Add gas optimization patterns
- [ ] Create adapter-specific knowledge bases

### Phase 3: Advanced RAG Features

- [ ] Implement multi-hop retrieval (chain related patterns)
- [ ] Add re-ranking with cross-encoder
- [ ] Implement query expansion (synonyms, related terms)
- [ ] Add context compression for long documents
- [ ] Create feedback loop for knowledge base updates

### Phase 4: Model Optimization

- [ ] Fine-tune embedding model on security corpus
- [ ] Create security-specific tokenizer
- [ ] Implement speculative decoding
- [ ] Add model quantization (GGUF support)
- [ ] Create smaller distilled models

### Proposed File Structure for Metrics

```
src/evaluation/
├── __init__.py
├── ground_truth.py         # Dataset management
├── metrics.py              # Metric computation
├── ab_testing.py           # A/B test framework
├── rag_evaluator.py        # RAG-specific evaluation
├── dashboard.py            # Results visualization
└── data/
    ├── labeled_contracts/  # Ground truth contracts
    └── results/            # Evaluation results
```

---

## Quick Reference

### Enable/Disable RAG

```python
# Disable RAG (for A/B testing)
export MIESC_DISABLE_RAG=1

# Force specific RAG type
export MIESC_RAG_TYPE=hybrid  # embedding, keyword, hybrid
```

### Monitor RAG Performance

```python
# In adapter code
if self._embedding_rag:
    results = self._embedding_rag.search(query, n_results=5)
    logger.info(f"RAG retrieved {len(results)} patterns")
    for r in results:
        logger.debug(f"  - {r.document.swc_id}: {r.score:.3f}")
```

### Add Custom Vulnerability Pattern

```python
from src.llm.embedding_rag import EmbeddingRAG, VulnerabilityDocument

rag = EmbeddingRAG()
rag.add_custom_vulnerability(VulnerabilityDocument(
    id="custom-001",
    swc_id="SWC-XXX",
    title="Custom Vulnerability",
    description="Description of the vulnerability...",
    severity="HIGH",
    category="defi",
    vulnerable_code="function vulnerable() { ... }",
    fixed_code="function safe() { ... }",
))
```

---

*Document Version: 1.0.0*
*Last Updated: 2026-02-06*
*Author: Claude Code (AI Assistant)*
