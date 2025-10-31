# CAPÍTULO 5 – METODOLOGÍA PROPUESTA: FRAMEWORK XAUDIT

## 5.1 Descripción General del Framework

### 5.1.1 Visión y Objetivos

**Xaudit** es un framework de auditoría híbrido que integra análisis estático, fuzzing, testing, verificación formal e inteligencia artificial para maximizar la detección de vulnerabilidades críticas en contratos inteligentes EVM, reduciendo simultáneamente falsos positivos y tiempo de análisis.

**Principios de Diseño:**

1. **Defensa en Profundidad:** Múltiples capas de análisis complementarias
2. **Automatización Máxima:** Pipeline completamente automatizado desde código hasta reporte
3. **Inteligencia Contextual:** IA para priorización y clasificación de hallazgos
4. **Reproducibilidad:** Configuración versionada, ejecución determinística
5. **Extensibilidad:** Arquitectura modular para agregar nuevas herramientas
6. **CI/CD Native:** Integración nativa con GitHub Actions y GitLab CI

### 5.1.2 Arquitectura General

```
┌─────────────────────────────────────────────────────────────────┐
│                    XAUDIT FRAMEWORK ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  INPUT: Smart Contract Repository                               │
│  └─> src/*.sol, test/*.sol, foundry.toml                       │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 1: STATIC ANALYSIS                       │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Slither (90+ detectors)                              │  │ │
│  │  │ └─> Output: slither_results.json (200-500 findings) │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 2: PROPERTY ANNOTATION                   │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Scribble (optional)                                  │  │ │
│  │  │ └─> Instrumentar contratos con invariantes          │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 3: FUZZING                               │ │
│  │  ┌──────────────┐         ┌──────────────┐                 │ │
│  │  │   Echidna    │         │    Medusa    │                 │ │
│  │  │   (100k runs)│         │  (coverage)  │                 │ │
│  │  └──────────────┘         └──────────────┘                 │ │
│  │         │                         │                         │ │
│  │         └────────────┬────────────┘                         │ │
│  │                      ▼                                      │ │
│  │            echidna_results.txt                              │ │
│  │            medusa_results.json                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 4: TESTING                               │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Foundry                                              │  │ │
│  │  │ ├─> Unit tests                                       │  │ │
│  │  │ ├─> Fuzz tests (10k runs)                           │  │ │
│  │  │ ├─> Invariant tests                                 │  │ │
│  │  │ └─> Gas profiling                                   │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 5: FORMAL VERIFICATION (Optional)        │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Certora Prover                                       │  │ │
│  │  │ └─> Verificar top 5 funciones críticas             │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 6: AI TRIAGE & CLASSIFICATION            │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ AI Assistant (GPT-4o-mini / Llama 3.2)              │  │ │
│  │  │ ├─> Clasificar severidad contextual                 │  │ │
│  │  │ ├─> Estimar false positive likelihood               │  │ │
│  │  │ ├─> Calcular exploitability score                   │  │ │
│  │  │ ├─> Generar recomendaciones                         │  │ │
│  │  │ └─> Priorizar hallazgos (1-10)                      │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                         │                                        │
│                         ▼                                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              PHASE 7: REPORT GENERATION                     │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ Metrics Dashboard                                    │  │ │
│  │  │ ├─> HTML dashboard con visualizaciones              │  │ │
│  │  │ ├─> PDF executive summary                           │  │ │
│  │  │ ├─> JSON/CSV de métricas                            │  │ │
│  │  │ └─> Markdown report detallado                       │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  OUTPUT: Consolidated Security Report                           │
│  ├─> analysis/dashboard/index.html                             │
│  ├─> analysis/reports/executive_summary.pdf                    │
│  ├─> analysis/reports/detailed_findings.md                     │
│  └─> analysis/metrics.json                                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.1.3 Flujo de Ejecución

**Modo Completo (Full Analysis):**
```bash
./run_full_analysis.sh --contracts src/contracts/ --output analysis/results
```

**Tiempo estimado:** 1-2 horas para contrato mediano (<1000 SLOC)

**Fases ejecutadas:**
1. Static Analysis (Slither): ~30 segundos
2. Property Annotation (Scribble): ~1 minuto (opcional)
3. Fuzzing (Echidna + Medusa): ~30-45 minutos
4. Testing (Foundry): ~5-10 minutos
5. Formal Verification (Certora): ~20-40 minutos (opcional)
6. AI Triage: ~2-5 minutos
7. Report Generation: ~30 segundos

**Modo Rápido (Fast Analysis):**
```bash
./run_full_analysis.sh --fast --contracts src/contracts/
```

Ejecuta solo: Slither + Foundry + AI Triage (~5 minutos)

## 5.2 Pipeline Híbrido de Análisis

### 5.2.1 Fase 1: Análisis Estático (Slither)

**Objetivo:** Cobertura completa del código, identificación rápida de patrones vulnerables.

**Configuración:**

```json
// slither.config.json
{
  "detectors_to_run": [
    "reentrancy-eth",
    "reentrancy-no-eth",
    "unprotected-upgrade",
    "suicidal",
    "uninitialized-state",
    "controlled-delegatecall",
    "arbitrary-send-eth",
    "tx-origin",
    "timestamp",
    "weak-prng"
  ],
  "detectors_to_exclude": [
    "naming-convention",
    "solc-version",
    "pragma"
  ],
  "exclude_informational": false,
  "exclude_low": false,
  "json": "analysis/slither/results.json",
  "markdown": "analysis/slither/results.md"
}
```

**Ejecución:**

```bash
slither . \
    --config-file slither.config.json \
    --solc-remaps "@openzeppelin=node_modules/@openzeppelin" \
    --filter-paths "test|mock|lib" \
    --json analysis/slither/results.json
```

**Output Esperado:**

```json
{
  "success": true,
  "results": {
    "detectors": [
      {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "Reentrancy in Vault.withdraw()...",
        "elements": [...],
        "first_markdown_element": "...",
        "markdown": "..."
      }
    ]
  }
}
```

**Criterios de Filtrado Inicial:**

- **Excluir:** Contratos en `test/`, `mock/`, `lib/`
- **Priorizar:** `impact=High` + `confidence=High|Medium`
- **Guardar:** Todos los findings para análisis posterior de IA

### 5.2.2 Fase 2: Anotación de Propiedades (Scribble - Opcional)

**Objetivo:** Agregar invariantes ejecutables para runtime verification.

**Ejemplo de Anotación:**

```solidity
contract Vault {
    mapping(address => uint256) public balances;

    /// #invariant {:msg "Contract solvency"}
    ///     address(this).balance >= sumOfBalances;

    /// #if_succeeds {:msg "Deposit increases balance"}
    ///     old(balances[msg.sender]) + msg.value == balances[msg.sender];
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// #if_succeeds {:msg "Withdraw decreases balance"}
    ///     old(balances[msg.sender]) == balances[msg.sender] + amount;
    /// #if_succeeds {:msg "Balance never negative"}
    ///     balances[msg.sender] >= 0;
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
```

**Instrumentación:**

```bash
scribble --arm \
    --output-mode files \
    --instrumentation-metadata-file analysis/scribble/metadata.json \
    src/contracts/*.sol
```

**Uso en Fuzzing:**
- Echidna/Medusa ejecutan versión instrumentada
- Violaciones de invariantes detectadas como reverts

### 5.2.3 Fase 3: Fuzzing Paralelo

**Estrategia Dual: Echidna + Medusa**

**Echidna (Property-Based):**

```yaml
# analysis/echidna/config.yaml
testMode: property
testLimit: 100000
shrinkLimit: 5000
seqLen: 100
timeout: 1800  # 30 minutos
coverage: true
corpusDir: "analysis/echidna/corpus"
format: text
workers: 4

# Configuración de senders
deployer: "0x30000"
sender: ["0x10000", "0x20000", "0x30000"]

# Diccionario de valores interesantes
constants:
  - 0
  - 1
  - "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  - 1000000000000000000  # 1 ether
```

**Ejecución:**

```bash
echidna src/contracts/properties/VaultProperties.sol \
    --config analysis/echidna/config.yaml \
    --contract VaultProperties \
    > analysis/echidna/results.txt 2>&1
```

**Medusa (Coverage-Guided):**

```json
// analysis/medusa/medusa.json
{
  "fuzzing": {
    "workers": 10,
    "testLimit": 100000,
    "timeout": 1800,
    "coverageEnabled": true,
    "corpusDirectory": "analysis/medusa/corpus",
    "targetContracts": ["VaultProperties"],
    "deployerAddress": "0x30000",
    "senderAddresses": ["0x10000", "0x20000", "0x30000"]
  },
  "compilation": {
    "platform": "crytic-compile",
    "platformConfig": {
      "target": ".",
      "solcVersion": "0.8.20"
    }
  },
  "chainConfig": {
    "codeSizeCheckDisabled": true,
    "cheatCodeConfig": {
      "cheatCodesEnabled": true,
      "enableFFI": false
    }
  }
}
```

**Ejecución:**

```bash
medusa fuzz \
    --config analysis/medusa/medusa.json \
    --compilation-target src/contracts/properties/VaultProperties.sol \
    > analysis/medusa/results.txt 2>&1
```

**Criterios de Éxito:**

- **Echidna:** Todas las propiedades `echidna_*` retornan `true`
- **Medusa:** Cobertura de código >90%, propiedades no violadas
- **Corpus:** Guardar secuencias interesantes para regression testing

### 5.2.4 Fase 4: Testing con Foundry

**Test Suite Estructura:**

```
test/
├── unit/
│   ├── Vault.t.sol              # Unit tests básicos
│   └── ERC4626.t.sol
├── fuzz/
│   ├── VaultFuzz.t.sol          # Fuzz tests con bounds
│   └── ERC4626Fuzz.t.sol
├── invariant/
│   ├── VaultInvariant.t.sol     # Invariant tests con handlers
│   └── handlers/
│       └── VaultHandler.sol
└── integration/
    └── VaultIntegration.t.sol   # Tests de integración
```

**Ejecución Completa:**

```bash
# Unit tests
forge test --match-path "test/unit/**/*.sol" -vvv

# Fuzz tests (10k runs)
forge test --match-path "test/fuzz/**/*.sol" --fuzz-runs 10000 -vvv

# Invariant tests
forge test --match-path "test/invariant/**/*.sol" \
    --invariant-runs 1000 \
    --invariant-depth 100 \
    -vvv

# Gas report
forge test --gas-report

# Coverage
forge coverage --report lcov
```

**Métricas Recolectadas:**

```json
{
  "tests": {
    "total": 150,
    "passed": 148,
    "failed": 2,
    "skipped": 0
  },
  "fuzz": {
    "runs": 10000,
    "failures": 0
  },
  "invariants": {
    "total": 12,
    "runs_per_invariant": 1000,
    "depth": 100,
    "failures": 0
  },
  "coverage": {
    "lines": "94.7%",
    "branches": "87.3%",
    "functions": "96.2%"
  },
  "gas": {
    "deposit": {"avg": 45234, "max": 48123},
    "withdraw": {"avg": 32112, "max": 35890}
  }
}
```

### 5.2.5 Fase 5: Verificación Formal (Certora - Opcional)

**Criterio de Selección:**

Solo aplicar Certora a:
1. Funciones que manejan fondos (withdraw, transfer)
2. Funciones con lógica matemática crítica (liquidaciones, precios)
3. Top 5 funciones por riesgo (identificadas por Slither + AI)

**Especificación CVL:**

```cvl
// analysis/certora/specs/Vault.spec

using ERC20 as asset;

methods {
    function deposit(uint256, address) external returns (uint256);
    function withdraw(uint256, address, address) external returns (uint256);
    function balances(address) external returns (uint256) envfree;
    function totalAssets() external returns (uint256) envfree;
}

// Invariante: Solvencia del contrato
invariant contractSolvency()
    to_mathint(nativeBalances[currentContract]) >= sumOfBalances()

// Rule: Withdraw no puede drenar más que el balance del usuario
rule withdrawBounded(address user, uint256 amount) {
    env e;
    require e.msg.sender == user;

    uint256 balanceBefore = balances(user);

    withdraw@withrevert(e, amount, user, user);

    assert !lastReverted => amount <= balanceBefore,
        "Cannot withdraw more than balance";
}

// Ghost function para sumar balances
ghost mathint sumOfBalances() {
    init_state axiom sumOfBalances() == 0;
}

hook Sstore balances[KEY address user] uint256 newBalance
    (uint256 oldBalance) STORAGE {
    havoc sumOfBalances assuming
        sumOfBalances@new() == sumOfBalances@old() + newBalance - oldBalance;
}
```

**Ejecución:**

```bash
certoraRun src/contracts/Vault.sol \
    --verify Vault:analysis/certora/specs/Vault.spec \
    --solc solc-0.8.20 \
    --optimistic_loop \
    --loop_iter 3 \
    --msg "Vault solvency verification" \
    > analysis/certora/results.txt 2>&1
```

**Tiempo estimado:** 20-40 minutos por spec

**Output:**

- **VERIFIED:** Propiedad matemáticamente demostrada ✅
- **VIOLATED:** Contraejemplo generado ❌
- **TIMEOUT:** Incrementar resources o simplificar spec ⏱️

### 5.2.6 Fase 6: Triage con Inteligencia Artificial

**Objetivo:** Reducir falsos positivos, priorizar hallazgos críticos, generar recomendaciones.

**Input:** Findings de Slither, Echidna, Medusa, Foundry, Certora

**Proceso de Clasificación:**

```python
# analysis/scripts/ai_assistant.py

class AIAssistant:
    def classify_finding(self, finding: Dict) -> Classification:
        """
        Clasifica un finding usando LLM.

        Returns:
            - severity: CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL/FALSE_POSITIVE
            - impact_score: 0-10 (daño real estimado)
            - exploitability: 0-10 (facilidad de explotación)
            - false_positive_likelihood: 0.0-1.0
            - priority: 1-10 (para ordenamiento)
            - recommendation: String con mitigación
            - poc_hint: Sugerencia de exploit (si aplica)
        """
        prompt = f"""
        Analiza esta vulnerabilidad de smart contract:

        **Detector:** {finding['check']}
        **Impact Original:** {finding['impact']}
        **Confidence:** {finding['confidence']}
        **Descripción:** {finding['description'][:500]}

        **Contexto del Contrato:**
        - Tipo: {self.contract_context['type']}  # DeFi, NFT, DAO, etc.
        - TVL estimado: ${self.contract_context['tvl']}
        - Complejidad: {self.contract_context['complexity']} SLOC

        **Tu tarea:**
        1. Evaluar si es FALSE_POSITIVE (muchos detectores tienen alta tasa)
        2. Si es real, clasificar severidad CRÍTICA/ALTA/MEDIA/BAJA
        3. Estimar impacto económico real (0-10)
        4. Estimar facilidad de explotación (0-10, donde 10=trivial)
        5. Calcular probabilidad de false positive (0.0-1.0)
        6. Dar recomendación específica de mitigación
        7. Si CRÍTICO/ALTO, sugerir approach de PoC

        Responde en JSON:
        {{
          "severity": "...",
          "impact_score": X.X,
          "exploitability": X.X,
          "false_positive_likelihood": 0.X,
          "priority": X,
          "recommendation": "...",
          "poc_hint": "..."
        }}
        """

        response = self.llm.chat(prompt)
        return parse_json(response)
```

**Ejemplo de Clasificación:**

```json
// Finding de Slither: reentrancy-eth en withdraw()
{
  "original": {
    "check": "reentrancy-eth",
    "impact": "High",
    "confidence": "Medium",
    "description": "Reentrancy in Vault.withdraw()..."
  },
  "ai_classification": {
    "severity": "CRITICAL",
    "impact_score": 9.5,
    "exploitability": 8.0,
    "false_positive_likelihood": 0.05,
    "priority": 10,
    "recommendation": "Apply Checks-Effects-Interactions pattern: update balances[msg.sender] BEFORE external call. Alternative: use OpenZeppelin ReentrancyGuard.",
    "poc_hint": "Create attacker contract with receive() that calls withdraw() again. Drain contract with loop."
  }
}
```

**Priorización Final:**

```python
def prioritize_findings(findings: List[Finding]) -> List[Finding]:
    """
    Prioriza findings por riesgo real.

    Priority Score = (severity_weight * 2) + impact + exploitability - (fp_likelihood * 10)

    Severity weights:
    - CRITICAL: 10
    - HIGH: 7
    - MEDIUM: 4
    - LOW: 2
    - INFORMATIONAL: 1
    - FALSE_POSITIVE: 0
    """
    for f in findings:
        sev_weight = SEVERITY_WEIGHTS[f.severity]
        f.priority = int(
            (sev_weight * 2) +
            f.impact_score +
            f.exploitability -
            (f.false_positive_likelihood * 10)
        )

    return sorted(findings, key=lambda x: x.priority, reverse=True)
```

### 5.2.7 Fase 7: Generación de Reportes

**Outputs Generados:**

**1. HTML Dashboard Interactivo:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Xaudit Security Report</title>
    <style>
        /* Estilos del dashboard */
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Xaudit Analysis Report</h1>
        <div class="metrics">
            <div class="metric critical">
                <div class="value">3</div>
                <div class="label">Critical Issues</div>
            </div>
            <div class="metric high">
                <div class="value">8</div>
                <div class="label">High Issues</div>
            </div>
            <!-- Más métricas -->
        </div>

        <div class="charts">
            <img src="severity_distribution.png" />
            <img src="test_results.png" />
            <img src="coverage.png" />
        </div>

        <div class="findings">
            <h2>Prioritized Findings</h2>
            <!-- Lista de findings ordenados por priority -->
        </div>
    </div>
</body>
</html>
```

**2. Executive Summary (PDF):**

```markdown
# Executive Security Summary

**Contract:** Vault.sol
**Analysis Date:** 2025-01-15
**Xaudit Version:** 1.0.0

## Overall Risk Rating: HIGH ⚠️

### Key Findings
- **3 Critical vulnerabilities** requiring immediate attention
- **8 High-severity issues** to be addressed before deployment
- **94.7% code coverage** achieved through testing
- **12 invariants verified** via formal methods

### Critical Issues
1. **Reentrancy in withdraw()** - PRIORITY 10/10
   - Can drain entire contract balance
   - PoC: Attacker contract with recursive call
   - Mitigation: Implement checks-effects-interactions

2. **Unprotected withdrawAll()** - PRIORITY 9/10
   - Anyone can withdraw all funds
   - Missing onlyOwner modifier
   - Mitigation: Add access control

3. **Integer overflow in unchecked block** - PRIORITY 8/10
   - Can mint unlimited tokens
   - Arithmetic in unchecked{} without bounds
   - Mitigation: Remove unchecked or add require()

### Recommendations
1. Do NOT deploy until Critical issues resolved
2. Conduct manual audit of priority >7 findings
3. Implement formal verification for fund-handling functions
4. Add comprehensive monitoring post-deployment

### Testing Summary
- ✅ 148/150 tests passed (98.7%)
- ✅ 100,000 fuzz runs (0 failures)
- ✅ 12 invariants maintained
- ⚠️ 2 test failures in edge cases

### Next Steps
[ ] Fix 3 critical vulnerabilities
[ ] Re-run Xaudit pipeline
[ ] Professional audit by security firm
[ ] Deploy to testnet with monitoring
```

**3. Detailed Findings (Markdown):**

```markdown
# Detailed Findings Report

## [XAUDIT-001] Reentrancy in Vault.withdraw()

**Severity:** CRITICAL (Priority: 10/10)
**Detector:** Slither `reentrancy-eth`
**Confidence:** High
**AI Classification:**
- Impact Score: 9.5/10
- Exploitability: 8.0/10
- False Positive Likelihood: 5%

### Description
External call to `msg.sender` is made before updating `balances[msg.sender]`, allowing reentrant calls.

### Location
`src/contracts/Vault.sol:45-50`

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // ❌ External call
    require(success);
    balances[msg.sender] -= amount;  // ❌ State update AFTER call
}
```

### Proof of Concept
```solidity
contract Attacker {
    Vault victim;
    uint256 count;

    receive() external payable {
        if (count++ < 10) {
            victim.withdraw(1 ether);  // Reentrant call
        }
    }

    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw(1 ether);
        // Result: Drained 10 ether with only 1 ether deposited
    }
}
```

### Impact
- **Financial:** Can drain entire contract balance
- **Probability:** HIGH (easily exploitable)
- **Users Affected:** All users

### Recommendation
Apply **Checks-Effects-Interactions** pattern:

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);  // Checks
    balances[msg.sender] -= amount;            // Effects
    (bool success, ) = msg.sender.call{value: amount}("");  // Interactions
    require(success);
}
```

Alternative: Use OpenZeppelin `ReentrancyGuard`

```solidity
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    function withdraw(uint256 amount) external nonReentrant {
        // ...
    }
}
```

### References
- SWC-107: Reentrancy
- CWE-841: Improper Enforcement of Behavioral Workflow
- [The DAO Hack (2016) - $60M loss](https://example.com)

---

<!-- Más findings... -->
```

**4. Métricas JSON:**

```json
{
  "summary": {
    "total_findings": 53,
    "critical": 3,
    "high": 8,
    "medium": 15,
    "low": 18,
    "informational": 9,
    "false_positives": 12,
    "analysis_time_minutes": 87
  },
  "tools": {
    "slither": {
      "findings": 45,
      "time_seconds": 28
    },
    "echidna": {
      "properties_tested": 15,
      "violated": 0,
      "time_seconds": 1847
    },
    "medusa": {
      "coverage": "94.7%",
      "runs": 100000,
      "time_seconds": 453
    },
    "foundry": {
      "tests_passed": 148,
      "tests_failed": 2,
      "gas_avg_deploy": 1234567,
      "time_seconds": 342
    },
    "certora": {
      "rules_verified": 5,
      "rules_violated": 0,
      "time_seconds": 2345
    },
    "ai_triage": {
      "findings_classified": 53,
      "false_positives_identified": 12,
      "time_seconds": 187
    }
  },
  "coverage": {
    "lines": 94.7,
    "branches": 87.3,
    "functions": 96.2
  },
  "prioritized_findings": [
    {
      "id": "XAUDIT-001",
      "severity": "CRITICAL",
      "priority": 10,
      "check": "reentrancy-eth",
      "contract": "Vault",
      "function": "withdraw",
      "impact_score": 9.5,
      "exploitability": 8.0,
      "false_positive_likelihood": 0.05
    }
  ]
}
```

## 5.3 Módulo de Inteligencia Artificial

### 5.3.1 Arquitectura del Módulo de IA

**Componentes:**

1. **Finding Classifier:** Clasifica severidad y FP likelihood
2. **Exploitability Estimator:** Calcula facilidad de explotación
3. **Impact Analyzer:** Estima daño económico potencial
4. **Recommendation Generator:** Genera mitigaciones específicas
5. **Summary Generator:** Crea executive summaries

**Modelos Soportados:**

| Proveedor | Modelo | Velocidad | Costo | Precisión |
|-----------|--------|-----------|-------|-----------|
| OpenAI | gpt-4o-mini | Rápido | Bajo | Alta |
| OpenAI | gpt-4o | Lento | Alto | Muy Alta |
| Ollama | llama3.2 (8B) | Medio | Gratis | Media-Alta |
| Ollama | mistral (7B) | Medio | Gratis | Media |
| Anthropic | claude-3-haiku | Rápido | Medio | Alta |

**Recomendación:** `gpt-4o-mini` para balance costo/performance

### 5.3.2 Prompts Engineering

**System Prompt:**

```
You are an expert smart contract security auditor with 10+ years of experience in Ethereum, Solidity, and EVM security. You specialize in:

- Identifying real vulnerabilities vs false positives
- Estimating exploitability and financial impact
- Providing actionable mitigation strategies
- Generating proof-of-concept exploits

When analyzing findings:
1. Consider the contract context (DeFi, NFT, DAO, etc.)
2. Evaluate actual risk vs theoretical risk
3. Be conservative: prefer false positives over false negatives for critical issues
4. Provide specific, implementable recommendations
5. Reference known exploits (The DAO, Parity, Ronin, etc.) when relevant

Respond ONLY in valid JSON format as specified.
```

**Classification Prompt Template:**

```
Analyze this smart contract vulnerability:

**Finding Details:**
- Detector: {detector_name}
- Original Severity: {original_severity}
- Confidence: {confidence}
- Description: {description}
- Contract: {contract_name}
- Function: {function_name}

**Contract Context:**
- Type: {contract_type}  # DeFi/NFT/DAO/Governance/Oracle
- Estimated TVL: ${tvl}
- Complexity: {sloc} SLOC
- External Calls: {external_calls_count}
- Critical Functions: {critical_functions}

**Additional Context:**
- Similar findings in codebase: {similar_count}
- OpenZeppelin imports: {oz_imports}
- Access control pattern: {access_control}

**Task:**
Provide a comprehensive security assessment in JSON:

{{
  "is_false_positive": boolean,
  "false_positive_reasoning": "string (if true)",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL",
  "severity_reasoning": "string",
  "impact_score": float (0-10, financial damage),
  "exploitability": float (0-10, ease of exploit),
  "attack_complexity": "LOW|MEDIUM|HIGH",
  "prerequisites": ["string"],
  "attack_vector": "string (how to exploit)",
  "poc_hint": "string (exploit approach)",
  "recommendation": "string (specific mitigation)",
  "references": ["SWC-XXX", "CWE-XXX", "Historical exploit"],
  "priority": int (1-10, 10=highest)
}}

Be precise and actionable.
```

### 5.3.3 False Positive Reduction

**Estrategia Multi-Factor:**

```python
def calculate_false_positive_likelihood(finding, context):
    """
    Calcula probabilidad de FP usando múltiples señales.
    """
    fp_score = 0.0

    # Factor 1: Detector histórico FP rate
    detector_fp_rates = {
        "reentrancy-benign": 0.60,
        "arbitrary-send-eth": 0.45,
        "controlled-delegatecall": 0.40,
        "reentrancy-eth": 0.10,
        "suicidal": 0.05
    }
    fp_score += detector_fp_rates.get(finding.check, 0.20)

    # Factor 2: Confidence del detector
    confidence_adjustment = {
        "High": -0.15,
        "Medium": 0.00,
        "Low": +0.20
    }
    fp_score += confidence_adjustment[finding.confidence]

    # Factor 3: Patrones de código conocidos
    if has_reentrancy_guard(finding.function):
        fp_score += 0.30  # Probablemente protegido

    if has_access_control(finding.function):
        fp_score += 0.25  # Probablemente protegido

    # Factor 4: Validación cruzada con otras herramientas
    if not confirmed_by_fuzzing(finding):
        fp_score += 0.15  # No se pudo explotar con fuzzing

    if verified_safe_by_certora(finding):
        fp_score += 0.40  # Formal verification confirms safety

    # Factor 5: AI assessment
    ai_fp_likelihood = ai_assistant.assess_false_positive(finding)
    fp_score = (fp_score * 0.6) + (ai_fp_likelihood * 0.4)

    return min(1.0, max(0.0, fp_score))
```

**Resultados Esperados:**

- Reducción de FP: 40-50% vs Slither standalone
- Precision increase: 60% → 85%+
- Recall mantenido: >95% (no perder vulnerabilidades reales)

## 5.4 Integración CI/CD

### 5.4.1 GitHub Actions Workflow

```yaml
# .github/workflows/xaudit.yml
name: Xaudit Security Analysis

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  quick-analysis:
    name: Quick Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 10

    steps:
      - uses: actions/checkout@v3
        with:
          submodules: recursive

      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1

      - name: Install Slither
        run: pip3 install slither-analyzer

      - name: Run Slither
        run: |
          slither . --json slither-report.json || true

      - name: Run Foundry Tests
        run: |
          forge test --gas-report

      - name: AI Triage (Fast Mode)
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          python analysis/scripts/ai_assistant.py \
            --input slither-report.json \
            --output ai-triage.md \
            --fast

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            slither-report.json
            ai-triage.md

      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const triage = fs.readFileSync('ai-triage.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔍 Xaudit Security Analysis\n\n${triage}`
            });

  full-analysis:
    name: Full Security Analysis
    runs-on: ubuntu-latest
    timeout-minutes: 120
    if: github.ref == 'refs/heads/main'

    steps:
      - uses: actions/checkout@v3

      - name: Setup Analysis Environment
        run: |
          # Install all tools
          pip3 install slither-analyzer mythril
          curl -L https://foundry.paradigm.xyz | bash
          foundryup

      - name: Run Full Xaudit Pipeline
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          ./run_full_analysis.sh \
            --contracts src/contracts/ \
            --output analysis/results/$(date +%Y%m%d_%H%M%S)

      - name: Generate Dashboard
        run: |
          python src/utils/metrics_dashboard.py \
            --results analysis/results/latest \
            --output analysis/dashboard

      - name: Deploy Dashboard to GitHub Pages
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./analysis/dashboard

      - name: Create Issue for Critical Findings
        if: steps.xaudit.outputs.critical_count > 0
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '🚨 Critical Security Issues Detected',
              body: 'Xaudit found critical vulnerabilities. Check the dashboard.',
              labels: ['security', 'critical']
            });
```

### 5.4.2 Pre-commit Hooks

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "Running Xaudit quick scan..."

# Run Slither on staged files
git diff --cached --name-only --diff-filter=ACMR | grep ".sol$" | while read file; do
    echo "Analyzing $file..."
    slither "$file" --json /tmp/slither-quick.json 2>/dev/null || true
done

# Check for critical findings
CRITICAL=$(jq '[.results.detectors[] | select(.impact=="High")] | length' /tmp/slither-quick.json)

if [ "$CRITICAL" -gt 0 ]; then
    echo "❌ Found $CRITICAL critical issues. Commit blocked."
    echo "Run 'slither .' for details or use --no-verify to bypass."
    exit 1
fi

echo "✅ Quick scan passed"
exit 0
```

## 5.5 Configuración y Deployment

### 5.5.1 Instalación

```bash
# Clone repository
git clone https://github.com/fboiero/MIESC.git
cd xaudit

# Install Python dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install Echidna (via Homebrew on macOS)
brew install echidna

# Install Medusa
go install github.com/crytic/medusa@latest

# Configure API keys
cp .env.example .env
# Edit .env and add OPENAI_API_KEY or configure Ollama
```

### 5.5.2 Configuración

```toml
# xaudit.toml
[project]
name = "MyDeFiProtocol"
version = "1.0.0"
contracts_path = "src/contracts"
tests_path = "test"
output_path = "analysis/results"

[tools]
slither = { enabled = true, config = "analysis/slither/config.json" }
echidna = { enabled = true, config = "analysis/echidna/config.yaml", timeout = 1800 }
medusa = { enabled = true, config = "analysis/medusa/medusa.json", timeout = 1800 }
foundry = { enabled = true, fuzz_runs = 10000, invariant_runs = 1000 }
certora = { enabled = false, critical_only = true }  # Expensive, optional

[ai]
provider = "openai"  # or "ollama"
model = "gpt-4o-mini"
temperature = 0.3
max_tokens = 1500

[reporting]
formats = ["html", "pdf", "markdown", "json"]
dashboard = { enabled = true, port = 8080 }
```

## 5.6 Síntesis del Capítulo

Este capítulo presentó la metodología completa del framework Xaudit:

1. **Pipeline Híbrido:** 7 fases integradas (estático, fuzzing, testing, formal, AI, reporting)
2. **Automatización:** Completamente automatizado con `run_full_analysis.sh`
3. **IA para Triage:** Reducción de FP en 40%, priorización inteligente
4. **Integración CI/CD:** GitHub Actions, pre-commit hooks
5. **Reportes Múltiples:** HTML dashboard, PDF summary, Markdown detailed, JSON metrics

**Próximo Capítulo:** Implementación experimental y validación del framework.

---

**Referencias del Capítulo**

1. Trail of Bits. (2023). "Building Secure Contracts"
2. OpenAI. (2024). "GPT-4 Technical Report"
3. Paradigm. (2023). "Foundry Book"
4. Certora. (2023). "CVL Tutorial"
5. GitHub. (2024). "GitHub Actions Documentation"
