# CAPÍTULO 6 – IMPLEMENTACIÓN Y EXPERIMENTOS

## 6.1 Entorno Experimental

### 6.1.1 Infraestructura Técnica

**Hardware:**
- **CPU:** Intel Core i9-12900K (16 cores, 24 threads) / Apple M2 Max
- **RAM:** 64 GB DDR5
- **Storage:** 2 TB NVMe SSD
- **GPU:** NVIDIA RTX 4090 (opcional, para modelos LLM locales)

**Software:**
- **OS:** Ubuntu 22.04 LTS / macOS Sonoma 14.2
- **Solidity Compiler:** solc 0.8.20-0.8.26
- **Python:** 3.11.7
- **Node.js:** 20.11.0
- **Go:** 1.21.6 (para Medusa)
- **Rust:** 1.75.0 (para Foundry)

**Versiones de Herramientas:**

| Herramienta | Versión | Fecha Release |
|-------------|---------|---------------|
| Slither | 0.10.0 | 2024-01-15 |
| Mythril | 0.24.8 | 2024-03-15 |
| Manticore | 0.3.7 | 2024-02-28 |
| Surya | 0.4.7 | 2023-12-10 |
| Solhint | 4.1.1 | 2024-01-25 |
| Echidna | 2.2.3 | 2024-01-20 |
| Medusa | 0.1.3 | 2024-02-15 |
| Foundry | nightly-2024-03-01 | 2024-03-01 |
| Certora | 5.0.5 | 2024-02-10 |
| OpenAI API | gpt-4o-mini | 2024-07-18 |

### 6.1.2 Dataset de Contratos Vulnerables

**Diseño del Dataset:**

El dataset comprende **35 contratos inteligentes** distribuidos en 7 categorías de vulnerabilidades:

| Categoría | SWC ID | Contratos | SLOC Total | Descripción |
|-----------|--------|-----------|------------|-------------|
| **Reentrancy** | SWC-107 | 6 | 450 | Variantes: simple, cross-function, read-only |
| **Access Control** | SWC-105 | 5 | 320 | Missing modifiers, tx.origin, delegatecall |
| **Arithmetic** | SWC-101 | 4 | 280 | Unchecked blocks, precision loss |
| **Proxy Patterns** | SWC-109 | 6 | 680 | Uninitialized, storage collision, selector clash |
| **ERC-4626** | Custom | 5 | 520 | Inflation attack, rounding errors |
| **Oracle** | Custom | 5 | 610 | Spot price manipulation, stale data |
| **Real-World** | Mixed | 4 | 2840 | Simplified versions de protocolos auditados |

**Total:** 35 contratos, ~5,700 SLOC

#### Categoría 1: Reentrancy (6 contratos)

**1.1 BasicReentrancy.sol** (SWC-107)
```solidity
// Reentrancy clásica
// Vulnerable: withdraw() con external call antes de state update
// Exploit: Attacker contract con receive() que re-entra
// SLOC: 75
```

**1.2 CrossFunctionReentrancy.sol**
```solidity
// Reentrancy cross-function
// Vulnerable: withdrawAll() llama a otra función vulnerable
// Más difícil de detectar: requiere análisis inter-funcional
// SLOC: 95
```

**1.3 ReadOnlyReentrancy.sol**
```solidity
// Read-only reentrancy
// Vulnerable: View functions leen state inconsistente
// Exploitable en protocolos que dependen de oracle externo
// SLOC: 110
```

**1.4 ERC721Reentrancy.sol**
```solidity
// Reentrancy via onERC721Received callback
// Vulnerable: safeTransferFrom con state update tardío
// SLOC: 85
```

**1.5 ERC777Reentrancy.sol**
```solidity
// Reentrancy via tokensReceived hook
// Vulnerable: ERC777 send con callback antes de balance update
// SLOC: 65
```

**1.6 ReentrancySecure.sol**
```solidity
// Implementación segura para comparación
// Patterns: Checks-Effects-Interactions, ReentrancyGuard
// SLOC: 80
```

#### Categoría 2: Access Control (5 contratos)

**2.1 UnprotectedWithdraw.sol** (SWC-105)
```solidity
// Missing access control en función crítica
// Vulnerable: withdrawAll() sin onlyOwner
// SLOC: 60
```

**2.2 TxOriginAuth.sol** (SWC-115)
```solidity
// tx.origin usado para autenticación
// Vulnerable: Phishing attack via intermediary contract
// SLOC: 70
```

**2.3 DelegateCallAuth.sol**
```solidity
// Delegatecall sin whitelist
// Vulnerable: Ejecutar código arbitrario en contexto del contract
// SLOC: 95
```

**2.4 UninitializedOwner.sol**
```solidity
// Owner sin inicializar
// Vulnerable: Primera llamada puede tomar ownership
// SLOC: 45
```

**2.5 AccessControlSecure.sol**
```solidity
// Implementación segura con OpenZeppelin AccessControl
// Roles: ADMIN, OPERATOR, PAUSER
// SLOC: 120
```

#### Categoría 3: Arithmetic (4 contratos)

**3.1 UncheckedMath.sol** (SWC-101)
```solidity
// Overflow/underflow en bloque unchecked
// Vulnerable: Aritmética sin bounds checking en Solidity 0.8+
// SLOC: 65
```

**3.2 PrecisionLoss.sol**
```solidity
// División antes de multiplicación
// Vulnerable: Rounding errors acumulativos
// SLOC: 80
```

**3.3 SignedIntegerOverflow.sol**
```solidity
// Overflow con signed integers
// Vulnerable: int256 overflow en unchecked
// SLOC: 70
```

**3.4 ArithmeticSecure.sol**
```solidity
// Implementación segura
// Patterns: SafeMath equivalents, bounds checking
// SLOC: 95
```

#### Categoría 4: Proxy Patterns (6 contratos)

**4.1 UninitializedProxy.sol** (SWC-109)
```solidity
// Logic contract sin initializer protection
// Vulnerable: Attacker inicializa implementation directamente
// SLOC: 110
```

**4.2 StorageCollision.sol**
```solidity
// Storage layout mismatch entre proxy y logic
// Vulnerable: Variables sobrescriben slots críticos
// SLOC: 130
```

**4.3 FunctionSelectorClash.sol**
```solidity
// Selector clash entre proxy y logic
// Vulnerable: Funciones con mismo selector 4-byte
// SLOC: 95
```

**4.4 UnprotectedUpgrade.sol**
```solidity
// Upgrade function sin access control
// Vulnerable: Cualquiera puede cambiar implementation
// SLOC: 85
```

**4.5 ConstructorInLogic.sol**
```solidity
// Constructor en logic contract
// Vulnerable: Constructor no se ejecuta en proxy context
// SLOC: 75
```

**4.6 ProxySecure.sol**
```solidity
// UUPS proxy seguro con OpenZeppelin
// Patterns: Initializable, UUPSUpgradeable
// SLOC: 185
```

#### Categoría 5: ERC-4626 Vaults (5 contratos)

**5.1 InflationAttack.sol**
```solidity
// First depositor share inflation attack
// Vulnerable: Depositar 1 wei, donar masivo, víctima recibe 0 shares
// SLOC: 140
```

**5.2 RoundingExploit.sol**
```solidity
// Rounding errors en convertToShares/Assets
// Vulnerable: Pérdida de fondos por redondeo hacia abajo
// SLOC: 130
```

**5.3 ReentrancyVault.sol**
```solidity
// Reentrancy en deposit/withdraw de vault
// Vulnerable: Callback en antes de mint/burn
// SLOC: 125
```

**5.4 FlashLoanAttack.sol**
```solidity
// Manipulación de share price via flash loan
// Vulnerable: totalAssets manipulable
// SLOC: 155
```

**5.5 SecureVault.sol**
```solidity
// ERC-4626 seguro con virtual shares
// Mitigations: OpenZeppelin ERC4626, dead shares
// SLOC: 170
```

#### Categoría 6: Oracle Manipulation (5 contratos)

**6.1 SpotPriceOracle.sol**
```solidity
// Oracle usando spot price de Uniswap
// Vulnerable: Flash loan para manipular reserves
// SLOC: 120
```

**6.2 StaleOracle.sol**
```solidity
// Oracle sin staleness check
// Vulnerable: Usar precios desactualizados
// SLOC: 95
```

**6.3 SingleSourceOracle.sol**
```solidity
// Dependencia de un solo oracle
// Vulnerable: Single point of failure
// SLOC: 80
```

**6.4 OracleRounding.sol**
```solidity
// Precision loss en conversión de precios
// Vulnerable: Rounding en liquidaciones
// SLOC: 110
```

**6.5 SecureOracle.sol**
```solidity
// Oracle seguro con TWAP y Chainlink fallback
// Patterns: Time-weighted average, multi-source
// SLOC: 205
```

#### Categoría 7: Casos Reales Simplificados (4 contratos)

**7.1 SimplifiedCompound.sol**
```solidity
// Lending protocol simplificado
// Vulnerabilidades: Oracle manipulation, interest rate exploit
// Basado en: Compound Finance
// SLOC: 780
```

**7.2 SimplifiedUniswapV2.sol**
```solidity
// DEX AMM simplificado
// Vulnerabilidades: Reentrancy en swap, fee manipulation
// Basado en: Uniswap V2
// SLOC: 650
```

**7.3 SimplifiedDAO.sol**
```solidity
// Governance DAO simplificado
// Vulnerabilidades: Vote manipulation, delegation attack
// Basado en: Compound Governance
// SLOC: 720
```

**7.4 SimplifiedBridge.sol**
```solidity
// Cross-chain bridge simplificado
// Vulnerabilidades: Replay attack, signature malleability
// Basado en: Ronin Bridge (exploit 2022)
// SLOC: 690
```

### 6.1.3 Ground Truth y Anotaciones

Cada contrato vulnerable incluye:

**1. Comentarios de Documentación:**
```solidity
/// @custom:vulnerability Reentrancy (SWC-107)
/// @custom:severity Critical
/// @custom:attack-vector Malicious contract calls withdraw recursively
/// @custom:impact Can drain entire contract balance
/// @custom:mitigation Apply Checks-Effects-Interactions pattern
```

**2. Exploit Contract:**
```solidity
// Cada vulnerabilidad acompañada de PoC functional
contract Exploit {
    Victim victim;

    function attack() external payable {
        // Paso a paso del exploit
    }
}
```

**3. Test de Explotación:**
```solidity
// Foundry test que demuestra el exploit
contract ExploitTest is Test {
    function testExploit() public {
        // Setup
        // Execute exploit
        // Assert success
    }
}
```

**4. JSON Metadata:**
```json
{
  "contract": "BasicReentrancy.sol",
  "swc_id": "SWC-107",
  "cwe_id": "CWE-841",
  "severity": "Critical",
  "category": "Reentrancy",
  "sloc": 75,
  "vulnerable_functions": ["withdraw"],
  "expected_detectors": {
    "slither": ["reentrancy-eth"],
    "mythril": ["Reentrancy"],
    "echidna": ["echidna_no_reentrancy"],
    "certora": ["withdrawBounded"]
  },
  "exploit_difficulty": "Easy",
  "financial_impact": "High",
  "historical_incidents": ["The DAO 2016"]
}
```

## 6.2 Diseño Experimental

### 6.2.1 Experimentos Planificados

**Experimento 1: Evaluación de Slither Individual**

**Objetivo:** Establecer baseline de detección y FP rate de Slither standalone.

**Hipótesis:** Slither detectará >85% de vulnerabilidades conocidas pero generará >40% FP.

**Metodología:**
1. Ejecutar Slither sobre 35 contratos vulnerables
2. Ejecutar Slither sobre 10 contratos seguros (control negativo)
3. Clasificar findings manualmente como TP/FP
4. Calcular: Precision, Recall, F1-Score, FP Rate

**Métricas:**
```python
TP = Vulnerabilidades detectadas correctamente
FP = Falsos positivos (warnings incorrectos)
TN = Contratos seguros sin warnings (esperado en control group)
FN = Vulnerabilidades no detectadas

Precision = TP / (TP + FP)
Recall = TP / (TP + FN)
F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
FP Rate = FP / (FP + TN)
```

**Experimento 2: Comparativa Echidna vs Medusa**

**Objetivo:** Evaluar efectividad de fuzzing property-based vs coverage-guided.

**Hipótesis:** Medusa alcanzará mayor cobertura en menor tiempo, pero Echidna tendrá mayor profundidad.

**Metodología:**
1. Definir 50 propiedades para los 35 contratos
2. Ejecutar Echidna (100k runs, 30min timeout)
3. Ejecutar Medusa (100k runs, 30min timeout)
4. Comparar: Coverage %, Properties violated, Time to violation

**Métricas:**
- Code coverage (lines %)
- Branch coverage (branches %)
- Properties violated (count)
- Time to first violation (seconds)
- Unique bugs found

**Experimento 3: Pipeline Híbrido vs Herramientas Individuales**

**Objetivo:** Demostrar que combinación de técnicas supera herramientas individuales.

**Hipótesis:** Pipeline Xaudit detectará +30% vulnerabilidades vs Slither solo, con -40% FP rate.

**Grupos de Comparación:**
- Grupo A: Slither solo
- Grupo B: Slither + Foundry
- Grupo C: Slither + Echidna
- Grupo D: Xaudit completo (Slither + Fuzzing + Foundry + AI)

**Metodología:**
1. Ejecutar cada configuración sobre dataset completo
2. Medir detección de vulnerabilidades conocidas
3. Clasificar findings con ground truth
4. Comparar métricas entre grupos

**Análisis Estadístico:**
- ANOVA para comparar medias entre grupos
- Tukey HSD post-hoc para pairwise comparisons
- Efecto de tamaño (Cohen's d)

**Experimento 4: Impacto del Módulo de IA**

**Objetivo:** Cuantificar reducción de FP y mejora de priorización con IA.

**Hipótesis:** IA reducirá FP en 40% manteniendo >95% recall de vulnerabilidades críticas.

**Metodología:**
1. Tomar output de Slither (alto FP)
2. **Grupo Control:** Clasificación manual por experto
3. **Grupo Experimental:** Clasificación con AI assistant
4. Comparar: Tiempo, Precision, Recall, Agreement con expert

**Métricas:**
- False Positive Reduction Rate
- True Positive Retention Rate
- Inter-rater reliability (Cohen's Kappa)
- Time savings (manual vs AI)

**Experimento 5: Verificación Formal con Certora**

**Objetivo:** Evaluar viabilidad de formal verification en pipeline CI/CD.

**Hipótesis:** Certora puede verificar funciones críticas en <1 hora con 99% precision.

**Metodología:**
1. Seleccionar 10 funciones críticas (fund-handling)
2. Escribir CVL specs para cada función
3. Ejecutar Certora Prover
4. Medir: Tiempo, Verificación exitosa, Contraejemplos encontrados

**Métricas:**
- Verification time (minutes per rule)
- Rules verified / total rules
- Counterexamples found (true vulnerabilities)
- False negatives (timeouts que ocultan bugs)

**Experimento 6: Evaluación en Contratos Reales**

**Objetivo:** Validar efectividad de Xaudit en protocolos de producción.

**Hipótesis:** Xaudit identificará issues conocidos en contratos auditados públicamente.

**Dataset:**
- 20 contratos de protocolos DeFi con auditorías públicas
- Fuentes: Code4rena, Sherlock, Immunefi
- Vulnerabilidades conocidas documentadas

**Metodología:**
1. Ejecutar Xaudit pipeline completo
2. Comparar findings con audit reports oficiales
3. Identificar: Known issues detected, New issues found, False positives

**Métricas:**
- Known vulnerability detection rate
- Novel findings (validated manually)
- False positives vs audit reports
- Time to analysis vs manual audit (weeks vs hours)

**Experimento 7: Análisis Simbólico - Mythril vs Manticore**

**Objetivo:** Comparar efectividad de SMT solving (Mythril) vs ejecución simbólica dinámica (Manticore).

**Hipótesis:** Manticore detectará más vulnerabilidades profundas pero con mayor tiempo de análisis. Mythril será más rápido pero con menor cobertura de paths.

**Metodología:**
1. Ejecutar Mythril sobre 35 contratos vulnerables
   - Configuración: max-depth=128, timeout=600s, parallel-solving
   - Medir: vulnerabilidades detectadas, paths explorados, tiempo
2. Ejecutar Manticore sobre mismos contratos
   - Configuración: max-depth=128, timeout=1200s, exploit-generation
   - Medir: estados explorados, exploits generados, tiempo
3. Comparar detección por categoría de vulnerabilidad
4. Analizar false positives vs Slither

**Métricas:**
- Vulnerabilidades detectadas (TP, FP, FN)
- Paths/estados explorados
- Tiempo de análisis (promedio, max, timeout rate)
- Exploits ejecutables generados (solo Manticore)
- Cobertura de código alcanzada
- Comparativa vs análisis estático (Slither)

**Categorías Esperadas:**
| Categoría | Mythril | Manticore | Slither |
|-----------|---------|-----------|---------|
| Reentrancy | Alto | Muy Alto | Alto |
| Access Control | Medio | Alto | Alto |
| Arithmetic | Alto | Alto | Medio |
| Uninitialized | Alto | Muy Alto | Alto |
| Delegatecall | Medio | Alto | Alto |

**Experimento 8: Invariant Testing con Foundry**

**Objetivo:** Evaluar efectividad de invariant-based fuzzing vs property-based fuzzing tradicional.

**Hipótesis:** Invariant tests detectarán violaciones de propiedades complejas que Echidna/Medusa no encuentran, especialmente en reentrancy y state consistency.

**Metodología:**
1. Implementar 5 invariants para reentrancy:
   - `invariant_balanceConsistency()`: Contract balance = sum(user balances)
   - `invariant_noOverWithdrawal()`: Withdrawn ≤ Deposited
   - `invariant_noNegativeBalance()`: All balances ≥ 0
   - `invariant_totalWithdrawalLimit()`: Total withdrawn ≤ Total deposited
   - `invariant_solvency()`: Contract balance ≥ Sum(user balances)
2. Implementar 4 invariants para access control:
   - `invariant_onlyOwnerCanGrantRoles()`
   - `invariant_adminActionsRestricted()`
   - `invariant_noPrivilegeEscalation()`
   - `invariant_protectedFunctionsSecure()`
3. Ejecutar con handler contracts y ghost variables
4. Comparar con Echidna property tests sobre mismos contratos

**Configuración:**
```toml
[profile.ci]
invariant = { runs = 1000, depth = 100, fail_on_revert = false }

[profile.intense]
invariant = { runs = 10000, depth = 500 }
```

**Métricas:**
- Invariants violados (count, tipos)
- Secuencias de llamadas hasta violación (length)
- Tiempo hasta primera violación
- Cobertura de estados explorados
- Comparativa Foundry vs Echidna:
  - Bugs únicos encontrados por cada herramienta
  - Overlapping bugs
  - False negatives

**Análisis Esperado:**
- Foundry debería detectar violaciones de consistency más fácilmente
- Handler contracts permiten exploración más dirigida
- Ghost variables facilitan tracking de state global

### 6.2.2 Variables Controladas

**Variables Independientes:**
- Herramienta de análisis (Slither, Echidna, Medusa, Foundry, Certora)
- Configuración del pipeline (individual, parcial, completo)
- Modelo de IA (gpt-4o-mini, llama3.2)
- Tiempo de ejecución (fast mode, full mode)

**Variables Dependientes:**
- Vulnerabilidades detectadas (count, severity distribution)
- Falsos positivos (count, rate)
- Tiempo de análisis (segundos, minutos)
- Cobertura de código (lines %, branches %)
- Costo computacional (CPU time, memory usage)
- Costo económico (API calls para IA)

**Variables de Confusión (Controladas):**
- Complejidad del código (SLOC normalizado)
- Versión de Solidity (todas 0.8.20-0.8.26)
- Librerías externas (OpenZeppelin versión fija)
- Hardware (mismo servidor para todos los tests)

## 6.3 Configuración de Herramientas

### 6.3.1 Slither

```json
// analysis/slither/config.json
{
  "filter_paths": "test|mock|lib|node_modules",
  "solc_remaps": [
    "@openzeppelin=node_modules/@openzeppelin",
    "@chainlink=node_modules/@chainlink",
    "forge-std=lib/forge-std/src"
  ],
  "detectors_to_run": "all",
  "detectors_to_exclude": [
    "naming-convention",
    "solc-version",
    "pragma",
    "similar-names",
    "constable-states",
    "external-function"
  ],
  "exclude_dependencies": true,
  "exclude_informational": false,
  "exclude_low": false,
  "exclude_medium": false,
  "exclude_high": false,
  "json": "analysis/slither/results/{contract}_slither.json",
  "markdown": "analysis/slither/results/{contract}_slither.md"
}
```

### 6.3.2 Echidna

```yaml
# analysis/echidna/config.yaml
testMode: property
testLimit: 100000
shrinkLimit: 5000
seqLen: 100
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x30000"
sender: ["0x10000", "0x20000", "0x30000", "0x40000", "0x50000"]
psender: 0.5
maxGasprice: "0"
maxTimeDelay: 100000
maxBlockDelay: 60000
propMaxGas: 12000000
testMaxGas: 12000000
coverage: true
corpusDir: "analysis/echidna/corpus"
format: "text"
workers: 4
seed: null  # Random seed for reproducibility
cryticArgs: ["--compile-force-framework", "foundry"]
```

### 6.3.3 Medusa

```json
// analysis/medusa/medusa.json
{
  "fuzzing": {
    "workers": 10,
    "workerResetLimit": 50,
    "timeout": 0,
    "testLimit": 100000,
    "shrinkLimit": 5000,
    "callSequenceLength": 100,
    "corpusDirectory": "analysis/medusa/corpus",
    "coverageEnabled": true,
    "targetContracts": [],
    "predeployedContracts": {},
    "constructorArgs": {},
    "deployerAddress": "0x30000",
    "senderAddresses": [
      "0x10000",
      "0x20000",
      "0x30000",
      "0x40000",
      "0x50000"
    ],
    "blockNumberDelayMax": 60480,
    "blockTimestampDelayMax": 604800,
    "blockGasLimit": 125000000,
    "transactionGasLimit": 12500000,
    "testing": {
      "stopOnFailedTest": false,
      "stopOnFailedContractMatching": true,
      "stopOnNoTests": true,
      "testAllContracts": false,
      "traceAll": false,
      "assertionTesting": {
        "enabled": true,
        "testViewMethods": false,
        "panicCodeConfig": {
          "failOnCompilerInsertedPanic": false,
          "failOnAssertion": true,
          "failOnArithmeticUnderflow": false,
          "failOnDivideByZero": false,
          "failOnEnumTypeConversionOutOfBounds": false,
          "failOnIncorrectStorageAccess": false,
          "failOnPopEmptyArray": false,
          "failOnOutOfBoundsArrayAccess": false,
          "failOnAllocateTooMuchMemory": false,
          "failOnCallUninitializedVariable": false
        }
      },
      "propertyTesting": {
        "enabled": true,
        "testPrefixes": [
          "property_"
        ]
      },
      "optimizationTesting": {
        "enabled": false,
        "testPrefixes": [
          "optimize_"
        ]
      }
    }
  },
  "compilation": {
    "platform": "crytic-compile",
    "platformConfig": {
      "target": ".",
      "solcVersion": "",
      "exportDirectory": "",
      "args": []
    }
  },
  "logging": {
    "level": "info",
    "logDirectory": "analysis/medusa/logs"
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

### 6.3.4 Foundry

```toml
# foundry.toml
[profile.default]
src = "src/contracts"
out = "out"
libs = ["lib"]
test = "test"
cache_path = "cache"

solc_version = "0.8.20"
evm_version = "paris"
optimizer = true
optimizer_runs = 200
via_ir = false

verbosity = 3
fuzz = { runs = 256, max_test_rejects = 65536 }
invariant = { runs = 256, depth = 15, fail_on_revert = false }

[profile.ci]
fuzz = { runs = 10000 }
invariant = { runs = 1000, depth = 100 }

[profile.intense]
fuzz = { runs = 100000 }
invariant = { runs = 10000, depth = 500 }

[rpc_endpoints]
mainnet = "${MAINNET_RPC_URL}"
sepolia = "${SEPOLIA_RPC_URL}"

[etherscan]
mainnet = { key = "${ETHERSCAN_API_KEY}" }
```

### 6.3.5 Certora

```conf
// analysis/certora/conf/Vault.conf
{
  "files": [
    "src/contracts/Vault.sol"
  ],
  "verify": "Vault:analysis/certora/specs/Vault.spec",
  "solc": "solc-0.8.20",
  "optimistic_loop": true,
  "loop_iter": "3",
  "optimistic_hashing": true,
  "hashing_length_bound": "512",
  "msg": "Vault verification",
  "rule_sanity": "basic",
  "multi_assert_check": true
}
```

### 6.3.6 Mythril

```bash
# analysis/mythril/run_mythril.sh

# Configuración básica
myth analyze "$CONTRACT_PATH" \
    --solv 0.8.20 \
    --max-depth 128 \
    --execution-timeout 600 \
    --parallel-solving \
    --solver-timeout 100000 \
    --max-transaction-count 3 \
    --call-depth-limit 10 \
    --create-timeout 30 \
    --output json \
    --output-file "results/mythril_${CONTRACT_NAME}.json"

# Quick mode (para CI/CD)
myth analyze "$CONTRACT_PATH" \
    --solv 0.8.20 \
    --max-depth 64 \
    --execution-timeout 300 \
    --quick
```

### 6.3.7 Manticore

```python
# src/manticore_tool.py - Configuración API

from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()

# Configuración de workspace
m.verbosity(1)  # 0=silent, 1=info, 2=debug, 3=verbose

# Configuración de detección
m.register_detector(ReentrancyDetector())
m.register_detector(UninitializedStorageDetector())
m.register_detector(IntegerOverflowDetector())

# Límites de exploración
m.context['max_depth'] = 128
m.context['timeout'] = 1200

# Generación de exploits
EXPLOIT_MODE = True
EXPLOIT_TYPE = 'reentrancy'  # 'reentrancy', 'overflow', 'uninitialized'
```

**Script de Ejecución:**
```bash
# analysis/scripts/run_manticore.sh

python src/manticore_tool.py \
    --contract "$CONTRACT_PATH" \
    --max-depth 128 \
    --timeout 1200 \
    --generate-exploit \
    --output-dir "analysis/manticore/results" \
    --verbose
```

### 6.3.8 Surya

```bash
# analysis/surya/run_surya.sh

# Call graph visualization
surya graph "$CONTRACT_PATH" | dot -Tpng > outputs/callgraph.png

# Inheritance tree
surya inheritance "$CONTRACT_PATH" | dot -Tpng > outputs/inheritance.png

# Describe contract
surya describe "$CONTRACT_PATH" > outputs/description.txt

# Function dependencies
surya dependencies "$CONTRACT_PATH" "$FUNCTION_NAME" > outputs/dependencies.txt

# Complexity analysis
surya metrics "$CONTRACT_PATH" > outputs/metrics.txt
```

**Integración en Python:**
```python
# src/surya_tool.py

SURYA_CONFIG = {
    "graph_format": "png",  # png, svg, dot
    "include_external": True,
    "include_internal": True,
    "include_modifiers": True,
    "complexity_threshold": 8,
    "max_depth": 10
}
```

### 6.3.9 Solhint

```json
// analysis/solhint/.solhintrc
{
  "extends": "solhint:recommended",
  "plugins": ["security"],
  "rules": {
    "avoid-suicide": "error",
    "avoid-sha3": "warn",
    "reentrancy": "error",
    "avoid-tx-origin": "error",
    "check-send-result": "error",
    "func-visibility": ["error", {"ignoreConstructors": true}],
    "state-visibility": "error",
    "not-rely-on-time": "warn",
    "avoid-call-value": "warn",
    "avoid-low-level-calls": "warn",
    "avoid-throw": "error",
    "code-complexity": ["warn", 8],
    "function-max-lines": ["warn", 50],
    "max-line-length": ["warn", 120],
    "payable-fallback": "warn",
    "no-empty-blocks": "error",
    "no-unused-vars": "error",
    "quotes": ["error", "double"],
    "bracket-align": "error",
    "indent": ["error", 4],
    "no-mix-tabs-and-spaces": "error",
    "compiler-version": ["error", "^0.8.0"]
  }
}
```

**Script de Ejecución:**
```bash
# analysis/solhint/run_solhint.sh

solhint --config analysis/solhint/.solhintrc \
    --formatter json \
    'src/contracts/**/*.sol' \
    > analysis/solhint/results/report.json

# Con fixing automático (donde sea posible)
solhint --config analysis/solhint/.solhintrc \
    --fix \
    'src/contracts/**/*.sol'
```

### 6.3.10 Pipeline de Análisis Simbólico Integrado

```bash
# analysis/scripts/run_symbolic.sh

# FASE 1: Mythril (SMT Solving)
echo "[1/3] Running Mythril..."
./analysis/mythril/run_mythril.sh "$CONTRACT" "full" > mythril.log

# FASE 2: Manticore (Symbolic Execution)
echo "[2/3] Running Manticore..."
python src/manticore_tool.py \
    --contract "$CONTRACT" \
    --max-depth 128 \
    --generate-exploit \
    > manticore.log

# FASE 3: Consolidación
echo "[3/3] Consolidating results..."
python analysis/scripts/consolidate_symbolic.py \
    --mythril mythril.log \
    --manticore manticore.log \
    --output symbolic_analysis.json
```

### 6.3.11 AI Assistant

```python
# analysis/scripts/config.py

AI_CONFIG = {
    "provider": "openai",  # or "ollama", "anthropic"
    "model": "gpt-4o-mini",
    "temperature": 0.3,
    "max_tokens": 1500,
    "timeout": 30,
    "retry": {
        "max_attempts": 3,
        "backoff_factor": 2
    },
    "classification": {
        "severity_threshold": {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0
        },
        "fp_threshold": 0.6,  # >60% FP likelihood → classify as FP
        "priority_weights": {
            "severity": 2.0,
            "impact": 1.0,
            "exploitability": 1.0,
            "fp_penalty": -10.0
        }
    },
    "batch_processing": {
        "enabled": true,
        "batch_size": 10,
        "parallel_requests": 5
    },
    "caching": {
        "enabled": true,
        "ttl_hours": 24
    }
}
```

## 6.4 Métricas de Evaluación

### 6.4.1 Métricas de Detección

**Confusion Matrix:**

```
                 Predicted
                 Positive  Negative
Actual Positive    TP        FN
       Negative    FP        TN
```

**Métricas Derivadas:**

| Métrica | Fórmula | Interpretación |
|---------|---------|----------------|
| **Precision** | TP / (TP + FP) | De los findings reportados, % que son reales |
| **Recall** | TP / (TP + FN) | De las vulnerabilidades reales, % detectadas |
| **F1-Score** | 2 × (P × R) / (P + R) | Media armónica de Precision y Recall |
| **Accuracy** | (TP + TN) / Total | % de clasificaciones correctas |
| **Specificity** | TN / (TN + FP) | De los contratos seguros, % identificados |
| **FPR** | FP / (FP + TN) | Tasa de falsos positivos |
| **FNR** | FN / (TP + FN) | Tasa de falsos negativos |

**Objetivos:**
- Precision: >85% (reducir FP vs Slither ~60%)
- Recall: >95% (no perder vulnerabilidades críticas)
- F1-Score: >90%
- FPR: <15%

### 6.4.2 Métricas de Cobertura

**Code Coverage:**

```python
Coverage_Lines = (Lines_Executed / Total_Lines) × 100%
Coverage_Branches = (Branches_Taken / Total_Branches) × 100%
Coverage_Functions = (Functions_Called / Total_Functions) × 100%
```

**Branch Coverage Detallado:**

```python
# Para cada branch (if, while, for, etc.):
Branch_Coverage = {
    "true_path_covered": bool,
    "false_path_covered": bool,
    "full_coverage": true_path AND false_path
}
```

**Objetivos:**
- Lines: >90%
- Branches: >85%
- Functions: >95%

### 6.4.3 Métricas de Performance

**Tiempo de Análisis:**

| Fase | Herramienta | Tiempo Objetivo | Timeout | Modo Rápido |
|------|-------------|-----------------|---------|-------------|
| 1 | Solhint | <10 sec | 1 min | <5 sec |
| 2 | Slither | 30-60 sec | 5 min | 15 sec |
| 3 | Surya | <5 sec | 30 sec | <5 sec |
| 4 | Mythril | 5-10 min | 15 min | 2-3 min |
| 5 | Manticore | 15-20 min | 30 min | 5-8 min |
| 6 | Echidna | 15-30 min | 60 min | 5 min |
| 7 | Medusa | 5-10 min | 30 min | 2 min |
| 8 | Foundry Fuzz | 5-10 min | 30 min | 2 min |
| 9 | Foundry Invariants | 10-15 min | 45 min | 3 min |
| 10 | Certora | 20-40 min | 120 min | N/A |
| 11 | AI Triage | 2-5 min | 15 min | 1 min |
| **Total Pipeline (Full)** | **10 herramientas** | **1.5-3 hours** | **6 hours** | **30-45 min** |

**Throughput:**

```python
Contracts_Per_Hour = 1 / (Total_Analysis_Time_Hours)
SLOC_Per_Minute = Total_SLOC / Total_Analysis_Time_Minutes
```

**Costo Computacional:**

```python
CPU_Hours = sum(Phase_CPU_Time for each phase)
Memory_Peak_GB = max(Phase_Memory_Usage)
API_Cost_USD = sum(OpenAI_API_Calls × Cost_Per_Call)
```

### 6.4.4 Métricas de Calidad de IA

**Classification Quality:**

```python
# Cohen's Kappa: Agreement entre AI y expert
K = (P_observed - P_expected) / (1 - P_expected)

# Interpretation:
# K < 0: No agreement
# 0.01-0.20: Slight agreement
# 0.21-0.40: Fair agreement
# 0.41-0.60: Moderate agreement
# 0.61-0.80: Substantial agreement
# 0.81-1.00: Almost perfect agreement
```

**Objetivo:** K > 0.75 (substantial agreement)

**Prioritization Quality:**

```python
# Normalized Discounted Cumulative Gain
NDCG@k = DCG@k / IDCG@k

where:
DCG@k = sum(relevance_i / log2(i+1) for i in 1..k)
IDCG@k = DCG of ideal ranking
```

**Objetivo:** NDCG@10 > 0.85

## 6.5 Procedimiento de Ejecución

### 6.5.1 Setup del Entorno

```bash
# 1. Clone del repositorio
git clone https://github.com/fboiero/MIESC.git
cd xaudit

# 2. Setup de entorno Python
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
pip install -r requirements.txt

# 3. Instalación de herramientas
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Echidna (macOS)
brew install echidna

# Medusa
go install github.com/crytic/medusa@latest

# 4. Configuración de API keys
cp .env.example .env
# Editar .env con OPENAI_API_KEY

# 5. Compilación de contratos
forge build

# 6. Verificación de setup
./scripts/verify_setup.sh
```

### 6.5.2 Ejecución de Experimentos

**Script de Automatización:**

```bash
#!/bin/bash
# scripts/run_experiments.sh

RESULTS_DIR="thesis/experiments/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Starting experiments at $TIMESTAMP"

# Experimento 1: Slither Baseline
echo "[1/6] Running Slither baseline experiment..."
python thesis/experiments/exp1_slither_baseline.py \
    --contracts src/contracts/vulnerable \
    --output "$RESULTS_DIR/exp1_$TIMESTAMP"

# Experimento 2: Fuzzing Comparison
echo "[2/6] Running Echidna vs Medusa comparison..."
python thesis/experiments/exp2_fuzzing_comparison.py \
    --contracts src/contracts/vulnerable \
    --echidna-runs 100000 \
    --medusa-runs 100000 \
    --timeout 1800 \
    --output "$RESULTS_DIR/exp2_$TIMESTAMP"

# Experimento 3: Hybrid Pipeline
echo "[3/6] Running hybrid pipeline evaluation..."
python thesis/experiments/exp3_hybrid_pipeline.py \
    --contracts src/contracts/vulnerable \
    --configurations "slither,slither+foundry,slither+echidna,xaudit_full" \
    --output "$RESULTS_DIR/exp3_$TIMESTAMP"

# Experimento 4: AI Impact
echo "[4/6] Evaluating AI triage impact..."
python thesis/experiments/exp4_ai_impact.py \
    --slither-results "$RESULTS_DIR/exp1_$TIMESTAMP/slither_results.json" \
    --model gpt-4o-mini \
    --ground-truth data/ground_truth.json \
    --output "$RESULTS_DIR/exp4_$TIMESTAMP"

# Experimento 5: Certora Verification
echo "[5/6] Running formal verification experiment..."
python thesis/experiments/exp5_certora_eval.py \
    --contracts src/contracts/vulnerable \
    --specs analysis/certora/specs \
    --timeout 7200 \
    --output "$RESULTS_DIR/exp5_$TIMESTAMP"

# Experimento 6: Real-World Evaluation
echo "[6/8] Evaluating on real-world contracts..."
python thesis/experiments/exp6_real_world.py \
    --contracts data/real_world_contracts \
    --audit-reports data/audit_reports \
    --output "$RESULTS_DIR/exp6_$TIMESTAMP"

# Experimento 7: Symbolic Analysis Comparison
echo "[7/8] Running Mythril vs Manticore comparison..."
python thesis/experiments/exp7_symbolic_comparison.py \
    --contracts src/contracts/vulnerable \
    --mythril-timeout 600 \
    --manticore-timeout 1200 \
    --categories "reentrancy,access_control,arithmetic,uninitialized" \
    --output "$RESULTS_DIR/exp7_$TIMESTAMP"

# Experimento 8: Invariant Testing Evaluation
echo "[8/8] Running Foundry invariant tests evaluation..."
python thesis/experiments/exp8_invariant_testing.py \
    --invariant-tests "analysis/foundry/invariants" \
    --target-contracts "src/contracts/vulnerable/reentrancy,src/contracts/vulnerable/access_control" \
    --runs 1000 \
    --depth 100 \
    --compare-with-echidna \
    --output "$RESULTS_DIR/exp8_$TIMESTAMP"

echo "All experiments completed!"
echo "Results saved to: $RESULTS_DIR"

# Generate consolidated report
python thesis/experiments/generate_report.py \
    --results-dir "$RESULTS_DIR" \
    --output "thesis/results/consolidated_report_$TIMESTAMP.pdf"
```

### 6.5.3 Validación de Resultados

**Checklist de Validación:**

```markdown
## Pre-Experiment Checklist
- [ ] Todos los contratos vulnerables compilan
- [ ] Ground truth metadata completo
- [ ] Exploit tests funcionan
- [ ] Configuraciones de herramientas validadas
- [ ] API keys configuradas y con crédito
- [ ] Espacio en disco suficiente (>50GB)
- [ ] Entorno aislado (no interferencia de otros procesos)

## Durante Ejecución
- [ ] Monitoreo de logs en tiempo real
- [ ] Alertas de errores configuradas
- [ ] Snapshots cada 6 horas
- [ ] Resource usage dentro de límites

## Post-Experiment Validation
- [ ] Todos los experimentos completados sin crashes
- [ ] Archivos de resultados generados
- [ ] Métricas calculadas correctamente
- [ ] Datos consistentes (no missing values críticos)
- [ ] Reproducibilidad verificada (re-run subset)
```

## 6.6 Arquitectura del Pipeline Xaudit v2.0

El pipeline completo integra **10 herramientas** en **12 fases** de análisis:

```
┌─────────────────────────────────────────────────────────────┐
│                    XAUDIT PIPELINE v2.0                      │
│            Análisis Multi-Técnica de Smart Contracts         │
└─────────────────────────────────────────────────────────────┘

 FASE 1: Linting                    [Solhint]
    ↓     • Security rules (30+)
    ↓     • Style enforcement
    ↓     • Best practices

 FASE 2: Análisis Estático          [Slither]
    ↓     • 90+ detectores
    ↓     • SlithIR analysis
    ↓     • Data flow

 FASE 3: Visualización              [Surya]
    ↓     • Call graphs
    ↓     • Complexity metrics
    ↓     • Dependencies

 FASE 4: Análisis Simbólico SMT     [Mythril]
    ↓     • Z3 solver
    ↓     • Path exploration
    ↓     • Constraint solving

 FASE 5: Ejecución Simbólica        [Manticore]
    ↓     • Dynamic exploration
    ↓     • Exploit generation
    ↓     • Concrete inputs

 FASE 6: Property Fuzzing           [Echidna]
    ↓     • Property-based
    ↓     • Shrinking
    ↓     • Corpus generation

 FASE 7: Coverage Fuzzing           [Medusa]
    ↓     • Coverage-guided
    ↓     • Instrumentation
    ↓     • Parallel workers

 FASE 8: Stateless Fuzzing          [Foundry - Fuzz]
    ↓     • Unit test fuzzing
    ↓     • Fast execution
    ↓     • Integrated tests

 FASE 9: Invariant Testing          [Foundry - Invariants]
    ↓     • State consistency
    ↓     • Handler contracts
    ↓     • Ghost variables

 FASE 10: Formal Verification       [Certora Prover]
    ↓     • CVL specifications
    ↓     • Mathematical proofs
    ↓     • Counterexamples

 FASE 11: AI Triage                 [GPT-4o-mini]
    ↓     • False positive filtering
    ↓     • Severity classification
    ↓     • Priority ranking

 FASE 12: Reporting
    └──→  • Consolidated JSON
          • HTML dashboard
          • Executive summary
```

**Innovación Clave:** Combinación de técnicas complementarias que se refuerzan mutuamente, reduciendo falsos positivos y aumentando cobertura de detección.

## 6.7 Síntesis del Capítulo

Este capítulo detalla la implementación experimental completa:

1. **Entorno:** Hardware, software, versiones de 10 herramientas
2. **Dataset:** 35 contratos vulnerables en 7 categorías, 5,700 SLOC
3. **Diseño Experimental:** 8 experimentos con hipótesis y metodología detallada
4. **Configuración:** Settings específicos para cada herramienta del pipeline
5. **Métricas:** Detección, cobertura, performance, calidad de IA
6. **Procedimiento:** Scripts de automatización completos y validación rigurosa
7. **Pipeline:** Arquitectura de 12 fases integrando análisis estático, simbólico, fuzzing, invariants y verificación formal

**Experimentos Implementados:**
1. Slither baseline individual
2. Echidna vs Medusa (fuzzing comparison)
3. Pipeline híbrido vs herramientas individuales
4. Impacto del módulo de IA en triage
5. Verificación formal con Certora
6. Evaluación en contratos reales auditados
7. **Nuevo:** Mythril vs Manticore (análisis simbólico)
8. **Nuevo:** Foundry invariant testing vs property testing

**Contribuciones del Capítulo:**
- Primera integración completa de 10 herramientas en pipeline único
- Metodología experimental reproducible con dataset público
- Configuraciones optimizadas para cada herramienta
- Scripts de automatización para 8 experimentos independientes
- Métricas cuantitativas para evaluación objetiva

**Próximo Capítulo:** Resultados experimentales y análisis estadístico de datos.

---

**Referencias del Capítulo**

1. Powers, D.M.W. (2011). "Evaluation: From Precision, Recall and F-Measure to ROC"
2. Cohen, J. (1960). "A Coefficient of Agreement for Nominal Scales"
3. Järvelin, K. (2002). "Cumulated Gain-Based Evaluation of IR Techniques"
4. Trail of Bits. (2023). "Properties: Writing Properties for Smart Contract Fuzzing"
