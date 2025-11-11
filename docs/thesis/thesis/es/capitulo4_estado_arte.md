# CAPÍTULO 4 – ESTADO DEL ARTE EN HERRAMIENTAS DE AUDITORÍA

## 4.1 Análisis Estático: Slither

### 4.1.1 Arquitectura y Funcionamiento

**Slither** es un framework de análisis estático desarrollado por Trail of Bits (2018), escrito en Python y diseñado específicamente para Solidity.

**Características Principales:**

- **Lenguaje intermedio:** SlithIR (Static Single Assignment form)
- **Detectores:** 90+ built-in detectors
- **Printers:** 45+ information extractors
- **API:** Extensible para detectores custom
- **Velocidad:** <1 segundo para contratos medianos (<1000 SLOC)

**Pipeline de Análisis:**

```
┌────────────────────────────────────────────────────────────┐
│               SLITHER ANALYSIS PIPELINE                     │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  1. COMPILATION                                             │
│     ├─> solc --combined-json ast,abi,bin                  │
│     └─> crytic-compile (multi-platform support)           │
│                                                             │
│  2. AST PARSING                                             │
│     ├─> Solidity AST → Internal representation            │
│     └─> Contract, Function, Variable objects              │
│                                                             │
│  3. SLITHIR CONVERSION                                      │
│     ├─> High-level Solidity → SSA form                    │
│     ├─> Temporary variables                                │
│     └─> Simplified control flow                           │
│                                                             │
│  4. ANALYSIS PHASE                                          │
│     ├─> Data dependency analysis                           │
│     ├─> Control flow graph construction                   │
│     └─> State variable tracking                           │
│                                                             │
│  5. DETECTOR EXECUTION                                      │
│     ├─> 90+ detectors run in parallel                     │
│     ├─> Categorization by impact/confidence               │
│     └─> JSON/Markdown output                              │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### 4.1.2 SlithIR: Representación Intermedia

**Ejemplo de Transformación:**

```solidity
// Solidity original
function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}

// SlithIR (SSA form)
SOLIDITY EXPRESSION: balances[msg.sender] -= amount
    TMP_0(uint256) = MEMBER_ACCESS balances[msg.sender]
    TMP_1(uint256) = TMP_0 - amount
    INDEX_ACCESS balances[msg.sender] = TMP_1

SOLIDITY EXPRESSION: balances[to] += amount
    TMP_2(uint256) = MEMBER_ACCESS balances[to]
    TMP_3(uint256) = TMP_2 + amount
    INDEX_ACCESS balances[to] = TMP_3
```

**Ventajas de SlithIR:**

- Simplifica análisis de data dependencies
- Normaliza expresiones complejas
- Facilita detección de taint propagation
- Permite reasoning sobre side effects

### 4.1.3 Detectores Clave

**Categor

ización por Impacto:**

| Impact | Descripción | Ejemplos |
|--------|-------------|----------|
| **High** | Vulnerabilidades críticas | reentrancy-eth, unprotected-upgrade, suicidal |
| **Medium** | Bugs con impacto significativo | unchecked-lowlevel, delegatecall-loop |
| **Low** | Mejores prácticas | naming-convention, unused-state |
| **Informational** | Code quality | dead-code, solc-version |

**Detectores de Alta Precisión (Bajo FP):**

1. **reentrancy-eth:**
   ```python
   # Detecta: External call → State write → Ether sent
   def _detect(self):
       for c in self.contracts:
           for f in c.functions:
               if self.KEY in f.context:
                   calls = f.context[self.KEY]
                   for call in calls:
                       if self._is_reentrancy(call):
                           results.append(call)
   ```

2. **suicidal:**
   ```python
   # Detecta: selfdestruct sin access control
   for function in contract.functions:
       if function.is_public() and function.contains_selfdestruct():
           if not self.is_protected(function):
               results.append(function)
   ```

3. **uninitialized-state:**
   ```python
   # Detecta: Variables storage sin inicializar
   for var in contract.state_variables:
       if var.is_uninitialized() and var.is_storage():
           results.append(var)
   ```

**Detectores con Alta Tasa de FP:**

- **reentrancy-benign:** Detecta reentrancy sin impacto (muchos FP)
- **arbitrary-send-eth:** Envíos de ether calculados (FP en lógica válida)
- **controlled-delegatecall:** DELEGATECALL con inputs controlados (FP en proxies)

### 4.1.4 Printers y Herramientas de Análisis

**Printers Útiles:**

```bash
# Call graph
slither contract.sol --print call-graph

# Inheritance graph
slither contract.sol --print inheritance-graph

# Variable order (storage layout)
slither contract.sol --print variable-order

# Function summary
slither contract.sol --print function-summary

# Human summary
slither contract.sol --print human-summary
```

**API para Detectores Custom:**

```python
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class CustomDetector(AbstractDetector):
    ARGUMENT = 'custom-detector'
    HELP = 'Detecta patrón específico'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    def _detect(self):
        results = []
        for contract in self.contracts:
            for function in contract.functions:
                if self.is_vulnerable(function):
                    info = [function, " es vulnerable\n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results
```

### 4.1.5 Limitaciones de Slither

1. **Falsos Positivos:**
   - Detectores de baja especificidad (reentrancy-benign ~60% FP)
   - No entiende lógica de negocio compleja
   - Asume worst-case en análisis de taint

2. **Falsos Negativos:**
   - No detecta vulnerabilidades de lógica personalizada
   - Limitado en análisis inter-contract complex interactions
   - No valida propiedades matemáticas (invariantes)

3. **Dependencia de Compilación:**
   - Requiere compilación exitosa (solc)
   - Problemas con código incompleto o librerías faltantes

## 4.2 Fuzzing Property-Based: Echidna

### 4.2.1 Arquitectura

**Echidna** (Trail of Bits, 2018) es un fuzzer property-based escrito en Haskell que ejecuta contratos en una EVM instrumentada.

**Características:**

- **Lenguaje:** Haskell (alto performance, concurrencia)
- **EVM Backend:** hevm (EVM implementation en Haskell)
- **Estrategia:** Random + dictionary-based fuzzing
- **Cobertura:** Tracking de branches ejecutados
- **Shrinking:** Minimización de inputs que causan fallos

**Flujo de Ejecución:**

```
┌─────────────────────────────────────────────────────────┐
│              ECHIDNA FUZZING WORKFLOW                    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  1. PROPERTY DEFINITION                                  │
│     └─> function echidna_property() returns (bool)     │
│                                                          │
│  2. CONTRACT DEPLOYMENT                                  │
│     └─> Deploy en hevm con initial state               │
│                                                          │
│  3. FUZZING LOOP (testLimit iterations)                 │
│     ├─> Generate random transaction sequence           │
│     ├─> Execute transactions                            │
│     ├─> Check properties after each tx                 │
│     └─> Track coverage metrics                         │
│                                                          │
│  4. SHRINKING (if property violated)                    │
│     ├─> Minimize transaction sequence                  │
│     ├─> Remove unnecessary transactions                │
│     └─> Output minimal failing case                    │
│                                                          │
│  5. CORPUS MANAGEMENT                                    │
│     └─> Save interesting inputs for future runs        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.2.2 Property-Based Testing

**Sintaxis de Propiedades:**

```solidity
contract ERC20Properties {
    ERC20Token token;

    constructor() {
        token = new ERC20Token();
    }

    // Propiedad: totalSupply debe igualar suma de balances
    function echidna_total_supply_equals_sum() public view returns (bool) {
        uint256 sum = token.balanceOf(address(0x10000)) +
                      token.balanceOf(address(0x20000)) +
                      token.balanceOf(address(0x30000));
        return token.totalSupply() == sum;
    }

    // Propiedad: transfer no debe aumentar totalSupply
    function echidna_transfer_preserves_supply() public view returns (bool) {
        uint256 supplyBefore = token.totalSupply();
        return token.totalSupply() == supplyBefore;
    }

    // Propiedad: balance nunca excede totalSupply
    function echidna_balance_leq_supply() public view returns (bool) {
        return token.balanceOf(msg.sender) <= token.totalSupply();
    }
}
```

**Configuración:**

```yaml
# echidna.yaml
testMode: property
testLimit: 100000
shrinkLimit: 5000
seqLen: 100
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x30000"
sender: ["0x10000", "0x20000", "0x30000"]
coverage: true
corpusDir: "corpus"
```

### 4.2.3 Técnicas de Generación de Inputs

**1. Random Fuzzing:**
```haskell
-- Genera valores aleatorios para cada tipo
genAddress :: Gen Address
genUint256 :: Gen Word256
genBytes   :: Gen ByteString
```

**2. Dictionary-Based:**
```yaml
# echidna usa diccionario de valores "interesantes"
- 0                 # Zero
- 1                 # One
- 2^256 - 1        # Max uint256
- 2^255            # Integer boundaries
- addresses from corpus
```

**3. Mutation:**
```haskell
-- Muta transactions previas que encontraron nueva cobertura
mutate :: Transaction -> Gen Transaction
mutate tx = do
    field <- choose [Value, Caller, Data]
    case field of
        Value  -> tx {value = mutateValue (value tx)}
        Caller -> tx {caller = mutateAddress (caller tx)}
        Data   -> tx {calldata = mutateBytes (calldata tx)}
```

### 4.2.4 Shrinking y Minimización

Cuando una propiedad falla, Echidna minimiza la secuencia de transacciones:

```
Failing sequence (10 transactions):
1. transfer(0x10000, 100)
2. approve(0x20000, 50)
3. transfer(0x30000, 25)
4. transferFrom(0x10000, 0x20000, 50)
5. mint(1000)
6. burn(500)
7. transfer(0x10000, 10)
8. transfer(0x20000, 5)
9. transferFrom(0x20000, 0x30000, 3)
10. burn(997)  ← Property fails here

After shrinking (3 transactions):
1. mint(1000)
2. burn(500)
3. burn(997)  ← Minimal failing case
```

### 4.2.5 Limitaciones de Echidna

1. **Exploración Limitada:**
   - Dificultad alcanzando estados profundos (deep states)
   - Random fuzzing poco efectivo para condiciones complejas
   - No usa symbolic execution para guiar búsqueda

2. **Performance:**
   - Haskell/hevm más lento que EVM nativa
   - testLimit de 100k puede tomar 30-60 minutos

3. **Expresividad de Propiedades:**
   - Solo propiedades boolean (sin LTL/CTL)
   - Difícil expresar propiedades temporales complejas

## 4.3 Fuzzing Coverage-Guided: Medusa

### 4.3.1 Arquitectura y Diseño

**Medusa** (Trail of Bits, 2023) es un fuzzer coverage-guided de próxima generación escrito en Go.

**Mejoras sobre Echidna:**

- **Performance:** 10-50x más rápido (Go + geth EVM)
- **Coverage-guided:** Prioriza inputs que exploran nuevo código
- **Corpus evolution:** Estrategias avanzadas de mutación
- **Paralelización:** Workers concurrentes
- **Cheatcodes:** Compatibilidad con Foundry cheatcodes

**Arquitectura:**

```
┌─────────────────────────────────────────────────────────┐
│              MEDUSA ARCHITECTURE                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐       ┌──────────────┐               │
│  │   Fuzzer     │◄─────►│   Corpus     │               │
│  │   Workers    │       │   Manager    │               │
│  │              │       │              │               │
│  │ - Worker 1   │       │ - Seed queue │               │
│  │ - Worker 2   │       │ - Coverage   │               │
│  │ - Worker N   │       │ - Mutations  │               │
│  └──────────────┘       └──────────────┘               │
│         │                       │                       │
│         └───────────┬───────────┘                       │
│                     ▼                                   │
│          ┌──────────────────┐                           │
│          │   geth EVM       │                           │
│          │   (instrumented) │                           │
│          └──────────────────┘                           │
│                     │                                   │
│                     ▼                                   │
│          ┌──────────────────┐                           │
│          │  Coverage        │                           │
│          │  Tracker         │                           │
│          └──────────────────┘                           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.3.2 Coverage-Guided Fuzzing

**Instrumentación de Bytecode:**

```go
// Medusa instrumenta cada JUMPI para tracking
type CoverageMap struct {
    branches map[uint64]bool  // PC → hit
    mu       sync.RWMutex
}

func (c *CoverageMap) RecordBranch(pc uint64, taken bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    key := (pc << 1) | (taken ? 1 : 0)
    c.branches[key] = true
}
```

**Algoritmo de Selección de Seeds:**

```
1. Corpus inicial: Transacciones básicas (constructor, funciones públicas)

2. Loop de fuzzing:
   a. Seleccionar seed del corpus (prioridad: menor coverage)
   b. Mutar seed (cambiar caller, value, calldata)
   c. Ejecutar mutación en EVM instrumentada
   d. Registrar nueva cobertura
   e. Si nueva cobertura:
      → Agregar input al corpus
      → Aumentar prioridad de este seed
   f. Si propiedad falló:
      → Guardar failing input
      → Minimizar secuencia
```

### 4.3.3 Estrategias de Mutación

**Mutaciones de Alto Nivel:**

```go
// 1. Dictionary-based: Usar valores conocidos
mutatedValue := chooseFrom([]uint256{
    0, 1, 2^256-1,
    existingBalances...,
    existingAllowances...,
})

// 2. Arithmetic: Modificar valores numéricos
mutatedValue := originalValue + randomDelta()

// 3. Splice: Combinar inputs anteriores
mutatedCalldata := splice(input1.calldata, input2.calldata)

// 4. Bit flips: Modificar bits individuales
mutatedCalldata := flipRandomBit(originalCalldata)
```

**Secuencias de Transacciones:**

```go
// Medusa evoluciona secuencias completas
type CallSequence struct {
    Calls []Call
}

func mutateSequence(seq CallSequence) CallSequence {
    mutations := []func(CallSequence) CallSequence{
        insertRandomCall,
        removeRandomCall,
        swapCalls,
        mutateCallParameters,
    }
    return choose(mutations)(seq)
}
```

### 4.3.4 Integración con Foundry

**Compatibilidad con Cheatcodes:**

```solidity
import "forge-std/Test.sol";

contract MedusaTest is Test {
    Counter counter;

    function setUp() public {
        counter = new Counter();
    }

    function medusa_counter_never_exceeds_max() public returns (bool) {
        // Medusa soporta vm.assume, vm.prank, etc.
        vm.assume(counter.count() < 1000);
        counter.increment();
        return counter.count() <= 1000;
    }
}
```

**Ventajas:**
- Reutilización de test suite de Foundry
- Integración con CI/CD existente
- Cheatcodes para setup complejo (vm.deal, vm.prank, vm.warp)

### 4.3.5 Comparativa Echidna vs Medusa

| Característica | Echidna | Medusa |
|----------------|---------|--------|
| **Lenguaje** | Haskell | Go |
| **EVM** | hevm | geth |
| **Velocidad** | 1x (baseline) | 10-50x más rápido |
| **Estrategia** | Random + dictionary | Coverage-guided |
| **Paralelización** | Limitada | Nativa (workers) |
| **Cheatcodes** | No | Sí (Foundry compat) |
| **Madurez** | Estable (2018) | Beta (2023) |
| **Comunidad** | Amplia | Creciente |

**Recomendación de Uso:**
- **Echidna:** Proyectos legacy, properties simples, estabilidad
- **Medusa:** Proyectos Foundry, necesidad de velocidad, deep states

## 4.4 Testing Avanzado: Foundry

### 4.4.1 Ecosistema Foundry

**Foundry** (Paradigm, 2021) es un toolkit completo para desarrollo de smart contracts escrito en Rust.

**Componentes:**

1. **forge:** Framework de testing y compilation
2. **anvil:** Local testnet (similar a Ganache)
3. **cast:** Herramienta CLI para interacción con contratos
4. **chisel:** REPL de Solidity

**Ventajas sobre Hardhat:**
- **10-100x más rápido:** Rust vs JavaScript
- **Tests en Solidity:** No requiere JavaScript/TypeScript
- **Fuzzing nativo:** Integrado en el framework
- **Gas profiling:** Métricas detalladas de consumo

### 4.4.2 Unit Testing

**Sintaxis:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault public vault;
    address alice = address(0x1);
    address bob = address(0x2);

    function setUp() public {
        vault = new Vault();
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function testDeposit() public {
        vm.prank(alice);
        vault.deposit{value: 10 ether}();

        assertEq(vault.balances(alice), 10 ether);
        assertEq(address(vault).balance, 10 ether);
    }

    function testWithdraw() public {
        vm.prank(alice);
        vault.deposit{value: 10 ether}();

        vm.prank(alice);
        vault.withdraw(5 ether);

        assertEq(vault.balances(alice), 5 ether);
        assertEq(address(vault).balance, 5 ether);
    }

    function testFailWithdrawMore ThanBalance() public {
        vm.prank(alice);
        vault.deposit{value: 5 ether}();

        vm.prank(alice);
        vault.withdraw(10 ether); // Should revert
    }
}
```

**Cheatcodes Esenciales:**

```solidity
// Time manipulation
vm.warp(timestamp);          // Set block.timestamp
vm.roll(blockNumber);         // Set block.number

// Identity manipulation
vm.prank(address);            // Set msg.sender for next call
vm.startPrank(address);       // Set msg.sender until stopPrank()
vm.stopPrank();

// Balance manipulation
vm.deal(address, amount);     // Set ETH balance

// Expectation cheatcodes
vm.expectRevert();            // Expect next call to revert
vm.expectEmit(true, true, false, true);

// Snapshots
uint256 snapshot = vm.snapshot();
vm.revertTo(snapshot);
```

### 4.4.3 Fuzz Testing

**Sintaxis:**

```solidity
contract VaultFuzzTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }

    /// forge-config: default.fuzz.runs = 10000
    function testFuzz_DepositWithdraw(uint256 amount) public {
        // Bound amount para evitar edge cases
        amount = bound(amount, 1, 1000 ether);

        vm.deal(address(this), amount);
        vault.deposit{value: amount}();

        assertEq(vault.balances(address(this)), amount);

        vault.withdraw(amount);

        assertEq(vault.balances(address(this)), 0);
        assertEq(address(this).balance, amount);
    }

    function testFuzz_MultipleUsers(
        address user1,
        address user2,
        uint256 amount1,
        uint256 amount2
    ) public {
        // Assumptions para evitar casos inválidos
        vm.assume(user1 != user2);
        vm.assume(user1 != address(0) && user2 != address(0));
        amount1 = bound(amount1, 1, 100 ether);
        amount2 = bound(amount2, 1, 100 ether);

        vm.deal(user1, amount1);
        vm.deal(user2, amount2);

        vm.prank(user1);
        vault.deposit{value: amount1}();

        vm.prank(user2);
        vault.deposit{value: amount2}();

        assertEq(address(vault).balance, amount1 + amount2);
    }
}
```

**Configuración de Fuzzing:**

```toml
# foundry.toml
[profile.default]
fuzz = { runs = 256, max_test_rejects = 65536 }

[profile.ci]
fuzz = { runs = 10000 }

[profile.intense]
fuzz = { runs = 100000 }
```

### 4.4.4 Invariant Testing

**Definición de Invariantes:**

```solidity
contract VaultInvariantTest is Test {
    Vault vault;
    VaultHandler handler;

    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);

        // Target contract para fuzzing
        targetContract(address(handler));
    }

    /// forge-config: default.invariant.runs = 1000
    /// forge-config: default.invariant.depth = 100
    function invariant_solvency() public {
        // Invariante: contract balance >= sum of user balances
        assertGe(
            address(vault).balance,
            handler.ghost_sumOfDeposits() - handler.ghost_sumOfWithdrawals()
        );
    }

    function invariant_balanceNonNegative() public {
        // Invariante: Ningún usuario tiene balance negativo
        for (uint256 i = 0; i < handler.actors.length; i++) {
            address actor = handler.actors[i];
            assertGe(vault.balances(actor), 0);
        }
    }
}

// Handler para guiar fuzzing con acciones válidas
contract VaultHandler is Test {
    Vault vault;

    address[] public actors;
    mapping(address => uint256) public actorIndexes;

    uint256 public ghost_sumOfDeposits;
    uint256 public ghost_sumOfWithdrawals;

    constructor(Vault _vault) {
        vault = _vault;
    }

    function deposit(uint256 amount, uint256 actorSeed) public {
        amount = bound(amount, 1, 100 ether);
        address actor = _getActor(actorSeed);

        vm.deal(actor, amount);
        vm.prank(actor);
        vault.deposit{value: amount}();

        ghost_sumOfDeposits += amount;
    }

    function withdraw(uint256 amount, uint256 actorSeed) public {
        address actor = _getActor(actorSeed);
        uint256 balance = vault.balances(actor);

        if (balance == 0) return;

        amount = bound(amount, 1, balance);

        vm.prank(actor);
        vault.withdraw(amount);

        ghost_sumOfWithdrawals += amount;
    }

    function _getActor(uint256 seed) internal returns (address) {
        uint256 index = seed % 10;
        if (actors.length <= index) {
            address newActor = address(uint160(0x10000 + actors.length));
            actors.push(newActor);
            actorIndexes[newActor] = actors.length - 1;
            return newActor;
        }
        return actors[index];
    }
}
```

### 4.4.5 Differential Testing

**Concepto:** Comparar implementaciones equivalentes para detectar inconsistencias.

```solidity
contract DifferentialTest is Test {
    VaultV1 vaultV1;
    VaultV2 vaultV2;

    function setUp() public {
        vaultV1 = new VaultV1();
        vaultV2 = new VaultV2();
    }

    function testDifferential_Deposit(address user, uint256 amount) public {
        vm.assume(user != address(0));
        amount = bound(amount, 1, 100 ether);

        vm.deal(user, amount * 2);

        // Execute same action en ambas versiones
        vm.prank(user);
        vaultV1.deposit{value: amount}();

        vm.prank(user);
        vaultV2.deposit{value: amount}();

        // Assert resultados idénticos
        assertEq(vaultV1.balances(user), vaultV2.balances(user));
        assertEq(address(vaultV1).balance, address(vaultV2).balance);
    }
}
```

## 4.5 Runtime Verification: Scribble

### 4.5.1 Concepto y Arquitectura

**Scribble** (Consensys Diligence, 2020) permite anotar contratos Solidity con especificaciones formales que se instrumentan en el bytecode.

**Workflow:**

```
┌──────────────────────────────────────────────────────┐
│            SCRIBBLE WORKFLOW                          │
├──────────────────────────────────────────────────────┤
│                                                       │
│  1. Annotate contract with specifications            │
│     /// #if_succeeds {:msg "Balance increased"}      │
│     /// old(balance) < balance;                      │
│                                                       │
│  2. Instrument contract                              │
│     $ scribble --arm contract.sol                    │
│                                                       │
│  3. Instrumented contract checks specs at runtime    │
│     ├─> Preconditions checked before function       │
│     ├─> Postconditions checked after function       │
│     └─> Invariants checked after state changes      │
│                                                       │
│  4. Deploy & test instrumented version               │
│     └─> Runtime violations throw exceptions         │
│                                                       │
└──────────────────────────────────────────────────────┘
```

### 4.5.2 Sintaxis de Anotaciones

**Invariantes:**

```solidity
contract ERC20 {
    /// #invariant {:msg "Total supply equals sum of balances"}
    ///     totalSupply == sum(balances);

    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public {
        // Scribble inserta checks automáticamente
    }
}
```

**Precondiciones y Postcondiciones:**

```solidity
/// #if_succeeds {:msg "Sender balance decreased"}
///     old(balances[msg.sender]) == balances[msg.sender] + amount;
/// #if_succeeds {:msg "Receiver balance increased"}
///     old(balances[to]) + amount == balances[to];
function transfer(address to, uint256 amount) public {
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

**Let bindings:**

```solidity
/// #define totalBalance := sum(balances);

/// #if_succeeds {:msg "Total balance unchanged"}
///     old(totalBalance) == totalBalance;
function transfer(address to, uint256 amount) public { ... }
```

### 4.5.3 Integración con Echidna/Medusa

```solidity
// 1. Anotar contrato con Scribble
// 2. Instrumentar: scribble --arm Contract.sol
// 3. Fuzzing con Echidna sobre versión instrumentada
//    → Violaciones de specs detectadas como reverts
```

**Ventajas:**
- Especificaciones reutilizables para testing y formal verification
- Runtime checks en production (opcional, con overhead)
- Documentación ejecutable

## 4.6 Verificación Formal: Certora Prover

### 4.6.1 Certora Verification Language (CVL)

**Certora** (Certora, 2018) es un prover SMT-based que verifica formalmente propiedades de smart contracts.

**Arquitectura:**

```
┌──────────────────────────────────────────────────────┐
│          CERTORA PROVER ARCHITECTURE                  │
├──────────────────────────────────────────────────────┤
│                                                       │
│  1. SPECIFICATION (CVL)                               │
│     ├─> Rules (invariants, parametric rules)        │
│     ├─> Methods declarations                         │
│     └─> Ghost variables                              │
│                                                       │
│  2. COMPILATION                                       │
│     ├─> Solidity → EVM bytecode                     │
│     └─> CVL → Internal representation                │
│                                                       │
│  3. VERIFICATION CONDITION GENERATION                 │
│     ├─> Symbolic execution de todas las paths       │
│     ├─> Loop unrolling (bounded)                    │
│     └─> Generate SMT formulas                        │
│                                                       │
│  4. SMT SOLVING                                       │
│     ├─> Z3, CVC5, etc.                              │
│     ├─> Timeout: 10-60 minutos por rule            │
│     └─> Result: VERIFIED / VIOLATED / TIMEOUT       │
│                                                       │
│  5. COUNTEREXAMPLE GENERATION                         │
│     └─> Si violated, genera trace de ejecución     │
│                                                       │
└──────────────────────────────────────────────────────┘
```

### 4.6.2 Sintaxis CVL

**Methods Block:**

```cvl
methods {
    function balanceOf(address) external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}
```

**Parametric Rules:**

```cvl
rule transferPreservesTotal Supply(address from, address to, uint256 amount) {
    env e;

    uint256 supplyBefore = totalSupply();

    require e.msg.sender == from;

    transfer(e, to, amount);

    uint256 supplyAfter = totalSupply();

    assert supplyAfter == supplyBefore,
        "Transfer should not change total supply";
}
```

**Invariants:**

```cvl
invariant totalSupplyEqualsSumOfBalances()
    to_mathint(totalSupply()) == sumOfBalances
    {
        preserved transfer(address to, uint256 amount) with (env e) {
            requireInvariant balanceOfLEQSupply(e.msg.sender);
            requireInvariant balanceOfLEQSupply(to);
        }
    }
```

**Ghost Variables:**

```cvl
ghost mathint sumOfBalances {
    init_state axiom sumOfBalances == 0;
}

hook Sstore balances[KEY address user] uint256 newBalance
    (uint256 oldBalance) STORAGE {
    sumOfBalances = sumOfBalances + newBalance - oldBalance;
}
```

### 4.6.3 Casos de Uso

**1. Verificación de ERC-20:**

```cvl
rule noBackdoorMint(method f, address user) {
    uint256 balanceBefore = balanceOf(user);

    env e;
    calldataarg args;
    f(e, args);

    uint256 balanceAfter = balanceOf(user);

    assert balanceAfter > balanceBefore =>
           (f.selector == sig:mint(address,uint256).selector ||
            f.selector == sig:transfer(address,uint256).selector ||
            f.selector == sig:transferFrom(address,address,uint256).selector),
        "Only mint/transfer functions should increase balance";
}
```

**2. Verificación de Access Control:**

```cvl
rule onlyOwnerCanWithdraw() {
    env e;
    address to;

    withdrawAll@withrevert(e, to);

    assert !lastReverted => e.msg.sender == owner(),
        "Only owner should be able to withdraw";
}
```

### 4.6.4 Ventajas y Limitaciones

**Ventajas:**

- **Garantías matemáticas:** Proof de correctitud para todas las ejecuciones posibles
- **Coverage exhaustiva:** Explora todos los paths (bounded)
- **Contraejemplos:** Genera traces de violaciones
- **Modularidad:** CVL reutilizable entre contratos similares

**Limitaciones:**

- **Costo computacional:** 10 minutos a varias horas por rule
- **Loop unrolling:** Loops deben tener bounds conocidos
- **Complejidad de specs:** Requiere expertise en lógica formal
- **Falsos negativos:** Timeouts pueden ocultar bugs
- **Costo económico:** Licencia comercial (gratis para open-source)

## 4.7 Mythril - Análisis Simbólico con SMT

### 4.7.1 Arquitectura y Funcionamiento

**Mythril** (ConsenSys, 2017) es un analizador simbólico que utiliza SMT (Satisfiability Modulo Theories) solving para detectar vulnerabilidades en smart contracts de manera exhaustiva.

**Características Principales:**

- **Lenguaje:** Python
- **SMT Solver:** Z3 (Microsoft Research)
- **Técnica:** Symbolic execution + constraint solving
- **Detección:** Formal proof de vulnerabilidades
- **Velocidad:** 30 segundos - 10 minutos (depende de complejidad)

**Pipeline de Análisis:**

```
┌────────────────────────────────────────────────────────────┐
│               MYTHRIL ANALYSIS PIPELINE                     │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  1. COMPILATION                                             │
│     └─> Solidity → EVM bytecode (via solc)                │
│                                                             │
│  2. CONTROL FLOW GRAPH (CFG)                                │
│     ├─> Disassemble bytecode                              │
│     ├─> Identify basic blocks                             │
│     └─> Build CFG with JUMP/JUMPI                        │
│                                                             │
│  3. SYMBOLIC EXECUTION                                      │
│     ├─> Execute cada path simbólicamente                  │
│     ├─> Variables → symbolic values                       │
│     ├─> Track constraints (path conditions)              │
│     └─> Bounded exploration (max_depth)                  │
│                                                             │
│  4. CONSTRAINT SOLVING (Z3)                                 │
│     ├─> Para cada path, verificar satisfiability         │
│     ├─> ¿Existe input que alcanza estado vulnerable?    │
│     └─> Generar concrete values si SAT                   │
│                                                             │
│  5. VULNERABILITY DETECTION                                 │
│     ├─> SWC-107: Reentrancy                              │
│     ├─> SWC-101: Integer overflow/underflow              │
│     ├─> SWC-105: Unprotected ether withdrawal            │
│     ├─> SWC-106: Unprotected SELFDESTRUCT                │
│     └─> SWC-104: Unchecked CALL return value             │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### 4.7.2 Symbolic Execution

**Ejemplo de Análisis:**

```solidity
// Contrato vulnerable
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;  // Vulnerable!
}
```

**Exploración Simbólica:**

```python
# Mythril representa variables simbólicamente
balances[msg.sender] = α  # Symbolic value
amount = β

# Path condition para línea 2:
constraint_1: α >= β

# External call (línea 3):
call_return = γ  # Symbolic

# Path condition para línea 4:
constraint_2: γ == true

# State update (línea 5):
balances[msg.sender] = α - β

# Reentrancy check:
# ¿Puede call recursivo ejecutar withdraw() nuevamente?
# Z3 solve: ∃ (α, β, γ) tal que:
#   - α >= β (primer require)
#   - α >= 2β (segundo withdraw en reentrancy)
#   - Ether disponible
# → SAT! Contraejemplo: α=2, β=1
```

### 4.7.3 Detectores Implementados

**Detección de Reentrancy:**

```python
def _execute_reentrancy_check(state, instruction):
    # Detecta: CALL → SSTORE después de external call
    if instruction.opcode == "CALL":
        # Registrar external call
        state.register_external_call(instruction)

    elif instruction.opcode == "SSTORE":
        # Verificar si hay external call previo sin state update
        if state.has_pending_external_call():
            # Posible reentrancy!
            constraints = state.get_path_constraints()

            # Verificar con Z3 si es explotable
            solver = z3.Solver()
            solver.add(constraints)

            if solver.check() == z3.sat:
                # Generar contraejemplo
                model = solver.model()
                return VulnerabilityReport(
                    type="REENTRANCY",
                    swc_id="107",
                    severity="HIGH",
                    model=model
                )
```

**Detección de Integer Overflow (pre-Solidity 0.8):**

```python
def _detect_overflow(state, instruction):
    if instruction.opcode == "ADD":
        a, b = state.stack.pop(2)
        result = a + b

        # Verificar overflow: result < a ∨ result < b
        overflow_condition = z3.Or(
            z3.ULT(result, a),
            z3.ULT(result, b)
        )

        solver = z3.Solver()
        solver.add(state.constraints)
        solver.add(overflow_condition)

        if solver.check() == z3.sat:
            return VulnerabilityReport(
                type="INTEGER_OVERFLOW",
                swc_id="101",
                severity="HIGH"
            )
```

### 4.7.4 Uso y Configuración

**Comando Básico:**

```bash
# Análisis simple
myth analyze contract.sol

# Con opciones avanzadas
myth analyze contract.sol \
    --solv 0.8.20 \
    --max-depth 128 \
    --execution-timeout 600 \
    --parallel-solving \
    --output json
```

**Salida JSON:**

```json
{
  "success": true,
  "issues": [
    {
      "swc-id": "107",
      "swc-title": "Reentrancy",
      "severity": "High",
      "contract": "VulnerableVault",
      "function": "withdraw",
      "address": 142,
      "description": "External call to user-controlled address before state update",
      "transaction_sequence": {
        "steps": [
          {"from": "0x1000", "to": "contract", "function": "deposit", "value": "1 ether"},
          {"from": "0x1000", "to": "contract", "function": "withdraw", "value": "0"}
        ]
      }
    }
  ]
}
```

### 4.7.5 Ventajas y Limitaciones

**Ventajas:**

1. **Detección Formal:** Proof matemático de vulnerabilidades
2. **False Positives Bajos:** ~15-25% (mejor que Slither)
3. **Contraejemplos Concretos:** Genera inputs que explotan el bug
4. **Cobertura Exhaustiva:** Explora todos los paths (bounded)

**Limitaciones:**

1. **Path Explosion:** Contratos complejos generan millones de paths
2. **Timeouts:** Análisis puede tomar >10 minutos y fallar
3. **Loops:** Requiere unrolling o bounded exploration
4. **External Contracts:** No analiza dependencias complejas
5. **False Negatives:** Depth limit puede perder bugs profundos

### 4.7.6 Comparativa Mythril vs Slither

| Aspecto | Mythril | Slither |
|---------|---------|---------|
| **Técnica** | Symbolic execution | Static analysis |
| **Velocidad** | 1-10 minutos | <1 segundo |
| **Precisión** | 75% (FP: 25%) | 60% (FP: 40%) |
| **Soundness** | Bounded complete | Overapproximate |
| **Contraejemplos** | Sí (concrete inputs) | No |
| **Escalabilidad** | Limitada (path explosion) | Excelente |
| **Recomendado para** | Contratos críticos | CI/CD, desarrollo |

---

## 4.8 Manticore - Ejecución Simbólica Dinámica

### 4.8.1 Arquitectura

**Manticore** (Trail of Bits, 2017) es un framework de symbolic execution que soporta múltiples plataformas (EVM, x86, ARM).

**Características:**

- **Lenguaje:** Python
- **Backend:** Unicorn (emulador) + Z3 (solver)
- **Técnica:** Dynamic symbolic execution (concolic testing)
- **Generación de Exploits:** Automática
- **Debugging:** Trace completo de ejecución

**Diferencias con Mythril:**

| Característica | Mythril | Manticore |
|----------------|---------|-----------|
| **Enfoque** | Detección rápida | Análisis profundo |
| **Exploits** | Abstractos | Ejecutables (código) |
| **Estados** | Explora selectivamente | Explora exhaustivamente |
| **Workspace** | No | Sí (estados guardados) |
| **Debugging** | Limitado | Completo (trace + hooks) |

**Flujo de Trabajo:**

```
┌────────────────────────────────────────────────────────────┐
│              MANTICORE WORKFLOW                             │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  1. CONTRACT INITIALIZATION                                 │
│     ├─> Deploy en EVM emulada                             │
│     └─> Crear initial symbolic state                      │
│                                                             │
│  2. SYMBOLIC EXECUTION                                      │
│     ├─> Ejecutar bytecode paso a paso                     │
│     ├─> Fork en cada JUMPI (branch)                       │
│     ├─> Mantener path constraints                         │
│     └─> Generar nuevos estados (workers)                  │
│                                                             │
│  3. STATE EXPLORATION                                       │
│     ├─> Workers procesan estados en paralelo             │
│     ├─> Detectar estados "interesantes"                  │
│     ├─> Prune estados redundantes                        │
│     └─> Save workspace con todos los estados             │
│                                                             │
│  4. VULNERABILITY DETECTION                                 │
│     ├─> Detectar: CALL con balance > 0 antes de SSTORE   │
│     ├─> Detectar: Integer overflow conditions            │
│     ├─> Detectar: Unprotected SELFDESTRUCT               │
│     └─> Generar finding por cada issue                   │
│                                                             │
│  5. EXPLOIT GENERATION                                      │
│     ├─> Extraer path constraints del estado vulnerable   │
│     ├─> Solve con Z3 para concrete values                │
│     ├─> Generar código Solidity del exploit              │
│     └─> Output: ExploitContract.sol                      │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### 4.8.2 Uso Básico

**Análisis con Manticore:**

```python
from manticore.ethereum import ManticoreEVM

# Crear instancia
m = ManticoreEVM()

# Deploy contract
with open('VulnerableVault.sol') as f:
    source_code = f.read()

user_account = m.create_account(balance=10**18)
contract_account = m.solidity_create_contract(
    source_code,
    owner=user_account,
    contract_name='VulnerableVault'
)

# Symbolic execution de función withdraw
symbolic_amount = m.make_symbolic_value()
m.transaction(
    caller=user_account,
    address=contract_account,
    data=m.make_symbolic_buffer(320),
    value=0
)

# Ejecutar exploration
for state in m.running_states:
    # Detectar revert
    if state.platform.is_revert():
        print(f"Revert en state {state.id}")

    # Detectar balance inconsistency
    balance_before = state.platform.get_balance(contract_account)
    balance_after = state.platform.get_balance(contract_account)

    if balance_before != balance_after:
        print(f"Possible vulnerability in state {state.id}")
        m.generate_testcase(state, "Vulnerability found")
```

### 4.8.3 Generación de Exploits

**Output de Manticore:**

```
mcore_VulnerableVault_0x1234/
├── test_00000001.tx        # Transacciones que llevan al bug
├── test_00000001.summary   # Resumen del issue
├── test_00000001.trace     # Trace de ejecución
└── test_00000001.constraints  # Path constraints

# test_00000001.tx
Transaction 1:
    From: 0x1000
    To: VulnerableVault
    Function: deposit()
    Value: 1000000000000000000 (1 ether)

Transaction 2:
    From: 0x1000
    To: VulnerableVault
    Function: withdraw(uint256)
    Params: amount=500000000000000000
    Value: 0

Transaction 3 (reentrancy):
    From: AttackerContract
    To: VulnerableVault
    Function: withdraw(uint256)
    Params: amount=500000000000000000
    Value: 0
```

**Exploit Auto-Generado:**

```solidity
// Auto-generated by Manticore
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./VulnerableVault.sol";

contract ManticoreExploit {
    VulnerableVault public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = VulnerableVault(_target);
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need 1 ETH");

        // Step 1: Deposit
        target.deposit{value: 1 ether}();

        // Step 2: Trigger reentrancy
        target.withdraw(0.5 ether);
    }

    receive() external payable {
        // Reentrancy callback
        if (address(target).balance >= 0.5 ether && attackCount < 3) {
            attackCount++;
            target.withdraw(0.5 ether);
        }
    }
}
```

### 4.8.4 Hooks y Debugging

**Custom Detectors:**

```python
from manticore.ethereum import ManticoreEVM, Detector

class ReentrancyDetector(Detector):
    def will_evm_execute_instruction_callback(self, state, instruction):
        # Hook antes de cada instrucción
        if instruction.semantics == 'CALL':
            # Registrar external call
            pc = state.platform.current_vm.pc
            state.context['external_calls'].append(pc)

        elif instruction.semantics == 'SSTORE':
            # Verificar si hay pending external call
            if len(state.context.get('external_calls', [])) > 0:
                # Posible reentrancy!
                self.add_finding(
                    state,
                    pc=state.platform.current_vm.pc,
                    finding="Potential reentrancy: SSTORE after CALL"
                )

# Usar detector
m = ManticoreEVM()
m.register_detector(ReentrancyDetector())
```

### 4.8.5 Limitaciones

1. **Performance:** Muy lento (10-30 min para contratos medianos)
2. **State Explosion:** Genera miles de estados → alto consumo de RAM
3. **Complejidad:** Requiere experiencia en symbolic execution
4. **Setup:** Más complejo que Mythril (workspace, hooks)

---

## 4.9 Surya - Visualización y Métricas

### 4.9.1 Propósito y Características

**Surya** (ConsenSys, 2018) es una herramienta de visualización y análisis de código Solidity que genera grafos y métricas de complejidad.

**Características:**

- **Call Graphs:** Visualización de llamadas entre funciones
- **Inheritance Trees:** Estructura de herencia de contratos
- **Métricas:** Complejidad ciclomática, SLOC, dependencias
- **Análisis de Dependencias:** Imports y external calls
- **Output:** DOT (Graphviz), Markdown, JSON

**Casos de Uso:**

1. **Auditorías Manuales:** Entender arquitectura rápidamente
2. **Documentación:** Generar diagramas para reports
3. **Code Review:** Identificar funciones complejas
4. **Refactoring:** Detectar acoplamiento excesivo

### 4.9.2 Funcionalidades

**1. Call Graph:**

```bash
surya graph src/contracts/**/*.sol | dot -Tpng > call-graph.png
```

Ejemplo de output:

```
VulnerableVault
  ├─ constructor()
  ├─ deposit() [PUBLIC] [PAYABLE]
  ├─ withdraw(uint256) [PUBLIC]
  │   └─> [EXTERNAL CALL] msg.sender.call
  ├─ getBalance() [PUBLIC] [VIEW]
  └─ receive() [EXTERNAL] [PAYABLE]
      └─> deposit()
```

**2. Inheritance Tree:**

```bash
surya inheritance src/ERC20Token.sol
```

```
ERC20Token
  ├─ Ownable
  │   └─ Context
  └─ IERC20
```

**3. Métricas de Complejidad:**

```bash
surya describe src/**/*.sol
```

```
┌──────────────────┬────────────┬─────────┬──────────┬───────────┐
│ Contract         │ Functions  │ SLOC    │ Complexity│ Interfaces│
├──────────────────┼────────────┼─────────┼──────────┼───────────┤
│ VulnerableVault  │ 5          │ 63      │ 12       │ 0         │
│  ├─ deposit      │ PUBLIC     │ 4       │ 1        │           │
│  ├─ withdraw     │ PUBLIC     │ 8       │ 3        │           │
│  ├─ getBalance   │ PUBLIC VIEW│ 2       │ 1        │           │
│  └─ receive      │ PAYABLE    │ 2       │ 1        │           │
└──────────────────┴────────────┴─────────┴──────────┴───────────┘
```

### 4.9.3 Análisis de Dependencias

```bash
surya dependencies src/Token.sol
```

Output:

```
Token.sol
├─ @openzeppelin/contracts/token/ERC20/ERC20.sol
│  ├─ @openzeppelin/contracts/token/ERC20/IERC20.sol
│  └─ @openzeppelin/contracts/utils/Context.sol
└─ @openzeppelin/contracts/access/Ownable.sol
   └─ @openzeppelin/contracts/utils/Context.sol
```

### 4.9.4 Integración en Workflow

```bash
# Pre-commit hook
#!/bin/bash
surya graph src/**/*.sol | dot -Tpng > docs/architecture.png
surya describe src/**/*.sol > docs/metrics.txt

# Detectar complejidad excesiva
HIGH_COMPLEXITY=$(surya describe src/**/*.sol | grep "Complexity" | awk '{if ($4 > 15) print $1}')

if [ -n "$HIGH_COMPLEXITY" ]; then
    echo "Warning: High complexity functions detected"
    echo "$HIGH_COMPLEXITY"
fi
```

---

## 4.10 Solhint - Linting y Best Practices

### 4.10.1 Propósito

**Solhint** es un linter de Solidity que verifica:

- **Security rules:** Vulnerabilidades conocidas
- **Style guide:** Convenciones de Solidity
- **Best practices:** Patrones recomendados
- **Gas optimization:** Ineficiencias de gas

### 4.10.2 Configuración

**.solhintrc:**

```json
{
  "extends": "solhint:recommended",
  "plugins": ["security"],
  "rules": {
    "avoid-suicide": "error",
    "avoid-sha3": "warn",
    "check-send-result": "error",
    "reentrancy": "error",
    "state-visibility": "error",
    "use-forbidden-name": "error",
    "avoid-tx-origin": "error",
    "compiler-version": ["error", "^0.8.0"],
    "func-name-mixedcase": "warn",
    "no-empty-blocks": "error",
    "no-unused-vars": "error",
    "code-complexity": ["warn", 8],
    "function-max-lines": ["warn", 50]
  }
}
```

### 4.10.3 Security Rules

```solidity
// ✗ BAD: avoid-tx-origin
function transferOwnership(address newOwner) public {
    require(tx.origin == owner);  // Vulnerable to phishing
    owner = newOwner;
}

// ✓ GOOD
function transferOwnership(address newOwner) public {
    require(msg.sender == owner);
    owner = newOwner;
}

// ✗ BAD: check-send-result
function withdraw() public {
    payable(msg.sender).send(amount);  // Ignores return value
}

// ✓ GOOD
function withdraw() public {
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Transfer failed");
}
```

### 4.10.4 Integración CI/CD

```yaml
# .github/workflows/lint.yml
name: Solidity Lint
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Solhint
        run: npm install -g solhint
      - name: Run Solhint
        run: solhint 'contracts/**/*.sol'
```

---

## 4.11 Comparativa Integral de Herramientas

| Herramienta | Técnica | Velocidad | Cobertura | Precisión | FP Rate | Expertise | Costo |
|-------------|---------|-----------|-----------|-----------|---------|-----------|-------|
| **Slither** | Estático | ★★★★★ <1s | ★★★★★ 100% | ★★★☆☆ 60% | Alto 40% | Bajo | Gratis |
| **Mythril** | Simbólico | ★★★☆☆ 5m | ★★★★☆ 85% | ★★★★☆ 75% | Medio 25% | Medio | Gratis |
| **Manticore** | Symb. Din. | ★★☆☆☆ 20m | ★★★★★ 95% | ★★★★★ 90% | Bajo 10% | Alto | Gratis |
| **Echidna** | Fuzzing | ★★★☆☆ 30m | ★★★☆☆ 60% | ★★★★★ 95% | Bajo 5% | Medio | Gratis |
| **Medusa** | Fuzzing | ★★★★☆ 5m | ★★★★☆ 80% | ★★★★★ 95% | Bajo 5% | Medio | Gratis |
| **Foundry** | Testing | ★★★★★ <1m | ★★★★☆ 70% | ★★★★★ 98% | Muy bajo 2% | Bajo | Gratis |
| **Certora** | Formal | ★☆☆☆☆ 1-2h | ★★★★★ 100% | ★★★★★ 99% | Muy bajo 1% | Alto | Alto |
| **Surya** | Visualización | ★★★★★ <1s | N/A | N/A | N/A | Bajo | Gratis |
| **Solhint** | Linting | ★★★★★ <1s | ★★★☆☆ | ★★★★☆ 80% | Medio 20% | Bajo | Gratis |

**Recomendaciones por Fase:**

```
Development Phase:
├─> IDE: Solhint, Slither extension
├─> Pre-commit: Slither (fast feedback)
└─> Local testing: Foundry unit + fuzz tests

CI/CD Phase:
├─> PR checks: Slither + Foundry test suite
├─> Nightly: Echidna/Medusa (long runs)
└─> Weekly: Mythril symbolic execution

Pre-Audit Phase:
├─> Invariant testing: Foundry + Echidna
├─> Differential testing: Foundry (v1 vs v2)
└─> Scribble instrumentation

Pre-Deployment Phase:
└─> Formal verification: Certora (critical functions)
```

## 4.8 Limitaciones del Estado del Arte

### 4.8.1 Problemas No Resueltos

1. **False Positives Overwhelm:**
   - Slither genera 50-200 findings por contrato mediano
   - 40-60% son falsos positivos
   - No hay priorización automática contextual

2. **Coverage Gaps:**
   - Fuzzing random no alcanza estados complejos
   - Formal verification limitada por costo computacional
   - Inter-contract interactions poco analizadas

3. **Falta de Integración:**
   - Herramientas operan en silos
   - No hay consolidación de resultados
   - Duplicación de esfuerzos entre técnicas

4. **Ausencia de Inteligencia Contextual:**
   - No se considera criticidad del protocolo
   - No se estima exploitabilidad real
   - No se adapta a patrones de código específicos

### 4.8.2 Oportunidades de Mejora

**1. Pipeline Híbrido:**
- Combinar fortalezas de cada técnica
- Usar resultados de una herramienta para guiar otra
- Ejemplo: Slither identifica candidates → Certora verifica formalmente

**2. AI-Assisted Triage:**
- Clasificación automática de severidad contextual
- Estimación de falsos positivos
- Generación de PoCs sintéticos

**3. Continuous Verification:**
- Análisis incremental en cada commit
- Regression testing de vulnerabilidades conocidas
- Dashboard centralizado de métricas

## 4.9 Síntesis del Capítulo

Este capítulo revisó el estado del arte en herramientas de auditoría:

1. **Slither:** Análisis estático rápido, 90+ detectores, alto FP rate
2. **Echidna:** Property-based fuzzing, alto precision, lento
3. **Medusa:** Coverage-guided fuzzing, 10-50x más rápido que Echidna
4. **Foundry:** Testing framework moderno, fuzz e invariant testing
5. **Scribble:** Runtime verification con anotaciones
6. **Certora:** Verificación formal con garantías matemáticas

**Gap Identificado:** Falta integración de herramientas con inteligencia contextual para priorización.

**Propuesta (Capítulo 5):** Framework Xaudit que combina todas estas técnicas con IA para triage automatizado.

---

**Referencias del Capítulo**

1. Feist, J. et al. (2019). "Slither: A Static Analysis Framework For Smart Contracts"
2. Trail of Bits. (2023). "Echidna: A Fast Smart Contract Fuzzer"
3. Trail of Bits. (2023). "Medusa: Coverage-Guided Fuzzer"
4. Paradigm. (2022). "Foundry Book"
5. Consensys Diligence. (2020). "Scribble: Runtime Verification Tool"
6. Certora. (2023). "Certora Verification Language Tutorial"
7. Grieco, G. et al. (2020). "Echidna: Effective, Usable, and Fast Fuzzing"
