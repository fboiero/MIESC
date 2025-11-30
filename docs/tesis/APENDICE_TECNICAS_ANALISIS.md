# Apéndice H: Fundamentos Técnicos de las Técnicas de Análisis

---

## H.1. Introducción

Este apéndice proporciona una descripción técnica detallada de las metodologías de análisis implementadas en cada capa de MIESC. Se explican los fundamentos teóricos, algoritmos subyacentes, y las fortalezas y limitaciones de cada técnica.

---

## H.2. Capa 1: Análisis Estático

### H.2.1. Fundamentos del Análisis Estático

El análisis estático examina el código fuente o bytecode sin ejecutarlo, utilizando técnicas de teoría de compiladores y análisis de programas.

#### H.2.1.1. Representación Intermedia (IR)

Las herramientas de análisis estático transforman el código Solidity en representaciones intermedias que facilitan el análisis:

```
Solidity Source → AST → CFG → IR → Analysis
```

**Componentes:**

1. **AST (Abstract Syntax Tree):** Árbol que representa la estructura sintáctica
2. **CFG (Control Flow Graph):** Grafo de flujo de control entre bloques básicos
3. **DFG (Data Flow Graph):** Grafo de flujo de datos entre variables

#### H.2.1.2. SlithIR - La IR de Slither

Slither utiliza una representación intermedia propia llamada SlithIR:

```
# Código Solidity
function withdraw() public {
    uint256 bal = balances[msg.sender];
    (bool s, ) = msg.sender.call{value: bal}("");
    balances[msg.sender] = 0;
}

# SlithIR equivalente
REF_0 -> balances[msg.sender]
bal = REF_0
TMP_0 = LOW_LEVEL_CALL, dest:msg.sender, value:bal, data:0x
(s, TMP_1) = TMP_0
REF_1 -> balances[msg.sender]
REF_1 := 0
```

#### H.2.1.3. Análisis de Flujo de Datos

El análisis de flujo de datos rastrea cómo los valores se propagan a través del programa:

**Algoritmo de Reaching Definitions:**
```
for each block B in CFG:
    IN[B] = ∪ OUT[P] for all predecessors P of B
    OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
```

**Aplicación a Reentrancy:**
```python
def detect_reentrancy(function):
    external_calls = find_external_calls(function)
    state_writes = find_state_writes(function)

    for call in external_calls:
        for write in state_writes:
            if dominates(call, write):  # call happens before write
                if depends_on_same_state(call, write):
                    report_vulnerability("reentrancy", call, write)
```

### H.2.2. Detectores de Slither

Slither implementa más de 80 detectores organizados por impacto:

| Categoría | Detectores | Ejemplo |
|-----------|-----------|---------|
| High | 15 | reentrancy-eth, arbitrary-send |
| Medium | 12 | controlled-delegatecall |
| Low | 25 | naming-convention |
| Informational | 30 | pragma, solc-version |

**Algoritmo de Detección de Reentrancy:**

```python
class ReentrancyDetector:
    def detect(self, contract):
        for function in contract.functions:
            # Encuentra llamadas externas
            external_calls = self._find_external_calls(function)

            # Encuentra escrituras de estado después de calls
            for call in external_calls:
                state_vars_written_after = self._get_state_vars_written_after(
                    function, call
                )
                state_vars_read_before = self._get_state_vars_read_before(
                    function, call
                )

                # Si la misma variable se lee antes y escribe después
                vulnerable_vars = state_vars_written_after & state_vars_read_before
                if vulnerable_vars:
                    yield Finding(
                        type="reentrancy-eth",
                        severity="High",
                        location=call.location,
                        variables=vulnerable_vars
                    )
```

### H.2.3. Análisis de Taint Tracking

El taint tracking rastrea datos controlados por el usuario:

```
Sources (Tainted):
- msg.sender
- msg.value
- tx.origin
- calldata
- function parameters

Sinks (Dangerous):
- address.call()
- address.transfer()
- selfdestruct()
- delegatecall()
- storage writes

Propagation Rules:
- assignment: taint(lhs) = taint(rhs)
- operation: taint(result) = taint(op1) ∪ taint(op2)
- array access: taint(arr[i]) = taint(arr) ∪ taint(i)
```

---

## H.3. Capa 2: Testing Dinámico (Fuzzing)

### H.3.1. Fundamentos del Fuzzing

El fuzzing genera entradas aleatorias o semi-aleatorias para descubrir comportamientos inesperados.

#### H.3.1.1. Tipos de Fuzzing

```
┌─────────────────────────────────────────────────────────────┐
│                    Taxonomía de Fuzzing                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐ │
│  │  Dumb Fuzzing  │  │ Smart Fuzzing  │  │Coverage-Guided │ │
│  ├────────────────┤  ├────────────────┤  ├────────────────┤ │
│  │ - Random input │  │ - Grammar-based│  │ - AFL-style    │ │
│  │ - No feedback  │  │ - Mutation     │  │ - Feedback loop│ │
│  │ - Low coverage │  │ - Type-aware   │  │ - High coverage│ │
│  └────────────────┘  └────────────────┘  └────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### H.3.1.2. Arquitectura de Echidna

Echidna es un fuzzer basado en propiedades para contratos Solidity:

```haskell
-- Pseudocódigo del algoritmo de Echidna
echidna :: Contract -> PropertyList -> TestResult
echidna contract properties = do
    corpus <- initializeCorpus

    replicateM testLimit $ do
        -- Selecciona y muta transacción
        tx <- selectAndMutate corpus

        -- Ejecuta en EVM
        result <- executeTransaction contract tx

        -- Verifica propiedades
        for_ properties $ \prop ->
            when (violates result prop) $
                reportViolation prop tx

        -- Actualiza corpus si aumenta cobertura
        when (increaseCoverage result corpus) $
            addToCorpus corpus tx
```

#### H.3.1.3. Propiedades de Echidna

```solidity
// Propiedad: balance nunca debe ser negativo (invariante)
function echidna_balance_positive() public view returns (bool) {
    return address(this).balance >= 0;
}

// Propiedad: solo owner puede pausar
function echidna_only_owner_pause() public view returns (bool) {
    return !paused || msg.sender == owner;
}

// Propiedad: supply total es constante
function echidna_constant_supply() public view returns (bool) {
    return totalSupply == INITIAL_SUPPLY;
}
```

### H.3.2. DogeFuzz: Coverage-Guided Fuzzing

DogeFuzz implementa fuzzing guiado por cobertura estilo AFL:

#### H.3.2.1. Power Scheduling

```python
class PowerScheduler:
    """Asigna 'energía' a semillas basado en su utilidad"""

    def calculate_energy(self, seed: Seed) -> int:
        # Factores que aumentan energía
        energy = BASE_ENERGY

        # Semillas que descubrieron nueva cobertura
        if seed.found_new_coverage:
            energy *= 2

        # Semillas más recientes tienen prioridad
        age_factor = 1.0 / (1 + seed.age)
        energy *= age_factor

        # Semillas con menos mutaciones tienen prioridad
        if seed.mutation_count < 10:
            energy *= 1.5

        return min(energy, MAX_ENERGY)
```

#### H.3.2.2. Mutación de Transacciones

```python
class TransactionMutator:
    def mutate(self, tx: Transaction) -> Transaction:
        mutation_type = random.choice([
            self._flip_bits,      # Flip bits aleatorios
            self._arithmetic,     # Operaciones aritméticas
            self._interesting,    # Valores interesantes
            self._splice,         # Combinar con otra tx
            self._dictionary      # Usar diccionario
        ])
        return mutation_type(tx)

    def _interesting_values(self):
        """Valores que frecuentemente causan bugs"""
        return [
            0, 1, 2**8-1, 2**16-1, 2**32-1, 2**64-1, 2**256-1,
            2**255,  # Overflow boundary
            -1,      # Underflow
        ]
```

---

## H.4. Capa 3: Ejecución Simbólica

### H.4.1. Fundamentos de la Ejecución Simbólica

La ejecución simbólica explora todos los caminos de ejecución posibles usando valores simbólicos en lugar de concretos.

#### H.4.1.1. Estados Simbólicos

```
Estado Simbólico = (PC, PathCondition, SymbolicMemory, SymbolicStorage)

Donde:
- PC: Program Counter
- PathCondition: Conjunción de condiciones del camino
- SymbolicMemory: Mapeo de direcciones a expresiones simbólicas
- SymbolicStorage: Mapeo de slots a expresiones simbólicas
```

#### H.4.1.2. Árbol de Ejecución

```
                    withdraw(amount)
                         │
                    ┌────┴────┐
                    │amount > 0│
                    └────┬────┘
              ┌──────────┴──────────┐
              │TRUE                 │FALSE
              ▼                     ▼
         balance >= amount      REVERT
              │
         ┌────┴────┐
         │         │
    ┌────┴────┐    │
    │TRUE     │FALSE
    ▼         ▼
  transfer  REVERT
    │
    ▼
  update_balance
```

#### H.4.1.3. Algoritmo de Mythril

```python
class SymbolicExecutor:
    def execute(self, contract_bytecode):
        # Estado inicial
        initial_state = State(
            pc=0,
            path_condition=True,
            memory={},
            storage={},
            constraints=[]
        )

        worklist = [initial_state]
        explored_states = set()

        while worklist:
            state = worklist.pop()

            # Evita estados duplicados
            if state.hash() in explored_states:
                continue
            explored_states.add(state.hash())

            # Ejecuta instrucción
            instruction = contract_bytecode[state.pc]
            new_states = self._execute_instruction(state, instruction)

            for new_state in new_states:
                # Verifica vulnerabilidades
                vulnerabilities = self._check_vulnerabilities(new_state)
                if vulnerabilities:
                    # Genera contraejemplo concreto
                    concrete = self._solve_constraints(new_state)
                    yield Finding(
                        vulnerability=vulnerabilities,
                        concrete_inputs=concrete,
                        path=new_state.path
                    )

                # Continúa exploración si es satisfacible
                if self._is_satisfiable(new_state.constraints):
                    worklist.append(new_state)
```

### H.4.2. SMT Solving

La ejecución simbólica usa solvers SMT (Satisfiability Modulo Theories) para razonar sobre constraints:

#### H.4.2.1. Teorías Usadas

```
QF_BV   - Bitvectors de tamaño fijo (uint256)
QF_ABV  - Arrays de bitvectors (mapping, storage)
QF_LIA  - Aritmética lineal de enteros
```

#### H.4.2.2. Ejemplo de Query SMT

```smt2
; Verificar si es posible retirar más del balance
(set-logic QF_BV)

; Variables simbólicas
(declare-fun balance () (_ BitVec 256))
(declare-fun amount () (_ BitVec 256))
(declare-fun msg_sender () (_ BitVec 160))

; Path condition: require(balance >= amount)
(assert (bvuge balance amount))

; Query: ¿Es posible que amount > balance después del call?
; (debido a reentrancy, balance no se actualizó)
(assert (bvugt amount balance))

(check-sat)
; Result: sat (vulnerable a reentrancy)
```

### H.4.3. Detección de Vulnerabilidades en Ejecución Simbólica

```python
class VulnerabilityDetector:
    def check_reentrancy(self, state):
        """SWC-107: Detecta reentrancy"""
        # Busca CALL seguido de SSTORE a la misma variable
        for i, op in enumerate(state.trace):
            if op.type == 'CALL':
                # Busca SSTORE posterior que dependa del mismo storage
                for j in range(i+1, len(state.trace)):
                    if state.trace[j].type == 'SSTORE':
                        if self._depends_on_same_storage(op, state.trace[j]):
                            return True
        return False

    def check_integer_overflow(self, state):
        """SWC-101: Detecta overflow/underflow"""
        for constraint in state.constraints:
            if constraint.type == 'ADD':
                # Verifica si a + b puede overflow
                a, b = constraint.operands
                overflow_condition = And(
                    UGT(a + b, MAX_UINT256),
                    UGE(a, 0),
                    UGE(b, 0)
                )
                if self._is_satisfiable(overflow_condition):
                    return True
        return False
```

---

## H.5. Capa 4: Invariant Testing

### H.5.1. Fundamentos del Testing de Invariantes

Los invariantes son propiedades que deben mantenerse verdaderas en todos los estados posibles del contrato.

#### H.5.1.1. Tipos de Invariantes

```solidity
// Invariante de Estado: Siempre verdadero
invariant totalSupply == sum(balances)

// Invariante de Transición: Verdadero antes y después de cada tx
invariant old(totalSupply) == totalSupply

// Invariante Condicional: Verdadero bajo ciertas condiciones
invariant paused => no_transfers_allowed
```

#### H.5.1.2. Verificación con Halmos

Halmos usa ejecución simbólica bounded para verificar invariantes:

```python
# test_invariants.py
from halmos import *

def test_balance_integrity(contract):
    """Verifica que los balances son consistentes"""
    # Setup simbólico
    user = symbolic('user', uint160)
    amount = symbolic('amount', uint256)

    # Estado inicial
    initial_balance = contract.balanceOf(user)

    # Ejecuta cualquier función
    contract.deposit(user, amount)

    # Verifica invariante
    assert contract.balanceOf(user) == initial_balance + amount

def test_no_free_money(contract):
    """Nadie puede obtener tokens sin pagar"""
    user = symbolic('user', uint160)

    initial_eth = eth_balance(user)
    initial_tokens = contract.balanceOf(user)

    # Cualquier secuencia de transacciones
    arbitrary_transactions(contract, user)

    final_eth = eth_balance(user)
    final_tokens = contract.balanceOf(user)

    # Si ganó tokens, debe haber gastado ETH
    if final_tokens > initial_tokens:
        assert final_eth < initial_eth
```

### H.5.2. Bounded Model Checking

```
BMC verifica propiedades hasta una profundidad k:

∀ paths de longitud ≤ k: invariant holds

Algoritmo:
1. Desenrolla el programa k veces
2. Codifica como fórmula SMT
3. Verifica satisfacibilidad
```

---

## H.6. Capa 5: Verificación Formal

### H.6.1. Fundamentos de la Verificación Formal

La verificación formal usa métodos matemáticos para demostrar propiedades de programas.

#### H.6.1.1. Lógica de Hoare

```
{P} S {Q}

P: Precondición
S: Programa
Q: Postcondición

Si P es verdadero antes de S, entonces Q es verdadero después.
```

#### H.6.1.2. Especificación en CVL (Certora)

```cvl
// VulnerableBank.spec

methods {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}

// Regla: Solo el dueño puede retirar su balance
rule only_owner_withdraws {
    env e;
    address user;

    uint256 balanceBefore = balanceOf(user);

    withdraw(e);

    uint256 balanceAfter = balanceOf(user);

    // Si el balance cambió, el caller debe ser el user
    assert balanceAfter < balanceBefore => e.msg.sender == user;
}

// Invariante: La suma de balances <= balance del contrato
invariant solvency_invariant()
    sum(balances) <= nativeBalances[currentContract]
```

### H.6.2. SMTChecker del Compilador Solidity

SMTChecker está integrado en solc y verifica:

```solidity
// SMTChecker verifica automáticamente:

// 1. Division by zero
function divide(uint a, uint b) returns (uint) {
    return a / b;  // SMTChecker: Warning if b can be 0
}

// 2. Overflow/Underflow (en versiones < 0.8.0)
function add(uint a, uint b) returns (uint) {
    return a + b;  // SMTChecker: Warning if overflow possible
}

// 3. Assert violations
function withdraw(uint amount) {
    assert(balance >= amount);  // SMTChecker verifica
    balance -= amount;
}

// 4. Unreachable code
function unreachable() {
    require(false);
    // SMTChecker: This code is unreachable
}
```

#### H.6.2.1. Motores de SMTChecker

```
┌─────────────────────────────────────────────────────────────┐
│                   SMTChecker Engines                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐       ┌─────────────┐                      │
│  │    BMC      │       │    CHC      │                      │
│  │  (Bounded)  │       │ (Unbounded) │                      │
│  ├─────────────┤       ├─────────────┤                      │
│  │ - Rápido    │       │ - Completo  │                      │
│  │ - Depth k   │       │ - Horn      │                      │
│  │ - Concreto  │       │   Clauses   │                      │
│  └─────────────┘       └─────────────┘                      │
│                                                              │
│  BMC: Busca bugs en k transacciones                         │
│  CHC: Prueba ausencia de bugs (inductivo)                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## H.7. Capa 6: Property Testing con IA

### H.7.1. PropertyGPT

PropertyGPT usa LLMs para generar propiedades formales automáticamente:

#### H.7.1.1. Pipeline de Generación

```
┌─────────────────────────────────────────────────────────────┐
│                  PropertyGPT Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Contract.sol                                                │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │  Extractor  │  → AST, CFG, Function signatures           │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │ LLM Prompt  │  → "Generate CVL rules for this contract"  │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │  Generator  │  → Candidate properties                     │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │  Verifier   │  → Run Certora to validate                 │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  Valid Properties + Counterexamples                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### H.7.1.2. Prompt Engineering para Propiedades

```python
PROPERTY_GENERATION_PROMPT = """
Analyze the following Solidity contract and generate formal
verification properties in Certora CVL format.

Contract:
{contract_source}

Generate properties for:
1. Access control invariants
2. State consistency invariants
3. Economic invariants (no free money)
4. Reentrancy safety
5. Arithmetic safety

Format each property as:
```cvl
rule property_name {
    // Setup
    env e;

    // Action
    function_call(e);

    // Assertion
    assert condition;
}
```
"""
```

### H.7.2. DA-GNN: Detección basada en Grafos

DA-GNN usa Graph Neural Networks para detectar vulnerabilidades:

#### H.7.2.1. Representación del Contrato como Grafo

```
Nodos = Instrucciones/Variables
Edges = {
    control_flow: CFG edges
    data_flow: DFG edges
    call_graph: Function calls
}

Cada nodo tiene features:
- Opcode embedding (128-dim)
- Variable type embedding
- Function context
```

#### H.7.2.2. Arquitectura GNN

```
Input: Graph G = (V, E, X)

Layer 1: h¹ᵢ = σ(W¹ · AGGREGATE({xⱼ : j ∈ N(i)}))
Layer 2: h²ᵢ = σ(W² · AGGREGATE({h¹ⱼ : j ∈ N(i)}))
...
Layer k: hᵏᵢ = σ(Wᵏ · AGGREGATE({hᵏ⁻¹ⱼ : j ∈ N(i)}))

Readout: g = READOUT({hᵏᵢ : i ∈ V})

Output: ŷ = softmax(MLP(g))

Donde ŷ ∈ {vulnerable, safe}
```

---

## H.8. Capa 7: Análisis con IA

### H.8.1. SmartLLM con RAG

SmartLLM combina LLMs con Retrieval-Augmented Generation:

#### H.8.1.1. Arquitectura RAG

```
┌─────────────────────────────────────────────────────────────┐
│                    SmartLLM RAG Pipeline                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Query: "Analyze this contract for reentrancy"               │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │  Embedder   │  → Query embedding                         │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐   ┌───────────────────────┐                │
│  │  Retriever  │◄──│  Knowledge Base       │                │
│  └─────────────┘   │  - ERC-20 spec        │                │
│       │            │  - SWC registry       │                │
│       │            │  - Past audit reports │                │
│       │            │  - Solidity best prac │                │
│       ▼            └───────────────────────┘                │
│  ┌─────────────┐                                            │
│  │  Generator  │  → LLM (Ollama/Llama)                      │
│  │  + Context  │                                            │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────┐                                            │
│  │ Verificator │  → Cross-check with tools                  │
│  └─────────────┘                                            │
│       │                                                      │
│       ▼                                                      │
│  Validated Findings                                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### H.8.1.2. Knowledge Base

```python
KNOWLEDGE_BASE = {
    "erc20": {
        "standard_functions": ["transfer", "approve", "transferFrom"],
        "common_vulnerabilities": [
            "approve front-running",
            "missing return value check",
            "fee-on-transfer issues"
        ]
    },
    "swc_registry": {
        "SWC-107": {
            "name": "Reentrancy",
            "pattern": "external_call before state_update",
            "fix": "CEI pattern or ReentrancyGuard"
        }
    },
    "audit_findings": [
        # Embeddings de hallazgos reales de auditorías
    ]
}
```

### H.8.2. Prompt Engineering para Análisis

```python
SECURITY_ANALYSIS_PROMPT = """
You are a smart contract security auditor. Analyze the following
Solidity code for vulnerabilities.

Context from knowledge base:
{retrieved_context}

Contract to analyze:
```solidity
{contract_code}
```

For each vulnerability found, provide:
1. Vulnerability type and SWC ID
2. Severity (Critical/High/Medium/Low/Informational)
3. Location (file, line, function)
4. Description of the issue
5. Proof of concept (if applicable)
6. Recommended fix

Be precise and avoid false positives. Only report issues you are
confident about.
"""
```

---

## H.9. Comparación de Técnicas

### H.9.1. Trade-offs

| Técnica | Soundness | Completeness | Escalabilidad | FP Rate |
|---------|-----------|--------------|---------------|---------|
| Static Analysis | Partial | No | Alta | Medio |
| Fuzzing | No | No | Alta | Bajo |
| Symbolic Execution | No | Partial | Baja | Bajo |
| Formal Verification | Sí | Sí* | Baja | Muy Bajo |
| ML/AI | No | No | Alta | Variable |

*Completeness depende de la especificación proporcionada

### H.9.2. Complementariedad en MIESC

```
          ┌────────────────────────────────────────────────────┐
          │           Coverage vs Depth Trade-off              │
          ├────────────────────────────────────────────────────┤
   High   │                                                    │
Coverage  │  Static Analysis ●                                 │
          │                    ╲                               │
          │  Fuzzing ●          ╲                              │
          │            ╲         ╲                             │
          │             ╲ ML/AI ● ╲                            │
          │              ╲         ╲                           │
          │               ╲         ╲                          │
          │  Symbolic ●    ╲         ╲                         │
          │                 ╲         ● Formal                 │
   Low    │                  ╲       Verification              │
          └────────────────────────────────────────────────────┘
                         Low ◄─────────────────► High
                                   Depth

MIESC combina todas las técnicas para maximizar tanto
coverage como depth.
```

---

## H.10. Referencias Técnicas

1. Feist, J., Grieco, G., & Groce, A. (2019). "Slither: A Static Analysis Framework for Smart Contracts." WOOT.

2. Mueller, B. (2018). "Mythril: Security Analysis Tool for EVM Bytecode." ConsenSys.

3. Grieco, G., et al. (2020). "Echidna: Effective, Usable, and Fast Fuzzing for Smart Contracts." ISSTA.

4. Ye, J., et al. (2024). "DogeFuzz: Coverage-guided Hybrid Fuzzing for Smart Contracts." arXiv:2409.01788.

5. Liu, Y., et al. (2025). "PropertyGPT: LLM-driven Formal Verification of Smart Contracts." NDSS.

6. Sun, M., et al. (2024). "SmartLLM: RAG-enhanced Security Analysis." arXiv:2502.13167.

7. Wang, S., et al. (2024). "DA-GNN: Domain-Adapted Graph Neural Networks for Smart Contract Vulnerability Detection." Computer Networks.

---

*Este apéndice proporciona los fundamentos técnicos para entender cómo cada capa de MIESC implementa sus técnicas de análisis de seguridad.*
