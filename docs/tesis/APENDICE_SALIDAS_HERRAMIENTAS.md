# Apendice A: Salidas de las 25 Herramientas de MIESC

## Catalogo Completo de Herramientas Integradas

---

## Tabla de Contenidos

1. [Capa 1: Analisis Estatico](#capa-1-analisis-estatico)
   - [A.1 Slither](#a1-slither)
   - [A.2 Solhint](#a2-solhint)
   - [A.3 Aderyn](#a3-aderyn)
2. [Capa 2: Testing Dinamico (Fuzzing)](#capa-2-testing-dinamico-fuzzing)
   - [A.4 Echidna](#a4-echidna)
   - [A.5 Foundry Fuzz](#a5-foundry-fuzz)
   - [A.6 Medusa](#a6-medusa)
   - [A.7 DogeFuzz](#a7-dogefuzz)
   - [A.8 Vertigo](#a8-vertigo)
3. [Capa 3: Ejecucion Simbolica](#capa-3-ejecucion-simbolica)
   - [A.9 Mythril](#a9-mythril)
   - [A.10 Manticore](#a10-manticore)
   - [A.11 Oyente](#a11-oyente)
4. [Capa 4: Analisis de Invariantes](#capa-4-analisis-de-invariantes)
   - [A.12 Halmos](#a12-halmos)
   - [A.13 Wake](#a13-wake)
5. [Capa 5: Verificacion Formal](#capa-5-verificacion-formal)
   - [A.14 SMTChecker](#a14-smtchecker)
   - [A.15 Certora](#a15-certora)
   - [A.16 PropertyGPT](#a16-propertygpt)
6. [Capa 6: Analisis con IA](#capa-6-analisis-con-ia)
   - [A.17 GPTScan](#a17-gptscan)
   - [A.18 SmartLLM](#a18-smartllm)
   - [A.19 LLMSmartAudit](#a19-llmsmartaudit)
   - [A.20 ThreatModel](#a20-threatmodel)
7. [Capa 7: Deteccion basada en ML](#capa-7-deteccion-basada-en-ml)
   - [A.21 SmartBugs-ML](#a21-smartbugs-ml)
   - [A.22 ContractCloneDetector](#a22-contractclonedetector)
   - [A.23 DAGNN](#a23-dagnn)
8. [Herramientas Especializadas](#herramientas-especializadas)
   - [A.24 GasAnalyzer](#a24-gasanalyzer)
   - [A.25 MEVDetector](#a25-mevdetector)
9. [Tabla Comparativa](#tabla-comparativa)

---

## Capa 1: Analisis Estatico

### A.1 Slither

**Descripcion:** Analizador estatico de Trail of Bits escrito en Python. Utiliza un framework de analisis intermedio (SlithIR) para detectar vulnerabilidades.

**Caracteristicas:**
- Mas de 80 detectores incorporados
- Soporte para herencia compleja
- Analisis de flujo de datos
- Integracion con CI/CD

**Salida de Ejemplo:**

```
$ slither contracts/audit/VulnerableBank.sol --json -

INFO:Printers:
Compiled with solc
Total number of contracts in source files: 2
Source lines of code (SLOC) in source files: 87
Number of assembly lines: 0
Number of optimization issues: 1
Number of informational issues: 4
Number of low issues: 2
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
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities

INFO:Detectors:
VulnerableBank.withdraw() (contracts/audit/VulnerableBank.sol#30-43) sends eth to arbitrary user
    Dangerous calls:
    - (success,None) = msg.sender.call{value: balance}() (line 35)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#functions-that-send-ether-to-arbitrary-destinations

INFO:Detectors:
VulnerableBank.withdrawAmount(uint256) (contracts/audit/VulnerableBank.sol#50-62) sends eth to arbitrary user
    Dangerous calls:
    - (success,None) = msg.sender.call{value: amount}() (line 57)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#functions-that-send-ether-to-arbitrary-destinations

INFO:Slither:contracts/audit/VulnerableBank.sol analyzed (2 contracts), 9 result(s) found
```

**Salida Normalizada MIESC (JSON):**

```json
{
  "tool": "slither",
  "version": "0.9.6",
  "status": "completed",
  "execution_time_ms": 2341,
  "findings": [
    {
      "id": "SLITHER-001",
      "type": "reentrancy-eth",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()",
        "contract": "VulnerableBank"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Reentrancy vulnerability. External call at line 35 followed by state modification at line 39.",
      "recommendation": "Apply checks-effects-interactions pattern"
    },
    {
      "id": "SLITHER-002",
      "type": "arbitrary-send-eth",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()",
        "contract": "VulnerableBank"
      },
      "swc_id": "SWC-105",
      "cwe_id": "CWE-284",
      "message": "Function sends ETH to arbitrary destination controlled by caller"
    }
  ]
}
```

---

### A.2 Solhint

**Descripcion:** Linter de Solidity que verifica mejores practicas de estilo y seguridad.

**Caracteristicas:**
- Reglas configurables via .solhint.json
- Plugins extensibles
- Integracion con editores (VSCode, Vim)
- Soporte para Solidity 0.8.x

**Salida de Ejemplo:**

```
$ solhint contracts/audit/VulnerableBank.sol

contracts/audit/VulnerableBank.sol
   2:1    warning  Compiler version ^0.8.19 does not satisfy the ^0.8.0
                   semver requirement                              compiler-version
   8:5    warning  Visibility modifier must be first in list of
                   modifiers                                       visibility-modifier-order
  35:9    error    Avoid using low level calls                     avoid-low-level-calls
  35:9    warning  Return value of low-level calls not checked     check-send-result
  57:9    error    Avoid using low level calls                     avoid-low-level-calls
  68:1    warning  Contract has 1 states declarations but
                   missing explicit visibility                     state-visibility
  78:5    warning  Function order is incorrect                     ordering
  92:9    error    Avoid using low level calls                     avoid-low-level-calls

8 problems (3 errors, 5 warnings)
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "solhint",
  "version": "4.1.1",
  "status": "completed",
  "execution_time_ms": 847,
  "findings": [
    {
      "id": "SOLHINT-001",
      "type": "avoid-low-level-calls",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "column": 9
      },
      "swc_id": "SWC-104",
      "cwe_id": "CWE-749",
      "message": "Avoid using low level calls. Use high-level Solidity constructs instead.",
      "rule": "security/avoid-low-level-calls"
    },
    {
      "id": "SOLHINT-002",
      "type": "check-send-result",
      "severity": "LOW",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "column": 9
      },
      "swc_id": "SWC-104",
      "message": "Return value of low-level calls not checked"
    }
  ]
}
```

---

### A.3 Aderyn

**Descripcion:** Analizador estatico escrito en Rust por Cyfrin. Ofrece velocidad superior y detectores especializados.

**Caracteristicas:**
- Extremadamente rapido (implementacion Rust)
- Detectores para DeFi
- Soporte para Foundry projects
- Reportes en multiple formatos

**Salida de Ejemplo:**

```
$ aderyn contracts/audit/VulnerableBank.sol

                             _
     /\      | |
    /  \   __| | ___ _ __ _   _ _ __
   / /\ \ / _` |/ _ \ '__| | | | '_ \
  / ____ \ (_| |  __/ |  | |_| | | | |
 /_/    \_\__,_|\___|_|   \__, |_| |_|
                           __/ |
                          |___/  v0.1.0

[INFO] Analyzing contracts...
[INFO] Found 2 contracts in 1 file

================================================================================
                            VULNERABILITY REPORT
================================================================================

[HIGH] Reentrancy Vulnerability Detected
  File: VulnerableBank.sol
  Line: 30-43
  Function: withdraw()

  The function performs an external call before updating state.
  This allows an attacker to re-enter the function before the
  balance is set to zero.

  Pattern detected:
    - External call: msg.sender.call{value: balance}()
    - State update after call: balances[msg.sender] = 0

[HIGH] Unprotected Ether Withdrawal
  File: VulnerableBank.sol
  Line: 30-43
  Function: withdraw()

  Any user can withdraw their full balance. Consider adding
  withdrawal limits or timelock mechanisms.

[MEDIUM] Missing Event Emission
  File: VulnerableBank.sol
  Line: 30
  Function: withdraw()

  No event is emitted for withdrawal. This makes off-chain
  tracking difficult.

[LOW] Floating Pragma
  File: VulnerableBank.sol
  Line: 2

  Pragma uses ^0.8.19. Consider locking to a specific version.

================================================================================
Summary: 2 High, 1 Medium, 1 Low
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "aderyn",
  "version": "0.1.0",
  "status": "completed",
  "execution_time_ms": 312,
  "findings": [
    {
      "id": "ADERYN-001",
      "type": "reentrancy",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 30,
        "end_line": 43,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Reentrancy vulnerability. External call before state update.",
      "recommendation": "Update balances before external call"
    },
    {
      "id": "ADERYN-002",
      "type": "missing-events",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 30,
        "function": "withdraw()"
      },
      "swc_id": null,
      "cwe_id": "CWE-778",
      "message": "No event emitted for withdrawal operation"
    }
  ]
}
```

---

## Capa 2: Testing Dinamico (Fuzzing)

### A.4 Echidna

**Descripcion:** Fuzzer de contratos inteligentes de Trail of Bits basado en property testing.

**Caracteristicas:**
- Property-based testing
- Campanas de fuzzing configurables
- Shrinking automatico de tests fallidos
- Cobertura de codigo

**Salida de Ejemplo:**

```
$ echidna contracts/audit/VulnerableBank.sol --contract VulnerableBank

Analyzing contract: VulnerableBank
Loaded 5 functions from VulnerableBank

echidna_balance_invariant: FAILED!
  Call sequence:
    1. deposit() value: 1000000000000000000
    2. deposit() from: 0x20000 value: 500000000000000000
    3. withdraw() (reentrancy triggered)

  Violation: Contract balance does not equal sum of user balances
  Expected: 1500000000000000000
  Actual: 0

  Shrunk sequence (2 calls):
    1. deposit() value: 1000000000000000000
    2. withdraw() via attack contract

echidna_no_ether_drain: FAILED!
  Call sequence:
    1. deposit() value: 2 ether
    2. attack() from malicious contract

  Violation: Contract can be drained completely

echidna_owner_unchanged: PASSED

Unique instructions: 847
Unique paths: 234
Tests: 50000/50000
Seed: 3141592653

================================================================================
Summary:
  PASSED: 1 (echidna_owner_unchanged)
  FAILED: 2 (echidna_balance_invariant, echidna_no_ether_drain)
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "echidna",
  "version": "2.2.1",
  "status": "completed",
  "execution_time_ms": 18542,
  "coverage": {
    "unique_instructions": 847,
    "unique_paths": 234,
    "tests_executed": 50000
  },
  "findings": [
    {
      "id": "ECHIDNA-001",
      "type": "invariant-violation",
      "severity": "HIGH",
      "confidence": "HIGH",
      "property": "echidna_balance_invariant",
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Balance invariant violated. Contract can be drained via reentrancy.",
      "call_sequence": [
        "deposit() value: 1 ether",
        "withdraw() via attack contract"
      ],
      "recommendation": "Implement ReentrancyGuard or checks-effects-interactions"
    },
    {
      "id": "ECHIDNA-002",
      "type": "ether-drain",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "property": "echidna_no_ether_drain",
      "swc_id": "SWC-105",
      "message": "Contract funds can be completely drained"
    }
  ]
}
```

---

### A.5 Foundry Fuzz

**Descripcion:** Framework de testing integrado en Forge de Paradigm.

**Caracteristicas:**
- Fuzzing integrado en tests
- Velocidad extrema (implementacion Rust)
- Cheatcodes para testing avanzado
- Integracion con fork de mainnet

**Salida de Ejemplo:**

```
$ forge test --match-test testFuzz -vvv

Running 3 tests for test/VulnerableBank.t.sol:VulnerableBankTest
[FAIL. Reason: Reentrancy attack successful]
  testFuzz_WithdrawSafety(uint256) (runs: 847, mu: 45231, ~: 42000)

    Logs:
      Initial deposit: 1000000000000000000
      Attacker balance before: 0
      Attacker balance after: 3000000000000000000
      Attack multiplied funds by 3x

    Counterexample:
      args=[1000000000000000000 [1e18]]

    Stack traces:
      [2134] VulnerableBank::withdraw()
        [1523] ReentrancyAttacker::receive()
          [1102] VulnerableBank::withdraw() <- REENTRANT CALL
            ...

[PASS] testFuzz_DepositWithdraw(uint96) (runs: 1000, mu: 23421, ~: 21000)
[PASS] testFuzz_MultipleDeposits(uint96,uint96) (runs: 1000, mu: 34521, ~: 32000)

Test result: FAILED. 2 passed; 1 failed; finished in 2.34s
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "foundry_fuzz",
  "version": "0.2.0",
  "status": "completed",
  "execution_time_ms": 2340,
  "findings": [
    {
      "id": "FOUNDRY-001",
      "type": "reentrancy-attack",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "test": "testFuzz_WithdrawSafety",
      "runs": 847,
      "counterexample": {
        "args": ["1000000000000000000"]
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Reentrancy attack successful. Attacker multiplied funds by 3x.",
      "logs": [
        "Initial deposit: 1 ether",
        "Attacker balance after: 3 ether"
      ]
    }
  ],
  "passed_tests": ["testFuzz_DepositWithdraw", "testFuzz_MultipleDeposits"]
}
```

---

### A.6 Medusa

**Descripcion:** Fuzzer de contratos inteligentes escrito en Go, enfocado en coverage-guided fuzzing.

**Caracteristicas:**
- Coverage-guided mutation
- Soporte para assertion testing
- Paralelizacion nativa
- API para integracion

**Salida de Ejemplo:**

```
$ medusa fuzz --target contracts/audit/VulnerableBank.sol

 __  __          _
|  \/  | ___  __| |_   _ ___  __ _
| |\/| |/ _ \/ _` | | | / __|/ _` |
| |  | |  __/ (_| | |_| \__ \ (_| |
|_|  |_|\___|\__,_|\__,_|___/\__,_|
                           v0.1.3

[*] Compiling target contracts...
[*] Starting fuzzing campaign...
[*] Workers: 4

================================================================================
PROPERTY VIOLATION DETECTED
================================================================================

Property: property_balance_integrity
Status: FALSIFIED

Call Sequence (optimized):
  Tx 1: deposit{value: 1 ether}() from: 0xDeaD
  Tx 2: attack() from: 0xBeef [ReentrancyAttacker]

Violation Details:
  - Expected: sum(balances) == address(this).balance
  - Actual: sum(balances) = 1 ether, contract balance = 0

================================================================================
COVERAGE STATISTICS
================================================================================

Total instructions covered: 892/1024 (87.1%)
Total branches covered: 156/189 (82.5%)
Total functions covered: 9/9 (100%)

Corpus size: 47 unique inputs
Time elapsed: 00:00:32

================================================================================
SUMMARY
================================================================================

Properties tested: 3
  - PASSED: 2
  - FAILED: 1
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "medusa",
  "version": "0.1.3",
  "status": "completed",
  "execution_time_ms": 32000,
  "coverage": {
    "instructions": {"covered": 892, "total": 1024, "percentage": 87.1},
    "branches": {"covered": 156, "total": 189, "percentage": 82.5},
    "functions": {"covered": 9, "total": 9, "percentage": 100}
  },
  "findings": [
    {
      "id": "MEDUSA-001",
      "type": "property-violation",
      "severity": "HIGH",
      "confidence": "HIGH",
      "property": "property_balance_integrity",
      "swc_id": "SWC-107",
      "message": "Balance integrity property violated via reentrancy",
      "call_sequence": [
        "deposit{value: 1 ether}() from: 0xDeaD",
        "attack() from: 0xBeef"
      ]
    }
  ]
}
```

---

### A.7 DogeFuzz

**Descripcion:** Fuzzer experimental basado en machine learning para guiar la generacion de inputs.

**Caracteristicas:**
- ML-guided input generation
- Integracion con Echidna
- Analisis de codigo para hot paths
- Deteccion de estados interesantes

**Salida de Ejemplo:**

```
$ dogefuzz contracts/audit/VulnerableBank.sol

DogeFuzz v0.1.0 - ML-Guided Smart Contract Fuzzer
=================================================

[*] Analyzing contract structure...
[*] Training ML model on contract patterns...
[*] Generating guided test inputs...

Round 1/10: Testing 1000 inputs
  Coverage improvement: +23.4%
  Interesting states found: 3

Round 2/10: Testing 1000 inputs
  Coverage improvement: +8.2%
  Interesting states found: 2

...

Round 10/10: Testing 1000 inputs
  Coverage improvement: +0.1%
  Plateau reached.

================================================================================
ANOMALY DETECTED
================================================================================

Type: State Inconsistency
Function: withdraw()
Trigger: ML-generated sequence #4521

The model detected unusual state transitions:
  Before: balances[attacker] = 1 ether, contract.balance = 5 ether
  After:  balances[attacker] = 0, contract.balance = 0

This indicates potential reentrancy exploitation.

Confidence: 94.2%
Similar patterns in training data: 847/1000 known exploits

================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "dogefuzz",
  "version": "0.1.0",
  "status": "completed",
  "execution_time_ms": 45000,
  "ml_metrics": {
    "rounds": 10,
    "total_inputs": 10000,
    "final_coverage": 91.3,
    "model_confidence": 0.942
  },
  "findings": [
    {
      "id": "DOGEFUZZ-001",
      "type": "state-inconsistency",
      "severity": "HIGH",
      "confidence": "HIGH",
      "ml_confidence": 0.942,
      "location": {
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "message": "ML model detected state inconsistency indicating reentrancy",
      "similar_exploits_in_training": 847
    }
  ]
}
```

---

### A.8 Vertigo

**Descripcion:** Herramienta de mutation testing para contratos inteligentes.

**Caracteristicas:**
- Mutation testing automatizado
- Integracion con Foundry/Hardhat
- Reportes de mutantes sobrevivientes
- Analisis de calidad de tests

**Salida de Ejemplo:**

```
$ vertigo run --target contracts/audit/VulnerableBank.sol

Vertigo v1.3.0 - Mutation Testing for Smart Contracts
======================================================

[*] Generating mutants...
[*] Generated 47 mutants across 2 contracts

Running mutations against test suite...

Mutant 1/47: [SURVIVED]
  File: VulnerableBank.sol:35
  Original: (success, ) = msg.sender.call{value: balance}("");
  Mutation: (success, ) = msg.sender.call{value: balance - 1}("");

  No test detected this mutation! Test suite may be insufficient.

Mutant 2/47: [KILLED]
  File: VulnerableBank.sol:39
  Original: balances[msg.sender] = 0;
  Mutation: balances[msg.sender] = 1;

  Killed by: testWithdrawAll

Mutant 3/47: [SURVIVED]
  File: VulnerableBank.sol:31
  Original: require(balance > 0, "No balance");
  Mutation: require(balance >= 0, "No balance");

  No test for zero balance case!

...

================================================================================
MUTATION TESTING REPORT
================================================================================

Total Mutants: 47
Killed: 32 (68.1%)
Survived: 15 (31.9%)

Mutation Score: 68.1% (target: >80%)

Surviving Mutations by Category:
  - Boundary conditions: 7
  - Arithmetic operations: 5
  - Access control: 3

Recommendation: Add tests for boundary conditions and zero-value cases.
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "vertigo",
  "version": "1.3.0",
  "status": "completed",
  "execution_time_ms": 23000,
  "mutation_score": 68.1,
  "findings": [
    {
      "id": "VERTIGO-001",
      "type": "surviving-mutant",
      "severity": "LOW",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35
      },
      "original_code": "(success, ) = msg.sender.call{value: balance}(\"\");",
      "mutated_code": "(success, ) = msg.sender.call{value: balance - 1}(\"\");",
      "message": "Mutant survived. Test suite may not detect off-by-one errors.",
      "category": "boundary-condition"
    },
    {
      "id": "VERTIGO-002",
      "type": "surviving-mutant",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 31
      },
      "original_code": "require(balance > 0, \"No balance\");",
      "mutated_code": "require(balance >= 0, \"No balance\");",
      "message": "No test for zero balance withdrawal case",
      "category": "boundary-condition"
    }
  ],
  "summary": {
    "total_mutants": 47,
    "killed": 32,
    "survived": 15
  }
}
```

---

## Capa 3: Ejecucion Simbolica

### A.9 Mythril

**Descripcion:** Framework de ejecucion simbolica de ConsenSys para analisis de seguridad.

**Caracteristicas:**
- Ejecucion simbolica con z3 solver
- Deteccion de patrones de vulnerabilidad
- Analisis de control flow
- Soporte para multiples contratos

**Salida de Ejemplo:**

```
$ myth analyze contracts/audit/VulnerableBank.sol --execution-timeout 120

==== External Call To User-Supplied Address ====
SWC ID: 107
Severity: Medium
Contract: VulnerableBank
Function name: withdraw()
PC address: 847
Estimated Gas Usage: 10783 - 65819

An external message call to an address specified by the caller is executed.
Note that the callee account might contain arbitrary code and could re-enter
any function within this contract. Reentering the contract in an intermediate
state may lead to unexpected behaviour.

--------------------
In file: VulnerableBank.sol:35

(success, ) = msg.sender.call{value: balance}("")

--------------------
Initial State:
Account: [CREATOR], balance: 0x0, nonce:0, storage:{}
Account: [ATTACKER], balance: 0x0, nonce:0, storage:{}

Transaction Sequence:
Caller: [CREATOR], calldata: , value: 0x0
Caller: [ATTACKER], function: deposit(), txdata: 0xd0e30db0, value: 0x1
Caller: [ATTACKER], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0

==== State access after external call ====
SWC ID: 107
Severity: Medium
Contract: VulnerableBank
Function name: withdraw()
PC address: 912

A state variable is accessed after an external call to a user defined address.
To prevent reentrancy issues, consider implementing a 'checks-effects-interactions'
pattern.

--------------------
In file: VulnerableBank.sol:39

balances[msg.sender] = 0

--------------------

==== Unprotected Ether Withdrawal ====
SWC ID: 105
Severity: High
Contract: VulnerableBank
Function name: withdraw()
PC address: 847

Any sender can withdraw Ether from the contract account.

--------------------
Transaction Sequence:
Caller: [SOMEGUY], function: deposit(), txdata: 0xd0e30db0, value: 0x1
Caller: [ATTACKER], function: withdraw(), txdata: 0x3ccfd60b, value: 0x0
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "mythril",
  "version": "0.24.7",
  "status": "completed",
  "execution_time_ms": 28432,
  "findings": [
    {
      "id": "MYTHRIL-001",
      "type": "external-call-reentrancy",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "pc_address": 847,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "External call to user-supplied address. Contract may be re-entered.",
      "gas_estimate": {"min": 10783, "max": 65819},
      "transaction_sequence": [
        "deposit() value: 0x1",
        "withdraw()"
      ]
    },
    {
      "id": "MYTHRIL-002",
      "type": "state-access-after-call",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 39,
        "pc_address": 912,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "message": "State variable accessed after external call"
    },
    {
      "id": "MYTHRIL-003",
      "type": "unprotected-ether-withdrawal",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "pc_address": 847,
        "function": "withdraw()"
      },
      "swc_id": "SWC-105",
      "cwe_id": "CWE-284",
      "message": "Any sender can withdraw Ether from contract account"
    }
  ]
}
```

---

### A.10 Manticore

**Descripcion:** Herramienta de ejecucion simbolica de Trail of Bits con capacidades avanzadas.

**Caracteristicas:**
- Ejecucion simbolica completa
- Soporte para EVM y WASM
- Deteccion de integer overflow
- Generacion de test cases

**Salida de Ejemplo:**

```
$ manticore contracts/audit/VulnerableBank.sol

Manticore 0.3.7
[*] Analyzing contract VulnerableBank
[*] Running symbolic execution...

=== Vulnerability Report ===

1. Reentrancy Detected
   Location: withdraw() at 0x847

   Path Constraints:
     - msg.sender can be malicious contract
     - balance[msg.sender] > 0
     - External call returns to attacker's receive()

   Exploit State:
     balance_before: 1000000000000000000
     balance_after: 0
     attacker_gained: 3000000000000000000

   Test Case Generated: testcase_reentrancy_0.tx

2. Integer Underflow Potential
   Location: withdrawAmount(uint256) at 0x1023

   Path Constraints:
     - amount > balances[msg.sender] (if unchecked)

   Note: Protected by require() but detectable in older Solidity

=== Summary ===
States explored: 1847
Vulnerabilities found: 2
Test cases generated: 2
Time elapsed: 127.4s
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "manticore",
  "version": "0.3.7",
  "status": "completed",
  "execution_time_ms": 127400,
  "symbolic_execution": {
    "states_explored": 1847,
    "paths_analyzed": 234
  },
  "findings": [
    {
      "id": "MANTICORE-001",
      "type": "reentrancy",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "address": "0x847",
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Reentrancy detected. Symbolic execution found exploit path.",
      "exploit_state": {
        "balance_before": "1 ether",
        "balance_after": "0",
        "attacker_gained": "3 ether"
      },
      "test_case": "testcase_reentrancy_0.tx"
    }
  ]
}
```

---

### A.11 Oyente

**Descripcion:** Uno de los primeros analizadores simbolicos para Ethereum, ahora disponible via Docker.

**Caracteristicas:**
- Analisis de control flow
- Deteccion de vulnerabilidades clasicas
- Soporte legacy para Solidity antiguo
- Rapido para contratos simples

**Salida de Ejemplo:**

```
$ docker run -v $(pwd):/contracts luongnguyen/oyente -s /contracts/VulnerableBank.sol

   ____                  _
  / __ \                | |
 | |  | |_   _  ___ _ __ | |_ ___
 | |  | | | | |/ _ \ '_ \| __/ _ \
 | |__| | |_| |  __/ | | | ||  __/
  \____/ \__, |\___|_| |_|\__\___|
          __/ |
         |___/          v0.2.7

Contract: VulnerableBank
=========================================

[INFO] Compiling contract...
[INFO] Building control flow graph...
[INFO] Analyzing for vulnerabilities...

CRITICAL: Re-Entrancy Vulnerability
  Location: Function withdraw()
  Pattern: CALL before state update

  The external CALL at PC 0x0847 is executed before
  the state variable at storage slot 0x0 is updated.
  This enables reentrancy attacks.

WARNING: Unchecked Call Return Value
  Location: Function withdraw(), line 35
  Pattern: CALL result not checked properly

  While (success, ) is captured, the require check
  could be bypassed in certain conditions.

INFO: Analysis Complete
  Time: 3.2 seconds
  Instructions analyzed: 487
  Paths explored: 23
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "oyente",
  "version": "0.2.7",
  "status": "completed",
  "execution_time_ms": 3200,
  "findings": [
    {
      "id": "OYENTE-001",
      "type": "reentrancy",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "function": "withdraw()",
        "pc_address": "0x0847"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Re-Entrancy vulnerability. CALL before state update."
    },
    {
      "id": "OYENTE-002",
      "type": "unchecked-call",
      "severity": "LOW",
      "confidence": "MEDIUM",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()"
      },
      "swc_id": "SWC-104",
      "message": "Call return value not properly validated"
    }
  ]
}
```

---

## Capa 4: Analisis de Invariantes

### A.12 Halmos

**Descripcion:** Verificador simbolico para Foundry que permite probar invariantes matematicamente.

**Caracteristicas:**
- Integracion nativa con Foundry
- Verificacion simbolica de propiedades
- Soporte para bounded model checking
- Contrajemplos detallados

**Salida de Ejemplo:**

```
$ halmos --contract VulnerableBank --function check_

Running halmos v0.1.10

[*] Checking check_balance_invariant...

[FAIL] check_balance_invariant
  Counterexample found:

    Symbolic values:
      p_amount_uint256 = 0x1 (1)
      p_caller_address = 0xaaaa...aaaa (attacker)

    Call trace:
      1. deposit{value: 1}() from attacker
      2. withdraw() from attacker
         -> receive() callback in attacker
         -> withdraw() reentrant call

    Invariant violated:
      assert(address(this).balance == totalDeposited)

      address(this).balance = 0
      totalDeposited = 1

    Counterexample block: 12345

[*] Checking check_no_unauthorized_withdrawal...

[PASS] check_no_unauthorized_withdrawal
  Verified for all inputs up to bound 256

[*] Checking check_owner_immutable...

[PASS] check_owner_immutable
  Verified: owner cannot be changed after deployment

================================================================================
Summary: 1 failed, 2 passed (3 total)
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "halmos",
  "version": "0.1.10",
  "status": "completed",
  "execution_time_ms": 14100,
  "verification": {
    "total_properties": 3,
    "passed": 2,
    "failed": 1
  },
  "findings": [
    {
      "id": "HALMOS-001",
      "type": "invariant-violation",
      "severity": "HIGH",
      "confidence": "HIGH",
      "property": "check_balance_invariant",
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Balance invariant violated. Contract balance != totalDeposited",
      "counterexample": {
        "p_amount_uint256": "0x1",
        "p_caller_address": "0xaaaa...aaaa",
        "result": {
          "contract_balance": 0,
          "total_deposited": 1
        }
      },
      "call_trace": [
        "deposit{value: 1}() from attacker",
        "withdraw() with reentrant callback"
      ]
    }
  ]
}
```

---

### A.13 Wake

**Descripcion:** Framework de testing y analisis con soporte para verificacion de propiedades.

**Caracteristicas:**
- Verificacion de propiedades Python
- Integracion con pytest
- Analisis de cobertura
- Soporte para forks

**Salida de Ejemplo:**

```
$ wake test contracts/audit/VulnerableBank.sol

Wake v4.5.0 - Smart Contract Testing Framework

Running property tests...

test_property_balance_integrity ................... FAILED

  AssertionError: Balance integrity violated

  Setup:
    - Deployed VulnerableBank at 0x1234...
    - Deployed ReentrancyAttacker at 0x5678...

  Execution:
    tx1 = bank.deposit(value=1 ether, from=attacker)
    tx2 = attacker.attack()

  Assertion Failed:
    assert bank.balance() == sum(bank.balances.values())
    Left:  0
    Right: 1000000000000000000

  Gas Used: 234521

test_property_withdrawal_authorized ............... PASSED
test_property_deposit_increases_balance ........... PASSED

================================================================================
Results: 1 failed, 2 passed
Coverage: 87.3%
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "wake",
  "version": "4.5.0",
  "status": "completed",
  "execution_time_ms": 8900,
  "coverage": 87.3,
  "findings": [
    {
      "id": "WAKE-001",
      "type": "property-test-failure",
      "severity": "HIGH",
      "confidence": "HIGH",
      "property": "test_property_balance_integrity",
      "swc_id": "SWC-107",
      "message": "Balance integrity property failed. Contract balance != sum of user balances.",
      "assertion": {
        "expected": "bank.balance() == sum(bank.balances.values())",
        "actual_left": 0,
        "actual_right": "1 ether"
      }
    }
  ],
  "passed_tests": [
    "test_property_withdrawal_authorized",
    "test_property_deposit_increases_balance"
  ]
}
```

---

## Capa 5: Verificacion Formal

### A.14 SMTChecker

**Descripcion:** Verificador formal integrado en el compilador Solidity usando SMT solvers.

**Caracteristicas:**
- Integrado en solc
- Soporte para CHC y BMC
- Verificacion de assertions
- Deteccion de overflow/underflow

**Salida de Ejemplo:**

```
$ solc --model-checker-engine chc --model-checker-targets all \
       --model-checker-timeout 60000 contracts/audit/VulnerableBank.sol

Warning: CHC: Assertion violation happens here.
  --> VulnerableBank.sol:39:9:
   |
39 |         balances[msg.sender] = 0;
   |         ^^^^^^^^^^^^^^^^^^^^^^^^
Note: Counterexample:
  msg.sender = 0x1234...
  balances[msg.sender] = 1000000000000000000

  Transaction trace:
  VulnerableBank.constructor()
  State: balances[0x1234] = 0
  VulnerableBank.deposit(){ msg.value: 1000000000000000000 }
  State: balances[0x1234] = 1000000000000000000
  VulnerableBank.withdraw()
    External call to msg.sender
    --> Reentrant call to withdraw()
        State accessed before update!

Warning: CHC: Reentrancy vulnerability detected.
  --> VulnerableBank.sol:35:9:
   |
35 |         (bool success, ) = msg.sender.call{value: balance}("");
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Warning: CHC: 3 verification condition(s) could not be proved.
Info: Consider increasing the solver timeout.
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "smtchecker",
  "version": "0.8.19",
  "status": "completed",
  "execution_time_ms": 9800,
  "verification": {
    "engine": "CHC",
    "timeout_ms": 60000,
    "conditions_checked": 8,
    "conditions_unproved": 3
  },
  "findings": [
    {
      "id": "SMT-001",
      "type": "assertion-violation",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 39,
        "column": 9
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Assertion violation. State accessed in inconsistent order.",
      "counterexample": {
        "msg_sender": "0x1234...",
        "initial_balance": "1 ether"
      },
      "transaction_trace": [
        "constructor()",
        "deposit() value: 1 ether",
        "withdraw() -> reentrant call"
      ]
    },
    {
      "id": "SMT-002",
      "type": "reentrancy",
      "severity": "HIGH",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35
      },
      "swc_id": "SWC-107",
      "message": "Formal verification detected reentrancy vulnerability"
    }
  ]
}
```

---

### A.15 Certora

**Descripcion:** Plataforma profesional de verificacion formal para smart contracts.

**Caracteristicas:**
- Lenguaje de especificacion CVL
- Verificacion de invariantes complejas
- Soporte para DeFi protocols
- Cloud-based analysis

**Salida de Ejemplo:**

```
$ certoraRun VulnerableBank.conf

Certora Prover v6.3.1
=====================

[INFO] Compiling contracts...
[INFO] Uploading to Certora cloud...
[INFO] Running verification...

Job URL: https://prover.certora.com/output/12345

================================================================================
SPECIFICATION: VulnerableBank.spec
================================================================================

Rule: balanceIntegrity
Status: VIOLATED

Counterexample:
  Initial state:
    balances[attacker] = 1 ether
    contract.balance = 1 ether

  Call sequence:
    1. attacker.call withdraw()
    2. attacker.receive() -> withdraw() [reentrant]

  Final state:
    balances[attacker] = 0
    contract.balance = 0
    attacker.balance = 2 ether (!)

  Violation: contract.balance < sum(balances)

--------------------------------------------------------------------------------

Rule: noUnauthorizedWithdrawal
Status: VERIFIED

Rule: ownerImmutable
Status: VERIFIED

================================================================================
SUMMARY
================================================================================

Total Rules: 3
Verified: 2
Violated: 1

Time: 45.2 seconds
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "certora",
  "version": "6.3.1",
  "status": "completed",
  "execution_time_ms": 45200,
  "job_url": "https://prover.certora.com/output/12345",
  "verification": {
    "total_rules": 3,
    "verified": 2,
    "violated": 1
  },
  "findings": [
    {
      "id": "CERTORA-001",
      "type": "rule-violation",
      "severity": "HIGH",
      "confidence": "HIGH",
      "rule": "balanceIntegrity",
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Balance integrity rule violated. Contract balance < sum of user balances.",
      "counterexample": {
        "initial_state": {
          "attacker_balance": "1 ether",
          "contract_balance": "1 ether"
        },
        "final_state": {
          "attacker_balance": "0",
          "contract_balance": "0",
          "attacker_wallet": "2 ether"
        }
      },
      "call_sequence": [
        "withdraw()",
        "receive() -> withdraw() [reentrant]"
      ]
    }
  ],
  "verified_rules": ["noUnauthorizedWithdrawal", "ownerImmutable"]
}
```

---

### A.16 PropertyGPT

**Descripcion:** Generador automatico de propiedades de verificacion usando LLM.

**Caracteristicas:**
- Generacion automatica de invariantes
- Integracion con Echidna/Foundry
- Soporte para lenguaje natural
- Backend Ollama (local)

**Salida de Ejemplo:**

```
$ python -m miesc.tools.propertygpt contracts/audit/VulnerableBank.sol

PropertyGPT v1.0.0 - AI-Powered Property Generation
====================================================

[*] Analyzing contract structure...
[*] Generating properties with LLM...

Generated Properties for VulnerableBank:
========================================

Property 1: Balance Conservation
  Description: The sum of all user balances should equal contract ETH balance
  Solidity:
    function invariant_balance_conservation() public view returns (bool) {
        uint256 sum = 0;
        // Note: In practice, iterate over all depositors
        return address(this).balance >= sum;
    }

  LLM Confidence: 95%
  Rationale: "Financial contracts must maintain balance integrity"

Property 2: No Double Withdrawal
  Description: A user cannot withdraw more than their balance
  Solidity:
    function invariant_no_double_withdrawal() public view returns (bool) {
        return balances[msg.sender] >= 0; // Always true in 0.8.x
    }

  LLM Confidence: 88%
  Rationale: "Prevent reentrancy from draining funds"

Property 3: Monotonic Total Deposits
  Description: Total deposits should only increase (no unauthorized drains)
  Solidity:
    function invariant_monotonic_deposits() public {
        uint256 before = address(this).balance;
        // ... operation ...
        assert(address(this).balance >= before || msg.sender == owner);
    }

  LLM Confidence: 72%
  Rationale: "Detect unauthorized fund extraction"

[!] Warning: Property 2 may not detect reentrancy (balance becomes 0 legitimately)
[*] Generated 3 properties. Export to Echidna format? (echidna_properties.sol)
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "propertygpt",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 21300,
  "llm_backend": "ollama/llama3.2:3b",
  "generated_properties": 3,
  "findings": [
    {
      "id": "PGPT-001",
      "type": "generated-property",
      "severity": "INFO",
      "confidence": "HIGH",
      "property_name": "invariant_balance_conservation",
      "llm_confidence": 0.95,
      "description": "Sum of user balances should equal contract ETH balance",
      "solidity_code": "function invariant_balance_conservation() public view returns (bool) { ... }",
      "rationale": "Financial contracts must maintain balance integrity"
    },
    {
      "id": "PGPT-002",
      "type": "property-warning",
      "severity": "LOW",
      "confidence": "MEDIUM",
      "property_name": "invariant_no_double_withdrawal",
      "llm_confidence": 0.88,
      "message": "Property may not detect reentrancy as balance becomes 0 legitimately"
    }
  ]
}
```

---

## Capa 6: Analisis con IA

### A.17 GPTScan

**Descripcion:** Escaner de vulnerabilidades basado en GPT adaptado para ejecucion local.

**Caracteristicas:**
- Analisis semantico con LLM
- Deteccion de vulnerabilidades de logica
- Soporte para patrones DeFi
- Backend Ollama (costo $0)

**Salida de Ejemplo:**

```
$ python -m miesc.tools.gptscan contracts/audit/VulnerableBank.sol

GPTScan v3.0.0 - LLM-Powered Vulnerability Scanner
==================================================

[*] Loading contract...
[*] Analyzing with Ollama (llama3.2:3b)...

Analysis Report:
================

[CRITICAL] Reentrancy Vulnerability
  Location: withdraw() function, line 35

  LLM Analysis:
    "The withdraw() function performs an external call to msg.sender
     before updating the balances mapping. This is the classic
     reentrancy vulnerability pattern. An attacker contract could:

     1. Call deposit() with 1 ETH
     2. Call withdraw()
     3. In receive(), call withdraw() again before balance updates
     4. Repeat until contract is drained

     The pattern detected matches SWC-107 (Reentrancy)."

  Confidence: 97%
  Similar Exploits: DAO hack (2016), Cream Finance (2021)

[HIGH] Missing Access Control
  Location: withdrawAll() function (if present)

  LLM Analysis:
    "While not present in this contract, the pattern suggests
     a potential for privileged functions without proper guards."

  Confidence: 45%
  Note: Lower confidence - based on code patterns, not direct finding

[MEDIUM] No Event Emission
  Location: withdraw(), deposit()

  LLM Analysis:
    "Functions modifying state do not emit events. This makes
     off-chain monitoring and debugging difficult."

  Confidence: 89%

================================================================================
Summary: 1 Critical, 1 High (low confidence), 1 Medium
Total analysis time: 3.7s
Tokens used: 2,847
Cost: $0.00 (local Ollama)
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "gptscan",
  "version": "3.0.0",
  "status": "completed",
  "execution_time_ms": 3748,
  "llm_backend": "ollama/llama3.2:3b",
  "tokens_used": 2847,
  "cost_usd": 0.00,
  "findings": [
    {
      "id": "GPTSCAN-001",
      "type": "reentrancy",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "llm_confidence": 0.97,
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Classic reentrancy pattern detected. External call before state update.",
      "llm_analysis": "The withdraw() function performs an external call to msg.sender before updating the balances mapping...",
      "similar_exploits": ["DAO hack (2016)", "Cream Finance (2021)"]
    },
    {
      "id": "GPTSCAN-002",
      "type": "missing-events",
      "severity": "MEDIUM",
      "confidence": "HIGH",
      "llm_confidence": 0.89,
      "location": {
        "file": "VulnerableBank.sol",
        "function": "withdraw(), deposit()"
      },
      "message": "State-modifying functions do not emit events"
    }
  ]
}
```

---

### A.18 SmartLLM

**Descripcion:** Framework de analisis de seguridad con LLM especializado en smart contracts.

**Caracteristicas:**
- RAG (Retrieval Augmented Generation) con base de conocimiento SWC
- Prompts especializados para cada categoria
- Explicaciones detalladas
- Multi-turn analysis

**Salida de Ejemplo:**

```
$ python -m miesc.tools.smartllm contracts/audit/VulnerableBank.sol

SmartLLM v1.0.0 - RAG-Enhanced Security Analysis
================================================

[*] Loading SWC knowledge base (175 entries)...
[*] Analyzing contract with RAG-enhanced prompts...

=== Multi-Turn Analysis ===

Turn 1: Initial Code Review
  "Identified potential reentrancy in withdraw() function.
   The external call at line 35 precedes state update at line 39."

Turn 2: Pattern Matching (SWC-107)
  "Retrieved SWC-107 pattern from knowledge base:
   - External call: PRESENT (msg.sender.call)
   - State modification after: PRESENT (balances[msg.sender] = 0)
   - Protection: ABSENT (no ReentrancyGuard, no mutex)

   Match confidence: 98%"

Turn 3: Exploit Path Analysis
  "Constructing theoretical exploit:

   contract Attacker {
       VulnerableBank target;
       uint256 count;

       function attack() external payable {
           target.deposit{value: msg.value}();
           target.withdraw();
       }

       receive() external payable {
           if (count < 3) {
               count++;
               target.withdraw();
           }
       }
   }

   Estimated drain: 3x initial deposit"

Turn 4: Remediation Suggestions
  "Recommended fixes in order of preference:
   1. Use OpenZeppelin ReentrancyGuard (most robust)
   2. Apply CEI pattern manually (update before call)
   3. Use transfer() instead of call() (less flexible)"

================================================================================
Final Assessment: CRITICAL vulnerability confirmed
================================================================================
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "smartllm",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 8234,
  "llm_backend": "ollama/llama3.2:3b",
  "rag_entries_used": 12,
  "analysis_turns": 4,
  "findings": [
    {
      "id": "SMARTLLM-001",
      "type": "reentrancy",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "llm_confidence": 0.98,
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "RAG-enhanced analysis confirms reentrancy vulnerability",
      "rag_match": {
        "pattern": "SWC-107",
        "confidence": 0.98,
        "evidence": [
          "External call: PRESENT",
          "State modification after: PRESENT",
          "Protection: ABSENT"
        ]
      },
      "exploit_code": "contract Attacker { ... }",
      "remediation": [
        "Use OpenZeppelin ReentrancyGuard",
        "Apply CEI pattern",
        "Use transfer() instead of call()"
      ]
    }
  ]
}
```

---

### A.19 LLMSmartAudit

**Descripcion:** Auditor automatico que simula el proceso de auditoria manual usando LLM.

**Caracteristicas:**
- Simula proceso de auditor humano
- Genera reportes profesionales
- Priorizacion de hallazgos
- Recomendaciones ejecutivas

**Salida de Ejemplo:**

```
$ python -m miesc.tools.llmsmartaudit contracts/audit/VulnerableBank.sol

LLMSmartAudit v3.0.0 - Automated Security Audit
===============================================

[*] Phase 1: Architecture Review
    - Contract type: Financial (ETH vault)
    - Complexity: Low (87 SLOC)
    - External dependencies: None
    - Upgrade pattern: None (immutable)

[*] Phase 2: Line-by-Line Analysis
    - Lines reviewed: 87/87 (100%)
    - Functions analyzed: 5
    - Critical paths identified: 2

[*] Phase 3: Vulnerability Assessment

=== AUDIT REPORT ===

Executive Summary:
  The VulnerableBank contract contains a CRITICAL reentrancy
  vulnerability that allows complete drainage of deposited funds.
  Immediate remediation is required before deployment.

Finding 1 [CRITICAL]: Reentrancy in withdraw()
  Risk: Complete loss of funds
  CVSS: 9.8 (Critical)
  Exploitability: Easy (public PoC available)

  Business Impact:
    - All deposited ETH can be stolen
    - Reputational damage if deployed
    - Potential legal liability

  Technical Details:
    [See detailed analysis above]

  Remediation:
    Priority: IMMEDIATE
    Effort: Low (add ReentrancyGuard)

    -    function withdraw() public {
    +    function withdraw() public nonReentrant {

Finding 2 [LOW]: Missing events
  [Details omitted for brevity]

=== AUDIT METRICS ===
  Findings: 1 Critical, 0 High, 0 Medium, 1 Low
  Coverage: 100% of code reviewed
  Confidence: 94%

  Recommendation: DO NOT DEPLOY without fixing Critical findings
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "llmsmartaudit",
  "version": "3.0.0",
  "status": "completed",
  "execution_time_ms": 12456,
  "audit_metrics": {
    "lines_reviewed": 87,
    "functions_analyzed": 5,
    "coverage": 100,
    "confidence": 0.94
  },
  "findings": [
    {
      "id": "AUDIT-001",
      "type": "reentrancy",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "cvss_score": 9.8,
      "location": {
        "file": "VulnerableBank.sol",
        "line": 30,
        "function": "withdraw()"
      },
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "Critical reentrancy vulnerability allowing complete fund drainage",
      "business_impact": {
        "financial": "Complete loss of deposited funds",
        "reputational": "High",
        "legal": "Potential liability"
      },
      "remediation": {
        "priority": "IMMEDIATE",
        "effort": "LOW",
        "fix": "Add ReentrancyGuard modifier"
      }
    }
  ],
  "recommendation": "DO NOT DEPLOY without fixing Critical findings"
}
```

---

### A.20 ThreatModel

**Descripcion:** Generador automatico de modelos de amenazas STRIDE para smart contracts.

**Caracteristicas:**
- Metodologia STRIDE adaptada a Web3
- Identificacion de actores maliciosos
- Diagramas de flujo de amenazas
- Contramedidas sugeridas

**Salida de Ejemplo:**

```
$ python -m miesc.tools.threatmodel contracts/audit/VulnerableBank.sol

ThreatModel v1.0.0 - STRIDE Analysis for Smart Contracts
=========================================================

[*] Analyzing contract architecture...
[*] Identifying assets and trust boundaries...
[*] Generating threat model...

=== THREAT MODEL: VulnerableBank ===

Assets Identified:
  1. User ETH deposits (HIGH value)
  2. Balance mapping state (HIGH integrity)
  3. Owner address (MEDIUM integrity)

Trust Boundaries:
  1. External -> Contract (untrusted callers)
  2. Contract -> External (callback to msg.sender)

=== STRIDE ANALYSIS ===

[S] Spoofing Identity
  Threat: Attacker impersonates legitimate depositor
  Risk: LOW (msg.sender is reliable)
  Mitigation: N/A (inherent to blockchain)

[T] Tampering with Data
  Threat: Manipulation of balance mapping
  Risk: HIGH (via reentrancy!)
  Attack Vector:
    - Attacker deposits 1 ETH
    - Calls withdraw()
    - Re-enters during external call
    - Manipulates effective balance
  Mitigation: ReentrancyGuard, CEI pattern

[R] Repudiation
  Threat: User denies transaction
  Risk: LOW (blockchain provides audit trail)
  Note: Missing events reduce off-chain visibility
  Mitigation: Add Deposit/Withdraw events

[I] Information Disclosure
  Threat: Exposure of user balances
  Risk: ACCEPTED (public blockchain)
  Note: All state is publicly visible

[D] Denial of Service
  Threat: Contract becomes unusable
  Risk: MEDIUM
  Attack Vector:
    - Drain all funds via reentrancy
    - Contract becomes "ghost" with no value
  Mitigation: Same as Tampering

[E] Elevation of Privilege
  Threat: Attacker gains owner capabilities
  Risk: LOW (owner is immutable after deploy)
  Note: No owner-only functions present

=== THREAT SUMMARY ===

Critical Threats: 1 (Tampering via Reentrancy)
High Threats: 0
Medium Threats: 1 (DoS via fund drain)
Low Threats: 3

Primary Attack Surface: withdraw() function
Recommended Priority: Fix reentrancy BEFORE deployment
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "threatmodel",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 5421,
  "methodology": "STRIDE",
  "assets": [
    {"name": "User ETH deposits", "value": "HIGH"},
    {"name": "Balance mapping", "integrity": "HIGH"},
    {"name": "Owner address", "integrity": "MEDIUM"}
  ],
  "findings": [
    {
      "id": "THREAT-001",
      "type": "tampering",
      "stride_category": "T",
      "severity": "HIGH",
      "confidence": "HIGH",
      "threat": "Manipulation of balance mapping via reentrancy",
      "swc_id": "SWC-107",
      "attack_vector": [
        "Attacker deposits 1 ETH",
        "Calls withdraw()",
        "Re-enters during external call"
      ],
      "mitigation": "ReentrancyGuard, CEI pattern"
    },
    {
      "id": "THREAT-002",
      "type": "denial-of-service",
      "stride_category": "D",
      "severity": "MEDIUM",
      "confidence": "MEDIUM",
      "threat": "Contract becomes unusable after fund drain",
      "attack_vector": "Drain all funds via reentrancy",
      "mitigation": "Prevent reentrancy to maintain funds"
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 1,
    "low": 3
  }
}
```

---

## Capa 7: Deteccion basada en ML

### A.21 SmartBugs-ML

**Descripcion:** Modelo de ML entrenado en el dataset SmartBugs para clasificacion de vulnerabilidades.

**Caracteristicas:**
- Modelo pre-entrenado en 143 contratos vulnerables
- Clasificacion multi-clase
- Features basados en AST
- Explicabilidad con SHAP

**Salida de Ejemplo:**

```
$ python -m miesc.tools.smartbugs_ml contracts/audit/VulnerableBank.sol

SmartBugs-ML v1.0.0 - ML-Based Vulnerability Classification
============================================================

[*] Extracting features from AST...
[*] Running classification model...

Feature Extraction:
  - Contract nodes: 47
  - Function nodes: 5
  - External calls: 3
  - State modifications: 8
  - Control flow complexity: 12

Classification Results:
=======================

Vulnerability: Reentrancy (SWC-107)
  Probability: 94.7%
  Confidence: HIGH

  Top Contributing Features (SHAP):
    1. external_call_before_state_update: +0.42
    2. uses_call_with_value: +0.28
    3. no_reentrancy_guard: +0.15
    4. balance_mapping_modified: +0.09

Vulnerability: Access Control (SWC-105)
  Probability: 23.4%
  Confidence: LOW

  Note: Some features overlap with reentrancy pattern

Vulnerability: Integer Overflow (SWC-101)
  Probability: 2.1%
  Confidence: NEGLIGIBLE

  Note: Solidity 0.8.x has built-in overflow protection

=== MODEL METRICS ===
  Model: RandomForest (n_estimators=100)
  Training accuracy: 89.3%
  Validation accuracy: 84.7%
  Features used: 47
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "smartbugs_ml",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 1234,
  "model_info": {
    "type": "RandomForest",
    "training_accuracy": 0.893,
    "validation_accuracy": 0.847
  },
  "feature_extraction": {
    "contract_nodes": 47,
    "function_nodes": 5,
    "external_calls": 3,
    "state_modifications": 8
  },
  "findings": [
    {
      "id": "SBML-001",
      "type": "reentrancy",
      "severity": "HIGH",
      "confidence": "HIGH",
      "ml_probability": 0.947,
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "ML model classifies contract as vulnerable to reentrancy",
      "shap_explanation": {
        "external_call_before_state_update": 0.42,
        "uses_call_with_value": 0.28,
        "no_reentrancy_guard": 0.15,
        "balance_mapping_modified": 0.09
      }
    }
  ]
}
```

---

### A.22 ContractCloneDetector

**Descripcion:** Detector de contratos clonados o similares a exploits conocidos.

**Caracteristicas:**
- Comparacion con base de datos de exploits
- Deteccion de code clones
- Analisis de similitud semantica
- Alertas de patrones peligrosos

**Salida de Ejemplo:**

```
$ python -m miesc.tools.clone_detector contracts/audit/VulnerableBank.sol

ContractCloneDetector v1.0.0 - Exploit Pattern Matching
========================================================

[*] Loading exploit database (2,847 patterns)...
[*] Analyzing contract structure...
[*] Computing similarity scores...

Clone Analysis Results:
=======================

High Similarity Match Found!

  Pattern: DAO_Hack_2016
  Similarity: 87.3%

  Matching Elements:
    - Withdrawal pattern: 92% similar
    - State update timing: 95% similar
    - External call pattern: 89% similar

  Original Exploit (2016-06-17):
    Contract: TheDAO
    Loss: ~3.6M ETH ($60M at the time)
    Root Cause: Reentrancy in splitDAO()

  Your Contract:
    withdraw() function matches DAO vulnerability pattern

Medium Similarity Matches:

  Pattern: Cream_Finance_2021
  Similarity: 45.2%
  Note: Different attack vector but similar withdrawal logic

  Pattern: Parity_Wallet_2017
  Similarity: 23.1%
  Note: Different vulnerability type (delegatecall)

=== ALERT ===
Your contract contains code patterns highly similar to known exploits.
Review and remediate before deployment!
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "contract_clone_detector",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 2341,
  "database_size": 2847,
  "findings": [
    {
      "id": "CLONE-001",
      "type": "exploit-pattern-match",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "similarity_score": 0.873,
      "matched_pattern": "DAO_Hack_2016",
      "swc_id": "SWC-107",
      "message": "Contract pattern 87.3% similar to DAO hack exploit",
      "matching_elements": {
        "withdrawal_pattern": 0.92,
        "state_update_timing": 0.95,
        "external_call_pattern": 0.89
      },
      "original_exploit": {
        "date": "2016-06-17",
        "contract": "TheDAO",
        "loss": "3.6M ETH (~$60M)",
        "root_cause": "Reentrancy in splitDAO()"
      }
    }
  ]
}
```

---

### A.23 DAGNN

**Descripcion:** Red neuronal basada en grafos para analisis de vulnerabilidades.

**Caracteristicas:**
- Representacion de contrato como grafo
- GNN para deteccion de patrones
- Analisis de flujo de datos
- Alta precision en patrones complejos

**Salida de Ejemplo:**

```
$ python -m miesc.tools.dagnn contracts/audit/VulnerableBank.sol

DAGNN v1.0.0 - Graph Neural Network Vulnerability Detection
============================================================

[*] Constructing Control Flow Graph...
[*] Building Data Flow Graph...
[*] Running GNN inference...

Graph Construction:
  - Nodes: 234
  - Edges: 512
  - Node features: 64-dimensional
  - Edge types: 5 (call, jump, store, load, control)

GNN Analysis:
  Model: GraphSAGE (3 layers, 128 hidden)
  Inference time: 0.8s

Vulnerability Detection:
========================

[DETECTED] Reentrancy Pattern

  Graph Evidence:
    - CALL node (id: 47) at line 35
    - SSTORE node (id: 52) at line 39
    - Edge: 47 -> 52 (control flow)
    - Missing: Guard node before CALL

  Attention Weights (top nodes):
    Node 47 (CALL): 0.89
    Node 52 (SSTORE): 0.78
    Node 31 (BALANCE_CHECK): 0.45

  Classification:
    Reentrancy: 96.2%
    Safe: 3.8%

Visualization saved to: dagnn_graph_VulnerableBank.png
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "dagnn",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 3200,
  "graph_stats": {
    "nodes": 234,
    "edges": 512,
    "node_features": 64
  },
  "model_info": {
    "architecture": "GraphSAGE",
    "layers": 3,
    "hidden_dim": 128
  },
  "findings": [
    {
      "id": "DAGNN-001",
      "type": "reentrancy",
      "severity": "HIGH",
      "confidence": "HIGH",
      "gnn_probability": 0.962,
      "swc_id": "SWC-107",
      "cwe_id": "CWE-841",
      "message": "GNN detected reentrancy pattern with 96.2% confidence",
      "graph_evidence": {
        "call_node": {"id": 47, "line": 35, "attention": 0.89},
        "sstore_node": {"id": 52, "line": 39, "attention": 0.78},
        "pattern": "CALL before SSTORE without guard"
      },
      "visualization": "dagnn_graph_VulnerableBank.png"
    }
  ]
}
```

---

## Herramientas Especializadas

### A.24 GasAnalyzer

**Descripcion:** Analizador de consumo de gas y optimizaciones.

**Caracteristicas:**
- Estimacion de gas por funcion
- Identificacion de patrones costosos
- Sugerencias de optimizacion
- Comparacion con benchmarks

**Salida de Ejemplo:**

```
$ python -m miesc.tools.gas_analyzer contracts/audit/VulnerableBank.sol

GasAnalyzer v1.0.0 - Gas Optimization Analysis
==============================================

[*] Analyzing gas consumption...

Function Gas Analysis:
======================

deposit()
  Base cost: 21,000
  Execution: ~23,400 (first deposit) / ~3,400 (subsequent)
  Storage: 20,000 (new slot) / 0 (update)
  Total estimated: 44,400 / 24,400

  Optimization opportunities:
    - None identified (minimal function)

withdraw()
  Base cost: 21,000
  Execution: ~8,200
  External call: ~2,300 + variable
  Storage clear: -15,000 (refund)
  Total estimated: ~16,500

  Optimization opportunities:
    [GAS-001] Use transfer() instead of call() for fixed gas
              Savings: ~200 gas
              Note: Reduces flexibility but prevents reentrancy

withdrawAmount(uint256)
  Similar to withdraw() with additional checks

  Optimization opportunities:
    [GAS-002] Cache balances[msg.sender] in memory
              Current: 2 SLOAD operations
              Optimized: 1 SLOAD + 1 MLOAD
              Savings: ~100 gas

getBalance()
  View function: 0 gas for external calls

=== GAS OPTIMIZATION SUMMARY ===

Total potential savings: ~300 gas per transaction
Priority optimizations: GAS-001 (also fixes security issue!)

Benchmark comparison:
  Your contract: ~24,000 gas average
  Industry average for vaults: ~22,000 gas
  Recommendation: Acceptable, focus on security first
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "gas_analyzer",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 1523,
  "findings": [
    {
      "id": "GAS-001",
      "type": "gas-optimization",
      "severity": "LOW",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "line": 35,
        "function": "withdraw()"
      },
      "message": "Use transfer() instead of call() for fixed gas limit",
      "current_gas": 2300,
      "optimized_gas": 2100,
      "savings": 200,
      "note": "Also prevents reentrancy vulnerability"
    },
    {
      "id": "GAS-002",
      "type": "gas-optimization",
      "severity": "INFO",
      "confidence": "HIGH",
      "location": {
        "file": "VulnerableBank.sol",
        "function": "withdrawAmount()"
      },
      "message": "Cache storage variable in memory",
      "current_pattern": "2 SLOAD operations",
      "optimized_pattern": "1 SLOAD + 1 MLOAD",
      "savings": 100
    }
  ],
  "summary": {
    "average_gas": 24000,
    "industry_benchmark": 22000,
    "total_potential_savings": 300
  }
}
```

---

### A.25 MEVDetector

**Descripcion:** Detector de vulnerabilidades relacionadas con MEV (Miner Extractable Value).

**Caracteristicas:**
- Deteccion de frontrunning
- Analisis de sandwich attacks
- Identificacion de oracles manipulables
- Sugerencias de proteccion

**Salida de Ejemplo:**

```
$ python -m miesc.tools.mev_detector contracts/audit/VulnerableBank.sol

MEVDetector v1.0.0 - MEV Vulnerability Analysis
===============================================

[*] Analyzing for MEV vulnerabilities...

MEV Analysis Results:
=====================

[LOW] Potential Frontrunning in deposit()

  Analysis:
    The deposit() function is a simple ETH transfer with no
    price-sensitive operations. Frontrunning has minimal impact.

  Risk: LOW
  Reason: No arbitrage opportunity for attackers

[INFO] withdraw() Transaction Ordering

  Analysis:
    Multiple withdrawals in same block are processed in order.
    No significant MEV opportunity unless combined with other
    contracts (e.g., DEX interactions).

  Risk: INFO
  Reason: Standalone vault with no external price dependencies

[N/A] No Oracle Dependencies

  Analysis:
    Contract does not use price oracles or external data feeds.
    Sandwich attacks and oracle manipulation not applicable.

=== MEV SUMMARY ===

Overall MEV Risk: LOW

This contract has minimal MEV exposure due to:
  1. No price-sensitive operations
  2. No oracle dependencies
  3. No interaction with DEX or lending protocols

Note: The reentrancy vulnerability (SWC-107) is a greater concern
than MEV for this contract.
```

**Salida Normalizada MIESC:**

```json
{
  "tool": "mev_detector",
  "version": "1.0.0",
  "status": "completed",
  "execution_time_ms": 987,
  "mev_risk_level": "LOW",
  "findings": [
    {
      "id": "MEV-001",
      "type": "frontrunning-potential",
      "severity": "LOW",
      "confidence": "MEDIUM",
      "location": {
        "function": "deposit()"
      },
      "message": "Minimal frontrunning impact - no price-sensitive operations",
      "mev_type": "frontrunning"
    }
  ],
  "analysis_summary": {
    "oracle_dependencies": false,
    "dex_interactions": false,
    "price_sensitive_ops": false,
    "recommendation": "Focus on reentrancy vulnerability (SWC-107) instead"
  }
}
```

---

## Tabla Comparativa

### Tabla A.1: Comparativa de las 25 Herramientas de MIESC

| # | Herramienta | Capa | Tecnica | Lenguaje | Tiempo* | Precision | Recall | Fortaleza Principal |
|---|-------------|------|---------|----------|---------|-----------|--------|---------------------|
| 1 | Slither | 1 | Estatico | Python | 2.3s | 87% | 89% | Cobertura amplia, 80+ detectores |
| 2 | Solhint | 1 | Linter | JavaScript | 0.8s | 95% | 60% | Mejores practicas, estilo |
| 3 | Aderyn | 1 | Estatico | Rust | 0.3s | 85% | 82% | Velocidad extrema |
| 4 | Echidna | 2 | Fuzzing | Haskell | 18s | 92% | 78% | Property testing robusto |
| 5 | Foundry Fuzz | 2 | Fuzzing | Rust | 2.3s | 90% | 75% | Integracion desarrollo |
| 6 | Medusa | 2 | Fuzzing | Go | 32s | 88% | 80% | Coverage-guided |
| 7 | DogeFuzz | 2 | ML+Fuzz | Python | 45s | 82% | 72% | ML-guided generation |
| 8 | Vertigo | 2 | Mutation | Python | 23s | N/A | N/A | Calidad de tests |
| 9 | Mythril | 3 | Simbolico | Python | 28s | 89% | 85% | Deteccion profunda |
| 10 | Manticore | 3 | Simbolico | Python | 127s | 91% | 88% | Analisis exhaustivo |
| 11 | Oyente | 3 | Simbolico | Python | 3.2s | 78% | 70% | Rapidez legacy |
| 12 | Halmos | 4 | Bounded MC | Python | 14s | 94% | 82% | Verificacion Foundry |
| 13 | Wake | 4 | Property | Python | 8.9s | 90% | 78% | Python-native |
| 14 | SMTChecker | 5 | Formal | C++ | 9.8s | 96% | 75% | Integrado en solc |
| 15 | Certora | 5 | Formal | - | 45s | 98% | 90% | Verificacion profesional |
| 16 | PropertyGPT | 5 | LLM+Formal | Python | 21s | 85% | 65% | Generacion automatica |
| 17 | GPTScan | 6 | LLM | Python | 3.7s | 88% | 82% | Analisis semantico |
| 18 | SmartLLM | 6 | RAG+LLM | Python | 8.2s | 90% | 85% | Conocimiento SWC |
| 19 | LLMSmartAudit | 6 | LLM | Python | 12s | 86% | 80% | Reportes profesionales |
| 20 | ThreatModel | 6 | LLM+STRIDE | Python | 5.4s | 82% | 75% | Modelo de amenazas |
| 21 | SmartBugs-ML | 7 | ML | Python | 1.2s | 85% | 78% | Clasificacion rapida |
| 22 | CloneDetector | 7 | Similarity | Python | 2.3s | 92% | 68% | Deteccion de exploits |
| 23 | DAGNN | 7 | GNN | Python | 3.2s | 88% | 82% | Patrones complejos |
| 24 | GasAnalyzer | Esp. | Estatico | Python | 1.5s | 95% | 90% | Optimizacion gas |
| 25 | MEVDetector | Esp. | Heuristico | Python | 1.0s | 80% | 70% | Vulnerabilidades MEV |

*Tiempos medidos en contrato VulnerableBank.sol (87 SLOC)

### Tabla A.2: Capacidades de Deteccion por Categoria SWC

| SWC ID | Vulnerabilidad | Herramientas que Detectan | Mejor Herramienta |
|--------|---------------|--------------------------|-------------------|
| SWC-107 | Reentrancy | Slither, Mythril, Manticore, Echidna, GPTScan, SmartLLM, DAGNN | Manticore (91%) |
| SWC-105 | Unprotected Ether | Slither, Mythril, Aderyn, GPTScan | Mythril (89%) |
| SWC-104 | Unchecked Call | Slither, Solhint, Oyente | Slither (92%) |
| SWC-101 | Integer Overflow | Mythril, Manticore, SMTChecker | SMTChecker (96%) |
| SWC-106 | Unprotected SELFDESTRUCT | Slither, Mythril, Aderyn | Slither (94%) |
| SWC-120 | Weak Randomness | Slither, GPTScan, SmartLLM | GPTScan (88%) |
| SWC-111 | Deprecated Functions | Solhint, Slither | Solhint (95%) |
| SWC-116 | Block Timestamp | Slither, Mythril, Aderyn | Slither (87%) |
| SWC-115 | Authorization through tx.origin | Slither, Solhint, Aderyn | Slither (98%) |
| SWC-131 | Unused Variables | Solhint, Slither | Solhint (99%) |

### Tabla A.3: Justificacion de Inclusion de Cada Herramienta

| Herramienta | Justificacion Tecnica | Contribucion Unica |
|-------------|----------------------|-------------------|
| Slither | Estandar de la industria, mantenido activamente | Mayor cobertura de detectores |
| Solhint | Complementa analisis con reglas de estilo | Detecta anti-patterns de codigo |
| Aderyn | Implementacion Rust para velocidad | Ciclos de feedback rapidos |
| Echidna | Property testing matematicamente riguroso | Encuentra edge cases no obvios |
| Foundry Fuzz | Integracion con flujo de desarrollo | Tests como documentacion |
| Medusa | Coverage-guided encuentra caminos profundos | Complementa Echidna |
| DogeFuzz | ML mejora generacion de inputs | Innovacion academica |
| Vertigo | Mutation testing valida calidad de tests | Meta-analisis de seguridad |
| Mythril | Ejecucion simbolica robusta | Genera exploits concretos |
| Manticore | Analisis mas exhaustivo disponible | Mayor profundidad de busqueda |
| Oyente | Herramienta historica, rapida | Baseline de comparacion |
| Halmos | Bounded model checking moderno | Puente entre testing y formal |
| Wake | Framework Python-native | Accesible para auditores |
| SMTChecker | Integrado en compilador | Zero-dependency formal |
| Certora | Verificacion industrial | Maxima garantia matematica |
| PropertyGPT | Automatiza escritura de specs | Reduce barrera de entrada |
| GPTScan | LLM para patrones semanticos | Detecta logica de negocio |
| SmartLLM | RAG con base SWC | Explicaciones educativas |
| LLMSmartAudit | Simula auditor humano | Reportes ejecutivos |
| ThreatModel | Metodologia STRIDE adaptada | Vision holistica de amenazas |
| SmartBugs-ML | Clasificacion entrenada | Rapida triaging inicial |
| CloneDetector | Compara con exploits conocidos | Deteccion de patrones historicos |
| DAGNN | Representacion de grafo avanzada | Patrones estructurales |
| GasAnalyzer | Foco en eficiencia | Optimizacion economica |
| MEVDetector | Amenazas DeFi especificas | Cobertura de ataques modernos |

---

## Referencias

- Trail of Bits. (2023). Slither Documentation. https://github.com/crytic/slither
- ConsenSys. (2023). Mythril Documentation. https://github.com/ConsenSys/mythril
- Paradigm. (2023). Foundry Book. https://book.getfoundry.sh/
- Certora. (2024). Certora Prover Documentation. https://docs.certora.com/
- SWC Registry. (2023). Smart Contract Weakness Classification. https://swcregistry.io/

---

*Documento generado como parte de la documentacion de tesis de MIESC v4.0.0*
*Fecha: 2024-11-29*
*Autor: Fernando Boiero*
