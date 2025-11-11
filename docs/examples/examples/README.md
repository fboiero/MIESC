# Contratos de Ejemplo para Testing

Este directorio contiene contratos de ejemplo para probar el framework MIESC MCP.

---

## 📁 Contratos Disponibles

### 1. **voting.sol** - Contrato de Votación Básico

Sistema simple de votación con propuestas y votos.

**Características**:
- Gestión de propuestas
- Sistema de votación
- Conteo de votos

**Vulnerabilidades Potenciales**:
- Posible manipulación de votos
- Falta de validaciones de entrada
- Sin límite temporal de votación

**Usar para probar**:
- StaticAgent (Slither detección básica)
- PolicyAgent (OWASP coverage)

**Comando de prueba**:
```bash
python demo_mcp_poc.py examples/voting.sol
```

---

### 2. **vulnerable_bank.sol** - Banco con Vulnerabilidades Intencionadas

Contrato diseñado con vulnerabilidades conocidas para testing exhaustivo.

**Vulnerabilidades Incluidas**:

| ID | Vulnerabilidad | Ubicación | OWASP Category |
|----|----------------|-----------|----------------|
| SWC-107 | Reentrancy | `withdraw()` | SC01-Reentrancy |
| SWC-105 | Missing Access Control | `setOwner()` | SC02-Access-Control |
| SWC-104 | Unchecked Call | `emergencyWithdraw()` | SC04-Unchecked-Calls |
| SWC-116 | Timestamp Dependence | `isLucky()` | SC08-Time-Manipulation |

**Descripción Detallada**:

#### Reentrancy (Línea 44)
```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];
    // ❌ External call BEFORE state change
    (bool success, ) = msg.sender.call{value: balance}("");
    balances[msg.sender] = 0;  // Too late!
}
```

#### Missing Access Control (Línea 56)
```solidity
function setOwner(address newOwner) public {
    // ❌ No onlyOwner modifier - anyone can become owner!
    owner = newOwner;
}
```

#### Unchecked Call (Línea 66)
```solidity
function emergencyWithdraw(...) public {
    // ❌ Return value not checked
    recipient.call{value: amount}("");
}
```

#### Timestamp Dependence (Línea 77)
```solidity
function isLucky() public view returns (bool) {
    // ❌ Miners can manipulate timestamp ±15 seconds
    return block.timestamp % 7 == 0;
}
```

**Contrato de Ataque Incluido**:
- `Attacker`: Demuestra explotación de reentrancy

**Usar para probar**:
- StaticAgent (debe detectar todas las vulnerabilidades)
- SymbolicAgent (Mythril debe encontrar paths de ataque)
- AIAgent (debe clasificar severidades correctamente)
- PolicyAgent (debe mapear a OWASP SC Top 10)

**Comando de prueba**:
```bash
# Análisis estático
python -c "
from agents.static_agent import StaticAgent
agent = StaticAgent()
results = agent.run('examples/vulnerable_bank.sol')
print(f'Findings: {len(results[\"static_findings\"])}')
"

# Auditoría completa
python -c "
from agents.coordinator_agent import CoordinatorAgent
coordinator = CoordinatorAgent()
results = coordinator.run('examples/vulnerable_bank.sol', priority='comprehensive')
"
```

**Resultados Esperados**:
- Slither: 4+ detecciones
- Mythril: 3+ vulnerabilidades
- OWASP Coverage: SC01, SC02, SC04, SC08
- ISO 27001: Violation en A.8.8

---

### 3. **secure_bank.sol** - Banco Seguro (Best Practices)

Versión corregida que implementa todas las mejores prácticas.

**Protecciones Implementadas**:

| Protección | Implementación |
|------------|----------------|
| ✅ Reentrancy Guard | `nonReentrant` modifier con lock |
| ✅ Access Control | `onlyOwner` modifier |
| ✅ Checks-Effects-Interactions | Estado actualizado antes de llamadas |
| ✅ Checked Return Values | `if (!success) revert` |
| ✅ Input Validation | Validación completa de parámetros |
| ✅ Custom Errors | Gas-efficient error handling |
| ✅ Events | Emisión completa de eventos |

**Patterns Aplicados**:

#### Checks-Effects-Interactions (Línea 93)
```solidity
function withdraw() public nonReentrant {
    // CHECKS
    if (balance == 0) revert InsufficientBalance();

    // EFFECTS
    balances[msg.sender] = 0;

    // INTERACTIONS (last!)
    (bool success, ) = msg.sender.call{value: balance}("");
    if (!success) revert TransferFailed();
}
```

#### Reentrancy Guard (Línea 60)
```solidity
modifier nonReentrant() {
    if (locked) revert ReentrancyGuard();
    locked = true;
    _;
    locked = false;
}
```

#### Access Control (Línea 53)
```solidity
modifier onlyOwner() {
    if (msg.sender != owner) revert Unauthorized();
    _;
}
```

**Usar para probar**:
- StaticAgent (debe reportar 0 vulnerabilidades críticas)
- PolicyAgent (debe mostrar 100% compliance)
- Comparación con vulnerable_bank.sol

**Comando de prueba**:
```bash
# Comparar seguro vs vulnerable
python -c "
from agents.static_agent import StaticAgent

agent = StaticAgent()

# Vulnerable
vuln_results = agent.run('examples/vulnerable_bank.sol')
print(f'Vulnerable: {len(vuln_results[\"static_findings\"])} issues')

# Secure
secure_results = agent.run('examples/secure_bank.sol')
print(f'Secure: {len(secure_results[\"static_findings\"])} issues')
"
```

**Resultados Esperados**:
- Slither: 0-2 informational findings
- Sin vulnerabilidades críticas o altas
- OWASP Coverage: Ninguna categoría detectada (correcto)
- ISO 27001: Full compliance

---

## 🧪 Tests Automatizados

### Test End-to-End Completo

```bash
# Ejecutar test suite completo
python test_mcp_e2e.py

# Salida esperada:
# ✅ Context Bus Initialization
# ✅ Agent Initialization (7 agentes)
# ✅ Static Analysis on voting.sol
# ✅ Compliance Checking
# ✅ Audit Trail Export
```

### Test por Contrato

```bash
# Test vulnerable_bank.sol
python -c "
from agents.static_agent import StaticAgent
from agents.policy_agent import PolicyAgent

# Static analysis
static = StaticAgent()
results = static.run('examples/vulnerable_bank.sol')
print(f'Static findings: {len(results[\"static_findings\"])}')

# Compliance check
policy = PolicyAgent()
compliance = policy.run('examples/vulnerable_bank.sol')
print(f'OWASP coverage: {compliance[\"owasp_coverage\"][\"coverage_score\"]}')
"
```

---

## 📊 Comparativa de Contratos

| Característica | voting.sol | vulnerable_bank.sol | secure_bank.sol |
|----------------|------------|---------------------|-----------------|
| **Complejidad** | Baja | Media | Media |
| **Vulnerabilidades** | 2-3 | 4+ | 0 |
| **OWASP Categories** | SC02, SC10 | SC01, SC02, SC04, SC08 | Ninguna |
| **Tiempo de Análisis** | ~30s | ~60s | ~30s |
| **Uso Recomendado** | Testing básico | Testing exhaustivo | Validación de fixes |

---

## 🔧 Crear Tus Propios Contratos de Prueba

### Template de Contrato de Prueba

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title My Test Contract
 * @notice Brief description
 * @dev Known vulnerabilities: [list]
 */
contract MyTestContract {
    // State variables
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Add functions with/without vulnerabilities
}
```

### Guidelines

1. **Documentar vulnerabilidades**: Usa comentarios para indicar vulnerabilidades intencionadas
2. **Incluir SWC/OWASP IDs**: Mapea cada vulnerabilidad a su categoría
3. **Agregar casos de prueba**: Incluye tests en `test/` directory
4. **Versión de Solidity**: Usa `^0.8.0` para consistencia

---

## 🎯 Casos de Uso por Agente

### StaticAgent
- ✅ `vulnerable_bank.sol` - Debe detectar 4 vulnerabilidades
- ✅ `secure_bank.sol` - Debe reportar 0 critical/high

### DynamicAgent
- ✅ `voting.sol` - Fuzz votación con propiedades invariantes
- ⚠️ Requiere archivos de test en `test/` (no incluidos aún)

### SymbolicAgent
- ✅ `vulnerable_bank.sol` - Mythril debe encontrar reentrancy path
- ⏱️ Tiempo de ejecución: ~5-10 min

### FormalAgent
- ⚠️ Requiere especificaciones CVL (no incluidas aún)
- Ver `specs/` para ejemplos futuros

### AIAgent
- ✅ Cualquier contrato con findings de StaticAgent
- Debe clasificar severity correctamente

### PolicyAgent
- ✅ Todos los contratos
- Debe generar compliance report completo

### CoordinatorAgent
- ✅ Todos los contratos
- Genera audit plan optimizado según complejidad

---

## 📚 Referencias

- [SWC Registry](https://swcregistry.io/)
- [OWASP SC Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [Slither Detectors](https://github.com/crytic/slither/wiki/Detector-Documentation)
- [Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)

---

**Última Actualización**: Octubre 2025
**Mantenedor**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
