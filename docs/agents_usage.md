## Guía de Uso de Agentes MCP

Documentación completa de todos los agentes especializados en la arquitectura MCP de MIESC.

---

## Tabla de Contenidos

- [BaseAgent](#baseagent)
- [StaticAgent](#staticagent)
- [DynamicAgent](#dynamicagent)
- [SymbolicAgent](#symbolicagent)
- [FormalAgent](#formalagent)
- [AIAgent](#aiagent)
- [PolicyAgent](#policyagent)
- [CoordinatorAgent](#coordinatoragent)

---

## BaseAgent

**Clase abstracta base** para todos los agentes MCP.

### Características

- Conexión automática al Context Bus
- Métodos abstractos: `analyze()`, `get_context_types()`
- Publicación estandarizada de findings
- Suscripción a context types
- Manejo de errores y logging

### Métodos Principales

```python
from agents.base_agent import BaseAgent

# Implementar agente personalizado
class MyAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            agent_name="MyAgent",
            capabilities=["custom_analysis"],
            agent_type="custom"
        )

    def analyze(self, contract_path: str, **kwargs):
        # Implementar lógica de análisis
        return {"findings": []}

    def get_context_types(self):
        return ["custom_findings"]
```

### Métodos Heredados

| Método | Descripción |
|--------|-------------|
| `publish_findings()` | Publica hallazgos al Context Bus |
| `subscribe_to()` | Suscribe a context types de otros agentes |
| `get_latest_context()` | Obtiene último mensaje de un context type |
| `aggregate_contexts()` | Agrega múltiples context types |
| `set_status()` | Actualiza estado del agente |
| `handle_error()` | Manejo estandarizado de errores |
| `run()` | Método principal de ejecución |
| `get_stats()` | Obtiene estadísticas del agente |

---

## StaticAgent

**Layer 1 - Análisis Estático**

Integra Slither, Solhint y Surya para detección temprana de vulnerabilidades a nivel de código fuente.

### Uso Básico

```python
from agents.static_agent import StaticAgent

# Inicializar agente
agent = StaticAgent()

# Ejecutar análisis
results = agent.run(
    contract_path="examples/voting.sol",
    solc_version="0.8.0"
)

# Acceder a resultados
findings = results["static_findings"]
slither_results = results["slither_results"]
solhint_results = results["solhint_results"]
```

### Context Types Publicados

- `static_findings`: Hallazgos unificados de todas las herramientas
- `slither_results`: Resultados brutos de Slither
- `solhint_results`: Issues de linting
- `surya_results`: Análisis de arquitectura

### Mapeo Automático

El StaticAgent mapea automáticamente:
- Detector ID → SWC ID (e.g., `reentrancy-eth` → `SWC-107`)
- SWC ID → OWASP Category (e.g., `SWC-107` → `SC01-Reentrancy`)

### Ejemplo de Hallazgo

```json
{
  "source": "Slither",
  "type": "vulnerability",
  "id": "reentrancy-eth",
  "severity": "High",
  "confidence": "High",
  "description": "Reentrancy in withdraw function",
  "location": {
    "file": "voting.sol",
    "line": 45,
    "function": "withdraw"
  },
  "swc_id": "SWC-107",
  "owasp_category": "SC01-Reentrancy"
}
```

---

## DynamicAgent

**Layer 2 - Testing Dinámico y Fuzzing**

Integra Echidna, Medusa y Foundry Fuzz para detección de edge cases y violaciones de propiedades.

### Uso Básico

```python
from agents.dynamic_agent import DynamicAgent

agent = DynamicAgent()

results = agent.run(
    contract_path="examples/voting.sol",
    fuzz_runs=10000,
    timeout=300,
    test_dir="test"
)

# Acceder a violaciones
violations = results["dynamic_findings"]
echidna_results = results["echidna_results"]
```

### Context Types Publicados

- `dynamic_findings`: Violaciones de propiedades unificadas
- `echidna_results`: Resultados de fuzzing basado en propiedades
- `medusa_results`: Resultados de fuzzing guiado por cobertura
- `foundry_results`: Resultados de fuzz tests integrados

### Parámetros

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `fuzz_runs` | int | 10000 | Número de ejecuciones de fuzzing |
| `timeout` | int | 300 | Timeout en segundos por herramienta |
| `test_dir` | str | "test" | Directorio con archivos de test |

### Ejemplo de Violación

```json
{
  "source": "Echidna",
  "type": "property_violation",
  "property": "echidna_test_balance",
  "severity": "High",
  "description": "Property failed after 1234 runs",
  "layer": "dynamic",
  "swc_id": "SWC-110",
  "owasp_category": "SC05-DoS"
}
```

---

## SymbolicAgent

**Layer 4 - Ejecución Simbólica**

Integra Mythril y Manticore para exploración exhaustiva de paths de ejecución y generación de exploits.

### Uso Básico

```python
from agents.symbolic_agent import SymbolicAgent

agent = SymbolicAgent()

results = agent.run(
    contract_path="examples/voting.sol",
    max_depth=128,
    timeout=900,
    solc_version="0.8.0"
)

# Acceder a vulnerabilidades simbólicas
findings = results["symbolic_findings"]
mythril_vulns = results["mythril_results"]["vulnerabilities"]
```

### Context Types Publicados

- `symbolic_findings`: Vulnerabilidades encontradas por análisis simbólico
- `mythril_results`: Resultados de Mythril con transaction sequences
- `manticore_results`: Exploits generados por Manticore

### Parámetros

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `max_depth` | int | 128 | Profundidad máxima de exploración |
| `timeout` | int | 900 | Timeout en segundos (15 min) |
| `solc_version` | str | "0.8.0" | Versión del compilador Solidity |

### Ejemplo de Hallazgo Simbólico

```json
{
  "source": "Mythril",
  "type": "symbolic_vulnerability",
  "id": "SWC-107",
  "title": "Reentrancy",
  "severity": "High",
  "description": "External call followed by state change",
  "location": {
    "file": "voting.sol",
    "line": 45,
    "function": "withdraw"
  },
  "transaction_sequence": "call withdraw() -> external call -> state change",
  "swc_id": "SWC-107",
  "owasp_category": "SC01-Reentrancy",
  "confidence": "High"
}
```

---

## FormalAgent

**Layer 5 - Verificación Formal**

Integra Certora Prover y Z3 para pruebas matemáticas de corrección funcional.

### Uso Básico

```python
from agents.formal_agent import FormalAgent

agent = FormalAgent()

results = agent.run(
    contract_path="examples/voting.sol",
    spec_file="specs/voting.spec",
    timeout=1800
)

# Acceder a violaciones de reglas
violations = results["formal_findings"]
certora_results = results["certora_results"]
```

### Context Types Publicados

- `formal_findings`: Violaciones de reglas formales y propiedades verificadas
- `certora_results`: Resultados de Certora Prover (CVL)
- `z3_results`: Estado de Z3 SMT solver

### Parámetros

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `spec_file` | str | None | Path a archivo de especificación CVL |
| `timeout` | int | 1800 | Timeout en segundos (30 min) |

### Verificación de Invariante con Z3

```python
# Verificar invariante específico
invariant_spec = """
(declare-const balance Int)
(assert (>= balance 0))
(check-sat)
"""

result = agent.verify_invariant(invariant_spec)
# result["valid"] == True si el invariante se cumple
```

### Ejemplo de Violación Formal

```json
{
  "source": "Certora",
  "type": "rule_violation",
  "rule": "rule_no_balance_decrease",
  "severity": "Critical",
  "description": "Rule violated: balance can decrease without withdrawal",
  "layer": "formal",
  "verification_type": "mathematical_proof",
  "confidence": "Very High"
}
```

---

## AIAgent

**Layer 6 - Inteligencia Cognitiva**

Utiliza GPT-4 para triage inteligente, detección de falsos positivos y root cause analysis.

### Uso Básico

```python
from agents.ai_agent import AIAgent
import os

agent = AIAgent(
    api_key=os.getenv("OPENAI_API_KEY"),
    model="gpt-4"
)

results = agent.run(
    contract_path="examples/voting.sol",
    aggregated_findings=all_findings,  # Findings de otros agentes
    contract_source=contract_code
)

# Acceder a triage
triaged = results["ai_triage"]
false_positives = results["false_positives"]
root_causes = results["root_cause_analysis"]
```

### Context Types Publicados

- `ai_triage`: Findings triados con severidad ajustada
- `false_positives`: Falsos positivos identificados
- `root_cause_analysis`: Análisis de causa raíz para issues críticos

### Suscripciones Automáticas

El AIAgent se suscribe automáticamente a:
- `static_findings`
- `dynamic_findings`
- `formal_findings`
- `symbolic_findings`

### Cross-Layer Correlation

```python
# Correlacionar hallazgo a través de múltiples capas
correlation = agent.cross_layer_correlation("SWC-107")

# Retorna:
{
  "finding_id": "SWC-107",
  "detected_by": [
    {"layer": "static", "agent": "StaticAgent", "severity": "High"},
    {"layer": "symbolic", "agent": "SymbolicAgent", "severity": "Critical"}
  ],
  "consistency_score": 1.0,
  "cross_layer_confidence": "High"
}
```

### Ejemplo de Triage

```json
{
  "id": "SWC-107",
  "original_severity": "High",
  "adjusted_severity": "Critical",
  "is_exploitable": true,
  "confidence": "High",
  "justification": "Reentrancy is exploitable: state changes after external call without reentrancy guard",
  "root_cause": "Missing checks-effects-interactions pattern",
  "remediation": "Add ReentrancyGuard from OpenZeppelin or reorder state changes",
  "source": "Slither",
  "swc_id": "SWC-107",
  "owasp_category": "SC01-Reentrancy"
}
```

---

## PolicyAgent

**Compliance y Políticas**

Verifica cumplimiento con ISO/IEC 27001, NIST SSDF y OWASP SC Top 10.

### Uso Básico

```python
from agents.policy_agent import PolicyAgent

agent = PolicyAgent()

results = agent.run(contract_path="examples/voting.sol")

# Acceder a compliance
compliance_report = results["compliance_report"]
iso_status = results["iso27001_status"]
nist_status = results["nist_ssdf_status"]
owasp_coverage = results["owasp_coverage"]
```

### Context Types Publicados

- `compliance_report`: Reporte completo de cumplimiento
- `iso27001_status`: Estado de controles ISO/IEC 27001:2022
- `nist_ssdf_status`: Estado de prácticas NIST SSDF
- `owasp_coverage`: Cobertura OWASP SC Top 10

### Controles ISO/IEC 27001:2022

| Control | Nombre | Estado |
|---------|--------|--------|
| A.8.8 | Management of technical vulnerabilities | ✅ Implementado |
| A.8.15 | Logging | ✅ Implementado |
| A.8.16 | Monitoring activities | ✅ Implementado |
| A.8.30 | Testing | ✅ Implementado |
| A.14.2.5 | Secure system engineering | ✅ Implementado |

### Prácticas NIST SSDF

| Práctica | Nombre | Estado |
|----------|--------|--------|
| PO.3.1 | Ensure acquisition of genuine software | ✅ Implementado |
| PS.2 | Review software design | ✅ Implementado |
| PW.8 | Review/analyze code | ✅ Implementado |
| RV.1.1 | Identify vulnerabilities | ✅ Implementado |
| RV.3 | Analyze root causes | ✅ Implementado |

### Ejemplo de Compliance Report

```json
{
  "contract": "voting.sol",
  "timestamp": "2025-10-12T20:00:00Z",
  "summary": {
    "total_findings": 5,
    "critical_findings": 1,
    "high_findings": 2
  },
  "standards_compliance": {
    "ISO_IEC_27001_2022": {
      "score": 1.0,
      "status": "compliant",
      "compliant_controls": 5,
      "total_controls": 5
    },
    "NIST_SSDF": {
      "score": 1.0,
      "status": "compliant"
    },
    "OWASP_SC_Top10": {
      "score": 0.8,
      "status": "high",
      "covered_categories": 8,
      "total_categories": 10
    }
  },
  "overall_compliance_index": 0.93,
  "audit_readiness": "ready_with_notes"
}
```

---

## CoordinatorAgent

**Orquestador LLM**

Coordina workflow multiagente con generación inteligente de audit plans.

### Uso Básico

```python
from agents.coordinator_agent import CoordinatorAgent
import os

coordinator = CoordinatorAgent(
    api_key=os.getenv("OPENAI_API_KEY"),
    model="gpt-4"
)

results = coordinator.run(
    contract_path="examples/voting.sol",
    priority="balanced",
    audit_scope=["static", "dynamic", "ai", "policy"],
    time_budget=600
)

# Acceder a plan y progreso
audit_plan = results["audit_plan"]
progress = results["audit_progress"]
summary = results["audit_summary"]
```

### Context Types Publicados

- `audit_plan`: Plan de auditoría con fases y tiempos
- `audit_progress`: Eventos de progreso en tiempo real
- `audit_summary`: Resumen final con compliance

### Prioridades de Auditoría

| Prioridad | Capas | Duración Estimada | Uso |
|-----------|-------|-------------------|-----|
| `fast` | Static, AI | ~3 min | Revisión rápida |
| `balanced` | Static, Dynamic, AI | ~10 min | Auditoría estándar |
| `comprehensive` | Todas (6 capas) | ~60 min | Auditoría completa |

### Optimización LLM

Con API key, el CoordinatorAgent analiza el contrato y optimiza el plan:

```python
# Plan optimizado por LLM considera:
# - Complejidad del contrato
# - Factores de riesgo detectados
# - Priorización de layers según patrones
# - Estimación realista de tiempos
```

### Ejemplo de Audit Plan

```json
{
  "contract": "voting.sol",
  "priority": "balanced",
  "scope": ["static", "dynamic", "ai"],
  "time_budget": 600,
  "phases": [
    {
      "layer": "static",
      "agent": "StaticAgent",
      "estimated_time": 120,
      "priority": "critical"
    },
    {
      "layer": "dynamic",
      "agent": "DynamicAgent",
      "estimated_time": 300
    },
    {
      "layer": "ai",
      "agent": "AIAgent",
      "estimated_time": 180
    }
  ],
  "estimated_duration": 600,
  "complexity_assessment": "medium",
  "risk_factors": ["state_changes", "external_calls"]
}
```

### Monitoreo de Estado

```python
# Obtener estado actual de auditoría
status = coordinator.get_audit_status()

{
  "status": "analyzing",
  "current_phase": "dynamic",
  "completed_phases": ["static"],
  "total_findings": 5,
  "active_agents": ["StaticAgent", "DynamicAgent", "AIAgent"]
}
```

---

## Flujo de Trabajo Típico

### Auditoría Completa

```python
from agents.coordinator_agent import CoordinatorAgent

# 1. Inicializar coordinador
coordinator = CoordinatorAgent(api_key=api_key)

# 2. Ejecutar auditoría completa
results = coordinator.run(
    contract_path="examples/voting.sol",
    priority="comprehensive"
)

# 3. Exportar audit trail para compliance
from mcp.context_bus import get_context_bus
bus = get_context_bus()
bus.export_audit_trail("outputs/evidence/audit_trail.json")

# 4. Revisar compliance
compliance = results["audit_summary"]["compliance"]
print(f"ISO 27001 Score: {compliance['ISO_IEC_27001_2022']['score']}")
```

### Análisis por Capas

```python
# Ejecutar cada capa individualmente
from agents import StaticAgent, DynamicAgent, AIAgent, PolicyAgent

# Layer 1: Static
static = StaticAgent()
static_results = static.run("contract.sol")

# Layer 2: Dynamic
dynamic = DynamicAgent()
dynamic_results = dynamic.run("contract.sol", fuzz_runs=50000)

# Layer 6: AI Triage
ai = AIAgent(api_key=api_key)
ai_results = ai.run("contract.sol")

# Compliance Check
policy = PolicyAgent()
compliance = policy.run("contract.sol")
```

---

## Buenas Prácticas

### 1. Uso de Context Bus

```python
from mcp.context_bus import get_context_bus

# Obtener instancia singleton
bus = get_context_bus()

# Agregar múltiples context types
findings = bus.aggregate_contexts([
    "static_findings",
    "dynamic_findings",
    "ai_triage"
])

# Exportar audit trail regularmente
bus.export_audit_trail("outputs/evidence/trail.json")
```

### 2. Manejo de Errores

```python
from agents.static_agent import StaticAgent

agent = StaticAgent()

try:
    results = agent.run("contract.sol")
except Exception as e:
    # Los agentes publican errores a "agent_error" context
    logger.error(f"Analysis failed: {e}")

    # Verificar estado del agente
    print(agent.status)  # "error"
```

### 3. Configuración de Timeouts

```python
# Para contratos grandes, aumentar timeouts
results = dynamic_agent.run(
    "large_contract.sol",
    fuzz_runs=100000,
    timeout=1800  # 30 minutos
)
```

### 4. Optimización de Recursos

```python
# Auditoría rápida para CI/CD
coordinator.run(
    "contract.sol",
    priority="fast",
    audit_scope=["static", "ai"]
)

# Auditoría completa para pre-mainnet
coordinator.run(
    "contract.sol",
    priority="comprehensive",
    audit_scope=["static", "dynamic", "symbolic", "formal", "ai", "policy"]
)
```

---

## Referencias

- [MCP Evolution Document](MCP_evolution.md)
- [OWASP SC Top 10 Mapping](../standards/owasp_sc_top10_mapping.md)
- [ISO 27001 Controls](../standards/iso27001_controls.md)
- [NIST SSDF Mapping](../standards/nist_ssdf_mapping.md)

---

**Última Actualización**: Octubre 2025
**Versión**: 2.0 (MCP Architecture)
