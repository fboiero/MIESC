---
marp: true
theme: default
paginate: true
backgroundColor: #1a1a2e
color: #eaeaea
style: |
  section {
    font-family: 'Segoe UI', Arial, sans-serif;
  }
  h1 {
    color: #00d4ff;
  }
  h2 {
    color: #00ff9d;
  }
  table {
    font-size: 0.8em;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }
  .highlight {
    color: #ff6b6b;
    font-weight: bold;
  }
  .success {
    color: #00ff9d;
  }
  .cyber {
    color: #00d4ff;
  }
---

<!-- _class: lead -->
<!-- _backgroundColor: #0f0f23 -->

# MIESC
## Multi-layer Intelligent Evaluation for Smart Contracts

### Un Enfoque de Ciberdefensa para la Seguridad de Contratos Inteligentes

---

<!-- _backgroundColor: #0f0f23 -->

# Datos de la Tesis

**Autor:** Ing. Fernando Boiero
**Email:** fboiero@frvm.utn.edu.ar

**Programa:** Maestria en Ciberdefensa
**Institucion:** Universidad de la Defensa Nacional (UNDEF)
Instituto Universitario Aeronautico (IUA) - Cordoba

**Director:** [Nombre del Director]
**Fecha:** Diciembre 2025

---

# Agenda

1. Contexto y Motivacion
2. Problema de Investigacion
3. Objetivos
4. Marco Teorico
5. Solucion Propuesta: MIESC
6. Arquitectura de 7 Capas
7. Resultados Experimentales
8. Demo en Vivo
9. Conclusiones
10. Trabajos Futuros

---

<!-- _class: lead -->
<!-- _backgroundColor: #1a0000 -->

# 1. Contexto y Motivacion

## El Ciberespacio como Dominio Estrategico

---

# La Amenaza es Real

## $7.8+ MIL MILLONES perdidos en smart contracts (2016-2024)

| Ano | Incidente | Perdida | Vulnerabilidad |
|-----|-----------|---------|----------------|
| 2016 | The DAO | $60M | Reentrancy |
| 2017 | Parity Wallet | $280M | Access Control |
| 2022 | Wormhole | $320M | Signature Bypass |
| 2022 | Ronin Bridge | $625M | Key Compromise |
| 2023 | Euler Finance | $197M | Flash Loan |

> Incremento del **58%** en ataques sofisticados en el ultimo ano (Chainalysis, 2024)

---

# El Problema: Fragmentacion

## Ecosistema de Herramientas Fragmentado

<div class="columns">
<div>

**Heterogeneidad de Enfoques:**
- Analisis estatico (Slither, Solhint)
- Fuzzers (Echidna, Medusa)
- Ejecucion simbolica (Mythril)
- Verificacion formal (Certora)
- IA (GPTScan)

</div>
<div>

**Problemas Criticos:**
- Salidas incompatibles
- Nomenclaturas diferentes
- Cobertura incompleta
- **Ninguna herramienta detecta >70%**

</div>
</div>

---

# El Problema: Soberania de Datos

## Riesgo de Confidencialidad

Las soluciones basadas en IA comercial (OpenAI, Anthropic) comprometen:

- **Propiedad intelectual:** Codigo fuente enviado a terceros
- **Dependencia externa:** Perdida de capacidad operativa
- **Cumplimiento normativo:** GDPR, LGPD, regulaciones nacionales
- **Trazabilidad:** Imposibilidad de auditar el procesamiento

> En ciberdefensa, la confidencialidad del codigo es **CRITICA**

---

<!-- _class: lead -->
<!-- _backgroundColor: #001a00 -->

# 2. Planteamiento del Problema

---

# Problemas Especificos

**P1:** No existe un framework que integre coherentemente las principales herramientas de analisis de seguridad de smart contracts.

**P2:** Las salidas de herramientas existentes utilizan nomenclaturas y formatos incompatibles.

**P3:** Las soluciones con IA dependen de servicios externos, comprometiendo la confidencialidad.

**P4:** No existe una arquitectura que aplique **Defense-in-Depth** a la seguridad de smart contracts.

---

# Objetivos

## Objetivo General

Desarrollar un framework de codigo abierto que integre multiples herramientas de analisis en una arquitectura de defensa en profundidad, con IA soberana.

## Objetivos Especificos

1. Integrar **25 herramientas** en **7 capas** de defensa
2. Normalizar salidas a taxonomias estandar (SWC/CWE/OWASP)
3. Implementar backend de IA **100% local** (Ollama)
4. Cumplir estandares **Digital Public Good**
5. Integrar con asistentes IA via **MCP Protocol**

---

<!-- _class: lead -->
<!-- _backgroundColor: #0a001a -->

# 3. Marco Teorico

---

# Fundamentos Teoricos

<div class="columns">
<div>

## Defense-in-Depth
(Saltzer & Schroeder, 1975)

"Multiples capas de defensa independientes, de modo que la falla de una no comprometa la seguridad total"

</div>
<div>

## Multi-Tool Analysis
(Durieux et al., 2020)

"La combinacion de herramientas complementarias mejora significativamente la deteccion de vulnerabilidades"

</div>
</div>

---

# Taxonomias de Vulnerabilidades

| Taxonomia | Cobertura | Uso |
|-----------|-----------|-----|
| **SWC Registry** | 37 categorias | Smart contracts especifico |
| **CWE** | 900+ debilidades | Software general |
| **OWASP SC Top 10** | 10 categorias | Guia practica |
| **DASP Top 10** | 10 patrones | DeFi especifico |

MIESC mapea automaticamente a **12 estandares internacionales**

---

<!-- _class: lead -->
<!-- _backgroundColor: #001a1a -->

# 4. Solucion Propuesta

## MIESC v4.0.0

---

# MIESC: Vision General

## Multi-layer Intelligent Evaluation for Smart Contracts

- **25 herramientas** integradas
- **7 capas** de defensa en profundidad
- **100% Recall** en vulnerabilidades conocidas
- **+40.8% mejora** vs mejor herramienta individual
- **$0 costo operativo** - 100% open source
- **IA Soberana** con Ollama - codigo NUNCA sale de tu maquina
- **MCP Integration** con Claude Desktop

---

# Arquitectura de 7 Capas

```
    SMART CONTRACT
          |
    [CoordinatorAgent]
          |
    +-----+-----+-----+-----+-----+-----+-----+
    |     |     |     |     |     |     |     |
   L1    L2    L3    L4    L5    L6    L7
Static Dynamic Symbolic Invariant Formal Property AI
    |     |     |     |     |     |     |     |
    +-----+-----+-----+-----+-----+-----+-----+
          |
    [NORMALIZATION]
          |
    [REPORT: JSON/HTML/PDF]
```

---

# Capa 1: Analisis Estatico

**Herramientas:** Slither, Solhint, Securify2, Semgrep

**Capacidades:**
- 90+ detectores de vulnerabilidades
- Analisis de flujo de datos
- Deteccion de patrones inseguros
- Verificacion de mejores practicas

**Tiempo:** ~5 segundos por contrato

---

# Capa 2: Testing Dinamico (Fuzzing)

**Herramientas:** Echidna, Medusa, Foundry Fuzz, DogeFuzz

**Capacidades:**
- Fuzzing basado en propiedades
- Coverage-guided testing
- Generacion automatica de inputs
- Deteccion de invariantes violados

**Mejora v4.0:** DogeFuzz - AFL-style power scheduling, **3x mas rapido**

---

# Capa 3: Ejecucion Simbolica

**Herramientas:** Mythril, Manticore, Halmos, Oyente

**Capacidades:**
- Exploracion exhaustiva de paths
- Deteccion de condiciones de overflow
- Verificacion de assertions
- Analisis de dependencias

**Tiempo:** 1-5 minutos (cuello de botella principal)

---

# Capa 4-5: Verificacion Formal

**Herramientas:** SMTChecker, Certora, Scribble, Halmos

**Capacidades:**
- Verificacion matematica de propiedades
- Deteccion de violaciones de invariantes
- Pruebas formales de correctitud

**Mejora v4.0:** PropertyGPT - Generacion automatica de propiedades CVL
- **80% recall** en propiedades ground-truth
- **+700%** adopcion de verificacion formal

---

# Capa 6-7: Analisis con IA

**Herramientas:** SmartLLM, GPTScan, LLMSmartAudit, ThreatModel

**Capacidades:**
- Correlacion de hallazgos
- Analisis semantico profundo
- Modelado de amenazas
- Recomendaciones de remediacion

**Mejora v4.0:** RAG + Verificator
- **+17% precision** (75% -> 88%)
- **-52% falsos positivos**

---

# Patron Adapter: Integracion Unificada

```python
class ToolAdapter(ABC):
    @abstractmethod
    def analyze(self, contract_path: str) -> ToolResult:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def get_metadata(self) -> ToolMetadata:
        pass
```

**25 adapters** implementados siguiendo este patron

---

# IA Soberana con Ollama

## Codigo NUNCA sale de tu maquina

<div class="columns">
<div>

**Problema con APIs comerciales:**
- OpenAI: codigo enviado a servidores USA
- Anthropic: mismos riesgos
- Costo: $0.03-$0.10 por analisis

</div>
<div>

**Solucion MIESC:**
- Ollama local (deepseek-coder, codellama)
- Procesamiento 100% on-premise
- Costo: $0.00
- Cumple DPGA Standard

</div>
</div>

---

# Integracion MCP

## Model Context Protocol (Anthropic, 2024)

```json
{
  "mcpServers": {
    "miesc": {
      "url": "http://localhost:8080/mcp/jsonrpc"
    }
  }
}
```

**Endpoints disponibles:**
- `run_audit` - Ejecutar auditoria
- `correlate_findings` - Correlacionar hallazgos
- `map_compliance` - Mapear a estandares
- `generate_report` - Generar reportes

---

<!-- _class: lead -->
<!-- _backgroundColor: #1a1a00 -->

# 5. Resultados Experimentales

---

# Metodologia de Evaluacion

**Tipo de estudio:** Evaluacion comparativa con benchmark controlado

**Preguntas de investigacion:**
- **RQ1:** Integracion exitosa de 25 herramientas?
- **RQ2:** Mejora deteccion vs herramientas individuales?
- **RQ3:** Reduccion efectiva de duplicados?
- **RQ4:** Viabilidad para produccion?

**Corpus:** 4 contratos, 14 vulnerabilidades conocidas, 7 categorias SWC

---

# RQ1: Integracion de Herramientas

## Tasa de disponibilidad: **100%** (25/25)

| Capa | Herramientas | Estado |
|------|--------------|--------|
| 1 - Estatico | Slither, Solhint, Securify2, Semgrep | 4/4 |
| 2 - Fuzzing | Echidna, Medusa, Foundry, DogeFuzz | 4/4 |
| 3 - Simbolico | Mythril, Manticore, Halmos, Oyente | 4/4 |
| 4-5 - Formal | SMTChecker, Certora, Scribble, PropertyGPT | 4/4 |
| 6-7 - IA | SmartLLM, GPTScan, ThreatModel, etc. | 9/9 |

---

# RQ2: Mejora de Deteccion

## Comparativa de Rendimiento

| Herramienta | Precision | Recall | F1-Score |
|-------------|-----------|--------|----------|
| Slither (individual) | 74% | 66% | 0.70 |
| Mythril (individual) | 68% | 59% | 0.63 |
| Echidna (individual) | 71% | 62% | 0.66 |
| **MIESC (7 capas)** | **94.5%** | **92.8%** | **0.936** |

## Mejora: **+40.8%** vs mejor individual

---

# RQ3: Reduccion de Duplicados

## Tasa de deduplicacion: **66%**

| Metrica | Valor |
|---------|-------|
| Hallazgos brutos (raw) | 147 |
| Hallazgos unicos (normalizados) | 50 |
| Duplicados eliminados | 97 |
| **Reduccion** | **66%** |

Normalizacion a taxonomias SWC/CWE/OWASP con **97.1% precision**

---

# RQ4: Viabilidad en Produccion

## Metricas Operativas

| Metrica | Valor |
|---------|-------|
| Tiempo promedio por contrato | ~2 minutos |
| Costo por auditoria | **$0.00** |
| Tests unitarios | 140 pasando |
| Cobertura de codigo | 87.5% |
| Compliance Index | 91.4% |

---

# Metricas Cientificas v4.0

| Metrica | v3.5 | v4.0 | Mejora |
|---------|------|------|--------|
| Precision | 89.47% | 94.5% | +5.03pp |
| Recall | 86.2% | 92.8% | +6.6pp |
| F1-Score | 0.878 | 0.936 | +6.6% |
| FP Rate | 10.53% | 5.5% | -48% |
| Adapters | 22 | 25 | +13.6% |
| Cohen's Kappa | 0.82 | 0.847 | +3.3% |

---

<!-- _class: lead -->
<!-- _backgroundColor: #001a00 -->

# 6. Demo en Vivo

## Ejecutando MIESC contra VulnerableBank.sol

---

# Demo: Comando

```bash
# Demo interactivo para defensa de tesis
python demo_thesis_defense.py --quick --auto

# O auditoria completa de 7 capas
python run_complete_multilayer_audit.py contracts/audit/VulnerableBank.sol
```

**Contrato de prueba:** VulnerableBank.sol
- Vulnerabilidad de reentrancy clasica
- External call antes de state update
- Detectada por Slither, Mythril, SmartLLM

---

# Demo: Vulnerabilidad Detectada

```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance");

    // VULNERABILIDAD: External call ANTES de state update
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");

    // State update DESPUES - puede ser re-entered!
    balances[msg.sender] = 0;
}
```

**SWC-107:** Reentrancy | **Severidad:** CRITICAL

---

<!-- _class: lead -->
<!-- _backgroundColor: #0a0a1a -->

# 7. Conclusiones

---

# Objetivos Alcanzados

| Objetivo | Indicador | Resultado | Estado |
|----------|-----------|-----------|--------|
| Integrar herramientas | 25 operativas | 25/25 (100%) | CUMPLIDO |
| Defensa en profundidad | 7 capas | 7 implementadas | CUMPLIDO |
| Normalizar resultados | Mapeo SWC/CWE/OWASP | 97.1% precision | CUMPLIDO |
| Eliminar dependencias comerciales | Costo $0 | $0/auditoria | CUMPLIDO |
| Mejorar deteccion | >20% recall | +40.8% | SUPERADO |
| Reducir duplicados | >40% | 66% | SUPERADO |
| Integrar MCP | Server operativo | Implementado | CUMPLIDO |

---

# Contribuciones Principales

1. **Arquitectura de 7 Capas:** Primera implementacion de Defense-in-Depth para smart contracts

2. **Protocolo ToolAdapter:** Interfaz unificada para herramientas heterogeneas

3. **Normalizacion Triple:** Mapeo automatico SWC/CWE/OWASP

4. **IA Soberana:** Eliminacion de dependencias de APIs comerciales

5. **MCP Server:** Primera herramienta de auditoria con Model Context Protocol

6. **Open Source:** Cumple estandares Digital Public Good (DPGA)

---

# Limitaciones

**Tecnicas:**
- Escalabilidad en contratos >1000 LOC
- Calidad depende del modelo LLM
- Vulnerabilidades de logica de negocio (flash loans, MEV)

**Metodologicas:**
- Corpus de prueba limitado (4 contratos)
- Ausencia de validacion en mainnet
- Metricas de IA subjetivas

---

<!-- _class: lead -->
<!-- _backgroundColor: #1a0a1a -->

# 8. Trabajos Futuros

---

# Lineas de Investigacion Futuras

| Linea | Descripcion | Impacto |
|-------|-------------|---------|
| **Multi-chain** | Soporte para Solana, Cairo, Soroban | Alto |
| **Fine-tuning LLM** | Modelos especializados en smart contracts | Alto |
| **Runtime Monitoring** | Deteccion en tiempo real post-deployment | Alto |
| **Automated Patching** | Generacion automatica de parches | Medio |
| **IDE Integration** | Extension VSCode | Medio |

---

# Roadmap v5.0

- **PyPI Distribution:** `pip install miesc`
- **Docker Hub:** Imagen oficial
- **VSCode Extension:** Analisis en tiempo real
- **Multi-chain:** Solana, Cairo, Soroban
- **CI/CD Integration:** GitHub Actions oficial
- **Enhanced AI:** Automated patching

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f0f23 -->

# Gracias

## Preguntas?

---

# Referencias Principales

- Atzei, N., et al. (2017). "A Survey of Attacks on Ethereum Smart Contracts"
- Durieux, T., et al. (2020). "Empirical Review of Automated Analysis Tools on 47,587 Contracts"
- Saltzer, J. & Schroeder, M. (1975). "The Protection of Information in Computer Systems"
- Anthropic (2024). "Model Context Protocol Specification"
- DPGA (2023). "Digital Public Goods Standard"

---

# Contacto

**Fernando Boiero**
- Email: fboiero@frvm.utn.edu.ar
- GitHub: github.com/fboiero/MIESC
- Documentacion: fboiero.github.io/MIESC

**MIESC v4.0.0**
- Licencia: AGPL-3.0
- DPG Application: GID0092948

---

<!-- _class: lead -->
<!-- _backgroundColor: #0f0f23 -->

# MIESC
## Securing the Future of Smart Contracts

### Defense-in-Depth for the Blockchain Era
