# RAG Source Selection Criteria

Fecha: 2026-05-06

Este documento define el criterio usado para seleccionar, ponderar y documentar
fuentes en la base RAG de MIESC para el Paper 1.

## Objetivo

El RAG no debe ser una acumulacion de textos. Debe aportar evidencia trazable y
reproducible para tres tareas:

1. Clasificar una posible vulnerabilidad con una taxonomia comprensible.
2. Explicar por que esa vulnerabilidad importa en auditoria real.
3. Dar contexto de mitigacion sin desplazar la evidencia primaria del codigo,
   benchmark, trace o herramienta.

## Principios

1. La fuente debe tener un rol claro.
   - Estandar: define requisitos o controles.
   - Documentacion oficial: explica semantica, API o patron mantenido.
   - Benchmark: provee evidencia reproducible.
   - Herramienta: explica la salida de un detector.
   - Auditoria: muestra como se reportan hallazgos reales.
   - Incidente: aporta contexto de impacto y ruta economica.
   - Legacy: sirve para compatibilidad historica, no como autoridad unica.

2. Se priorizan fuentes mantenidas.
   Fuentes actuales como EEA EthTrust v3, OWASP SCSVS/SCWE/SCSTG, Solidity,
   ethereum.org, OpenZeppelin, Chainlink, Uniswap, Trail of Bits/Crytic,
   Code4rena, Sherlock y SCSFG tienen prioridad sobre guias antiguas.

3. Se separa autoridad de utilidad.
   Un incidente o reporte de perdidas puede justificar prioridad de riesgo, pero
   no prueba que un contrato sea vulnerable. La prueba debe venir del codigo,
   benchmark, PoC, trace, detector calibrado o reproduccion local.

4. Se penalizan fuentes no mantenidas o historicas.
   SWC y ConsenSys Best Practices siguen siendo utiles para compatibilidad con
   SmartBugs, literatura previa y etiquetas historicas, pero se ponderan como
   `legacy_taxonomy`.

5. Se evita una fuente generica cuando existe una fuente especifica.
   Por ejemplo, OpenZeppelin se separa en access control, security utilities,
   proxy/upgradeability, governance/timelock y ERC4626. Chainlink se separa en
   Data Feeds y VRF. Uniswap se usa especificamente para TWAP/oracles.

6. Se favorecen fuentes con aplicacion directa al Paper 1.
   La base prioriza vulnerabilidades y flujos que afectan SmartBugs, EVMBench,
   DeFi, LLM-auditing y evaluacion reproducible: access control, business logic,
   oraculos, flash loans, reentrancy, randomness, proxies, vaults, governance y
   evidencia de herramientas.

## Jerarquia de fuentes

| Tier | Peso | Criterio | Ejemplos |
|---|---:|---|---|
| `standard` | 1.00 | Norma mantenida o checklist verificable. | EEA EthTrust v3, OWASP SCSVS, OWASP Top 10, SCWE/SCSTG. |
| `official_docs` | 0.95 | Documentacion oficial de lenguaje, ecosistema, libreria o protocolo. | Solidity, ethereum.org, OpenZeppelin, Chainlink, Uniswap. |
| `benchmark` | 0.90 | Evidencia reproducible local o dataset curado. | EVMBench local extraction, SmartBugs. |
| `incident` | 0.85 | Contexto de explotacion real o impacto. | DeFiHackLabs, Immunefi, SlowMist. |
| `audit_guide` | 0.80 | Guia o corpus de auditoria util para razonamiento y reporte. | SCSFG, Code4rena, Sherlock. |
| `tool_docs` | 0.78 | Documentacion de herramientas usadas como evidencia. | Slither/Crytic/Trail of Bits. |
| `curated` | 0.70 | Patrones curados internos con utilidad practica. | Documentos MIESC de patrones y mitigaciones. |
| `legacy_taxonomy` | 0.65 | Taxonomia o guia historica no mantenida como autoridad primaria. | SWC, ConsenSys Best Practices archive. |

## Reglas de inclusion

Una fuente entra al RAG si cumple al menos una de estas condiciones:

1. Define controles revisables por un juez o auditor.
2. Es documentacion oficial del lenguaje, ecosistema, libreria o protocolo.
3. Explica una herramienta que MIESC usa como evidencia.
4. Es un benchmark o dataset usado en el paper.
5. Aporta casos reales para razonar impacto o rutas economicas.
6. Mejora compatibilidad con literatura y datasets previos.

Una fuente se excluye o se degrada si:

1. No esta mantenida y existe una alternativa actual.
2. Es principalmente marketing sin detalles tecnicos verificables.
3. No aporta trazabilidad a una categoria evaluada por el paper.
4. Duplica una fuente mas especifica.
5. No permite distinguir entre contexto general y evidencia tecnica.

## Uso correcto en el paper

El paper puede decir que el RAG usa una jerarquia de evidencia documentada para
enriquecer prompts y explicaciones. No debe presentar todas las fuentes del RAG
como evidencia experimental directa.

La evidencia experimental directa sigue siendo:

- `benchmarks/results/paper1_smartbugs_eval.json`
- `benchmarks/results/evmbench/evmbench_ensemble_40.json`
- `benchmarks/results/evmbench/evmbench_static_40.json`
- `benchmarks/results/paper1_claims_matrix.json`
- comandos de reproduccion documentados

Las fuentes RAG respaldan interpretacion, clasificacion, mitigacion y
priorizacion, no sustituyen los resultados medidos.

## Auditoria de fuentes

Para revisar o ampliar el RAG:

1. Asignar `source_tier` y `source_type`.
2. Registrar referencias canonicas.
3. Preferir URLs estables y oficiales.
4. Separar subdominios tecnicos cuando una fuente amplia contenga varios temas.
5. Reindexar ChromaDB mediante cambio de `KNOWLEDGE_BASE_VERSION`.
6. Verificar que `EmbeddingRAG().get_stats()` refleje el conteo esperado.
7. Probar una consulta representativa por familia agregada.
