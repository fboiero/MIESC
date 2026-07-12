# Paper 1 Reproducibility

Fecha: 2026-06-23

Este documento fija la v2 de los artefactos que respaldan los resultados
cuantitativos del Paper 1. La v2 no cambia la claim primaria de SmartBugs ni la
claim central de EVMBench; consolida la evidencia del seguimiento local-Ollama
de SmartBugs, regenera la matriz de claims con timestamp reproducible y evita
reutilizar artefactos historicos como fuente primaria cuando ya existe una
fuente canonica mas reciente.

## Nota v3 editorial

La v3 del documento es una revision editorial sobre la evidencia v2: baja el
tono promocional, explicita la diferencia entre claims primarias y secundarias,
y refuerza las limitaciones metodologicas. No cambia los artefactos
cuantitativos ni las metricas de esta pagina.

## Artefactos principales

| Artefacto | Proposito |
|---|---|
| `benchmarks/generate_paper1_artifacts.py` | Genera artefactos reproducibles del paper a partir de JSONs locales. |
| `benchmarks/results/evmbench/evmbench_ensemble_40.json` | Union reproducible de detecciones EVMBench por proveedor. |
| `benchmarks/results/evmbench/evmbench_static_40.json` | Baseline static-only EVMBench reproducido sobre 40 audits. |
| `benchmarks/results/paper1_claims_matrix.json` | Matriz de claims cuantitativos y fuentes. |
| `benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json` | Corrida SmartBugs completa con seleccion `solc` por `pragma` y Layer 6 especializado. |
| `benchmarks/results/paper1_smartbugs_local_ollama_followup_20260623.json` | Evidencia secundaria del lift local-Ollama: 137/143 -> 140/143 sobre los misses SmartBugs. |
| `benchmarks/results/paper1_exploits_eval_20260621.json` | Evidencia de exploits reales: 9/11, kappa 0.773, $1.59B evaluados. |
| `benchmarks/results/paper1_smartbugs_full_all_layers_smoke_20260506.json` | Smoke reproducible de las 9 capas completas sobre un contrato SmartBugs. |
| `benchmarks/results/tooling_smoke_layers_1_6.json` | Smoke test de herramientas faltantes: Semgrep, Wake, DA-GNN y SmartGuard integrados en el pipeline. |
| `src/llm/embedding_rag.py` | Base RAG versionada para evidencia LLM y recuperacion hibrida. |
| `docs/guides/RAG_SOURCE_POLICY.md` | Politica canonica para seleccionar, ponderar y usar fuentes RAG. |
| `paper/RAG_SOURCE_SELECTION_CRITERIA.md` | Criterio detallado historico usado durante la expansion del corpus RAG del Paper 1. |

## Comandos

Generar ensemble EVMBench y matriz de claims:

```bash
SOURCE_DATE_EPOCH=0 python3 benchmarks/generate_paper1_artifacts.py
```

Resultado esperado:

```text
EVMBench ensemble: 111/120 (92.5%)
Wrote benchmarks/results/evmbench/evmbench_ensemble_40.json
Wrote benchmarks/results/paper1_claims_matrix.json
```

Inspeccionar resumen:

```bash
jq '{total_vulns,total_detected,recall,missed,audits_evaluated,detected_by_provider_count}' \
  benchmarks/results/evmbench/evmbench_ensemble_40.json
```

Resultado esperado:

```json
{
  "total_vulns": 120,
  "total_detected": 111,
  "recall": 0.925,
  "missed": 9,
  "audits_evaluated": 40,
  "detected_by_provider_count": {
    "1": 13,
    "2": 16,
    "3": 23,
    "4": 59
  }
}
```

## EVMBench

Fuente primaria oficial:

- OpenAI, "Introducing EVMbench", 2026-02-18:
  https://openai.com/index/introducing-evmbench/
- arXiv:2603.04915:
  https://arxiv.org/abs/2603.04915
- Paradigm repository:
  https://github.com/paradigmxyz/evmbench

Nota metodologica: la fuente oficial describe 117 vulnerabilidades curadas. Los
artefactos locales de MIESC evaluan 120 high-severity findings. El paper debe
llamar a esto "EVMBench local extraction" o "local high-severity extraction" y
no mezclarlo con el conteo oficial sin aclaracion.

### Provider files

| Provider | Source | Recall |
|---|---|---:|
| Static only | `benchmarks/results/evmbench/evmbench_static_40.json` | 18.3% |
| Claude Sonnet 4.6 | `benchmarks/results/evmbench/evmbench_claude46_40_FINAL.json` | 82.5% |
| GPT-5 | `benchmarks/results/evmbench/evmbench_gpt5_40.json` | 77.5% |
| GPT-4o | `benchmarks/results/evmbench/evmbench_gpt4o_40.json` | 73.7% |
| Ollama qwen2.5-coder:32b | `benchmarks/results/evmbench/evmbench_ollama_qwen32b_40_FINAL.json` | 59.2% |
| Union ensemble | `benchmarks/results/evmbench/evmbench_ensemble_40.json` | 92.5% |

Static-only regeneration command used on 2026-05-06:

```bash
git clone --recurse-submodules https://github.com/paradigmxyz/evmbench \
  /private/tmp/evmbench_static_run

EVMBENCH_AUDITS_DIR=/private/tmp/evmbench_static_run/frontier-evals/project/evmbench/audits \
  python3 benchmarks/evmbench_eval.py \
  --max-audits 40 \
  --output benchmarks/results/evmbench/evmbench_static_40.json
```

Observed static-only summary:

```json
{
  "audits_evaluated": 40,
  "total_findings": 152,
  "total_detected": 22,
  "total_vulns": 120,
  "recall": 0.1833,
  "precision": 0.1447,
  "f1": 0.1618
}
```

The static-only run clones each `evmbench-org/<audit>` repository during
execution. Network access is therefore required for first-time reproduction;
subsequent runs can be accelerated by caching those repositories.

## SmartBugs

El artefacto local completo mas reciente es:

```text
benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json
```

Resumen:

```json
{
  "contracts_evaluated": 143,
  "precision": 0.2219,
  "recall": 0.958,
  "f1": 0.3604,
  "tp": 137,
  "fp": 481,
  "fn": 6
}
```

Comando usado el 2026-05-06:

```bash
python3 -m miesc.cli.main evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \
  --layers 1,6,7 \
  --timeout 120 \
  --output benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.json \
  --jsonl benchmarks/results/paper1_smartbugs_eval_layers_1_6_7.jsonl
```

La corrida completa finalizo en 737.0s. La seleccion de compilador de Slither
se hace por `pragma`: para contratos SmartBugs legacy el adaptador selecciona
un artefacto instalado compatible de `solc-select` como `0.4.26`, `0.4.25` o
`0.5.17` en lugar de forzar `0.8.20`.

El paper tambien reporta un seguimiento con Ollama local sobre los 6 misses del
perfil reproducible. Ese seguimiento agrega 3 verdaderos positivos (2 front
running y 1 short-addresses), elevando la lectura editorial a 140/143 = 97.9%
recall sin costo de API. En v2 esta claim queda respaldada por
`benchmarks/results/paper1_smartbugs_local_ollama_followup_20260623.json` y por
la matriz `paper1_claims_matrix.json` con estado `supported_secondary`. La claim
primaria para tablas reproducibles sigue siendo 137/143 = 95.8%, porque proviene
de una corrida full-corpus deterministica.

El resultado anterior `paper1_smartbugs_eval.json` queda preservado como
baseline historico `1,5,7,9` (89.5% recall, 22.3% precision, 35.6% F1). El
perfil recomendado para el Paper 1 pasa a ser `1,6,7` porque activa los
detectores especializados de SmartBugs, DA-GNN, SmartBugs-ML y Peculiar sin
forzar una corrida LLM completa de varias horas.

Smoke test de herramientas integradas despues de instalar dependencias:

```bash
python3 -m miesc.cli.main evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \
  --layers 1,6 \
  --timeout 180 \
  --limit 1 \
  --output benchmarks/results/tooling_smoke_layers_1_6.json \
  --jsonl benchmarks/results/tooling_smoke_layers_1_6.jsonl
```

Resultado observado: Semgrep, Wake, DA-GNN y SmartGuard reportaron
`AVAILABLE` y entraron al pipeline. El contrato de smoke alcanzo 100.0% recall,
33.3% precision y 50.0% F1 en 34.9s. Wake no produjo hallazgos porque el
contrato SmartBugs no incluye directorio de tests, pero el adaptador ejecuto y
degrado correctamente.

### Full-tool smoke

Para verificar que la herramienta completa entra por las 9 capas sin depender
del perfil reducido del paper, se ejecuto un smoke test sobre el primer contrato
SmartBugs:

```bash
python3 -m miesc.cli.main evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \
  --layers 1,2,3,4,5,6,7,8,9 \
  --timeout 180 \
  --limit 1 \
  --output benchmarks/results/paper1_smartbugs_full_all_layers_smoke_20260506.json \
  --jsonl benchmarks/results/paper1_smartbugs_full_all_layers_smoke_20260506.jsonl
```

Resultado observado:

```json
{
  "contracts_evaluated": 1,
  "precision": 0.1667,
  "recall": 1.0,
  "f1": 0.2857,
  "tp": 1,
  "fp": 5,
  "fn": 0,
  "total_time_s": 183.7
}
```

La evidencia JSONL registra ejecucion de las 9 capas y `intelligence`:

```text
Layer 1: 6 tools, 7.905s
Layer 2: 6 tools, 1.997s
Layer 3: 5 tools, 0.380s
Layer 4: 5 tools, 128.859s
Layer 5: 6 tools, 42.725s
Layer 6: 5 tools, 1.745s
Layer 7: 7 tools, 0.009s
Layer 8: 5 tools, 0.033s
Layer 9: 5 tools, 0.007s
```

Observaciones de disponibilidad registradas durante la corrida:

| Herramienta | Estado observado |
|---|---|
| Slither, Aderyn, Solhint, Semgrep, FourAnalyzer | Ejecutan en Layer 1. |
| Echidna, Medusa, Foundry, DogeFuzz | Ejecutan en Layer 2. |
| Vertigo | Instalado como `eth-vertigo`; ejecuta y degrada a `skipped` si el contrato no es un proyecto Truffle/Hardhat soportado. |
| Wake, Halmos | Ejecutan y degradan sin hallazgos cuando SmartBugs no trae directorio de tests. |
| Oyente, Pakala, SMTChecker, Scribble | Ejecutan en las capas simbolica/formal. |
| PropertyGPT | Usa Ollama HTTP y modelo local `qwen2.5-coder:32b`; en este contrato corta por timeout controlado y retorna fallback sin bloquear. |
| GPTScan, SmartLLM, LLMSmartAudit, GPTLens, LlamaAudit, iAudit, SmartGuard, LLMBugScanner | Ejecutan con Ollama local y RAG; varias respuestas se sirven desde cache versionada. |
| DA-GNN, SmartBugs-ML, SmartBugsDetector, Peculiar | Ejecutan en Layer 6; Peculiar usa fallback pattern-based si no hay pesos GNN locales. |
| Hardhat | No aplicable: no hay `hardhat.config.js` en SmartBugs-curated. |
| Mythril | No instalado en `.venv`; `pyproject.toml` documenta que debe aislarse por conflicto de dependencias con Slither/Web3. |
| Manticore | No instalado; requiere entorno Python antiguo/aislado. |
| Certora | No instalado; requiere licencia/servicio externo. |
| SolCMC | No instalado. |
| ZK circuit analyzer | No aplicable a `.sol`; soporta `.circom` y `.nr`. |

Se intento inicialmente una corrida completa `1,2,3,4,5,6,7,8,9` sobre todo
SmartBugs. Esa ejecucion fue interrumpida antes de producir JSON porque
`LLMBugScanner` usaba `ollama run codellama` y el proceso excedio el timeout
sin terminar. El adapter fue corregido para usar `/api/generate`, nombres
exactos de modelos instalados (`codellama:13b`, `mistral:7b`) y timeouts
controlados. Por costo temporal, el claim cuantitativo publicable del Paper 1
se mantiene sobre la corrida completa `1,6,7`; el full-tool queda documentado
como smoke de integracion de 9 capas.

## RAG

El RAG embebido usa `sentence-transformers` y ChromaDB. Para reproducir la
configuracion usada por los adaptadores LLM:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[rag]'
.venv/bin/python -c "from src.llm.embedding_rag import EmbeddingRAG; print(EmbeddingRAG().get_stats())"
```

Resultado esperado despues de la expansion y ranking por evidencia del
2026-05-06:

```text
'total_documents': 93
'knowledge_base_version': '2026-05-06-paper1-source-review-v4'
'embedding_model': 'all-MiniLM-L6-v2'
```

La base RAG se reindexa automaticamente si el conteo o
`knowledge_base_version` no coinciden con el indice persistido en ChromaDB.
Esto evita que un revisor ejecute una version nueva del codigo contra un indice
viejo. Las caches de `SmartLLM` y `LLM-SmartAudit` tambien
incluyen `knowledge_base_version` en la clave, por lo que una expansion del RAG
no reutiliza respuestas generadas con evidencia anterior.

La recuperacion usa una jerarquia de fuentes:

| Tier | Uso en el RAG |
|---|---|
| `standard` | EEA EthTrust v3 y OWASP SCSVS como normas mantenidas. |
| `official_docs` | Documentacion oficial de Solidity, ethereum.org, OpenZeppelin, Chainlink y Uniswap. |
| `benchmark` | EVMBench local y SmartBugs para evidencia reproducible. |
| `incident` | Incidentes y reproducciones DeFi para rutas economicas reales. |
| `tool_docs` | Trail of Bits/Crytic/Slither para calibrar evidencia estatica. |
| `audit_guide` | Smart Contract Security Field Guide, Code4rena y Sherlock para razonamiento y proceso de auditoria. |
| `legacy_taxonomy` | SWC solo como compatibilidad historica, no como autoridad unica. |

La politica canonica de inclusion, exclusion, ponderacion y uso esta documentada
en `docs/guides/RAG_SOURCE_POLICY.md`. El detalle historico de la expansion del
corpus del Paper 1 se preserva en `paper/RAG_SOURCE_SELECTION_CRITERIA.md`. La
regla editorial es que las fuentes RAG respaldan interpretacion, clasificacion,
mitigacion y priorizacion; no sustituyen la evidencia experimental directa de
SmartBugs, EVMBench ni la matriz de claims.

Las fuentes OpenZeppelin no se tratan como una unica referencia generica. El RAG
incluye documentos separados para Contracts/Security Center, Access Control,
Security Utilities, Proxy/Upgradeability, Governance/Timelock y ERC4626
inflation attacks. Esto permite que las consultas sobre roles, proxies, vaults,
governance o reentrancy recuperen la guia especifica en lugar de una cita amplia.

La revision ampliada tambien incorpora fuentes separadas para Chainlink Data
Feeds, Chainlink VRF, Uniswap V2/V3 TWAP oracles, Trail of Bits/Crytic/Slither,
Code4rena, Sherlock, Immunefi y SlowMist. Estas fuentes no tienen el mismo rol:
Chainlink/Uniswap explican integraciones de oraculos y randomness; Trail of
Bits/Slither calibra evidencia de herramientas; Code4rena/Sherlock aportan
formato y proceso de auditoria competitiva; Immunefi/SlowMist se usan solo para
contexto de impacto e incidentes, no como prueba de vulnerabilidad en un contrato
particular.

## Evaluacion de exploits reales (Tabla III)

La Tabla III evalua 11 exploits reales que cuentan con fixture de contrato,
extraidos de un corpus curado de 25 incidentes. Las clases de vulnerabilidad y
los montos provienen de `data/datasets/rekt_exploits/exploits_ground_truth.json`;
los 11 contratos evaluados suman **$1.59B** (el corpus completo de 25 incidentes
totaliza un monto mayor, que no debe atribuirse al subconjunto evaluado). El
resultado por exploit (9/11 detectados, recall 81.8%, Cohen's kappa = 0.773 con
n=11, reportado como **indicativo** dado el tamano de muestra) esta registrado en
`benchmarks/results/paper1_exploits_eval_20260621.json` y referenciado en la
claims-matrix como `real_world_exploits` (estado `supported_with_note`).

Los contratos vulnerables se obtienen de DeFiHackLabs
(`github.com/SunWeb3Sec/DeFiHackLabs`) y no se incluyen en el repositorio; la
re-ejecucion completa via `benchmarks/evaluate_exploits.py` requiere descargarlos
primero. El artefacto actual transcribe el resultado de las corridas v5.1.6/v5.1.7
y su distribucion por clase fue verificada contra el ground-truth.

## Regla editorial

Una claim numerica del Paper 1 queda publicable solo si aparece en
`benchmarks/results/paper1_claims_matrix.json` con estado `supported`,
`supported_secondary`, `supported_with_note`, `external_primary_source` o
`external_secondary_source`.

Claims canonicas v2:

| Claim | Valor | Fuente |
|---|---:|---|
| SmartBugs primaria | 137/143 = 95.8% recall | `paper1_smartbugs_eval_layers_1_6_7.json` |
| SmartBugs local-Ollama secundaria | 140/143 = 97.9% recall | `paper1_smartbugs_local_ollama_followup_20260623.json` |
| EVMBench local extraction ensemble | 111/120 = 92.5% recall | `evmbench_ensemble_40.json` |
| EVMBench static-only | 22/120 = 18.3% recall | `evmbench_static_40.json` |
| Real-world exploits | 9/11 = 81.8% recall, kappa 0.773 | `paper1_exploits_eval_20260621.json` |

No usar `paper1_smartbugs_eval_layers_1_6_7.jsonl` como fuente primaria de
metricas agregadas: ese JSONL preserva una corrida anterior de 93.7% y queda
solo como traza historica. La fuente canonica v2 para SmartBugs es el JSON
agregado `paper1_smartbugs_eval_layers_1_6_7.json`.
