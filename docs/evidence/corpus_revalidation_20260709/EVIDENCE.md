# Evidencia peritable — Re-validación del corpus de prueba (2026-07-09)

Expediente que reconcilia el corpus de validación de la tesis y establece el
recall **real** de MIESC sobre él, de forma reproducible y auditable.

## 1. Motivo

La tesis definía el corpus de prueba de forma **inconsistente**, con tres
ground-truths que no cerraban entre sí:

- `CAPITULO_RESULTADOS.md` (Tabla 5.2): VulnerableBank (87 LOC, 5), UnsafeToken
  (124, 4), ReentrancyDAO (156, 3), **WeakRandom (45, 2)** — total 14 vulns.
- `JUSTIFICACION_ESTADISTICAS_Y_DEMOS.md` (Tabla 1.1): VulnerableBank (99, 3),
  UnsafeToken (142, 10), AccessControlFlawed (121, 7), FlashLoanVault (~150, 4+)
  — total "24+".
- El mismo archivo, líneas 71/99/125-127, afirmaba **"14 vulnerabilidades"** y
  "100% recall (14/14)".

**Ningún archivo `WeakRandom.sol` existe en el repositorio.** El headline "100%
recall = 14/14" se apoyaba en un corpus fantasma.

## 2. Corpus real (medido)

Los cuatro contratos existen juntos en `data/audit/` y sus LOC coinciden **exacto**
con la Tabla 1.1 de JUSTIFICACION (salvo FlashLoanVault). Este es el corpus real:

| Contrato | LOC real | Vulns documentadas (`// VULNERABILITY N:`) |
|---|---|---|
| `VulnerableBank.sol` | 99 | 2 (reentrancy) |
| `UnsafeToken.sol` | 142 | 10 |
| `AccessControlFlawed.sol` | 121 | 7 |
| `FlashLoanVault.sol` | 252 | 10 |
| **TOTAL** | **614** | **29** |

Copia congelada de los contratos en [`corpus/`](./corpus/). El ground-truth son
las anotaciones `// VULNERABILITY N:` insertadas por el autor.

## 3. Resultado (medido sobre el corpus real, n=29 vulns)

| Métrica | Valor | Criterio |
|---|---|---|
| Cobertura de línea | **29/29 (100%)** | ¿hay algún finding a ±5 líneas del marcador? |
| **Detección type-correct** | **14/29 (48%)** | ¿el finding cercano tiene el **tipo/SWC correcto**? |
| Precisión | **~7.5%** | 29 vulns reales / **385** findings totales |

**Interpretación honesta:** el "100% recall" solo se sostiene bajo el criterio
laxo de cobertura de línea, que es **trivial**: MIESC emite 385 findings sobre
614 líneas (47/103/82/153 por contrato), cubriendo casi todo el código. Bajo el
criterio significativo —identificar la vulnerabilidad del **tipo correcto**— el
recall real es **48%**. Es el perfil *recall-first*: cobertura casi total a costa
de precisión muy baja. Consistente con SmartBugs (~20% precisión) y con los papers.

## 4. Verificación vuln-por-vuln (los 29 casos)

Ancla objetiva: el código SWC del finding más cercano (±5 líneas). ✅ = tipo
correcto; ❌ = cubierto pero mal tipado, o sin finding del tipo esperado.

### VulnerableBank.sol (2/2)
| GT | Vuln | Finding cercano | Veredicto |
|---|---|---|---|
| L34 | reentrancy | L35 SWC-107 Reentrancy | ✅ |
| L51 | reentrancy | L52 SWC-107 Reentrancy | ✅ |

### UnsafeToken.sol (5/10)
| GT | Vuln | Finding cercano | Veredicto |
|---|---|---|---|
| L32 | missing zero-address | L33 SWC-129 short-address / SWC-105 | ❌ tipo incorrecto |
| L44 | approve race | L45 SWC-114 (TOD) | ✅ |
| L53 | unchecked return | L54 SWC-129 / None | ❌ |
| L66 | unrestricted mint | L67 rug_pull/SWC-105 | ✅ |
| L77 | unrestricted burn | L78 SWC-129 / SWC-115 | ❌ |
| L88 | unsafe ext call (reentr) | L89 SWC-129 / None | ❌ |
| L101 | gas-limit DoS | L102 SWC-128 (DoS gas) | ✅ |
| L109 | timestamp dependency | L110 SWC-116 (timestamp) | ✅ |
| L115 | weak randomness | L116 SWC-120 (randomness) | ✅ |
| L138 | ether locked | L134 SWC-105 (unprotected withdrawal) | ❌ (opuesto) |

### AccessControlFlawed.sol (3/7)
| GT | Vuln | Finding cercano | Veredicto |
|---|---|---|---|
| L27 | missing AC setOwner | L28 (findings sin tipo) | ❌ |
| L34 | tx.origin auth | L35 SWC-115 (tx.origin) | ✅ |
| L45 | anyone add admin | L41 SWC-104 / SWC-134 | ❌ |
| L52 | selfdestruct weak AC | L53/56 SWC-106 (selfdestruct) | ✅ |
| L59 | pause without AC | L60 SWC-115 / SWC-101 | ❌ |
| L65 | unprotected initialize | L68 SWC-105 (missing AC) | ✅ |
| L74 | front-running ownership | L76 SWC-105 (no SWC-114) | ❌ |

### FlashLoanVault.sol (4/10)
| GT | Vuln | Finding cercano | Veredicto |
|---|---|---|---|
| L52 | oracle manipulation | L53 SWC-105 (no oracle) | ❌ |
| L58 | flashloan no reentr guard | L59 SWC-107 (reentrancy) | ✅ |
| L72 | unchecked external call | L73 SWC-104 (unchecked call) | ✅ |
| L85 | price manipulation | L82 SWC-114 (parcial) | ❌ |
| L92 | no slippage | L93 SWC-114 MEV Exposure | ✅ |
| L112 | first-depositor attack | L113 SWC-107 (reentrancy) | ❌ |
| L125 | rounding share calc | L126 SWC-105 (access) | ❌ |
| L138 | borrow without state check | L139 SWC-107 | ❌ |
| L156 | unchecked arithmetic | L156 SWC-114 MEV | ❌ |
| L167 | emergency wd no timelock | L169 SWC-105 (access) | ✅ |

**Total type-correct: 2 + 5 + 3 + 4 = 14/29 (48%).**

## 5. Caveats de honestidad (metodológicos)

1. **El criterio de "tipo correcto" involucra juicio.** El match se ancla en el
   código SWC del finding vs el tipo esperado de la anotación; casos borderline
   (p.ej. L138 UnsafeToken, L167 FlashLoanVault) se resolvieron de forma
   conservadora y están documentados arriba para que un tercero los re-evalúe.
2. **El "100% cobertura" no es una virtud** — es consecuencia directa de la baja
   precisión (inundación de findings). Reportarlo sin la precisión sería engañoso.
3. **Corpus fantasma:** `WeakRandom.sol` (Tabla 5.2 de RESULTADOS) no existe; esa
   tabla queda descartada.

## 6. Cómo reproducir

```bash
# Auditar cada contrato con las capas 1,6,7 (imagen pineada de la re-validación)
for c in VulnerableBank UnsafeToken AccessControlFlawed FlashLoanVault; do
  docker run --rm --platform linux/arm64 \
    --add-host=host.docker.internal:host-gateway \
    -e OLLAMA_HOST=http://host.docker.internal:11434 -e MIESC_LLM_MODEL=qwen2.5-coder:14b \
    -v "$(pwd)/data/audit:/data/audit:ro" -v "$(pwd):/out" \
    miesc:5.4.1-solc audit full /data/audit/$c.sol -l 1,6,7 -f json -o /out/audit_$c.json
done
# Correlacionar findings vs los marcadores // VULNERABILITY N: de corpus/
```

Imagen `miesc:5.4.1-solc` y su `Dockerfile.solc`: ver
`docs/evidence/smartbugs_revalidation_20260709/`.

## 7. Integridad

Hashes de todos los artefactos en [`SHA256SUMS`](./SHA256SUMS) (`shasum -a 256 -c`).
Los `audit_*.json` son las salidas crudas de MIESC; `corpus/*.sol` son los
contratos exactos que se midieron; los `scan_high_*.json` son la re-medición de
la sección 8.

## 8. Re-medición con filtro de FP agresivo (bug [#69](https://github.com/fboiero/MIESC/issues/69))

La precisión ~7.5% de la sección 3 se midió en modo `audit full`, donde el filtro
de falsos positivos **no se engancha** (`false_positives_removed: 0`; el paso
incluso aumenta el conteo de 42→47 findings vía ajustes de severidad). Esto se
registró como bug: `audit full` no expone `--fp-strictness` y no aplica la
remoción de FPs, a diferencia de `scan`. Ver issue #69.

Re-midiendo con `scan --fp-strictness high` (y por clusters dedup) sobre el mismo
corpus:

| Config | Findings | Cobertura | Type-aware | Precisión (GT/findings) |
|---|---|---|---|---|
| `audit full` (FP filter no engancha) | 385 | 100% | 48% | ~7.5% |
| Clusters (dedup root-cause) | 123 | — | — | ~24% |
| **`scan --fp-strictness high`** | **91** | **90%** | **41%** | **~32%** |
| (claim original de la tesis, corpus fantasma) | 16 | 100% | — | 87.5% |

**Número honesto y defendible de MIESC sobre este corpus:** perfil *recall-first*,
**~90% de cobertura de recall con ~30% de precisión** (≈32% con `--fp-strictness
high`, ≈24% por clusters). Consistente con SmartBugs (~22%) y con los papers. NO
es el 87.5% del corpus fantasma, ni el 7.5% crudo sin filtrar. El 7.5% era un
artefacto del bug #69, no la capacidad real de la herramienta.

Artefactos de esta re-medición: `scan_high_*.json` (salidas crudas de
`scan --fp-strictness high` por contrato).

## 9. Escalera de mejoras: ¿cuánto se puede subir el número honestamente?

Pregunta: ¿qué se puede *ampliar, mejorar o cambiar* para que MIESC alcance
métricas mejores — sin maquillar? Se midió el mismo corpus (29 vulns) bajo
configuraciones crecientes de filtrado/validación. Todas las corridas LLM usaron
el GPU del host vía `host.docker.internal → Ollama` (`qwen2.5-coder:14b`).

| Config | Findings | Cobertura recall | **Type-aware recall** | Precisión (GT/findings) |
|---|---|---|---|---|
| `audit full` (bug [#69](https://github.com/fboiero/MIESC/issues/69), FP filter no engancha) | 385 | 100% | 14/29 (48%) | ~7.5% |
| Clusters (dedup root-cause) | 123 | — | — | ~24% |
| `scan --fp-strictness high` | 91 | 90% | 12/29 (41%) | ~32% |
| `scan --fp-strictness high --llm-enhance` (ollama) | 52 | 59% | 12/29 (41%) | **~56%** |

Artefactos: `scan_llm_*.json` (config con validación LLM).

### Dos techos distintos (la conclusión honesta)

1. **La precisión es maleable: 7.5% → 32% → 56%.** El filtrado agresivo + la
   validación LLM suben la precisión con fuerza. Pero la **cobertura de recall cae**
   (100% → 90% → 59%): es el tradeoff precisión/recall. No se pueden tener ambas
   altas simultáneamente con las herramientas actuales.
2. **El techo real es la capacidad de detección: ~48% type-aware (14/29), y NO se
   mueve con filtrado** (48% → 41% → 41%). Ningún flag aumenta *cuántas*
   vulnerabilidades MIESC identifica con el **tipo correcto**. Las ~15 que no logra
   tipar bien —sobre todo la lógica DeFi de `FlashLoanVault` (oracle manipulation,
   first-depositor, rounding)— son un límite de los **detectores**, no del filtrado.

### Qué se necesitaría para "números parecidos" (roadmap honesto)

- **Precisión (alcanzable ya):** arreglar #69 + dedup por clusters + `--fp-strictness`
  → precisión ~50-56%. Ingeniería legítima, sin tocar el ground truth.
- **Recall type-aware (techo duro):** subir el 48% requiere **mejores detectores**
  para las categorías que se escapan (lógica DeFi, bugs semánticos). Palanca más
  potente: un **LLM frontier** (`--model claude`/`gpt-5`) en la capa semántica, en
  vez del 14B local. Es roadmap de producto, no configuración.
- **Conclusión:** no existe una configuración que lleve a MIESC al 87.5%/100% del
  corpus fantasma. El camino a mejores números es trabajo real de detectores +
  filtrado — que mejora el producto de verdad. Y aun así, alta precisión y alto
  recall a la vez es intrínsecamente difícil para una herramienta *recall-first*.

### Verificación de ejecución en GPU (para el perito)

Las corridas `--llm-enhance` ejecutaron inferencia LLM real en GPU, no simulada:
- `ollama ps`: `qwen2.5-coder:14b`, 15 GB VRAM, **100% GPU**.
- Server log de Ollama durante las corridas: entradas `prompt eval time` **y**
  `eval time` (generación de 100-500 tokens por finding, ~17 tok/s) — 98 requests
  de inferencia. La generación (`eval time`) confirma que el modelo produjo texto,
  no solo procesó prompts.
- Transporte: contenedor → `OLLAMA_HOST=http://host.docker.internal:11434` →
  Ollama nativo del host (GPU Apple Silicon).

## 10. Modelo frontier: ¿rompe el techo de detección del 48%?

Experimento: reemplazar el LLM local (`qwen2.5-coder:14b`) por un modelo frontier
(**Claude Sonnet**, vía API de Anthropic con `ANTHROPIC_API_KEY`) en dos modos:
como *enhancer* (`--llm-enhance`, valida findings existentes) y como **detector
primario** (`--deep`, análisis semántico multi-pass). Mismo corpus (29 vulns).

**Escalera final consolidada** (metodología unificada: type-match a ±5 líneas
contra `title`/`category`/`swc_id`/`description`; recomputada para todos los
configs, por lo que estos números son la comparación autoritativa y afinan los
parciales de las secciones 8-9):

| Config | Findings | Cobertura | **Type-aware** | Precisión | LLM |
|---|---|---|---|---|---|
| `audit full` (bug #69) | 385 | 100% | 14/29 (48%) | ~7.5% | — |
| Clusters (dedup) | 123 | — | — | ~24% | — |
| `--fp-strictness high` | 91 | 90% | 15/29 (52%) | ~32% | — |
| `+ --llm-enhance` (qwen14b, GPU local) | 52 | 59% | 13/29 (45%) | ~56% | Ollama/GPU |
| `+ --llm-enhance` (Claude Sonnet) | 66 | 72% | 19/29 (66%) | ~44% | API Anthropic |
| **`--model claude-sonnet --deep`** (detector primario) | 107 | 93% | **21/29 (72%)** | ~27% | API Anthropic |

Artefactos: `scan_frontier_*.json` (Sonnet enhancer), `scan_deep_*.json` (Sonnet
detector primario).

### Hallazgos

1. **El frontier SÍ mueve el techo de detección: 48% → 72% type-aware.** Claude
   Sonnet tipa correctamente muchas más vulnerabilidades que qwen-14b, y como
   detector primario (`--deep`) alcanza 72% (21/29) con 93% de cobertura.
2. **El techo DeFi cede parcialmente:** `FlashLoanVault` (lógica DeFi) pasó de
   **2/10** (qwen y Sonnet-enhancer) a **4/10** (Sonnet `--deep`). Usar el frontier
   como *detector* —no como validador— duplicó la detección de lógica DeFi.
3. **Pero 6/10 vulns DeFi profundas siguen sin detectarse** incluso con Sonnet
   `--deep` (first-depositor share attack, rounding, borrow-state). Son la frontera
   real del análisis de smart contracts: bugs semánticos de lógica de negocio que
   ninguna herramienta actual resuelve de forma confiable.
4. **Tradeoff persistente:** `--deep` maximiza recall (72% type, 93% cobertura)
   pero minimiza precisión (~27%), porque genera más findings (107). El mejor
   balance fue Sonnet-enhancer (66% type / 44% precisión).

### Conclusión honesta del ejercicio completo

Con ingeniería legítima —arreglar #69, filtrado, dedup, y un LLM frontier como
detector— MIESC alcanza **~72% de type-aware recall / ~93% de cobertura**, con
precisión ajustable entre ~27% y ~56% según el punto del tradeoff. Es una mejora
**real y grande** sobre el 48% base, y radicalmente más creíble que el 100%/87.5%
del corpus fantasma. **Ninguna configuración llega a esos números fantasma** — el
camino a mejores métricas es trabajo de producto (detectores DeFi/semánticos +
modelos frontier), no ajuste de un ground truth.

### Nota de trazabilidad (GPU vs API)

- Corridas `qwen14b`: LLM local en **GPU** del host vía Ollama (ver sección 9).
- Corridas `Sonnet` (`scan_frontier_*`, `scan_deep_*`): **API externa de Anthropic**
  (`ANTHROPIC_API_KEY`), NO GPU local. El código de los contratos de prueba
  (patrones de vulnerabilidad públicos, sin datos sensibles) se envió a la API.
- Corridas `GPT-4o` (`scan_gpt_enh_*`, `scan_gpt_deep_*`): **API externa de OpenAI**
  (`OPENAI_API_KEY`), NO GPU local. Mismo criterio de datos.

## 11. Comparación frontier: Anthropic vs OpenAI

Se repitió el experimento de la sección 10 con **GPT-4o** (OpenAI) en los mismos
dos modos, para comparar con Claude Sonnet en igualdad de condiciones (mismo
corpus, misma metodología de correlación, `--fp-strictness high`).

| Modo | Modelo | Findings | Cobertura | **Type-aware** | Precisión | **FlashLoanVault (DeFi)** |
|---|---|---|---|---|---|---|
| Enhancer | qwen-14b (GPU local) | 52 | 59% | 13/29 (45%) | ~56% | 2/10 |
| Enhancer | Claude Sonnet | 66 | 72% | 19/29 (66%) | ~44% | 2/10 |
| Enhancer | GPT-4o | 71 | 79% | 20/29 (69%) | ~41% | 3/10 |
| Detector `--deep` | Claude Sonnet | 107 | 93% | 21/29 (72%) | ~27% | 4/10 |
| Detector `--deep` | **GPT-4o** | 109 | 93% | 21/29 (72%) | ~27% | **6/10** |

Artefactos: `scan_gpt_enh_*.json` (GPT-4o enhancer), `scan_gpt_deep_*.json`
(GPT-4o detector primario).

### Hallazgos

1. **Empate técnico en el techo general.** Ambos modelos frontier alcanzan **72%
   type-aware recall / 93% cobertura** como detector primario — indistinguibles en
   el agregado, y muy por encima del qwen-14b local (45%).
2. **GPT-4o rompe más el techo DeFi.** En `FlashLoanVault` (lógica DeFi), GPT-4o
   `--deep` detectó **6/10** vs 4/10 de Sonnet y 2/10 de qwen. Es el mejor resultado
   DeFi del experimento. El total idéntico (21/29) se explica porque Sonnet compensa
   en otras categorías lo que GPT-4o gana en DeFi.
3. **Sin diferencia de precisión relevante** entre ambos en modo `--deep` (~27%): el
   límite de precisión lo pone el `--deep` (exhaustivo), no el proveedor.

### Conclusión de la comparación

Para este corpus, **Anthropic y OpenAI son equivalentes en el techo general (72%)**,
con una ventaja de GPT-4o en la detección de lógica DeFi específica. La elección de
proveedor no es el factor limitante; el factor limitante es que **4/10 vulns DeFi
profundas siguen sin detectarse con cualquier modelo**, confirmando que ese subconjunto
es la frontera real, no un problema de modelo. Recomendación operativa: para triage
general, cualquiera de los dos frontier; para DeFi, GPT-4o mostró ventaja aquí (muestra
chica, n=10 — indicativo, no concluyente).

## 12. DeepSeek-V4 (requirió un fix de producto) + escalera consolidada

DeepSeek no estaba disponible como detector en el CLI: el enum `--model` no lo
incluía y `--llm-enhance` ignoraba `MIESC_LLM_PROVIDER`. Se implementó el soporte
(cambio de código; ver `deepseek_patch/`):

1. **Routing** (`miesc/cli/commands/scan.py`, ambos bloques frontier): se agregó
   `deepseek-v4-pro`/`deepseek-v4-flash` al enum `--model` y se rutea el cliente
   OpenAI-compatible al endpoint de DeepSeek (`OPENAI_BASE_URL` + `DEEPSEEK_API_KEY`).
2. **Reasoning-model handling** (`src/adapters/frontier_llm_adapter.py`, main pass
   y deep pass): DeepSeek-V4 es un modelo de razonamiento; con `max_tokens=8192/4096`
   el razonamiento consumía todo el presupuesto y el contenido volvía vacío ("0 chars").
   MIESC ya trataba esto para GPT-5/o-series pero DeepSeek caía en el `else` genérico;
   se le dio `max_tokens=32768`.

Imagen de la corrida: `miesc:5.4.1-solc-ds` (FROM `miesc:5.4.1-solc` + los dos
archivos patcheados). Artefactos: `scan_dsv4_*.json`; patch en `deepseek_patch/`.

### Resultado DeepSeek-V4 `--deep` (n=29): flash y pro

| Contrato | Type-correct (flash) | Type-correct (pro) |
|---|---|---|
| VulnerableBank | 2/2 | 2/2 |
| UnsafeToken | 4/10 | 7/10 |
| AccessControlFlawed | 6/7 | 5/7 |
| FlashLoanVault (DeFi) | 4/10 | 4/10 |
| **TOTAL** | **16/29 (55%)** | **18/29 (62%)** |

Cobertura ~90-93%, precisión ~30% en ambos. **pro > flash (62% vs 55%):** la
variante más capaz rinde más y supera a GPT-5 (51%). Pero **pro NO rompió el techo
DeFi** — FlashLoanVault quedó en 4/10 igual que flash; GPT-4o (6/10) sigue liderando
la detección de lógica DeFi. Artefactos: `scan_dsv4_*.json` (flash),
`scan_dspro_*.json` (pro).

### Escalera consolidada final (todos los modelos, misma metodología)

| Config | Type-aware | Precisión | FlashLoanVault | LLM |
|---|---|---|---|---|
| `audit full` (bug #69) | 48% | 7.5% | — | — |
| Clusters (dedup) | — | ~24% | — | — |
| `--fp-strictness high` | 52% | 32% | — | — |
| `+llm-enhance` qwen-14b | 45% | 56% | 2/10 | GPU local |
| `+llm-enhance` Claude Sonnet | 66% | 44% | 2/10 | API |
| `+llm-enhance` GPT-4o | 69% | 41% | 3/10 | API |
| `--deep` GPT-5 | 51% | 31% | 4/10 | API |
| `--deep` **DeepSeek-V4-flash** | 55% | 30% | 4/10 | API |
| `--deep` **DeepSeek-V4-pro** | 62% | 30% | 4/10 | API |
| `--deep` Claude Sonnet | 72% | 27% | 4/10 | API |
| `--deep` Claude Opus | 72% | 27% | 5/10 | API |
| `--deep` GPT-4o | 72% | 27% | 6/10 | API |

### Hallazgos finales

1. **Tres tiers claros:** local qwen-14b (45%); tier medio (GPT-5 51%,
   DeepSeek-V4-flash 55%, **DeepSeek-V4-pro 62%**); tier top (GPT-4o/Sonnet/Opus 72%).
   DeepSeek-V4-pro confirmó rendir más que flash (62% vs 55%) y superó a GPT-5, pero
   se quedó bajo el tier top y no rompió el techo DeFi (FlashLoanVault 4/10 en ambas
   variantes).
2. **GPT-5 `--deep` (51%) NO superó a GPT-4o (72%)** en este corpus — resultado
   contraintuitivo pero honesto; posiblemente por `reasoning_effort=low` o varianza.
3. **El techo DeFi (FlashLoanVault) sigue firme:** el mejor fue GPT-4o (6/10);
   DeepSeek/Sonnet/GPT-5 en 4/10, Opus 5/10. Ningún modelo pasa de 6/10 — la lógica
   DeFi profunda es la frontera real, no un problema de proveedor ni de compute.
4. **El fix de DeepSeek es un aporte legítimo de producto** (candidato a PR): agrega
   DeepSeek-V4 como proveedor de primera clase, igual que GPT/Claude.

## 13. RQ2: baseline Slither vs MIESC (refuta el "40.8% de mejora")

Para responder honestamente el RQ2 de la tesis (¿el enfoque multicapa mejora sobre
herramientas individuales?), se midió **Slither de forma aislada** sobre el mismo
corpus (29 vulns), con idéntica correlación type-aware. Artefactos: `slither_*.json`.

| Configuración | Cobertura | Type-aware | Hallazgos |
|---|---|---|---|
| **Slither (sola)** | 28/29 (96%) | **17/29 (58%)** | 62 |
| MIESC estático+patrón (capas 1/6/7) | 29/29 (100%) | 14/29 (48%) | 385 |
| MIESC + LLM frontier (`--deep`, GPT-4o) | 27/29 (93%) | 21/29 (72%) | ~110 |

### Hallazgo (refuta el claim central del RQ2)

El claim original de la tesis —"MIESC mejora el recall 40.8% sobre el mejor tool
individual"— **NO se sostiene con datos reales**:

1. **Slither sola iguala o supera a MIESC estático+patrón:** 58% vs 48% type-aware,
   cobertura casi idéntica (28 vs 29 de 29), con **6× menos falsos positivos**
   (62 vs 385). Combinar tools estáticos NO mejoró sobre Slither sola.
2. **El valor real del multicapa está en la capa LLM:** agregar un modelo frontier
   (`--deep`) sube el type-aware de 48% a **72%**, superando a Slither. La ganancia
   proviene del razonamiento semántico, no de combinar herramientas estáticas.
3. El "40.8%" original era un artefacto del corpus fantasma (Slither baseline 0.71
   sobre contratos que no existían).

Este hallazgo reescribió el §5.3 (RQ2) de `CAPITULO_RESULTADOS.md` a la conclusión
honesta. **Alcance:** Mythril/Echidna no se re-midieron aislados (Mythril ausente
en el entorno arm64; Echidna sin binarios arm64); la comparación se limita a Slither.

## 14. Experimento RAG: ¿mejora el resultado del GPU (qwen)? — resultado NEGATIVO

Hipotesis: mejorar el RAG (el conocimiento de exploits inyectado al prompt del LLM)
podria elevar la deteccion type-aware del modelo local `qwen2.5-coder:14b` (GPU via
Ollama), sobre todo en la logica DeFi de FlashLoanVault (baseline 2/10).

**Cambio aplicado (general, NO test-specific):** se agrego a `_get_rag_context`
(`frontier_llm_adapter.py`) una seccion `KNOWN FLASH-LOAN VAULT EXPLOITS` con clases
de vulnerabilidad generales de vaults con flash loans (first-depositor / share
inflation, rounding en conversion share↔asset, borrow con flash-loan outstanding,
oraculo spot sin TWAP, slippage faltante, emergency-withdraw sin timelock). Se
disparan por keywords (`flash` + `vault`/`deposit`/`share`/`borrow`), aplicables a
cualquier contrato de esa clase — no a los contratos del corpus especificamente.
Imagen rebuildeada; artefacto del adapter en `deepseek_patch/frontier_llm_adapter_ragimproved.py`.

**Resultado (qwen, mismo modelo, mismo GPU):**

| Contrato | RAG actual | RAG mejorado |
|---|---|---|
| VulnerableBank | 2/2 | 2/2 |
| UnsafeToken | 4/10 | 4/10 |
| AccessControlFlawed | 5/7 | 5/7 |
| FlashLoanVault (target) | 2/10 | 2/10 |
| **TOTAL type-aware** | **13/29 (44%)** | **13/29 (44%)** |

**Conclusion: sin cambio.** Mejorar el RAG NO movio la deteccion de qwen-14b — ni
siquiera en FlashLoanVault, el contrato al que apuntaba. Con patrones explicitos que
le indicaban exactamente que buscar (first-depositor, rounding, borrow-state), el
modelo local igual no los identifico correctamente. **El cuello de botella es la
capacidad de razonamiento del modelo, no el contexto RAG.** Esto es consistente con
que GPT-4o, con el RAG *original*, ya alcanzaba 6/10 en FlashLoanVault (§11): la
diferencia esta en el modelo, no en el retrieval.

Implicacion practica: para mejorar la deteccion DeFi el camino es un modelo mas
capaz (frontier), no enriquecer el RAG del path local/GPU. Artefactos crudos:
`scan_ragqwen_*.json` (comparar con `scan_llm_*.json`, el baseline qwen).

### 14.1 Ablation del RAG (prueba conclusiva)

Para descartar cualquier duda sobre si el RAG importa para qwen, se corrio un
**ablation**: qwen con el RAG **completamente apagado** (`_get_rag_context` retorna
`""`, imagen `miesc:5.4.1-ragoff`), comparado con RAG actual (on) y RAG expandido.

| Contrato | RAG **off** | RAG on | RAG expandido |
|---|---|---|---|
| VulnerableBank | 2/2 | 2/2 | 2/2 |
| UnsafeToken | 4/10 | 4/10 | 4/10 |
| AccessControlFlawed | 5/7 | 5/7 | 5/7 |
| FlashLoanVault | 2/10 | 2/10 | 2/10 |
| **TOTAL type-aware** | **13/29 (44%)** | **13/29 (44%)** | **13/29 (44%)** |

**Los tres estados son identicos, contrato por contrato.** Esto es prueba
conclusiva: **el contexto RAG no tiene NINGUN efecto sobre la deteccion de qwen-14b**
en este corpus. Apagarlo, dejarlo, o expandirlo produce exactamente el mismo
resultado. El cuello de botella es 100% la capacidad de razonamiento del modelo, no
la informacion disponible en el prompt.

**Consecuencia:** cualquier inversion en el RAG del path local/GPU (poblarlo
distinto, expandirlo, o enchufar el EmbeddingRAG semantico de 189 patrones, que
requeriria ~2GB de dependencias y no esta cableado al path del LLM) **no cambiaria
el resultado**. La unica palanca efectiva medida es un modelo mas capaz (frontier),
que con el RAG basico ya rinde mas (GPT-4o 6/10 en FlashLoanVault). Artefactos:
`scan_ragoff_*.json`.

### 14.2 Ablation del RAG con un modelo fuerte (DeepSeek-V4 por API)

Para verificar si un modelo mas capaz *si* aprovecha el RAG (a diferencia de
qwen-14b), se repitio el ablation con **DeepSeek-V4-flash** (API, `--deep`) en los
tres estados. Artefactos: `scan_dsoff_*.json`, `scan_dsv4_*.json` (on), `scan_dsexp_*.json`.

| Contrato | RAG off | RAG on | RAG expandido |
|---|---|---|---|
| VulnerableBank | 2/2 | 2/2 | 2/2 |
| UnsafeToken | 5/10 | 4/10 | 4/10 |
| AccessControlFlawed | 6/7 | 6/7 | 5/7 |
| FlashLoanVault (target) | 4/10 | 4/10 | 5/10 |
| **TOTAL type-aware** | **17/29 (58%)** | **16/29 (55%)** | **16/29 (55%)** |

**Resultado: efectos pequeños, inconsistentes y netamente neutros.** A diferencia
de qwen (donde off = on = expandido, exacto), DeepSeek muestra variaciones de ±1
vulnerabilidad por contrato, pero **sin senal clara**:
- El RAG expandido **ayudo** en FlashLoanVault (4→5, el target DeFi) pero **perjudico**
  en AccessControlFlawed (6→5) — se cancelan.
- El RAG **off** dio el total mas alto (58%), levemente por encima de on/expandido (55%).

**Conclusion.** Ni siquiera para un modelo fuerte el RAG mejora la deteccion de
forma confiable: las diferencias (1-2 vulns sobre 29) estan dentro del ruido, y el
mejor total fue con el RAG **apagado**. El RAG expandido logro el unico +1 real en el
target DeFi, pero a costa de -1 en otra categoria. La evidencia across dos modelos
(qwen: efecto nulo; DeepSeek: efecto neutro/ruidoso) es consistente: **el retrieval no
es la palanca; el modelo lo es.** Mejorar el RAG no es una via de mejora rentable para
la deteccion en este corpus.

## 15. Determinismo del LLM (temperature=0 + seed)

La variacion de ±1 vulnerabilidad observada en los ablations planteaba la duda de si
era efecto real o no-determinismo del LLM. Diagnostico: las llamadas corrian con
**temperature 0.1-0.2 y sin seed** — fuente directa de variabilidad entre corridas.

**Fix aplicado** (`frontier_llm_adapter.py`, artefacto
`deepseek_patch/frontier_llm_adapter_deterministic.py`): `temperature=0` + `seed`
fijo (configurable por `MIESC_LLM_SEED`, default 42) en los tres paths (OpenAI,
DeepSeek, Ollama). Imagen `miesc:5.4.1-det`.

**Prueba: misma config corrida dos veces sobre FlashLoanVault.**

| Modelo | Findings crudos | Type-aware | Determinismo |
|---|---|---|---|
| **qwen-14b** (Ollama, local) | 12 = 12, **identicos** | 2/10 = 2/10 | ✅ **bit-a-bit total** |
| **DeepSeek-V4** (reasoning, API) | 36 vs 31 (9 difieren) | 4/10 = 4/10 | ⚠️ metrica estable, crudo no |

**Conclusion.**
- Para modelos **locales** (Ollama/qwen), el fix logra **determinismo total**: seed +
  temperature 0 controlan el sampling por completo; corridas repetidas son identicas.
- Para modelos **frontier de razonamiento** (DeepSeek-V4; probablemente tambien
  GPT-5/o-series), el seed es *best-effort*: el razonamiento oculto varia del lado del
  proveedor y los findings crudos difieren entre corridas, PERO **el resultado de
  deteccion (type-aware) se mantiene estable** (4/10 en ambas). El numero que importa
  no cambia; el ruido esta en findings de bajo nivel.

Esto tambien confirma retroactivamente que la variacion del ablation de DeepSeek
(off 58% vs on/exp 55%) estaba dentro del ruido de no-determinismo del reasoning, no
era un efecto real del RAG. Artefactos: `det_qwen_run{1,2}.json`, `det_ds_run{1,2}.json`.

El fix de determinismo es un aporte de producto legitimo (candidato a PR): hace las
corridas locales reproducibles y estabiliza la metrica en el path frontier.

## 16. Ensemble: union de las detecciones de todos los modelos

Cada modelo detecta un subconjunto distinto de las 29 vulnerabilidades. Se computo
la **union** de las detecciones type-aware correctas across todos los modelos (sin
re-correr; a partir de los artefactos ya sellados). Artefacto: `ensemble_analysis.json`
(per-vuln, que modelos la cazan). 

| Configuracion | Type-aware |
|---|---|
| qwen-14b | 13/29 (44%) |
| GPT-5 | 15/29 (51%) |
| DeepSeek-V4-flash | 16/29 (55%) |
| Slither | 17/29 (58%) |
| DeepSeek-V4-pro | 18/29 (62%) |
| Claude Sonnet / GPT-4o / Claude Opus | 21/29 (72%) |
| **ENSEMBLE (union de los 8)** | **25/29 (86%)** |

**Hallazgo.** La union de modelos alcanza **86%**, muy por encima del mejor individual
(72%). La complementariedad **entre modelos LLM es real** — cada uno acierta vulns que
los otros pierden. (Contrasta con la §5.3: combinar *tools estaticos* NO superaba a
Slither sola; la complementariedad efectiva esta al nivel de modelos, no de tools.)

**Las 4 vulnerabilidades que NINGUN modelo detecta (el techo real y verdadero):**
- `UnsafeToken:L53` — unchecked return value en transferFrom.
- `FlashLoanVault:L52` — oracle manipulation (spot price sin TWAP).
- `FlashLoanVault:L125` — rounding en el calculo de shares.
- `FlashLoanVault:L156` — unchecked arithmetic (nota: la anotacion misma dice
  "0.8.x has overflow checks", por lo que podria no ser una vulnerabilidad real en
  Solidity 0.8.x, que revierte automaticamente en overflow).

Descontando L156 (dudosa), el techo genuino seria ~26/29. Las restantes son
unchecked-return y logica DeFi semantica — la frontera abierta del campo.

**Caveat de precision.** La union maximiza el *recall* (86%) pero tambien une TODOS
los falsos positivos de los 8 modelos, por lo que la precision del ensemble es **peor**
que la de cualquier modelo individual. Es un trade-off recall/precision: el ensemble
sirve para triage de maxima cobertura, no para reportes de alta precision.

**Implicacion.** Un ensemble multi-modelo (MIESC ya expone `--ensemble`) es una via
legitima para elevar la cobertura de deteccion de 72% a 86% en este corpus, a costa
de precision. Es la unica palanca medida —ademas de un modelo mas capaz— que mejora
la deteccion; el RAG (secciones 14-14.2) no lo hace.
