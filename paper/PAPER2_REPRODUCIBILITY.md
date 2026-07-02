# Paper 2 Reproducibility

Fecha: 2026-07-01

Este documento fija la iteracion v-next de los artefactos que respaldan los
resultados cuantitativos del Paper 2 sobre remediacion automatizada.

## Nota v-next baseline

La v-next promueve la evidencia post-Spank del 2026-06-30 como baseline
canonico de Paper 2. Mantiene el denominador de 143 contratos, 123 patches
emitidos, 123/123 compilacion standalone y 121/123 no-regresion bounded, pero
actualiza la eliminacion por re-scan de 86/123 a 88/123 y la validacion externa
Slither clean-HIGH de 58/123 a 70/123. La corrida registra 2 scan-empty retries
y 53 HIGH residuales externos, con `reentrancy-eth` reducido a 3 en el corpus
completo.

## Nota v3 editorial

La v3 del documento es una revision editorial sobre la evidencia v2: reduce el
tono de venta, separa con mas claridad las metricas de aplicacion, compilacion,
re-scan, no-regresion y Slither externo, y presenta el 58/123 clean-HIGH como
control independiente y no como exito agregado. No cambia los artefactos
cuantitativos ni las metricas de esta pagina.

## Baseline v-next

La v-next reemplaza el baseline congelado anterior `141/90/93/91` por una corrida
con validacion externa Slither sobre cada contrato parcheado que compila. El
cambio no es un simple reemplazo de numeros: tambien cambia el denominador.

En la v-next:

- el corpus total sigue siendo SmartBugs-curated, 143 contratos;
- el scan actual deja 18 contratos sin HIGH/CRITICAL y 2 con salida vacia antes
  de aplicar fixes;
- el denominador de contratos parcheados es 123;
- todos los 123 contratos parcheados compilan standalone;
- los mismos 123 contratos se validan con Slither externo, sin errores de
  validacion externa.

## Artefactos principales

| Artefacto | Proposito |
|---|---|
| `benchmarks/fix_eval.py` | Evalua `miesc scan` + `miesc fix` sobre SmartBugs-curated, con opcion de validacion externa Slither. |
| `benchmarks/results/fix_eval_results.json` | Fuente canonica v-next para las metricas 123/143, 123/123, 88/123, 121/123 y 70/123. |
| `benchmarks/results/fix_eval_full_external_slither_post_spank_20260630_codex.json` | Evidencia fechada promovida de la corrida v-next externa. |
| `benchmarks/results/fix_eval_full_external_slither_post_spank_details_20260630_codex.json` | Evidencia fechada con detalles por contrato, ejemplos y ranking de checks HIGH externos. |
| `benchmarks/generate_paper2_artifacts.py` | Genera matriz de claims y derivados desde `fix_eval_results.json`. |
| `benchmarks/audit_paper2_experiment.py` | Genera controles de validez original-vs-patched y metricas conjuntas. |
| `benchmarks/results/paper2_claims_matrix.json` | Matriz de claims cuantitativos y fuentes. |
| `benchmarks/results/paper2_patch_quality_by_transform.json` | Taxonomia derivada por clase de transformacion de patch. |
| `benchmarks/results/paper2_compile_failure_by_category.json` | Fallas de compilacion standalone derivadas por categoria. En v2 son cero sobre patches emitidos. |
| `benchmarks/results/paper2_compile_failure_taxonomy.json` | Detalle por contrato y evidencia externa; preserva `compile_failure_taxonomy`, que queda vacia en v2. |
| `benchmarks/results/paper2_experiment_audit.json` | Auditoria experimental: compilacion original, patched, metricas conjuntas y sensibilidad. |

## Comandos

Reproducir la evaluacion completa con validacion externa Slither:

```bash
python3 benchmarks/fix_eval.py \
  --external-validator slither \
  --scan-timeout 15 \
  --scan-empty-retries 1 \
  --results-output benchmarks/results/fix_eval_results.json \
  --details-output benchmarks/results/paper2_compile_failure_taxonomy.json
```

La evaluacion completa ejecuta `miesc scan`, `miesc fix`, compilacion standalone
con `solc`, re-scan MIESC por contrato y validacion externa Slither sobre los
patched artifacts que compilan. Requiere el dataset SmartBugs-curated en una de
estas rutas:

- `data/benchmarks/smartbugs-curated/dataset`
- `benchmarks/datasets/smartbugs-curated/dataset`

Generar matriz de claims y artefactos derivados:

```bash
SOURCE_DATE_EPOCH=0 python3 benchmarks/generate_paper2_artifacts.py
```

Resultado esperado:

```text
Paper 2 fix claims: 123/143 applied, 123/123 compiled, 88/123 eliminated
Wrote benchmarks/results/paper2_claims_matrix.json
Wrote benchmarks/results/paper2_patch_quality_by_transform.json
Wrote benchmarks/results/paper2_compile_failure_by_category.json
```

Generar auditoria de validez del experimento:

```bash
python3 benchmarks/audit_paper2_experiment.py
```

Resultado esperado:

```text
Wrote benchmarks/results/paper2_experiment_audit.json
Original standalone compilation: 142/143; patched: 123/143; patched given original compiled: 123/142
```

## Resultados v-next

Resumen local preservado:

```json
{
  "contracts": 143,
  "fix_applied": 123,
  "fix_compiles": 123,
  "vuln_eliminated": 88,
  "no_regression": 121,
  "fix_failed": 0,
  "scan_empty": 2,
  "scan_retries": 2,
  "no_high": 18,
  "external_checked": 123,
  "external_clean_high": 70,
  "external_findings": 53,
  "external_errors": 0
}
```

Metricas derivadas:

| Metrica | Resultado |
|---|---:|
| Fix application, current scan | 123/143 = 86.0% |
| Standalone compilation | 123/123 = 100.0% |
| Vulnerability eliminated by MIESC re-scan | 88/123 = 71.5% |
| Bounded no-regression criterion | 121/123 = 98.4% |
| External Slither clean-HIGH | 70/123 = 56.9% |
| External Slither validation errors | 0/123 = 0.0% |

## Interpretacion

La v-next mejora fuertemente dos puntos debiles del baseline anterior:

- la compilacion standalone de patches emitidos sube de 90/141 a 123/123;
- la no-regresion bounded sube de 91/141 a 121/123.

La comparacion no es directa porque la v-next declara el denominador filtrado por el
scan actual: 18 contratos ya no presentan HIGH/CRITICAL y 2 tienen scan vacio
antes de aplicar fixes. Por eso el paper v-next reporta `123/143` como cobertura de
fix application bajo el scan actual, y usa `123` como denominador para calidad
de patch.

La validacion externa Slither es mas estricta que el re-scan MIESC: 70/123
patched contracts quedan sin HIGH findings externos, mientras que 53 residual
HIGH findings permanecen. Esta metrica se reporta separada para no inflar la
claim de eliminacion. Los residuales se concentran en clases semanticas que
requieren invariantes de contrato o redisenio de protocolo, no en fallas de
compilacion standalone.

La no-regresion se mide por crecimiento del conteo de findings en re-scan,
permitiendo hasta dos findings informacionales adicionales causados por codigo
inline de guardas. Por lo tanto, esta metrica no prueba equivalencia funcional
completa; prueba que el fix no incrementa materialmente el perfil de hallazgos
de seguridad bajo el mismo pipeline.

## Relacion con Paper 1

Paper 2 usa Paper 1 solo como etapa de deteccion. La claim de deteccion que debe
heredar es:

- SmartBugs full-corpus reproducible profile: 95.8% recall, 22.2% precision,
  36.0% F1.
- EVMBench local high-severity extraction: ensemble 111/120 = 92.5% recall.

Paper 2 no recalcula recall, precision, F1, datasets, providers, capas ni
matrices de claims de deteccion. Sus nuevas evidencias aplican solo a etapas
posteriores a la deteccion: aplicacion de fixes, compilacion, re-scan,
validacion externa Slither, tests, verificacion, compliance y reporting.

## Regla editorial

Una claim numerica del Paper 2 v-next queda publicable solo si aparece en
`benchmarks/results/paper2_claims_matrix.json` o si deriva explicitamente de la
matriz de claims de Paper 1.

No reutilizar el baseline anterior `141/90/93/91` dentro del texto v-next salvo para
explicar la diferencia metodologica.
