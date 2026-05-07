# Paper 2 Reproducibility

Fecha: 2026-05-07

Este documento fija los artefactos que respaldan los resultados cuantitativos
del Paper 2 sobre remediacion automatizada.

## Artefactos principales

| Artefacto | Proposito |
|---|---|
| `benchmarks/fix_eval.py` | Evalua `miesc scan` + `miesc fix` sobre SmartBugs-curated. |
| `benchmarks/results/fix_eval_results.json` | Fuente local para las metricas 141/143, 90/141, 93/141 y no-regresion. |
| `benchmarks/generate_paper2_artifacts.py` | Genera la matriz de claims del Paper 2. |
| `benchmarks/audit_paper2_experiment.py` | Genera controles de validez original-vs-patched, metricas conjuntas y sensibilidad de no-regresion. |
| `benchmarks/results/paper2_claims_matrix.json` | Matriz de claims cuantitativos y fuentes. |
| `benchmarks/results/paper2_patch_quality_by_transform.json` | Taxonomia derivada por clase de transformacion de patch. |
| `benchmarks/results/paper2_compile_failure_by_category.json` | Fallas de compilacion standalone derivadas por categoria. |
| `benchmarks/results/paper2_compile_failure_taxonomy.json` | Detalle por contrato con stderr de `solc` y taxonomia de fallas. |
| `benchmarks/results/paper2_experiment_audit.json` | Auditoria experimental: compilacion original, transiciones compile, metricas conjuntas y umbrales. |
| `docs/guides/RAG_SOURCE_POLICY.md` | Politica canonica de fuentes RAG usada para contexto, clasificacion y mitigacion; no introduce claims cuantitativos del Paper 2. |
| `tests/test_fix_command.py` | Tests unitarios e integracion del comando `miesc fix`. |
| `tests/test_spec_generator.py` | Tests de generacion CVL/Scribble/SMTChecker. |
| `tests/test_compliance_command.py` | Tests de mapeo de compliance. |

## Comandos

Generar matriz de claims:

```bash
python3 benchmarks/generate_paper2_artifacts.py
```

Resultado esperado:

```text
Paper 2 fix claims: 141/143 applied, 90/141 compiled, 93/141 eliminated
Wrote benchmarks/results/paper2_claims_matrix.json
Wrote benchmarks/results/paper2_patch_quality_by_transform.json
Wrote benchmarks/results/paper2_compile_failure_by_category.json
```

Reproducir la evaluacion completa de fixes:

```bash
python3 benchmarks/fix_eval.py
```

La evaluacion completa ejecuta `miesc scan`, `miesc fix`, compilacion
standalone con `solc` y re-scan por contrato. Requiere el dataset
SmartBugs-curated en una de estas rutas:

- `data/benchmarks/smartbugs-curated/dataset`
- `benchmarks/datasets/smartbugs-curated/dataset`

Para preservar stderr por contrato y la taxonomia de fallas:

```bash
python3 benchmarks/fix_eval.py --details-output benchmarks/results/paper2_compile_failure_taxonomy.json
```

Generar auditoria de validez del experimento:

```bash
python3 benchmarks/audit_paper2_experiment.py
```

## Resultados

Resumen local preservado:

```json
{
  "contracts": 143,
  "fix_applied": 141,
  "fix_compiles": 90,
  "vuln_eliminated": 93,
  "no_regression": 91,
  "fix_failed": 0
}
```

Metricas derivadas:

| Metrica | Resultado |
|---|---:|
| Fix application | 141/143 = 98.6% |
| Standalone compilation | 90/141 = 63.8% |
| Vulnerability elimination | 93/141 = 66.0% |
| No-regression criterion | 91/141 = 64.5% |

Artefactos derivados adicionales:

- `paper2_patch_quality_by_transform.json`: agrupa resultados por clase de
  transformacion. Esta agrupacion se deriva de la categoria SmartBugs y del
  comportamiento actual del patcher; no es un diff AST por finding.
- `paper2_compile_failure_by_category.json`: identifica que 51/141 patched
  artifacts fallan compilacion standalone y que unchecked low-level calls
  concentra 31 de esas 51 fallas.
- `paper2_compile_failure_taxonomy.json`: preserva stderr de `solc` por contrato
  y clasifica las 51 fallas en 42 `undefined_symbol` y 9
  `other_compile_error`.
- `paper2_experiment_audit.json`: compila los originales bajo el mismo criterio
  standalone y muestra que 141/141 originales compilan y 90/141 patched
  compilan. Tambien reporta metricas conjuntas: 42/141 compilan y eliminan el
  target finding; 30/141 compilan, eliminan y satisfacen no-regresion.

La no-regresion se mide por crecimiento del conteo de findings en re-scan,
permitiendo hasta dos findings informacionales adicionales causados por el
codigo inline de guardas. Por lo tanto, esta metrica no prueba equivalencia
funcional completa; prueba que el fix no incrementa materialmente el perfil de
hallazgos de seguridad bajo el mismo pipeline.

## Relacion con Paper 1

Paper 2 usa Paper 1 solo como etapa de deteccion. La claim de deteccion que debe
heredar es:

- SmartBugs full-corpus reproducible profile: 93.7% recall, 19.1% precision,
  31.7% F1.
- EVMBench local high-severity extraction: ensemble 111/120 = 92.5% recall.

No debe reutilizar claims historicas de 96.5% o 98.6% salvo que exista un nuevo
artefacto reproducible que las sostenga.

Las mejoras futuras de Paper 2 no deben requerir nueva evidencia de Paper 1. En
particular, no deben cambiar recall, precision, F1, datasets, providers, capas o
matrices de claims de deteccion. Paper 2 puede agregar evidencia nueva solo para
etapas posteriores a la deteccion: aplicacion de fixes, compilacion, tests,
verificacion independiente, compliance y reporting.

## Regla editorial

Una claim numerica del Paper 2 queda publicable solo si aparece en
`benchmarks/results/paper2_claims_matrix.json` o si deriva explicitamente de la
matriz de claims de Paper 1.
