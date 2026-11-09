# Paper 2 Improvement Plan

Fecha: 2026-05-07

## Diagnostico

El Paper 2 tiene una tesis valida: MIESC convierte findings de seguridad en
artefactos de remediacion revisables. La debilidad principal no es la idea, sino
la asimetria de evidencia:

- patching esta evaluado corpus-wide sobre 143 contratos;
- test generation, formal specs, compliance y reporting estan demostrados
  end-to-end sobre un contrato ilustrativo;
- la metrica de eliminacion depende de re-scan con la misma familia de pipeline;
- la compilacion standalone penaliza contratos con imports externos.

La mejora debe apuntar a cerrar esas brechas con artifacts reproducibles, no a
agregar claims.

## Regla De Compatibilidad Con Paper 1

Paper 1 queda congelado como evidencia de deteccion. Las mejoras de Paper 2 no
deben requerir reejecutar, reinterpretar ni cambiar:

- SmartBugs detection recall/precision/F1 de Paper 1;
- EVMBench local extraction y ensemble recall de Paper 1;
- matriz de claims, denominadores o configuracion de capas de Paper 1.

Paper 2 puede consumir esas claims como entrada, pero sus nuevos experimentos
deben medir solo etapas posteriores:

- patch application,
- standalone/dependency-aware compilation,
- generated tests,
- independent verification of patched artifacts,
- compliance/report artifacts.

Si una mejora requiere cambiar el scanner, capas, providers, prompt de
deteccion o dataset de Paper 1, queda fuera de alcance para esta iteracion y se
documenta como trabajo futuro de Paper 1, no como evidencia nueva de Paper 2.

## Prioridad 1: Evidence Matrix Mas Fuerte

Estado: completado en esta iteracion.

Objetivo: que cada claim importante tenga fuente local y que el paper no dependa
de texto narrativo.

Acciones:

1. Extender `benchmarks/results/paper2_claims_matrix.json` para incluir:
   - metric definitions,
   - denominator exacto de cada claim,
   - status: `corpus_wide`, `illustrative`, `derived`, `limitation`.
   - campo `paper1_dependency` solo para claims heredadas de deteccion.
2. Agregar claims negativas explicitas:
   - no semantic equivalence,
   - no corpus-wide formal proof,
   - no dependency-aware compilation yet.
3. Marcar las claims de deteccion como `inherited_from_paper1`, sin regenerar
   evidencia.
4. Hacer que el paper cite la matriz de claims en la seccion experimental.

Resultado esperado:

- Un revisor puede auditar rapidamente que no hay claims sueltas.

Artefacto generado:

- `benchmarks/results/paper2_claims_matrix.json`

## Prioridad 2: Corpus-Wide Test Generation Smoke

Objetivo: evitar que `test-gen` parezca solo demo.

Experimento minimo:

- Seleccionar un subconjunto estratificado desde contratos ya presentes en la
  evaluacion de fixes de Paper 2:
  - 10 reentrancy,
  - 10 access control/selfdestruct,
  - 10 unchecked low-level calls,
  - 10 arithmetic si aplica.
- Ejecutar `miesc test-gen` por finding fixable.
- Medir:
  - test file generated,
  - Foundry compile,
  - vulnerable-path confirmation when fixture supports execution,
  - patched-path blocked/pass.

Artifact propuesto:

- `benchmarks/results/paper2_testgen_eval.json`
- `benchmarks/generate_paper2_testgen_eval.py`

Uso en paper:

- Agregar una tabla corta: "Test Generation Smoke Evaluation".
- Mantener el E2E como ejemplo detallado.

Restriccion Paper 1:

- No correr un nuevo `miesc scan` para generar nuevas claims de deteccion.
- Usar los findings/fixes ya registrados por la evaluacion de Paper 2, o
  registrar claramente que el test smoke empieza despues de la etapa detection.

## Prioridad 3: Dependency-Aware Compilation Subset

Objetivo: transformar el 64% de compilacion de debilidad a resultado explicado.

Estado: completado para compilacion standalone. Se re-ejecuto la herramienta
completa con el patcher actual, se genero `fix_eval_results.json` nuevo y se
preservo stderr por contrato en `paper2_compile_failure_taxonomy.json`.

Experimento minimo:

- Tomar los 66 contratos que fallan standalone.
- Clasificar automaticamente o manualmente:
  - missing import,
  - Solidity version mismatch,
  - undefined symbol introduced by patch,
  - parser/formatting issue.
- Para un subconjunto con imports OpenZeppelin o npm/forge resolubles:
  - restaurar dependencias,
  - recompilar patched contract,
  - medir mejora contra standalone.

Artifact propuesto:

- `benchmarks/results/paper2_compile_failure_taxonomy.json`
- `benchmarks/results/paper2_dependency_aware_compile.json`

Artifact generado en esta iteracion:

- `benchmarks/results/paper2_compile_failure_by_category.json`
- `benchmarks/results/paper2_compile_failure_taxonomy.json`

Soporte implementado y usado en corrida reproducible:

- `benchmarks/fix_eval.py --skip-rescan --details-output <path>`

Uso en paper:

- Reemplazar porcentajes estimativos por datos:
  - standalone compile,
  - dependency-aware compile on resolvable subset,
  - unresolved legacy cases.

Restriccion Paper 1:

- No modifica recall/precision de deteccion. Solo reclasifica por que el
  artifact patched compila o no compila.

## Prioridad 4: Independent Verification Layer

Objetivo: reducir objecion de circularidad del re-scan.

Experimento minimo:

- Para patched contracts que compilan, correr una verificacion independiente:
  - Slither if available,
  - solc SMTChecker for applicable contracts,
  - Foundry tests where generated.
- Registrar si la evidencia de eliminacion viene de:
  - MIESC re-scan only,
  - independent static tool,
  - exploit test,
  - SMTChecker.

Artifact propuesto:

- `benchmarks/results/paper2_independent_verification.json`

Uso en paper:

- Cambiar "vulnerability eliminated" por categorias de confianza:
  - re-scan supported,
  - independently supported,
  - exploit-test supported,
  - formal supported.

Restriccion Paper 1:

- La verificacion independiente empieza desde patched artifacts ya generados.
  No se reporta como nuevo detection benchmark.

## Prioridad 5: Patch Quality Taxonomy

Objetivo: mostrar madurez de ingenieria y no solo numeros agregados.

Estado: completado como taxonomia derivada por categoria/transformacion. Queda
como mejora futura registrar per-finding diffs si se necesita mas granularidad.

Acciones:

- Clasificar fixes aplicados por tipo de transformacion:
  - modifier insertion,
  - guard injection,
  - require wrapper,
  - SafeMath insertion,
  - generic/manual remediation block.
- Medir por tipo:
  - applied,
  - compiled,
  - eliminated,
  - failed.

Artifact propuesto:

- `benchmarks/results/paper2_patch_quality_by_transform.json`

Artifact generado:

- `benchmarks/results/paper2_patch_quality_by_transform.json`

Uso en paper:

- Agregar una tabla o reemplazar parte de failure analysis.
- Esto permite explicar por que unchecked calls elimina mucho pero compila poco.

Restriccion Paper 1:

- La taxonomia clasifica transformaciones de remediacion, no findings de
  deteccion.

## Prioridad 6: Reproducible E2E Bundle

Objetivo: que el ejemplo ilustrativo sea ejecutable por jueces.

Acciones:

- Guardar contrato vulnerable, contrato patched, tests generados y outputs:
  - `paper/evidence/paper2_e2e/AuditTarget.sol`
  - `paper/evidence/paper2_e2e/AuditTarget.fixed.sol`
  - `paper/evidence/paper2_e2e/ReentrancyTest.t.sol`
  - `paper/evidence/paper2_e2e/compliance.json`
  - `paper/evidence/paper2_e2e/smtchecker_before_after.txt`
- Agregar `README.md` con comandos exactos.

Uso en paper:

- Citar el bundle en la seccion End-to-End.

## Prioridad 7: Paper Rewrite Despues De Experimentos

Cambios editoriales recomendados cuando existan artifacts:

1. Abstract:
   - Mantener tres resultados maximos.
   - Separar "corpus-wide" de "illustrative E2E".
2. Evaluation:
   - Dividir en:
     - corpus-wide patching,
     - test generation smoke,
     - independent verification subset,
     - E2E case study.
3. Threats:
   - Mover limitaciones reconocidas a claims medibles.
4. Conclusion:
   - Cerrar con "artifact-generating remediation pipeline", no "repair solver".

## Orden recomendado

1. Claims matrix extendida.
2. Patch quality taxonomy.
3. Failure taxonomy de compilacion.
4. E2E bundle reproducible.
5. Test generation smoke.
6. Independent verification subset.
7. Dependency-aware compilation.
8. Rewrite final del paper.

## Criterio De Terminado

Paper 2 queda fuerte si puede responder con artifacts a estas preguntas:

- Que contratos entraron y por que?
- Que significa exactamente cada metrica?
- Que parte es corpus-wide y que parte es caso ilustrativo?
- Cuantos fixes compilan con y sin dependencias?
- Cuantos fixes tienen evidencia independiente ademas del re-scan?
- Que categorias fallan y por que?
- Que claims son heredadas de Paper 1 y cuales son evidencia nueva de Paper 2?
