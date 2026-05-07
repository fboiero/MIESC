# Paper 2 Review And Presentation Plan

Fecha: 2026-05-07

## Tesis defendible

El Paper 2 tiene sentido si se presenta como un pipeline de artefactos de
remediacion: deteccion -> parche candidato -> test de exploit -> especificacion
formal -> evidencia de compliance. No debe presentarse como solucion completa de
program repair ni como prueba semantica de correccion.

La frase central para presentaciones:

> MIESC no intenta reemplazar al auditor; reduce el salto entre finding y
> evidencia accionable, dejando cada artefacto inspeccionable y reproducible.

## Puntos fuertes

- La contribucion no es solo el patcher. La fuerza esta en encadenar artefactos:
  patch, test, specs y compliance.
- La evaluacion corpus-wide de patching esta trazada a
  `benchmarks/results/fix_eval_results.json`.
- Las metricas principales son concretas: 125/143 fixes aplicados, 79/125
  compilan standalone, 105/125 reducen HIGH/CRITICAL en re-scan.
- La comparacion con trabajos previos queda bien si se enfoca en cobertura de
  artefactos, no en ganar todas las metricas numericas.

## Puntos flojos que un revisor atacaria

1. **Tests/specs/compliance no estan evaluados corpus-wide.**
   Respuesta: el paper mide patching a escala corpus y traza el pipeline completo
   sobre un contrato ilustrativo. No afirma prueba corpus-wide para todos los
   artefactos.

2. **Re-scan con la misma familia de herramientas puede inflar eliminacion.**
   Respuesta: correcto; por eso se reporta como metrica bounded, no como prueba
   semantica. Se complementa con tests de exploit y SMTChecker cuando es
   tractable.

3. **63% de compilacion es bajo.**
   Respuesta: es standalone compilation sin restaurar dependencias. El resultado
   mide una condicion estricta de reproducibilidad, no el escenario ideal de un
   repo con npm/forge instalado.

4. **Text-level patching puede romper casos raros.**
   Respuesta: aceptado como tradeoff. La ventaja es portabilidad sobre Solidity
   legacy; el future work es AST-level patching via Slither IR.

5. **No hay equivalencia funcional.**
   Respuesta: el paper no la reclama. La no-regresion es crecimiento acotado de
   findings bajo re-scan.

## Mejoras recomendadas antes de presentar

### Prioridad alta

- Preparar una slide con la distincion:
  - Corpus-wide: patching metrics.
  - Illustrative E2E: tests, specs, compliance, report.
- Mostrar una matriz de claims con fuente:
  - `fix_eval_results.json`
  - `paper2_claims_matrix.json`
  - Paper 1 claims matrix para deteccion.
- Incluir una slide de "What we do not claim":
  - no semantic equivalence,
  - no corpus-wide formal proof,
  - no dependency-aware compilation yet.

### Prioridad media

- Generar un anexo de evidencias E2E con capturas o snippets:
  - vulnerable exploit test passing,
  - patched regression test passing,
  - SMTChecker warnings before/after,
  - compliance output for MiCA/NIST/ISO.
- Preparar una tabla de failure modes con ejemplos concretos:
  - missing OpenZeppelin import,
  - Solidity legacy constructor syntax,
  - undefined owner/symbol.

### Prioridad experimental

- Re-ejecutar una evaluacion dependency-aware en un subconjunto:
  - restaurar dependencias npm/forge cuando el contrato las declare,
  - comparar standalone vs dependency-aware compilation,
  - agregar el resultado solo si queda trazado en JSON.
- Evaluar test generation sobre mas contratos:
  - al menos 10 por categoria soportada,
  - registrar compile/pass/fail en un artifact nuevo.
- Separar re-scan verification de independent verification:
  - Slither/MIESC re-scan,
  - Foundry test,
  - SMTChecker cuando aplica.

## Narrativa para charla

1. **Problema:** los scanners terminan en findings; el trabajo real empieza
   despues.
2. **Idea:** convertir cada finding en artefactos auditables.
3. **Pipeline:** scan, fix, test-gen, specs, compliance/report.
4. **Evidencia corpus:** patching sobre 143 contratos SmartBugs.
5. **Evidencia E2E:** contrato vulnerable con tests, specs y reporte.
6. **Comparacion:** no ganamos en compilacion frente a todos; ganamos en
   amplitud de artefactos.
7. **Limitaciones:** dependencia, semantic equivalence, cross-contract fixes.
8. **Cierre:** plataforma reproducible para iterar hacia remediation CI/CD.

## Preguntas dificiles y respuestas cortas

**P: El 84% de eliminacion no puede ser falso negativo del mismo scanner?**
R: Puede inflarse; por eso lo llamamos re-scan elimination y no semantic proof.
La herramienta produce evidencia adicional con tests y specs cuando aplica.

**P: Por que 63% de compilacion si otros reportan 91%?**
R: Nuestra metrica es standalone y no restaura dependencias. Es mas estricta y
peor para contratos mainnet con imports externos.

**P: Esto reemplaza una auditoria?**
R: No. Reduce trabajo repetitivo y produce artefactos revisables; el auditor
sigue validando semantica y contexto de negocio.

**P: Por que text-level patching?**
R: Portabilidad sobre Solidity legacy y corpus heterogeneo. El costo es menor
precision que un AST patcher.

