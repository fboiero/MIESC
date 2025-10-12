# ROADMAP: INTEGRACIÓN DE NUEVAS HERRAMIENTAS AL FRAMEWORK XAUDIT

**Universidad de la Defensa Nacional (UNDEF)**
**Centro Regional Universitario Córdoba - IUA**
**Maestría en Ciberdefensa**
**Autor:** Fernando Boiero
**Fecha:** 2025-01-11

---

## 🎯 OBJETIVO

Expandir el framework Xaudit integrando herramientas adicionales de análisis para:
1. Ampliar cobertura de detección de vulnerabilidades
2. Fortalecer la tesis con más técnicas de análisis
3. Mejorar visualización y reporting
4. Incrementar el valor científico y práctico del framework

---

## 📊 ESTADO ACTUAL

### Herramientas Ya Implementadas
- ✅ **Slither** - Análisis estático (90+ detectores)
- ✅ **Echidna** - Property-based fuzzing
- ✅ **Medusa** - Coverage-guided fuzzing
- ✅ **Foundry** - Testing framework
- ✅ **Scribble** - Runtime verification
- ✅ **Certora** - Verificación formal
- ✅ **GPT-4o-mini/Llama** - IA para clasificación
- ⚠️ **Mythril** - Implementado pero no integrado al pipeline

---

## 🚀 HERRAMIENTAS A INTEGRAR

### 1. ANÁLISIS SIMBÓLICO Y EJECUCIÓN SIMBÓLICA

#### A) Mythril (Ya tenemos código base)
- **Tipo:** Análisis simbólico con SMT solving
- **Fortalezas:** Detecta reentrancy, integer overflow, delegatecall inseguro
- **Integración:**
  - Crear `/analysis/mythril/` con configs
  - Agregar a `thesis_demo.sh` como Fase 8
  - Comparativa con Slither en Capítulo 7

**Implementación:**
```bash
analysis/mythril/
├── configs/
│   └── mythril.json
├── run_mythril.sh
└── results/
```

#### B) Manticore (NUEVO)
- **Tipo:** Ejecución simbólica dinámica
- **Fortalezas:** Exploración exhaustiva de paths, generación de inputs
- **Diferenciador:** Más profundo que Mythril, genera exploits reales

**Implementación:**
```python
# src/manticore_tool.py
def run_manticore(contract_path, max_depth=128):
    """Symbolic execution con Manticore"""
    pass
```

**Script:**
```bash
analysis/manticore/
├── configs/
│   └── manticore_config.yaml
├── run_manticore.sh
└── results/
```

---

### 2. VISUALIZACIÓN Y MÉTRICAS

#### A) Surya (NUEVO - Alta prioridad)
- **Tipo:** Visualización de contratos + métricas de complejidad
- **Outputs:**
  - Call graphs (visualización de funciones)
  - Inheritance trees
  - Métricas de complejidad ciclomática
  - Análisis de dependencias

**Implementación:**
```bash
analysis/surya/
├── run_surya.sh
└── outputs/
    ├── call_graph.dot
    ├── inheritance.png
    └── metrics.json
```

**Beneficio para tesis:** Agregar figuras visuales en Capítulo 3 y 6

#### B) Solidity Metrics (NUEVO)
- **Tipo:** Métricas de código (LOC, complejidad, cobertura)
- **Integración:** Script simple con Python

---

### 3. FUZZING AVANZADO

#### A) Foundry Invariant Testing (Expandir uso actual)
- Ya tienes Foundry, pero agregar:
  - Tests de invariantes específicos
  - Fuzzing basado en propiedades complejas
  - Integración con Medusa para comparativa

**Script mejorado:**
```bash
analysis/foundry/
├── invariants/
│   ├── InvariantBalances.t.sol
│   ├── InvariantAccess.t.sol
│   └── InvariantState.t.sol
└── run_invariants.sh
```

#### B) Echidna con Properties Avanzadas
- Expandir propiedades en `/analysis/echidna/`
- Comparativa detallada: Echidna vs Medusa vs Foundry

---

### 4. ANÁLISIS ADICIONALES

#### A) Solhint (NUEVO - Fácil de integrar)
- **Tipo:** Linter con reglas de seguridad
- **Complementa:** Slither con best practices
- **Integración:** 5 minutos

```bash
solhint 'src/contracts/**/*.sol' --config analysis/solhint/.solhintrc
```

#### B) Ethlint (Solium) - Opcional
- Similar a Solhint, considerar si aporta valor diferencial

---

## 📈 PLAN DE INTEGRACIÓN POR FASES

### FASE 1: Quick Wins (1-2 días)
1. ✅ Integrar Mythril al pipeline
2. ✅ Agregar Surya para visualización
3. ✅ Incluir Solhint como linter
4. ✅ Actualizar `thesis_demo.sh`

### FASE 2: Análisis Simbólico (2-3 días)
1. ✅ Implementar Manticore tool
2. ✅ Crear scripts de análisis comparativo
3. ✅ Experimento 7: Mythril vs Manticore vs Slither
4. ✅ Documentar resultados

### FASE 3: Fuzzing Avanzado (2-3 días)
1. ✅ Expandir Foundry invariants
2. ✅ Comparativa exhaustiva: Echidna/Medusa/Foundry
3. ✅ Experimento 8: Invariant testing comparison
4. ✅ Análisis de cobertura combinada

### FASE 4: Documentación y Tesis (3-4 días)
1. ✅ Actualizar Capítulo 4 (Estado del Arte)
   - Sección 4.6: Mythril (análisis simbólico)
   - Sección 4.7: Manticore (ejecución simbólica)
   - Sección 4.8: Surya (visualización)
   - Sección 4.9: Comparativa completa de todas las herramientas

2. ✅ Expandir Capítulo 6 (Implementación)
   - 6.7: Integración de análisis simbólico
   - 6.8: Pipeline completo (10 fases)

3. ✅ Agregar experimentos en Capítulo 7
   - 7.7: Experimento 7 - Análisis simbólico
   - 7.8: Experimento 8 - Invariant testing
   - 7.9: Análisis comparativo completo

4. ✅ Actualizar Capítulo 8 (Conclusiones)
   - Impacto de las nuevas herramientas
   - Cobertura total alcanzada

---

## 🏗️ ARQUITECTURA ACTUALIZADA

### Pipeline Xaudit v2.0 (10 Fases)

```
┌─────────────────────────────────────────────────────────────┐
│                    XAUDIT PIPELINE v2.0                     │
└─────────────────────────────────────────────────────────────┘

FASE 1: Análisis Estático Básico
  ├─ Slither (90+ detectores)
  └─ Solhint (linting + best practices)

FASE 2: Visualización y Métricas
  ├─ Surya (call graphs, inheritance)
  └─ Solidity Metrics (complejidad)

FASE 3: Análisis Simbólico
  ├─ Mythril (SMT solving, path exploration)
  └─ Manticore (ejecución simbólica dinámica)

FASE 4: Anotación de Propiedades
  └─ Scribble (pre/post conditions)

FASE 5: Property-Based Fuzzing
  └─ Echidna (Haskell-based fuzzer)

FASE 6: Coverage-Guided Fuzzing
  └─ Medusa (Go-based, paralelo)

FASE 7: Invariant Testing
  └─ Foundry (Rust-based, invariants)

FASE 8: Verificación Formal
  └─ Certora (CVL specs)

FASE 9: IA Triage y Clasificación
  ├─ GPT-4o-mini (clasificación contextual)
  └─ Llama 3.2 (opción local)

FASE 10: Reporting
  ├─ Consolidación de findings
  ├─ Eliminación de duplicados
  ├─ Priorización por severidad
  └─ Generación de reportes (HTML/PDF/JSON)
```

---

## 📊 EXPERIMENTOS ADICIONALES

### Experimento 7: Análisis Simbólico Comparativo
**Objetivo:** Comparar efectividad de Slither vs Mythril vs Manticore

**Métricas:**
- Vulnerabilidades detectadas (TP/FP/FN/TN)
- Tiempo de ejecución
- False positive rate
- Tipos de vulnerabilidades por herramienta

**Dataset:** 30 contratos vulnerables + 20 reales

**Hipótesis:**
- Mythril detecta más integer overflows que Slither
- Manticore genera exploits ejecutables
- Combinación de los 3 maximiza detección

---

### Experimento 8: Invariant Testing Showdown
**Objetivo:** Comparar Echidna vs Medusa vs Foundry en invariant testing

**Métricas:**
- Invariantes violados
- Tiempo hasta encontrar contraejemplo
- Calidad del shrinking
- Code coverage alcanzado

**Dataset:** 20 contratos con invariantes complejos

**Hipótesis:**
- Foundry tiene mejor integración con código existente
- Medusa es más rápido en coverage
- Echidna mejor en property-based testing puro

---

## 📁 ESTRUCTURA DE DIRECTORIOS ACTUALIZADA

```
xaudit/
├── analysis/
│   ├── slither/
│   ├── solhint/              # NUEVO
│   ├── surya/                # NUEVO
│   ├── mythril/              # ACTUALIZAR
│   ├── manticore/            # NUEVO
│   ├── echidna/
│   ├── medusa/
│   ├── foundry/
│   │   └── invariants/       # EXPANDIR
│   ├── scribble/
│   ├── certora/
│   └── scripts/
│       ├── run_all.sh
│       ├── run_symbolic.sh   # NUEVO
│       └── run_fuzzers.sh    # NUEVO
├── src/
│   ├── slither_tool.py
│   ├── mythril_tool.py       # ACTUALIZAR
│   ├── manticore_tool.py     # NUEVO
│   ├── surya_tool.py         # NUEVO
│   └── utils/
│       └── metrics_collector.py  # NUEVO
├── thesis/
│   ├── es/
│   │   ├── capitulo4_estado_arte.md      # EXPANDIR
│   │   ├── capitulo6_implementacion.md   # EXPANDIR
│   │   └── capitulo7_resultados.md       # EXPANDIR
│   └── en/
└── experiments/              # NUEVO
    ├── exp7_symbolic/
    └── exp8_invariants/
```

---

## 🎯 MÉTRICAS DE ÉXITO

### Objetivo: Incrementar detección y reducir FP

**Baseline (actual):**
- Vulnerabilidades detectadas: 78/80 (97.5%)
- False positives: 24 (-80.6% vs Slither solo)
- Tiempo: <2 horas

**Meta con nuevas herramientas:**
- Vulnerabilidades detectadas: 80/80 (100%) ✅
- False positives: <15 (-90% vs Slither solo)
- Cobertura de tipos: 100% SWC críticos
- Tiempo: <3 horas (acceptable con más análisis)

---

## 📝 TAREAS INMEDIATAS

### Día 1-2: Setup básico
- [ ] Crear directorios para nuevas herramientas
- [ ] Instalar Mythril, Manticore, Surya, Solhint
- [ ] Crear scripts base de integración
- [ ] Probar en 1 contrato vulnerable

### Día 3-4: Implementación
- [ ] Desarrollar `manticore_tool.py`
- [ ] Desarrollar `surya_tool.py`
- [ ] Crear `run_symbolic.sh` pipeline
- [ ] Integrar al `thesis_demo.sh`

### Día 5-6: Experimentación
- [ ] Ejecutar Experimento 7 (análisis simbólico)
- [ ] Ejecutar Experimento 8 (invariants)
- [ ] Recolectar métricas y resultados

### Día 7-10: Documentación
- [ ] Actualizar Capítulo 4 con nuevas herramientas
- [ ] Agregar Experimentos 7 y 8 al Capítulo 7
- [ ] Actualizar conclusiones en Capítulo 8
- [ ] Revisar abstract y resumen ejecutivo

---

## 💡 CONTRIBUCIONES ADICIONALES A LA TESIS

### Científicas
1. **Primera comparativa exhaustiva** de 10 herramientas en un solo framework
2. **Benchmark público** con 50+ contratos evaluados
3. **Métricas estandarizadas** para comparar herramientas

### Prácticas
1. **Pipeline completo automatizado** listo para producción
2. **Reducción de costos** aún mayor (-99.9%)
3. **Democratización** del acceso a múltiples herramientas

### Educativas
1. **Tutorial completo** de cada herramienta
2. **Guía de selección** según tipo de vulnerabilidad
3. **Casos de uso** documentados

---

## 🔗 REFERENCIAS A AGREGAR

1. **Mythril:** https://github.com/ConsenSys/mythril
2. **Manticore:** https://github.com/trailofbits/manticore
3. **Surya:** https://github.com/ConsenSys/surya
4. **Solhint:** https://github.com/protofire/solhint
5. **Trail of Bits Blog:** Building Secure Contracts

---

## ✅ CHECKLIST DE COMPLETITUD

### Código
- [ ] `manticore_tool.py` implementado
- [ ] `surya_tool.py` implementado
- [ ] Scripts de análisis simbólico
- [ ] Foundry invariants expandidos
- [ ] Pipeline actualizado en `thesis_demo.sh`

### Experimentación
- [ ] Experimento 7 ejecutado
- [ ] Experimento 8 ejecutado
- [ ] Datos recolectados y analizados
- [ ] Gráficos y tablas generados

### Documentación
- [ ] Capítulo 4 expandido (4.6-4.9)
- [ ] Capítulo 6 actualizado (6.7-6.8)
- [ ] Capítulo 7 con experimentos 7-8
- [ ] Capítulo 8 conclusiones actualizadas
- [ ] README actualizado
- [ ] Abstract actualizado

### Defensa
- [ ] `thesis_demo.sh` muestra nuevas herramientas
- [ ] Slides actualizados (si aplica)
- [ ] Talking points preparados

---

**Estado:** 📋 Planificado
**Próximo paso:** Empezar con Fase 1 (Quick Wins)

---

**Fernando Boiero**
**UNDEF - IUA Córdoba**
**Maestría en Ciberdefensa**
**2025**
