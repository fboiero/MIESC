# Justificación de Estadísticas y Guía de Demos

**Documento para Defensa de Tesis - 18 de Diciembre 2025**

---

## PARTE 1: JUSTIFICACIÓN DE ESTADÍSTICAS

### 1.1 Corpus de Validación

El corpus de validación fue diseñado siguiendo las recomendaciones de **Ghaleb & Pattabiraman (2020)** y **Durieux et al. (2020)**:

| Contrato | LOC | Vulnerabilidades | Categorías SWC | Fuente |
|----------|-----|------------------|----------------|--------|
| **VulnerableBank.sol** | 99 | 2 | SWC-107 (Reentrancy) | Diseño propio |
| **UnsafeToken.sol** | 142 | 10 | SWC-101, 104, 114, 116, 120, 128 | Diseño propio |
| **AccessControlFlawed.sol** | 121 | 7 | SWC-105, 106, 115 | Diseño propio |
| **FlashLoanVault.sol** | 252 | 10 | SWC-107, 104, 114 (lógica DeFi) | Diseño propio |
| **TOTAL** | **614 LOC** | **29 vulnerabilidades** | **9+ categorías SWC** | |

### 1.2 Vulnerabilidades Conocidas por Contrato

#### VulnerableBank.sol (Reentrancy - SWC-107)
```
Linea 35: (bool success, ) = msg.sender.call{value: balance}("");
         Llamada externa ANTES de actualizar estado (linea 39)

Vulnerabilidades documentadas (2):
1. Reentrancy en withdraw() - CRITICO
2. Reentrancy en withdrawAmount() - CRITICO
(Causa raiz comun: ausencia del patron checks-effects-interactions)
```

#### UnsafeToken.sol (Múltiples - SWC-101, 111, 131, 120)
```
Vulnerabilidades documentadas:
1. Missing zero address check (transfer) - SWC-111
2. Approve race condition - SWC-114
3. Unrestricted mint - SWC-105
4. Unrestricted burnFrom - SWC-105
5. Unsafe external call (transferWithCallback) - SWC-107
6. DoS with unbounded loop (batchTransfer) - SWC-128
7. Timestamp manipulation - SWC-116
8. Weak randomness - SWC-120
9. Missing return value check - SWC-104
10. Ether locked (no withdraw) - SWC-132
```

#### AccessControlFlawed.sol (Access Control - SWC-105, 115)
```
Vulnerabilidades documentadas:
1. setOwner sin control de acceso - SWC-105 CRITICO
2. tx.origin para autorizacion - SWC-115 CRITICO
3. addAdmin sin autorizacion - SWC-105
4. selfdestruct con control debil - SWC-106
5. togglePause sin autorizacion - SWC-105
6. Re-initialization posible - SWC-105
7. Front-running en transferOwnership - SWC-114
```

### 1.3 Cálculo de Métricas

**Nota metodológica.** Una herramienta *recall-first* como MIESC produce muchos hallazgos por contrato, por lo que se distinguen dos criterios de detección: **cobertura de línea** (existe algún hallazgo cerca del marcador) y **detección type-aware** (el hallazgo identifica el tipo/SWC correcto — el criterio significativo). Todos los números son reproducibles; ver `docs/evidence/corpus_revalidation_20260709/`.

#### Recall
```
Cobertura de recall  = 29 / 29 = 100%   (MIESC cubre todos los marcadores)
Recall type-aware    = 14 / 29 = 48%    (identifica el tipo correcto)
```
MIESC cubre la totalidad de las 29 vulnerabilidades documentadas, pero identifica correctamente el tipo en el 48% (configuración estático+patrón, capas 1/6/7).

#### Precisión
```
Precision = TP / (TP + FP) ~ 29 / 385 ~ 7.5%
```
La precisión baja refleja la inundación de hallazgos (385 sobre 614 LOC); sube a ~32% con filtrado de FP agresivo. Es el trade-off consciente del perfil *recall-first* de una herramienta de triage pre-auditoría.

#### Comparación con Slither (RQ2)
```
Slither sola:               cobertura 96%,  type-aware 58%,  62 hallazgos
MIESC estatico+patron:      cobertura 100%, type-aware 48%,  385 hallazgos
MIESC + capa LLM frontier:  cobertura 93%,  type-aware 72%
```
Combinar herramientas estáticas (MIESC 48%) **NO supera** a Slither sola (58%). La mejora real proviene de **agregar razonamiento LLM** (48% -> 72%). El "40.8%" original era un artefacto del corpus fantasma y queda descartado.

#### Deduplicación
```
Hallazgos brutos:  385
Hallazgos unicos (clustering por causa-raiz):  123
Tasa de deduplicacion = (385 - 123) / 385 * 100 = 68%
```

### 1.4 Tabla de Resultados por Contrato (type-aware)

| Contrato | Vulns | Cobertura | Type-correct | Hallazgos |
|----------|-------|-----------|--------------|-----------|
| VulnerableBank.sol | 2 | 2/2 | 2/2 | 47 |
| UnsafeToken.sol | 10 | 10/10 | 5/10 | 103 |
| AccessControlFlawed.sol | 7 | 7/7 | 3/7 | 82 |
| FlashLoanVault.sol | 10 | 10/10 | 4/10 | 153 |
| **AGREGADO** | **29** | **29/29 (100%)** | **14/29 (48%)** | **385** |

### 1.5 Comparativa con Herramientas Individuales

Medido sobre el corpus real (29 vulnerabilidades) con correlación type-aware:

| Configuración | Cobertura | Type-aware | Hallazgos | Precisión aprox. |
|---------------|-----------|------------|-----------|------------------|
| Slither (sola) | 28/29 (96%) | **17/29 (58%)** | 62 | ~27% |
| MIESC estático+patrón (capas 1/6/7) | 29/29 (100%) | 14/29 (48%) | 385 | ~7.5% |
| MIESC + capa LLM frontier (`--deep`) | 27/29 (93%) | **21/29 (72%)** | ~110 | ~27% |
| **Ensemble (unión de modelos)** | — | **25/29 (86%)** | unión | peor (une FPs) |

> **Complementariedad al nivel de modelos.** Combinar modelos LLM diversos en ensemble eleva la detección type-aware de 72% (mejor modelo individual) a **86%** (unión de detecciones), a costa de precisión (une los falsos positivos de todos). Solo 4 vulnerabilidades no las detecta ningún modelo. Es la palanca de mejora medida — el RAG no lo es. Ver §16 del expediente `docs/evidence/corpus_revalidation_20260709/`.

> **Nota de alcance.** Mythril/Echidna no se re-midieron aislados sobre este corpus (no disponibles en el entorno arm64 de reproducción); la comparativa de RQ2 se limita a Slither, la herramienta estática de referencia.

### 1.6 Por Que Estas Métricas Son Validas

1. **Ground Truth Explicito:** Cada vulnerabilidad fue plantada intencionalmente y documentada
2. **Metodología Estándar:** Siguiendo Durieux et al. (2020) - referencia académica aceptada
3. **Corpus Representativo:** Cubre 7+ categorías SWC diferentes
4. **Limitación Reconocida:** Corpus pequeño (4 contratos) - suficiente para proof-of-concept

### 1.7 Validación Extendida (Post-Tesis)

Después de la entrega, se realizó validación con SmartBugs benchmark:

| Dataset | Contratos | Precisión | Recall (cobertura / type-aware) | F1 |
|---------|-----------|-----------|--------------------------------|-----|
| Corpus Tesis | 4 (29 vulns) | ~7.5% | 100% / 48% (72% con LLM) | 0.13 |
| SmartBugs (completo) | 143 | 22.2% | 95.8% | 0.360 |

> **Nota de honestidad metodológica:** MIESC prioriza **recall (95.8%, 137/143)** sobre precisión (22.2%). La baja precisión refleja 481 falsos positivos: es el trade-off consciente de una herramienta de *triage pre-auditoría* (mismo criterio reportado en los papers). Este resultado fue **re-validado de forma independiente el 2026-07-09** en un entorno Docker pineado (imagen `miesc:5.4.1-solc`, modelo `qwen2.5-coder:14b`), obteniendo precisión 19.9% y recall 97.9% sobre n=143 — confirmando el perfil recall-first. Evidencia peritable completa (comando exacto, digests de imagen, hashes de artefactos, versiones de `solc`) en [`docs/evidence/smartbugs_revalidation_20260709/`](../evidence/smartbugs_revalidation_20260709/).

---

## PARTE 2: GUÍA DE DEMOS

### 2.1 Demos Disponibles

```
demo_thesis_defense.py       - Demo principal para la defensa (recomendado)
demo_miesc_v4_complete.py    - Demo completa de todas las funcionalidades
docs/evidence/demo_exporters.py  - Demo de exportadores (SARIF, SonarQube)
docs/evidence/demo_metrics.py    - Demo de metricas Prometheus
docs/evidence/demo_websocket.py  - Demo de WebSocket (post-tesis)
```

### 2.2 Demo Principal para la Defensa

#### Comando Básico
```bash
python demo_thesis_defense.py
```

#### Con Opciones
```bash
# Modo rapido (solo herramientas principales)
python demo_thesis_defense.py --quick

# Modo automatico (sin pausas interactivas)
python demo_thesis_defense.py --auto

# Contrato especifico
python demo_thesis_defense.py --contract contracts/audit/VulnerableBank.sol

# Modo silencioso
python demo_thesis_defense.py --quiet
```

#### Demo Recomendada para Defensa
```bash
python demo_thesis_defense.py --quick --auto
```

### 2.3 Que Muestra la Demo

1. **Banner MIESC** - Logo ASCII art
2. **Verificación de herramientas** - Muestra 25 herramientas disponibles
3. **Análisis del contrato** - Ejecuta las 7 capas
4. **Progress bars** - Visualización de progreso por capa
5. **Hallazgos detectados** - Lista de vulnerabilidades con severidad
6. **Correlación** - Deduplicación y mapeo SWC/CWE
7. **Resumen final** - Métricas y estadísticas

### 2.4 Secuencia de Demo Recomendada

#### Paso 1: Mostrar el Contrato (30 segundos)
```bash
cat contracts/audit/VulnerableBank.sol | head -50
```

**Decir:**
> "Observen la función withdraw en la línea 30. La llamada externa se hace en la línea 35, ANTES de actualizar el estado en la línea 39. Este es el patrón clásico de reentrancy."

#### Paso 2: Ejecutar MIESC (2-3 minutos)
```bash
python demo_thesis_defense.py --quick --auto
```

**Decir:**
> "MIESC ejecuta 7 capas de análisis en paralelo. Primero análisis estático con Slither, luego fuzzing, ejecución simbólica..."

**Pausar cuando aparezcan los hallazgos:**
> "Observen como cada capa detecta la vulnerabilidad. Slither la encuentra en Capa 1, Mythril la confirma en Capa 3."

#### Paso 3: Mostrar Correlación (30 segundos)
> "El sistema correlaciona 385 hallazgos brutos y los reduce a 123 únicos - un 68% de deduplicación. Cada hallazgo se mapea automáticamente a SWC-107, CWE-841, y OWASP SC Top 10."

#### Paso 4: Mostrar Resultado Final (30 segundos)
> "El reporte final identifica la vulnerabilidad como CRÍTICA, con múltiples herramientas confirmandola. Cobertura completa del ground truth, con el tipo correcto identificado (perfil recall-first)."

### 2.5 Alternativa: Demo sin Herramientas

Si las herramientas no están instaladas, usar modo simulado:

```bash
python demo_thesis_defense.py --simulate
```

Esto muestra el flujo completo con datos de ejemplo pregenerados.

### 2.6 Video de Backup

Si la demo en vivo falla, mostrar video pregrabado:

**Contenido del video (2-3 min):**
1. Terminal limpia
2. `cat contracts/audit/VulnerableBank.sol`
3. Resaltar la vulnerabilidad
4. `python demo_thesis_defense.py --quick --auto`
5. Esperar output de cada capa
6. Mostrar resumen final

**Como grabar:**
```bash
# Opcion 1: QuickTime (macOS)
# Archivo > Nueva grabacion de pantalla

# Opcion 2: asciinema (terminal)
asciinema rec demo_defensa.cast

# Opcion 3: OBS Studio
# Captura de ventana de terminal
```

### 2.7 Demo de MCP (Opcional - Avanzado)

Si preguntan sobre MCP, mostrar integración con Claude:

```bash
# Iniciar servidor MCP stdio
python -m miesc.mcp_server

# Para inspeccion HTTP local, iniciar REST API
python -m miesc.api.rest --host 127.0.0.1 --port 8000
curl http://localhost:8000/api/v1/tools/ | jq
```

### 2.8 Troubleshooting de Demo

#### Error: "Module not found"
```bash
pip install -e .
# o
export PYTHONPATH=$PWD:$PYTHONPATH
```

#### Error: "Slither not found"
```bash
pip install slither-analyzer
```

#### Error: "Ollama not running"
```bash
ollama serve &
ollama pull deepseek-coder
```

#### La demo es muy lenta
```bash
# Usar modo rapido sin IA
python demo_thesis_defense.py --quick --no-llm
```

---

## PARTE 3: RESPUESTAS A PREGUNTAS SOBRE ESTADÍSTICAS

### P: "El corpus de 4 contratos no es muy pequeño?"

**R:** Sí, es una limitación reconocida. Sin embargo:
1. Los 4 contratos contienen 29 vulnerabilidades documentadas (anotadas en el código fuente)
2. Cubren 9+ categorías SWC diferentes
3. El objetivo era validar la arquitectura, no hacer benchmark exhaustivo
4. La validación con SmartBugs (143 contratos) fue completada post-tesis: precisión 22.2%, recall 95.8% (re-validada el 2026-07-09, ver `docs/evidence/smartbugs_revalidation_20260709/`)

### P: "Que recall alcanza MIESC realmente en el corpus?"

**R:** Se distinguen dos criterios (una herramienta *recall-first* genera muchos hallazgos):
- **Cobertura:** MIESC cubre 29/29 (100%) — hay algún hallazgo cerca de cada vulnerabilidad.
- **Type-aware:** identifica el tipo correcto en 14/29 (48%) con capas estático+patrón, y 21/29 (72%) al agregar la capa LLM frontier.

El "100% recall" solo aplica al criterio laxo de cobertura; el número significativo y honesto es el type-aware (48-72%).

### P: "Por que la precisión es tan baja (~7.5%)?"

**R:** Es el trade-off consciente del perfil *recall-first*. MIESC genera 385 hallazgos sobre 614 LOC para no perder ninguna vulnerabilidad; muchos son falsos positivos que el auditor filtra. Con filtrado de FP agresivo la precisión sube a ~32%. Es una herramienta de triage pre-auditoría, no un detector de precisión quirúrgica.

### P: "El enfoque multicapa mejora sobre las herramientas individuales? (RQ2)"

**R:** Solo parcialmente, y la mejora **NO** viene de combinar tools estáticos:
- Slither sola: 58% type-aware (28/29 cobertura, 62 hallazgos).
- MIESC estático+patrón: 48% type-aware (385 hallazgos) — **no supera a Slither sola.**
- MIESC + LLM frontier: 72% type-aware — **la mejora real proviene de la capa de razonamiento LLM.**

El "40.8% de mejora" original era un artefacto del corpus fantasma y fue descartado tras la re-validación (ver `docs/evidence/corpus_revalidation_20260709/`, §13).

---

## PARTE 4: CONTRATOS VULNERABLES DETALLADOS

### VulnerableBank.sol - Reentrancy Clásico

**Ubicación:** `contracts/audit/VulnerableBank.sol`
**LOC:** 99
**Vulnerabilidad Principal:** SWC-107 (Reentrancy)

**Patrón vulnerable (líneas 30-42):**
```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance");

    // VULNERABILIDAD: Llamada externa ANTES de actualizar estado
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");

    // Estado se actualiza DESPUES - puede ser re-entrado!
    balances[msg.sender] = 0;
}
```

**Por que es detectado por múltiples herramientas:**
- **Slither (Capa 1):** Detector `reentrancy-eth` - patrón estático
- **Mythril (Capa 3):** Ejecución simbólica encuentra path explotable
- **Echidna (Capa 2):** Fuzzing viola invariante de balance
- **SmartLLM (Capa 7):** Reconoce patrón checks-effects-interactions violado

### UnsafeToken.sol - Múltiples Vulnerabilidades

**Ubicación:** `contracts/audit/UnsafeToken.sol`
**LOC:** 142
**Vulnerabilidades:** 10 documentadas

| # | Vulnerabilidad | SWC | Severidad |
|---|---------------|-----|-----------|
| 1 | Missing zero address check | SWC-111 | MEDIO |
| 2 | Approve race condition | SWC-114 | MEDIO |
| 3 | Unrestricted mint | SWC-105 | CRÍTICO |
| 4 | Unrestricted burnFrom | SWC-105 | CRÍTICO |
| 5 | Unsafe external call | SWC-107 | ALTO |
| 6 | DoS unbounded loop | SWC-128 | ALTO |
| 7 | Timestamp manipulation | SWC-116 | BAJO |
| 8 | Weak randomness | SWC-120 | ALTO |
| 9 | Missing return check | SWC-104 | MEDIO |
| 10 | Ether locked | SWC-132 | MEDIO |

### AccessControlFlawed.sol - Control de Acceso

**Ubicación:** `contracts/audit/AccessControlFlawed.sol`
**LOC:** 121
**Vulnerabilidades:** 7 documentadas

| # | Vulnerabilidad | SWC | Línea |
|---|---------------|-----|-------|
| 1 | setOwner sin auth | SWC-105 | 28 |
| 2 | tx.origin | SWC-115 | 37 |
| 3 | addAdmin sin auth | SWC-105 | 46 |
| 4 | selfdestruct débil | SWC-106 | 56 |
| 5 | togglePause sin auth | SWC-105 | 61 |
| 6 | Re-initialization | SWC-105 | 68 |
| 7 | Front-running | SWC-114 | 76 |

---

## Resumen

**Para la defensa, recordar:**

1. **Corpus:** 4 contratos, 29 vulnerabilidades, 9+ categorías SWC
2. **Cobertura 100% / type-aware 48%:** Contra ground truth conocido (14/29 con tipo correcto; 72% al agregar la capa LLM)
3. **Precisión ~7.5%:** Perfil recall-first (385 hallazgos; ~32% con filtrado agresivo)
4. **RQ2:** Combinar tools estáticos NO supera a Slither sola (48% vs 58%); la mejora proviene de la capa LLM
5. **SmartBugs:** precisión 22.2%, recall 95.8% (143 contratos)
6. **Deduplicación 68%:** De 385 hallazgos brutos a 123 únicos

**Demo recomendada:**
```bash
python demo_thesis_defense.py --quick --auto
```

---

*Documento de soporte para defensa de tesis - 18 de Diciembre 2025*
*MIESC v4.0.0 - Maestría en Ciberdefensa, UNDEF/IUA*
