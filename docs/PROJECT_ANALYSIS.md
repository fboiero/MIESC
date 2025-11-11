# MIESC - Análisis de Proyectos Multi-Contrato

## 🎯 Nuevas Funcionalidades

MIESC ahora soporta análisis de proyectos completos con múltiples contratos:

### Características

1. **📁 Entrada Flexible**
   - Archivos individuales: `contract.sol`
   - Carpetas locales: `contracts/`
   - Repositorios GitHub: `https://github.com/user/repo`

2. **🔗 Análisis de Dependencias**
   - Detecta imports entre contratos
   - Identifica herencia de contratos
   - Reconoce interfaces y libraries

3. **📊 Visualización**
   - Gráfico interactivo HTML (vis.js)
   - Diagrama Mermaid (para documentación)
   - Formato Graphviz DOT (para herramientas)
   - Árbol ASCII (para consola)

4. **🎯 Estrategias de Análisis**
   - **scan**: Analiza cada contrato individualmente
   - **unified**: Combina todos en uno y analiza
   - **both**: Ejecuta ambas estrategias

---

## 📖 Guía de Uso

### Instalación

No requiere dependencias adicionales. Las funcionalidades están incluidas en MIESC.

### Uso Básico

#### 1. Analizar Carpeta Local

```bash
# Escaneo individual (recomendado)
python main_project.py contracts/ myproject --strategy scan

# Con visualización
python main_project.py contracts/ myproject --visualize

# Con Ollama (análisis AI local)
python main_project.py contracts/ myproject --use-ollama
```

#### 2. Analizar Repositorio GitHub

```bash
# Clonar y analizar automáticamente
python main_project.py https://github.com/user/repo myproject --strategy scan

# Análisis rápido
python main_project.py https://github.com/user/repo myproject --quick

# Con visualización completa
python main_project.py https://github.com/user/repo myproject --visualize --use-ollama
```

#### 3. Análisis Unificado

```bash
# Combinar todos los contratos en uno
python main_project.py contracts/ myproject --strategy unified

# Útil para proyectos pequeños o análisis global
python main_project.py contracts/ myproject --strategy unified --use-ollama
```

#### 4. Ambas Estrategias

```bash
# Ejecutar análisis individual Y unificado
python main_project.py contracts/ myproject --strategy both --use-ollama
```

---

## 🎛️ Opciones Avanzadas

### Filtros de Análisis

```bash
# Solo contratos de alta prioridad
python main_project.py contracts/ myproject --priority-filter high

# Limitar cantidad de contratos
python main_project.py contracts/ myproject --max-contracts 5

# Combinar filtros
python main_project.py contracts/ myproject --priority-filter medium --max-contracts 10
```

### Opciones de Análisis

```bash
# Modelo específico de Ollama
python main_project.py contracts/ myproject --use-ollama --ollama-model deepseek-coder:33b

# Análisis rápido (codellama:7b)
python main_project.py contracts/ myproject --quick

# Solo Slither (sin AI)
python main_project.py contracts/ myproject --use-slither
```

---

## 📊 Interpretando los Resultados

### Estadísticas del Proyecto

Al ejecutar el análisis, verás:

```
📊 Project Statistics
┌────────────────────────┬────────┐
│ Total Contracts        │ 12     │
│ Total Lines of Code    │ 1,584  │
│ Total Functions        │ 149    │
│ ├─ Contracts           │ 12     │
│ ├─ Interfaces          │ 0      │
│ └─ Libraries           │ 0      │
│ Avg Lines per Contract │ 132.0  │
│ Pragma Versions        │ ^0.8.0 │
└────────────────────────┴────────┘
```

### Plan de Escaneo

El sistema genera un plan optimizado:

```
📋 Scan Plan
┏━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━┓
┃ #  ┃ Contract     ┃ Priority ┃ Lines ┃ Est. Time ┃
┡━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━┩
│ 1  │ Token        │ HIGH     │   250 │      80s  │
│ 2  │ Sale         │ HIGH     │   180 │      65s  │
│ 3  │ Utils        │ LOW      │    50 │      35s  │
└────┴──────────────┴──────────┴───────┴───────────┘
```

**Prioridades:**
- **HIGH**: Contratos grandes (>200 líneas) o con muchas funciones (>10)
- **MEDIUM**: Contratos medianos (100-200 líneas, 5-10 funciones)
- **LOW**: Contratos pequeños, interfaces, libraries

### Visualizaciones Generadas

En `output/<tag>/visualizations/`:

1. **dependency_graph.html** - Gráfico interactivo
   - Abre en navegador
   - Haz clic en nodos para ver detalles
   - Zoom y pan con mouse

2. **dependency_graph.mmd** - Diagrama Mermaid
   - Para incluir en README.md
   - Compatible con GitHub, GitLab

3. **dependency_graph.dot** - Formato Graphviz
   - Para herramientas como `dot`, `neato`
   - Genera PNG: `dot -Tpng dependency_graph.dot -o graph.png`

4. **dependency_tree.txt** - Árbol ASCII
   - Visualización rápida en consola
   - Muestra jerarquía de dependencias

---

## 🔍 Casos de Uso

### Caso 1: Auditoría de Proyecto Completo

**Situación:** Tienes un proyecto DeFi con 20+ contratos.

```bash
# Paso 1: Analizar estructura
python main_project.py contracts/ audit_v1 --visualize

# Paso 2: Revisar visualización
open output/audit_v1/visualizations/dependency_graph.html

# Paso 3: Análisis completo con prioridades
python main_project.py contracts/ audit_v1 \
  --strategy scan \
  --use-ollama \
  --priority-filter high
```

**Resultado:**
- Gráfico de dependencias para entender arquitectura
- Análisis individual de contratos críticos
- Reportes en `output/audit_v1/<contract>/`

### Caso 2: Análisis de Repositorio GitHub

**Situación:** Quieres analizar un proyecto open-source.

```bash
# Clonar y analizar directamente
python main_project.py https://github.com/OpenZeppelin/openzeppelin-contracts oz_audit \
  --visualize \
  --max-contracts 10 \
  --use-ollama

# Resultados automáticos
ls output/oz_audit/
# -> visualizations/
# -> ContractA/
# -> ContractB/
# ...
```

### Caso 3: Análisis Rápido Pre-Deploy

**Situación:** Necesitas verificación rápida antes de deployment.

```bash
# Análisis unificado rápido
python main_project.py contracts/ pre_deploy \
  --strategy unified \
  --quick \
  --use-ollama

# ~30 segundos de análisis
# Resultados en output/pre_deploy/unified/
```

### Caso 4: Comparación de Estrategias

**Situación:** Proyecto mediano, quieres análisis exhaustivo.

```bash
# Ejecutar ambas estrategias
python main_project.py contracts/ comparison \
  --strategy both \
  --use-ollama \
  --visualize

# Resultados:
# - output/comparison/scan/ContractA/
# - output/comparison/scan/ContractB/
# - output/comparison/unified/
# - output/comparison/visualizations/
```

---

## 📈 Ejemplo Completo

### Análisis de Proyecto DeFi

```bash
# 1. Estructura del proyecto
ls contracts/
# -> Token.sol
# -> Sale.sol
# -> Staking.sol
# -> interfaces/
#    -> IToken.sol
#    -> ISale.sol
# -> libraries/
#    -> SafeMath.sol

# 2. Análisis completo
python main_project.py contracts/ defi_audit \
  --strategy scan \
  --visualize \
  --use-ollama \
  --ollama-model codellama:13b

# 3. Salida esperada
Analyzing: contracts/
============================================================

📊 Project Statistics:
  Total Contracts: 6
  Total Lines: 890
  Total Functions: 52
  Contracts: 3, Interfaces: 2, Libraries: 1

📋 Scan Plan (6 contracts):
  1. Token - HIGH priority (75s)
  2. Sale - HIGH priority (68s)
  3. Staking - HIGH priority (70s)
  4. IToken - LOW priority (30s)
  5. ISale - LOW priority (30s)
  6. SafeMath - LOW priority (32s)

📊 Generating visualizations...
✓ Saved to output/defi_audit/visualizations/

🔍 Scanning 6 contracts...
  [1/6] Token... ✓ (72s)
  [2/6] Sale... ✓ (69s)
  [3/6] Staking... ✓ (71s)
  [4/6] IToken... ✓ (28s)
  [5/6] ISale... ✓ (29s)
  [6/6] SafeMath... ✓ (30s)

✅ Complete! 6/6 successful (299s total)
```

### Estructura de Resultados

```
output/defi_audit/
├── visualizations/
│   ├── dependency_graph.html   # ← Abre este en navegador
│   ├── dependency_graph.mmd
│   ├── dependency_graph.dot
│   └── dependency_tree.txt
├── Token/
│   ├── Ollama.txt
│   ├── Slither.txt
│   └── summary.txt
├── Sale/
│   ├── Ollama.txt
│   └── Slither.txt
└── Staking/
    ├── Ollama.txt
    └── Slither.txt
```

---

## 🎨 Visualización Interactiva

### Gráfico HTML

El gráfico interactivo (`dependency_graph.html`) muestra:

**Nodos:**
- 🟣 **Contratos** - Púrpura
- 🔵 **Interfaces** - Azul claro
- 🟠 **Libraries** - Naranja

**Conexiones:**
- **━━→** Imports (línea sólida)
- **╌╌→** Herencia (línea punteada)

**Interacción:**
- Click en nodo: Ver detalles (líneas, funciones)
- Zoom: Scroll del mouse
- Pan: Arrastrar con mouse
- Layout: Jerárquico automático (izq → der)

### Ejemplo de Visualización

```
Token ━━→ SafeMath
  ↑
  ╌╌  (inherits)
  │
Sale ━━→ IToken
  │
  ╌╌→ Token
  ↓
Staking
```

---

## ⚙️ Estrategias de Análisis

### 1. Estrategia "Scan" (Individual)

**Ventajas:**
- ✅ Análisis detallado de cada contrato
- ✅ Resultados separados por archivo
- ✅ Fácil identificar fuente de problemas
- ✅ Útil para proyectos grandes

**Cuándo usar:**
- Proyectos con >5 contratos
- Contratos independientes
- Necesitas rastrear problemas específicos

**Comando:**
```bash
python main_project.py contracts/ myproject --strategy scan
```

### 2. Estrategia "Unified" (Unificado)

**Ventajas:**
- ✅ Análisis global del proyecto
- ✅ Más rápido que scan individual
- ✅ Detecta interacciones entre contratos
- ✅ Un solo reporte consolidado

**Cuándo usar:**
- Proyectos pequeños (<5 contratos)
- Análisis rápido
- Vista global de seguridad

**Comando:**
```bash
python main_project.py contracts/ myproject --strategy unified
```

### 3. Estrategia "Both" (Ambas)

**Ventajas:**
- ✅ Lo mejor de ambos mundos
- ✅ Análisis exhaustivo
- ✅ Permite comparar resultados

**Cuándo usar:**
- Auditorías críticas
- Proyectos complejos
- Máxima cobertura

**Comando:**
```bash
python main_project.py contracts/ myproject --strategy both
```

---

## 🔧 Tips y Mejores Prácticas

### 1. Estructura de Proyecto Óptima

```
project/
├── contracts/
│   ├── Token.sol           # Contratos principales
│   ├── Sale.sol
│   ├── interfaces/         # Interfaces separadas
│   │   └── IToken.sol
│   └── libraries/          # Libraries separadas
│       └── SafeMath.sol
├── test/                   # Excluido automáticamente
└── node_modules/           # Excluido automáticamente
```

### 2. Orden de Análisis

El sistema analiza en orden de dependencias:
1. Libraries
2. Interfaces
3. Contratos base
4. Contratos derivados

Esto asegura que las dependencias se analizan primero.

### 3. Filtrar Eficientemente

```bash
# Solo contratos críticos (grandes y complejos)
python main_project.py contracts/ audit --priority-filter high

# Top 5 contratos más importantes
python main_project.py contracts/ audit --max-contracts 5

# Combinar para análisis enfocado
python main_project.py contracts/ audit \
  --priority-filter high \
  --max-contracts 3
```

### 4. Usar Modelos Apropiados

```bash
# Desarrollo diario: modelo rápido
python main_project.py contracts/ dev --quick

# Pre-deploy: modelo balanceado
python main_project.py contracts/ staging --use-ollama --ollama-model codellama:13b

# Auditoría: modelo potente
python main_project.py contracts/ audit --use-ollama --ollama-model deepseek-coder:33b
```

### 5. Visualización Primero

Siempre genera visualizaciones primero:

```bash
# Ver estructura antes de analizar
python main_project.py contracts/ explore --visualize --max-contracts 0

# Revisa dependency_graph.html
# Luego decide estrategia de análisis
```

---

## 🚀 Performance

### Tiempos Estimados

| Contratos | Líneas Tot. | Quick (7b) | Balanced (13b) | Quality (33b) |
|-----------|-------------|------------|----------------|---------------|
| 5         | 500         | ~2 min     | ~4 min         | ~8 min        |
| 10        | 1,000       | ~4 min     | ~7 min         | ~15 min       |
| 20        | 2,000       | ~8 min     | ~15 min        | ~30 min       |
| 50        | 5,000       | ~20 min    | ~35 min        | ~75 min       |

**Nota:** Tiempos aproximados en Apple Silicon M1/M2

### Optimización

```bash
# Más rápido: solo alta prioridad
python main_project.py contracts/ fast \
  --priority-filter high \
  --quick

# Balanceado: filtrar y modelo medio
python main_project.py contracts/ balanced \
  --max-contracts 10 \
  --use-ollama

# Calidad: sin límites, modelo potente
python main_project.py contracts/ quality \
  --strategy both \
  --ollama-model deepseek-coder:33b
```

---

## 🐛 Troubleshooting

### Problema: "Git clone failed"

**Causa:** URL de GitHub incorrecta o repo privado

**Solución:**
```bash
# Verificar URL
curl -I https://github.com/user/repo

# Si es privado, clonar manualmente
git clone https://github.com/user/repo temp_repo
python main_project.py temp_repo/ myproject
```

### Problema: "No .sol files found"

**Causa:** Directorio incorrecto o contratos en subdirectorio no estándar

**Solución:**
```bash
# Verificar estructura
find contracts/ -name "*.sol"

# Ajustar ruta
python main_project.py contracts/src/ myproject
```

### Problema: "Analysis timeout"

**Causa:** Contrato muy grande o modelo pesado

**Solución:**
```bash
# Usar modelo más rápido
python main_project.py contracts/ myproject --quick

# O aumentar timeout en main_project.py
# (editar timeout en subprocess.run)
```

---

## 📚 Recursos Adicionales

- **MIESC Docs**: `docs/OLLAMA_CREWAI_GUIDE.md`
- **Config Avanzada**: `config/model_optimization.yml`
- **Ejemplos**: `examples/specific_use_cases.py`

---

## ✅ Checklist de Uso

- [ ] Estructura de proyecto organizada
- [ ] Ollama instalado y modelo descargado
- [ ] Verificar con: `python src/project_analyzer.py contracts/`
- [ ] Generar visualización: `--visualize`
- [ ] Revisar gráfico HTML
- [ ] Elegir estrategia apropiada
- [ ] Ejecutar análisis completo
- [ ] Revisar resultados en `output/<tag>/`

---

¡Listo para analizar proyectos completos con MIESC! 🚀
