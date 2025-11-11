# MIESC - Análisis Multi-Contrato: Resumen Ejecutivo

## 🎯 ¿Qué se agregó?

MIESC ahora puede analizar **proyectos completos** con múltiples contratos de forma inteligente, no solo archivos individuales.

---

## 🚀 Quick Start (3 pasos)

### 1. Analizar tu proyecto

```bash
# Carpeta local
python main_project.py contracts/ myproject --visualize --use-ollama

# Repositorio GitHub
python main_project.py https://github.com/user/repo myproject --visualize --use-ollama
```

### 2. Ver visualización

```bash
open output/myproject/visualizations/dependency_graph.html
```

### 3. Revisar resultados

```bash
ls output/myproject/
# -> ContractA/  ContractB/  ContractC/  visualizations/
```

---

## 📦 Módulos Creados

### 1. `src/project_analyzer.py`
**Función:** Analiza estructura de proyectos multi-contrato

**Características:**
- ✅ Detecta todos los archivos .sol en un directorio
- ✅ Clona repositorios GitHub automáticamente
- ✅ Extrae dependencias (imports, herencia)
- ✅ Calcula estadísticas del proyecto
- ✅ Genera plan de escaneo optimizado
- ✅ Crea contrato unificado si se requiere

**Uso independiente:**
```bash
python src/project_analyzer.py contracts/
python src/project_analyzer.py https://github.com/user/repo
```

### 2. `src/graph_visualizer.py`
**Función:** Genera visualizaciones de dependencias

**Formatos soportados:**
- **HTML Interactivo** (vis.js) - Para exploración visual
- **Mermaid** - Para documentación GitHub/GitLab
- **Graphviz DOT** - Para herramientas profesionales
- **ASCII Tree** - Para consola

**Uso independiente:**
```python
from src.project_analyzer import ProjectAnalyzer
from src.graph_visualizer import GraphVisualizer

with ProjectAnalyzer('contracts/') as analyzer:
    analysis = analyzer.analyze_project()
    viz = GraphVisualizer(analysis)
    viz.save_all_formats('output/viz/')
```

### 3. `main_project.py`
**Función:** Script principal de análisis de proyectos

**Flujo:**
1. Analiza estructura del proyecto
2. Genera visualizaciones
3. Ejecuta análisis (individual, unificado, o ambos)
4. Genera reportes consolidados

**Opciones clave:**
- `--strategy scan|unified|both`
- `--visualize`
- `--use-ollama`
- `--priority-filter high|medium|low`
- `--max-contracts N`

---

## 🎨 Visualizaciones

### Gráfico Interactivo HTML

![Example Graph](https://via.placeholder.com/800x400?text=Interactive+Dependency+Graph)

**Características:**
- Click en nodos para ver detalles
- Zoom/pan con mouse
- Layout jerárquico automático
- Código de colores:
  - 🟣 Contratos
  - 🔵 Interfaces
  - 🟠 Libraries

### Ejemplo de Salida ASCII

```
Contract Dependency Tree
============================================================

├── SafeMath [L] 45L 8F
│   ├── Token [C] 250L 15F
│   │   ├── Sale [C] 180L 12F
│   │   └── Staking [C] 200L 14F
├── IToken [I] 25L 6F
└── Ownable [C] 50L 4F
    └── Whitelist [C] 80L 6F
```

---

## 🔄 Estrategias de Análisis

### Opción A: Scan Individual

```bash
python main_project.py contracts/ myproject --strategy scan
```

**Qué hace:**
- Analiza cada contrato por separado
- Genera reporte individual para cada uno
- Respeta orden de dependencias

**Output:**
```
output/myproject/
├── Token/
│   ├── Ollama.txt
│   └── Slither.txt
├── Sale/
│   ├── Ollama.txt
│   └── Slither.txt
└── Staking/
    ├── Ollama.txt
    └── Slither.txt
```

**Ventajas:**
- ✅ Trazabilidad clara (sabes qué contrato tiene qué problema)
- ✅ Útil para proyectos grandes
- ✅ Fácil revisar cambios incrementales

**Cuándo usar:**
- Proyectos con >5 contratos
- Desarrollo continuo
- Auditorías detalladas

---

### Opción B: Análisis Unificado

```bash
python main_project.py contracts/ myproject --strategy unified
```

**Qué hace:**
- Combina todos los contratos en uno solo
- Analiza como unidad completa
- Genera un reporte consolidado

**Output:**
```
output/myproject/
├── unified_contract.sol  (todos los contratos combinados)
└── unified/
    ├── Ollama.txt
    └── Slither.txt
```

**Ventajas:**
- ✅ Más rápido (1 análisis vs N análisis)
- ✅ Detecta interacciones entre contratos
- ✅ Vista global del proyecto

**Cuándo usar:**
- Proyectos pequeños (<5 contratos)
- Análisis rápido pre-deploy
- Detección de problemas sistémicos

---

### Opción C: Ambas Estrategias

```bash
python main_project.py contracts/ myproject --strategy both
```

**Qué hace:**
- Ejecuta scan individual Y unificado
- Doble verificación completa

**Output:**
```
output/myproject/
├── scan/
│   ├── Token/
│   ├── Sale/
│   └── Staking/
├── unified/
│   └── unified_contract.sol
└── visualizations/
```

**Cuándo usar:**
- Auditorías críticas
- Análisis exhaustivo
- Proyectos complejos

---

## 📊 Plan de Escaneo Inteligente

El sistema genera un plan optimizado:

### Priorización Automática

**HIGH Priority:**
- Contratos grandes (>200 líneas)
- Muchas funciones (>10)
- Contratos principales (no libraries/interfaces)

**MEDIUM Priority:**
- Contratos medianos (100-200 líneas)
- Funciones moderadas (5-10)

**LOW Priority:**
- Contratos pequeños (<100 líneas)
- Interfaces
- Libraries

### Orden de Ejecución

```
1. Libraries/Interfaces primero
2. Contratos base
3. Contratos derivados (que heredan)
```

Esto asegura que las dependencias se analizan antes que los contratos que las usan.

### Estimación de Tiempos

El sistema calcula tiempo estimado por contrato:

```
Tiempo Base: 30s
+ (Líneas / 100) * 10s
+ (Funciones) * 2s
```

**Ejemplo:**
- Contrato de 250 líneas con 15 funciones:
  - 30 + (250/100)*10 + 15*2 = 30 + 25 + 30 = **85 segundos**

---

## 🎯 Casos de Uso Reales

### Caso 1: Auditoría de DeFi Protocol

**Situación:**
- 15 contratos
- Token, Staking, Farming, Governance
- Múltiples interdependencias

**Solución:**
```bash
# Paso 1: Visualizar arquitectura
python main_project.py contracts/ defi_audit --visualize

# Paso 2: Revisar gráfico
open output/defi_audit/visualizations/dependency_graph.html

# Paso 3: Análisis enfocado
python main_project.py contracts/ defi_audit \
  --strategy scan \
  --priority-filter high \
  --use-ollama
```

**Resultado:**
- Gráfico muestra que Token es el contrato central
- Sale, Staking, Farming todos dependen de Token
- Análisis detecta 8 problemas críticos
- Reporte detallado por contrato

---

### Caso 2: Fork de OpenZeppelin

**Situación:**
- Clonar y analizar contratos de OZ
- Ver estructura de dependencias
- Entender herencia

**Solución:**
```bash
python main_project.py \
  https://github.com/OpenZeppelin/openzeppelin-contracts \
  oz_analysis \
  --visualize \
  --max-contracts 10
```

**Resultado:**
- Clonación automática del repo
- Gráfico muestra herencia compleja
- Análisis de top 10 contratos más importantes
- ~5 minutos total

---

### Caso 3: Pre-Deploy Check

**Situación:**
- 3 contratos para deploy mañana
- Verificación rápida
- Un solo reporte

**Solución:**
```bash
python main_project.py contracts/ pre_deploy \
  --strategy unified \
  --quick
```

**Resultado:**
- Análisis en ~45 segundos
- Un reporte unificado
- Detecta 2 problemas menores
- Listo para deploy

---

## 💰 Costo y Tiempo

### Comparativa

| Proyecto | Contratos | Estrategia | Tiempo | Costo |
|----------|-----------|------------|--------|-------|
| Pequeño  | 3-5       | unified    | ~1min  | $0    |
| Mediano  | 6-10      | scan       | ~5min  | $0    |
| Grande   | 11-20     | scan       | ~15min | $0    |
| Enorme   | 20+       | both       | ~30min | $0    |

**Con GPT-4** (sin Ollama):
- Pequeño: ~$0.15
- Mediano: ~$0.50
- Grande: ~$1.50
- Enorme: ~$3.00+

**Con Ollama:**
- Todos: **$0** 🎉

---

## 📈 Métricas y Estadísticas

Al ejecutar análisis verás:

```
📊 Project Statistics
┌────────────────────────┬────────┐
│ Total Contracts        │ 12     │
│ Total Lines of Code    │ 1,584  │
│ Total Functions        │ 149    │
│ ├─ Contracts           │ 10     │
│ ├─ Interfaces          │ 1      │
│ └─ Libraries           │ 1      │
│ Avg Lines per Contract │ 132.0  │
│ Pragma Versions        │ ^0.8.0 │
└────────────────────────┴────────┘
```

**Interpretación:**
- **Complejidad**: Avg lines/contract y functions/contract
- **Arquitectura**: Ratio contracts/interfaces/libraries
- **Consistencia**: Pragma versions (ideal: 1 versión)

---

## 🔧 Comandos Útiles

### Exploración Rápida

```bash
# Ver estructura sin analizar
python src/project_analyzer.py contracts/

# Solo visualizar
python main_project.py contracts/ explore --visualize --max-contracts 0
```

### Análisis Focalizados

```bash
# Solo contratos críticos
python main_project.py contracts/ critical --priority-filter high

# Top 5 más importantes
python main_project.py contracts/ top5 --max-contracts 5

# Análisis exhaustivo
python main_project.py contracts/ full --strategy both --use-ollama
```

### Diferentes Modelos

```bash
# Rápido (7b)
python main_project.py contracts/ fast --quick

# Balanceado (13b) - recomendado
python main_project.py contracts/ balanced --use-ollama

# Calidad máxima (33b)
python main_project.py contracts/ quality \
  --use-ollama \
  --ollama-model deepseek-coder:33b
```

---

## 🎓 Tips para Mejores Resultados

### 1. Estructura de Proyecto Limpia

```
contracts/
├── core/          # Contratos principales
├── interfaces/    # Interfaces
├── libraries/     # Libraries
└── utils/         # Utilities
```

### 2. Usar Visualización Primero

Siempre genera el gráfico antes de analizar:
```bash
python main_project.py contracts/ explore --visualize
open output/explore/visualizations/dependency_graph.html
```

Esto te ayuda a:
- Entender la arquitectura
- Identificar contratos clave
- Planificar el análisis

### 3. Filtrar Inteligentemente

```bash
# Solo lo crítico
--priority-filter high

# Limitar cantidad
--max-contracts 10

# Combinar
--priority-filter medium --max-contracts 15
```

### 4. Estrategia por Tamaño

- **1-3 contratos**: `--strategy unified`
- **4-10 contratos**: `--strategy scan`
- **10+ contratos**: `--strategy scan --priority-filter high`
- **Crítico**: `--strategy both`

---

## 📚 Documentación Completa

- **Guía Detallada**: `docs/PROJECT_ANALYSIS.md`
- **Ollama Setup**: `docs/INSTALL_MACOS.md`
- **Ejemplos**: `examples/specific_use_cases.py`

---

## ✅ Resumen de Beneficios

### Antes (MIESC v1)
- ❌ Solo archivos individuales
- ❌ Análisis manual de dependencias
- ❌ Sin visualización de relaciones
- ❌ Múltiples comandos para proyectos

### Ahora (MIESC v2)
- ✅ Carpetas completas y GitHub
- ✅ Detección automática de dependencias
- ✅ Gráficos interactivos
- ✅ Un comando para todo el proyecto
- ✅ Plan de escaneo inteligente
- ✅ Análisis unificado o individual
- ✅ Priorización automática
- ✅ Estimación de tiempos
- ✅ $0 de costo con Ollama

---

## 🚀 Próximos Pasos

1. **Probar con tus contratos:**
   ```bash
   python main_project.py contracts/ test --visualize --use-ollama
   ```

2. **Revisar visualización:**
   ```bash
   open output/test/visualizations/dependency_graph.html
   ```

3. **Análisis completo:**
   ```bash
   python main_project.py contracts/ full --strategy scan --use-ollama
   ```

4. **Explorar resultados:**
   ```bash
   ls -R output/full/
   ```

---

¡MIESC ahora es una herramienta profesional para análisis de proyectos completos! 🎉
