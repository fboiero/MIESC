# MIESC - Referencia Rápida Multi-Contrato

## 🚀 Comandos Más Usados

### Análisis Básico
```bash
# Carpeta local con visualización
python main_project.py contracts/ output --visualize --use-ollama

# GitHub repo
python main_project.py https://github.com/user/repo output --use-ollama

# Análisis rápido
python main_project.py contracts/ output --quick
```

### Análisis Avanzado
```bash
# Solo contratos críticos
python main_project.py contracts/ output --priority-filter high --use-ollama

# Top 10 más importantes
python main_project.py contracts/ output --max-contracts 10 --use-ollama

# Análisis exhaustivo (ambas estrategias)
python main_project.py contracts/ output --strategy both --visualize --use-ollama
```

### Solo Exploración
```bash
# Ver estructura sin analizar
python src/project_analyzer.py contracts/

# Solo generar visualización
python main_project.py contracts/ output --visualize --max-contracts 0
```

---

## 📋 Opciones del Comando

| Opción | Descripción | Ejemplo |
|--------|-------------|---------|
| `--strategy` | scan \| unified \| both | `--strategy scan` |
| `--visualize` | Generar gráficos | `--visualize` |
| `--use-ollama` | Usar Ollama AI | `--use-ollama` |
| `--ollama-model` | Modelo específico | `--ollama-model codellama:7b` |
| `--quick` | Modo rápido (7b) | `--quick` |
| `--priority-filter` | high \| medium \| low | `--priority-filter high` |
| `--max-contracts` | Límite de contratos | `--max-contracts 10` |

---

## 🎯 Estrategias de Análisis

### Scan (Individual)
```bash
python main_project.py contracts/ output --strategy scan
```
**✅ Usa cuando:**
- Proyecto con >5 contratos
- Necesitas identificar problemas específicos
- Quieres reportes separados

**📁 Output:**
```
output/
├── Token/
│   ├── Ollama.txt
│   └── Slither.txt
├── Sale/
└── Staking/
```

### Unified (Unificado)
```bash
python main_project.py contracts/ output --strategy unified
```
**✅ Usa cuando:**
- Proyecto pequeño (<5 contratos)
- Quieres análisis rápido
- Necesitas vista global

**📁 Output:**
```
output/
├── unified_contract.sol
└── unified/
    ├── Ollama.txt
    └── Slither.txt
```

### Both (Ambas)
```bash
python main_project.py contracts/ output --strategy both
```
**✅ Usa cuando:**
- Auditoría crítica
- Proyecto complejo
- Máxima cobertura

**📁 Output:**
```
output/
├── scan/
│   ├── Token/
│   ├── Sale/
│   └── Staking/
└── unified/
    └── unified_contract.sol
```

---

## 📊 Visualizaciones

### Archivos Generados

Con `--visualize`:
```
output/<tag>/visualizations/
├── dependency_graph.html  ⭐ Abre este primero
├── dependency_graph.mmd   📝 Para README.md
├── dependency_graph.dot   🖼️  Para Graphviz
└── dependency_tree.txt    🌳 Para consola
```

### Ver Visualización
```bash
# macOS
open output/myproject/visualizations/dependency_graph.html

# Linux
xdg-open output/myproject/visualizations/dependency_graph.html

# Windows
start output/myproject/visualizations/dependency_graph.html
```

### Usar Mermaid en GitHub

Copia el contenido de `dependency_graph.mmd` a tu README.md:

\`\`\`mermaid
graph TD
  Token[Token\\n250 lines, 15 fn]:::contract
  Sale[Sale\\n180 lines, 12 fn]:::contract
  Token -.->|inherits| ERC20
  Sale -->|imports| Token
\`\`\`

---

## 🔍 Filtros y Límites

### Por Prioridad
```bash
# Solo críticos
--priority-filter high

# Medianos y críticos
--priority-filter medium

# Todos (default)
# sin flag
```

### Por Cantidad
```bash
# Top 5
--max-contracts 5

# Top 10
--max-contracts 10

# Todos (default)
# sin flag
```

### Combinado
```bash
# Top 3 críticos
python main_project.py contracts/ output \
  --priority-filter high \
  --max-contracts 3 \
  --use-ollama
```

---

## 🤖 Modelos de Ollama

### Rápido (Desarrollo Diario)
```bash
--quick
# o
--ollama-model codellama:7b
```
- ⚡ ~30s por contrato
- 💰 $0
- ✅ Calidad: Buena

### Balanceado (Recomendado)
```bash
--ollama-model codellama:13b
```
- ⚡ ~60s por contrato
- 💰 $0
- ✅ Calidad: Muy buena

### Máxima Calidad (Auditorías)
```bash
--ollama-model deepseek-coder:33b
```
- ⚡ ~120s por contrato
- 💰 $0
- ✅ Calidad: Excelente

**Descargar modelos:**
```bash
ollama pull codellama:7b
ollama pull codellama:13b
ollama pull deepseek-coder:33b
```

---

## 📖 Casos de Uso Comunes

### Caso 1: Primera Vez con un Proyecto

```bash
# 1. Ver estructura
python src/project_analyzer.py contracts/

# 2. Generar visualización
python main_project.py contracts/ explore --visualize --max-contracts 0

# 3. Abrir gráfico
open output/explore/visualizations/dependency_graph.html

# 4. Análisis completo
python main_project.py contracts/ full --strategy scan --use-ollama
```

### Caso 2: Análisis Pre-Deploy

```bash
# Rápido y efectivo
python main_project.py contracts/ pre_deploy \
  --strategy unified \
  --quick
```

### Caso 3: Auditoría Completa

```bash
# Exhaustivo
python main_project.py contracts/ audit \
  --strategy both \
  --visualize \
  --use-ollama \
  --ollama-model deepseek-coder:33b
```

### Caso 4: Análisis de GitHub

```bash
# Clonar y analizar
python main_project.py \
  https://github.com/OpenZeppelin/openzeppelin-contracts \
  oz_analysis \
  --visualize \
  --max-contracts 10 \
  --priority-filter high \
  --use-ollama
```

### Caso 5: Solo Contratos Críticos

```bash
# Enfoque en lo importante
python main_project.py contracts/ critical \
  --priority-filter high \
  --use-ollama \
  --ollama-model codellama:13b
```

---

## 🐛 Solución Rápida de Problemas

### Problema: "Git clone failed"
```bash
# Clonar manualmente primero
git clone https://github.com/user/repo temp
python main_project.py temp/ output --use-ollama
```

### Problema: "No .sol files found"
```bash
# Verificar ubicación
find . -name "*.sol"

# Usar ruta correcta
python main_project.py ./src/ output --use-ollama
```

### Problema: "Ollama not found"
```bash
# Verificar Ollama
ollama --version

# Agregar a PATH
export PATH="/usr/local/bin:$PATH"

# O abrir Ollama app
open -a Ollama
```

### Problema: "Model not found"
```bash
# Descargar modelo
ollama pull codellama:13b

# Verificar modelos instalados
ollama list
```

### Problema: "Out of memory"
```bash
# Usar modelo más pequeño
python main_project.py contracts/ output --quick

# O reducir cantidad
python main_project.py contracts/ output --max-contracts 5
```

---

## 📈 Tiempos Estimados

| Contratos | Quick (7b) | Balanced (13b) | Quality (33b) |
|-----------|------------|----------------|---------------|
| 1-3       | ~2 min     | ~4 min         | ~8 min        |
| 4-10      | ~5 min     | ~10 min        | ~20 min       |
| 11-20     | ~10 min    | ~20 min        | ~40 min       |
| 20+       | ~15+ min   | ~30+ min       | ~60+ min      |

*Tiempos aproximados en Apple Silicon M1/M2*

---

## 🎯 Recomendaciones por Escenario

### Desarrollo Diario
```bash
python main_project.py contracts/ dev \
  --strategy unified \
  --quick
```
⚡ Rápido | ✅ Suficiente | 💰 $0

### Pre-Commit / CI/CD
```bash
python main_project.py contracts/ ci \
  --strategy unified \
  --use-ollama \
  --ollama-model codellama:7b \
  --max-contracts 5
```
⚡ Rápido | ✅ Bueno | 💰 $0

### Pre-Deploy Review
```bash
python main_project.py contracts/ staging \
  --strategy scan \
  --use-ollama \
  --ollama-model codellama:13b \
  --priority-filter high
```
⚡ Medio | ✅ Muy Bueno | 💰 $0

### Auditoría Profesional
```bash
python main_project.py contracts/ audit \
  --strategy both \
  --visualize \
  --use-ollama \
  --ollama-model deepseek-coder:33b
```
⚡ Lento | ✅ Excelente | 💰 $0

---

## 📚 Archivos de Documentación

| Archivo | Contenido |
|---------|-----------|
| `PROJECT_ANALYSIS.md` | Guía completa y detallada |
| `MULTI_CONTRACT_SUMMARY.md` | Resumen ejecutivo |
| `IMPLEMENTACION_MULTI_CONTRATO.md` | Detalles técnicos |
| `QUICK_REFERENCE_MULTI_CONTRACT.md` | Esta guía |

---

## 🎓 Flujo de Trabajo Recomendado

### 1. Exploración Inicial
```bash
# Ver estructura
python src/project_analyzer.py contracts/

# Generar visualización
python main_project.py contracts/ explore --visualize --max-contracts 0
```

### 2. Análisis Incremental
```bash
# Primero críticos
python main_project.py contracts/ phase1 \
  --priority-filter high \
  --use-ollama

# Luego el resto
python main_project.py contracts/ phase2 \
  --priority-filter medium \
  --use-ollama
```

### 3. Verificación Final
```bash
# Análisis exhaustivo
python main_project.py contracts/ final \
  --strategy both \
  --visualize \
  --use-ollama \
  --ollama-model deepseek-coder:33b
```

---

## 💡 Tips Útiles

### Tip 1: Siempre Visualiza Primero
```bash
# Entender antes de analizar
python main_project.py contracts/ viz --visualize --max-contracts 0
```

### Tip 2: Usa Filtros para Proyectos Grandes
```bash
# No analices todo a la vez
python main_project.py contracts/ big \
  --priority-filter high \
  --max-contracts 10
```

### Tip 3: Guarda el Output
```bash
# Usa tags descriptivos
python main_project.py contracts/ audit_v1_2024_01_15 --strategy scan
```

### Tip 4: Combina con Git
```bash
# Tag por commit
TAG=$(git rev-parse --short HEAD)
python main_project.py contracts/ audit_$TAG --use-ollama
```

### Tip 5: Automatiza con Script
```bash
#!/bin/bash
# analyze.sh

DATE=$(date +%Y%m%d)
python main_project.py contracts/ audit_$DATE \
  --strategy scan \
  --visualize \
  --use-ollama \
  --priority-filter high

open output/audit_$DATE/visualizations/dependency_graph.html
```

---

## ⚡ One-Liners Útiles

```bash
# Análisis completo con un comando
python main_project.py contracts/ $(date +%Y%m%d) --strategy both --visualize --use-ollama --ollama-model codellama:13b

# GitHub a visualización
python main_project.py https://github.com/user/repo repo_viz --visualize --max-contracts 0 && open output/repo_viz/visualizations/dependency_graph.html

# Top 5 críticos
python main_project.py contracts/ top5 --priority-filter high --max-contracts 5 --quick

# Análisis y abrir resultados
python main_project.py contracts/ quick --quick && ls -R output/quick/

# Ver estadísticas rápido
python src/project_analyzer.py contracts/ | grep "Total"
```

---

## 📊 Ejemplos de Output

### Estadísticas
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

### Plan de Escaneo
```
📋 Scan Plan
┏━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━┓
┃ #  ┃ Contract ┃ Priority ┃ Lines ┃ Est. Time ┃
┡━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━┩
│ 1  │ Token    │ HIGH     │   250 │      80s  │
│ 2  │ Sale     │ HIGH     │   180 │      65s  │
│ 3  │ Staking  │ MEDIUM   │   120 │      50s  │
└────┴──────────┴──────────┴───────┴───────────┘
```

### Resultados
```
✅ Analysis Results
┏━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┓
┃ Contract ┃  Status   ┃   Time ┃
┡━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━┩
│ Token    │ ✓ Success │  72.3s │
│ Sale     │ ✓ Success │  68.9s │
│ Staking  │ ✓ Success │  50.1s │
└──────────┴───────────┴────────┘

Summary:
  ✓ Successful: 3/3
  ⏱️  Total time: 191.3s
```

---

## ✅ Checklist Rápido

Antes de analizar:
- [ ] Ollama instalado (`ollama --version`)
- [ ] Modelo descargado (`ollama list`)
- [ ] Contratos en carpeta organizada
- [ ] PATH configurado correctamente

Para análisis:
- [ ] ¿Qué estrategia necesito? (scan/unified/both)
- [ ] ¿Necesito visualización? (--visualize)
- [ ] ¿Todos o solo críticos? (--priority-filter)
- [ ] ¿Qué modelo usar? (7b/13b/33b)

Después del análisis:
- [ ] Revisar `output/<tag>/`
- [ ] Abrir visualización HTML
- [ ] Leer reportes individuales
- [ ] Verificar contratos con problemas

---

¡Todo listo para analizar proyectos multi-contrato con MIESC! 🚀

**Comando para empezar ahora:**
```bash
python main_project.py contracts/ myproject --visualize --use-ollama
open output/myproject/visualizations/dependency_graph.html
```
