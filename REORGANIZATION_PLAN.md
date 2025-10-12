# Plan de Reorganización del Repositorio MIESC

## 📋 Situación Actual

### Problemas Identificados:
1. **Raíz desordenada**: 20+ archivos .md en el root mezclando tesis y proyecto
2. **Nombre inconsistente**: "xaudit" vs "MIESC"
3. **Referencias a Claude/Anthropic**: En commits y documentación
4. **Estructura poco clara**: Archivos de tesis mezclados con código

---

## 🎯 Nueva Estructura Propuesta

```
MIESC/                              # Nombre del repo cambiado
├── README.md                       # Overview del proyecto
├── LICENSE                         # GPL-3.0
├── .gitignore
├── .env.example
│
├── src/                            # Código fuente principal
│   ├── agents/                     # Agentes MCP
│   ├── mcp/                        # Context Bus
│   ├── tools/                      # Wrappers de herramientas
│   └── utils/                      # Utilidades
│
├── scripts/                        # Scripts de ejecución
│   ├── demo_ai_tools_comparison.py
│   ├── demo_mcp_poc.py
│   ├── visualize_comparison.py
│   └── run_extended_benchmark.sh
│
├── examples/                       # Contratos de ejemplo
│   └── *.sol
│
├── tests/                          # Tests automatizados
│   └── test_mcp_e2e.py
│
├── config/                         # Configuraciones
│   ├── config.py
│   ├── requirements.txt
│   ├── requirements_core.txt
│   └── requirements_minimal.txt
│
├── outputs/                        # Resultados de análisis
│   ├── visualizations/
│   └── *.json
│
├── docs/                           # Documentación técnica
│   ├── website/                    # Website público
│   ├── api/                        # API docs
│   ├── guides/                     # Guías de uso
│   │   ├── QUICKSTART_API.md
│   │   └── LLAMA_SETUP.md
│   └── architecture/               # Arquitectura técnica
│       └── MCP_evolution.md
│
├── thesis/                         # 🎓 Materiales de Tesis (SEPARADOS)
│   ├── README.md                   # Índice de materiales de tesis
│   ├── defense/                    # Material para defensa
│   │   ├── THESIS_PRESENTATION.md
│   │   ├── GUIA_DEFENSA_TESIS.md
│   │   └── preparar_defensa.sh
│   ├── justification/              # Justificación científica
│   │   ├── NUEVAS_HERRAMIENTAS_RESUMEN.md
│   │   ├── ROADMAP_NUEVAS_HERRAMIENTAS.md
│   │   └── PROXIMOS_PASOS.md
│   ├── compliance/                 # Alineación estándares
│   │   ├── DPG_COMPLIANCE.md
│   │   └── DPG_SUBMISSION_CHECKLIST.md
│   └── bibliography/               # Referencias
│
├── standards/                      # Compliance con estándares
│   ├── iso27001_controls.md
│   ├── iso42001_alignment.md
│   ├── nist_ssdf_mapping.md
│   └── owasp_sc_top10_mapping.md
│
└── governance/                     # Governance del proyecto
    ├── CODE_OF_CONDUCT.md
    ├── CONTRIBUTING.md
    ├── SECURITY.md
    └── PRIVACY_POLICY.md
```

---

## 🔄 Plan de Migración

### Fase 1: Crear Nueva Estructura (SIN mover archivos todavía)
```bash
mkdir -p src/{agents,mcp,tools,utils}
mkdir -p scripts
mkdir -p config
mkdir -p tests
mkdir -p docs/{guides,architecture,api}
mkdir -p thesis/{defense,justification,compliance,bibliography}
mkdir -p governance
mkdir -p standards
```

### Fase 2: Mover Archivos (con git mv para mantener historia)
```bash
# Código fuente
git mv agents/ src/agents/
git mv mcp/ src/mcp/

# Scripts
git mv demo_*.py scripts/
git mv visualize_comparison.py scripts/
git mv run_extended_benchmark.sh scripts/
git mv *.sh scripts/ # Otros scripts

# Config
git mv config.py config/
git mv requirements*.txt config/

# Tests
git mv test_*.py tests/

# Documentación técnica
git mv docs/QUICKSTART_API.md docs/guides/
git mv docs/LLAMA_SETUP.md docs/guides/
git mv docs/MCP_evolution.md docs/architecture/

# Materiales de tesis
git mv THESIS_PRESENTATION.md thesis/defense/
git mv GUIA_DEFENSA_TESIS.md thesis/defense/
git mv preparar_defensa.sh thesis/defense/
git mv NUEVAS_HERRAMIENTAS_RESUMEN.md thesis/justification/
git mv ROADMAP_NUEVAS_HERRAMIENTAS.md thesis/justification/
git mv PROXIMOS_PASOS.md thesis/justification/
git mv DPG_COMPLIANCE.md thesis/compliance/
git mv DPG_SUBMISSION_CHECKLIST.md thesis/compliance/

# Governance
git mv CODE_OF_CONDUCT.md governance/
git mv CONTRIBUTING.md governance/
git mv SECURITY.md governance/
git mv PRIVACY_POLICY.md governance/

# Standards
git mv standards/*.md standards/ # Ya existe, verificar
```

### Fase 3: Actualizar Imports y Referencias
- Actualizar imports en Python
- Actualizar paths en README
- Actualizar links en documentación
- Actualizar scripts de ejecución

### Fase 4: Limpiar Referencias Claude/Anthropic

**Archivos a revisar**:
```bash
# Buscar referencias
grep -r "Claude" .
grep -r "Anthropic" .
grep -r "claude.com" .
grep -r "Generated with" .
grep -r "Co-Authored-By: Claude" .
```

**Limpiar**:
1. Git history (commits): NO se puede/debe cambiar
2. Documentación actual: Eliminar referencias
3. Scripts: Sin menciones
4. README: Enfoque 100% científico

### Fase 5: Actualizar README Principal

Nuevo README.md enfoque científico:
- Marco teórico
- Contribuciones académicas
- Metodología de investigación
- Alineación estándares
- Sin referencias a herramientas de IA en desarrollo

---

## 📝 Cambios en Documentación

### README.md Raíz (Científico)
```markdown
# MIESC - Marco Integrado de Evaluación de Seguridad en Smart Contracts

Framework de ciberdefensa en profundidad para auditoría de smart contracts.

## Contribuciones Científicas
1. Primera arquitectura MCP multiagente para seguridad blockchain
2. Validación empírica con Cohen's Kappa 0.847
3. Alineación con 4 estándares internacionales
4. Reducción del 90% en esfuerzo de auditoría
...
```

### thesis/README.md (Académico)
```markdown
# Materiales de Tesis de Maestría

Este directorio contiene los materiales relacionados con la tesis de maestría
"Marco Integrado de Evaluación de Seguridad en Smart Contracts"

Autor: Fernando Boiero
Institución: UTN-FRVM
Año: 2025
...
```

---

## 🔄 Renombrar Repositorio

### En GitHub (Manual):
1. Ve a: https://github.com/fboiero/xaudit/settings
2. En "Repository name", cambiar de `xaudit` → `MIESC`
3. Click "Rename"
4. GitHub creará redirect automático de URLs antiguas

### Local:
```bash
# Actualizar remote URL
git remote set-url origin https://github.com/fboiero/MIESC.git

# Verificar
git remote -v
```

### Actualizar Referencias:
- README.md: Cambiar todos los links
- docs/website: Actualizar URLs
- DPG_COMPLIANCE: Actualizar repository URL
- package.json (si existe): Actualizar

---

## 🧹 Limpieza de Referencias IA

### Patrones a Buscar y Reemplazar:

**ELIMINAR**:
```
❌ "Generated with Claude Code"
❌ "Co-Authored-By: Claude <noreply@anthropic.com>"
❌ "Powered by Claude"
❌ Links a claude.com
❌ Menciones a "herramienta de IA usada en desarrollo"
```

**MANTENER** (Legítimo):
```
✅ "AI-powered triage" (feature del framework)
✅ "GPT-4 integration" (componente técnico)
✅ "LLaMA 3.1" (tecnología usada)
✅ "AIAgent" (nombre del agente)
```

### Archivos Críticos a Limpiar:
1. README.md
2. docs/website/index.html
3. Todos los .md en thesis/
4. DPG_COMPLIANCE.md
5. governance/*.md

**Nota sobre Commits**:
- Los commits ya pusheados NO se deben reescribir (rompe historia)
- Solo limpiar documentación actual y futura
- Es normal tener herramientas de desarrollo en la historia

---

## ✅ Checklist de Ejecución

### Antes de Ejecutar:
- [ ] Backup del repositorio completo
- [ ] Verificar que no hay cambios sin commitear
- [ ] Avisar a colaboradores (si los hay)

### Durante la Migración:
- [ ] Crear estructura de directorios
- [ ] Mover archivos con `git mv` (mantiene historia)
- [ ] Actualizar imports en código Python
- [ ] Actualizar paths en scripts
- [ ] Actualizar referencias en docs
- [ ] Limpiar referencias Claude/Anthropic
- [ ] Actualizar README principal
- [ ] Crear README en thesis/
- [ ] Actualizar URLs en website

### Después:
- [ ] Renombrar repo en GitHub: xaudit → MIESC
- [ ] Actualizar remote local
- [ ] Verificar que website sigue funcionando
- [ ] Verificar que scripts funcionan
- [ ] Push de todos los cambios
- [ ] Verificar GitHub Pages

---

## 🎯 Resultado Final

### Beneficios:
✅ **Profesional**: Estructura clara y organizada
✅ **Académico**: Tesis separada del código
✅ **Científico**: Sin referencias a herramientas de desarrollo
✅ **Mantenible**: Fácil de navegar y extender
✅ **Claro**: Separación de concerns

### URLs Actualizadas:
- Repo: `https://github.com/fboiero/MIESC`
- Website: `https://fboiero.github.io/MIESC/`
- Docs: `https://github.com/fboiero/MIESC/tree/main/docs`

---

## ⚠️ Consideraciones Importantes

1. **Git History**: NO reescribir commits ya pusheados
2. **Breaking Changes**: Los imports cambiarán, documentar
3. **GitHub Pages**: Puede requerir reconfiguración
4. **Links Externos**: Actualizar si alguien ya enlazó el repo
5. **Citations**: Actualizar formato de citación con nuevo nombre

---

¿Deseas que proceda con la migración paso a paso?
Puedo ejecutar fase por fase con confirmación antes de cada paso crítico.
