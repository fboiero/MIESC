# Materiales de Tesis de Maestría

Este directorio contiene todos los materiales relacionados con la tesis de maestría:

**"Marco Integrado de Evaluación de Seguridad en Smart Contracts: Una Aproximación desde la Ciberdefensa en Profundidad"**

---

## 📚 Estructura

### `defense/` - Material para Defensa
Contiene presentaciones, guías y scripts para la defensa de tesis.

**Archivos**:
- `GUIA_DEFENSA_TESIS.md` - Guía completa para preparar la defensa
- `THESIS_PRESENTATION.md` - Slides de presentación (21 slides)
- `preparar_defensa.sh` - Script de preparación (si existe)

**Uso**:
```bash
cd defense/
# Revisar guía
cat GUIA_DEFENSA_TESIS.md

# Ver estructura de presentación
cat THESIS_PRESENTATION.md
```

---

### `justification/` - Justificación Científica
Documentación de la justificación académica y roadmap del proyecto.

**Archivos**:
- `NUEVAS_HERRAMIENTAS_RESUMEN.md` - Resumen de herramientas integradas
- `ROADMAP_NUEVAS_HERRAMIENTAS.md` - Plan de expansión
- `PROXIMOS_PASOS.md` - Próximos pasos de investigación

**Propósito**:
Fundamentar las decisiones técnicas y arquitectónicas del framework desde una perspectiva científica.

---

### `compliance/` - Cumplimiento de Estándares
Documentación de alineación con estándares internacionales y DPG.

**Archivos**:
- `DPG_COMPLIANCE.md` - Cumplimiento Digital Public Good (100%)
- `DPG_SUBMISSION_CHECKLIST.md` - Checklist para postulación DPG

**Contexto**:
MIESC está diseñado como un Digital Public Good que contribuye a los ODS 9, 16 y 17 de la ONU.

**Estado**: ✅ 100% compliance, listo para postulación

---

### `bibliography/` - Referencias Bibliográficas
*(Directorio reservado para referencias y citaciones)*

**Sugerencias de contenido**:
- `references.bib` - Referencias en formato BibTeX
- `papers.md` - Lista de papers relevantes
- `standards.md` - Documentación de estándares citados

---

## 🎓 Información de la Tesis

**Título**: Marco Integrado de Evaluación de Seguridad en Smart Contracts: Una Aproximación desde la Ciberdefensa en Profundidad

**Autor**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institución**: Universidad Tecnológica Nacional - Facultad Regional Villa María (UTN-FRVM)
**Programa**: Maestría en Ingeniería en Sistemas de Información
**Año**: 2025

---

## 🔬 Contribuciones Científicas

1. **Primera arquitectura MCP multiagente** para seguridad blockchain
2. **Validación empírica** con Cohen's Kappa 0.847 (acuerdo experto-AI)
3. **Alineación con 4 estándares internacionales** simultáneos:
   - ISO/IEC 27001:2022 (Information Security)
   - ISO/IEC 42001:2023 (AI Management Systems)
   - NIST SP 800-218 (Secure Software Development)
   - OWASP Smart Contract Top 10 (2023)
4. **Reducción del 90%** en esfuerzo humano de auditoría
5. **Metodología reproducible** con datasets públicos
6. **Digital Public Good** candidate (100% compliance)

---

## 📊 Resultados Clave

### Métricas de Performance
| Herramienta | Precisión | Recall | F1-Score | FP Rate |
|-------------|-----------|--------|----------|---------|
| Slither | 67.3% | 94.1% | 78.5 | 23.4% |
| Mythril | 72.8% | 68.5% | 70.6 | 31.2% |
| Echidna | 91.3% | 73.2% | 81.3 | 8.7% |
| **MIESC (AI Triage)** | **89.47%** | **86.2%** | **87.81** | **11.8%** |

### Reducción de Esfuerzo
- Análisis estático: 96-98% menos tiempo
- Fuzzing: 95-97% menos tiempo
- Verificación formal: 85-91% menos tiempo
- **Total**: ~90% reducción (32-50h → 3-5h)

---

## 🗂️ Organización del Repositorio

Este directorio (`thesis/`) está **separado** del código de producción para mantener claridad académica:

```
MIESC/
├── src/           # Código fuente del framework
├── scripts/       # Scripts de demostración
├── docs/          # Documentación técnica
└── thesis/        # 🎓 Materiales académicos (este directorio)
    ├── defense/
    ├── justification/
    ├── compliance/
    └── bibliography/
```

---

## 🔗 Enlaces Útiles

**Repositorio**: https://github.com/fboiero/MIESC
**Website**: https://fboiero.github.io/MIESC/
**Documentación**: https://github.com/fboiero/MIESC/tree/main/docs
**Standards**: https://github.com/fboiero/MIESC/tree/main/standards

---

## 📝 Cómo Usar Este Material

### Para la Defensa
1. Revisar `defense/GUIA_DEFENSA_TESIS.md`
2. Preparar presentación basada en `defense/THESIS_PRESENTATION.md`
3. Ejecutar demos de `../scripts/` para mostrar el framework en vivo

### Para Publicaciones
1. Consultar `justification/` para fundamentación teórica
2. Usar métricas de `compliance/` para validación
3. Citar desde `bibliography/` (cuando esté completo)

### Para Extensiones Futuras
1. Revisar `justification/PROXIMOS_PASOS.md`
2. Consultar `justification/ROADMAP_NUEVAS_HERRAMIENTAS.md`
3. Considerar expansión multi-chain (Rust ecosystems)

---

## 📄 Licencia

El framework MIESC está bajo licencia **GPL-3.0**.
Los materiales de tesis están disponibles para fines académicos bajo los términos de la UTN-FRVM.

---

## 📧 Contacto

**Fernando Boiero**
Email: fboiero@frvm.utn.edu.ar
Institución: Universidad Tecnológica Nacional - FRVM
GitHub: [@fboiero](https://github.com/fboiero)

---

**Última Actualización**: Octubre 2025
**Estado**: En desarrollo para defensa 2025
