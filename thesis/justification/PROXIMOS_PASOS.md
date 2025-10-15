# 🎯 PRÓXIMOS PASOS INMEDIATOS PARA DEFENSA

**Generado:** $(date '+%Y-%m-%d %H:%M:%S')
**Estado:** 5 pasos de preparación completados ✅

---

## ✅ COMPLETADO

- [x] **Paso 1:** Demo de práctica generado
- [x] **Paso 2:** Reporte de tesis en Markdown
- [x] **Paso 3:** Métricas experimentales empíricas
- [x] **Paso 4:** Dataset para Zenodo empaquetado
- [x] **Paso 5:** Presentación base en Markdown

---

## 🔄 PENDIENTE (Acciones Manuales)

### 1. Convertir Presentación a PowerPoint (15 min)

**Opción A - Marp (Recomendado):**
```bash
cd defensa_20251011
npm install -g @marp-team/marp-cli
marp presentacion_defensa.md -o presentacion.pptx --theme default
```

**Opción B - Reveal.js (Presentación Web):**
```bash
cd defensa_20251011
pandoc presentacion_defensa.md -o presentacion.html -t revealjs -s
# Abrir en navegador: open presentacion.html
```

**Opción C - Manual:**
- Abrir presentacion_defensa.md
- Copiar contenido slide por slide a PowerPoint
- Agregar gráficos e imágenes

---

### 2. Publicar Dataset en Zenodo (30 min)

**Pasos:**
1. Ir a: https://zenodo.org/
2. Crear cuenta / Login con GitHub
3. Click en "New Upload"
4. Subir archivo: `defensa_20251011/zenodo_dataset.zip`
5. Completar formulario:
   - **Title:** Xaudit v2.0: Empirical Metrics Dataset
   - **Authors:** Fernando Boiero (UTN-FRVM)
   - **Description:** Copiar desde zenodo_dataset/README.md
   - **Keywords:** smart contracts, security, AI, static analysis
   - **Access:** Open Access
   - **License:** GPL-3.0
6. Publish
7. **Copiar DOI** (formato: 10.5281/zenodo.XXXXXXX)
8. Actualizar README.md y tesis con el DOI

---

### 3. Practicar Demo de Defensa (3 sesiones x 20 min)

**Secuencia recomendada (20-22 minutos):**
```bash
./demo_tesis_completo.sh
```

**Seleccionar opciones:** 1 → 2 → 4 → 5 → 7 → 8 → 10 → 11 → 0

**Timing sugerido:**
- Opción 1 (Estructura): 2 min
- Opción 2 (Método Científico): 3 min
- Opción 4 (Pipeline): 2 min
- Opción 5 (AI Triage): 3 min
- Opción 7 (Validación Hipótesis): 4 min
- Opción 8 (Métricas): 2 min
- Opción 10 (ISO 42001): 2 min
- Opción 11 (Datasets): 2 min

**Práctica:**
- Sesión 1: Familiarización (sin tiempo)
- Sesión 2: Con cronómetro (ajustar timing)
- Sesión 3: Simulación completa con preguntas

---

### 4. Pushear Cambios a GitHub (2 min)

```bash
git push origin main
```

**Verificar:**
- Ir a: https://github.com/fboiero/MIESC
- Confirmar que aparecen los 4 nuevos commits
- Verificar que defensa_20251011/ está disponible

---

### 5. Preparar Material del Día de Defensa (30 min)

**Checklist:**
- [ ] Laptop cargada + cargador de respaldo
- [ ] Presentación PowerPoint copiada a USB (backup)
- [ ] Adaptador HDMI/VGA para proyector
- [ ] Conexión a internet verificada (si demo en vivo)
- [ ] Reporte PDF impreso (2 copias)
- [ ] Notas con respuestas a preguntas frecuentes
- [ ] Cronómetro/reloj visible
- [ ] Botella de agua

**Archivos a tener abiertos:**
1. Presentación PowerPoint (principal)
2. Terminal con `./demo_tesis_completo.sh` (demo en vivo)
3. `defensa_20251011/reporte_tesis.md` (referencia rápida)
4. `GUIA_DEFENSA_TESIS.md` (comandos de emergencia)

---

## 📊 RESUMEN DE RESULTADOS (Memorizar)

| Métrica | Valor | vs Baseline |
|---------|-------|-------------|
| **Precisión** | 89.47% | +32.9% (67.3%) |
| **Cohen's Kappa** | 0.847 | Acuerdo casi perfecto |
| **Reducción FP** | 73.6% | 2.4x mejora objetivo (30%) |
| **F1-Score** | 87.81 | +11.9% (78.5) |
| **Vulnerabilidades** | 1,247 | +47% vs mejor individual |

**4 Hipótesis Validadas (p < 0.05):**
- H1: Xaudit > Slither ✅
- H2: FP reduction ≥ 30% ✅
- H3: Kappa ≥ 0.60 ✅
- H4: Más vulnerabilidades ✅

---

## 🎤 PREGUNTAS FRECUENTES DEL JURADO

### Q1: "¿Por qué Cohen's Kappa y no otra métrica?"
**R:** Kappa mide acuerdo inter-evaluador considerando la probabilidad de acuerdo por azar. Es el estándar en ML para validación con expertos. κ=0.847 = "acuerdo casi perfecto" según Landis & Koch (1977).

### Q2: "¿Cómo garantizan que la IA no introduce sesgos?"
**R:** 3 mecanismos:
1. Human-in-the-Loop obligatorio (ISO 42001 Cláusula 6.3)
2. Explicabilidad: 100% decisiones justificadas
3. Validación con 3 expertos independientes (κ=0.847)

### Q3: "¿Qué pasa si GPT-4o-mini deja de estar disponible?"
**R:** Diseño modular permite reemplazar modelo sin cambiar arquitectura. Evaluamos: GPT-3.5, GPT-4, Llama 2, Claude. GPT-4o-mini elegido por balance cost/performance.

### Q4: "¿Por qué Xaudit detectó más vulnerabilidades que Slither?"
**R:** Complementariedad de herramientas:
- Slither: 847 (estático puro)
- + Mythril: 234 simbólico
- + Echidna/Medusa/Foundry: 156+89+201 fuzzing
- + Certora: 78 formal
- **Total único:** 1,247 (47% más)

### Q5: "¿Cómo manejan el tiempo de ejecución (500s vs 2.3s)?"
**R:** Trade-off aceptable para auditoría de seguridad:
- 500s = 8.3 minutos por contrato
- Auditoría manual: 4-8 horas
- **Reducción:** 96-98% vs proceso manual
- Target: Pre-despliegue, no en producción

---

## 📅 TIMELINE SUGERIDA

**1 semana antes:**
- [ ] Convertir presentación
- [ ] Publicar dataset en Zenodo
- [ ] Primera práctica de demo

**3 días antes:**
- [ ] Segunda práctica de demo
- [ ] Push a GitHub
- [ ] Preparar USB backup

**1 día antes:**
- [ ] Tercera práctica (simulación completa)
- [ ] Verificar laptop/adaptadores
- [ ] Imprimir reporte PDF
- [ ] Dormir bien 😴

**Día de defensa:**
- [ ] Llegar 30 min antes
- [ ] Probar proyector
- [ ] Verificar internet (si demo en vivo)
- [ ] Respirar profundo
- [ ] ¡A defender con confianza! 🎓

---

## 🔗 RECURSOS ÚTILES

- **Guía completa:** `GUIA_DEFENSA_TESIS.md`
- **Demo interactivo:** `./demo_tesis_completo.sh`
- **Materiales generados:** `defensa_20251011/`
- **Script automático:** `./preparar_defensa.sh` (si re-ejecutar)
- **GitHub:** https://github.com/fboiero/MIESC
- **Zenodo:** https://zenodo.org/ (para publicar dataset)

---

## ✅ CRITERIOS DE ÉXITO

**Defensa exitosa si:**
- ✅ Presentación clara en 20-25 minutos
- ✅ Demo funcional sin errores críticos
- ✅ Respuestas sólidas a preguntas del jurado
- ✅ Demostración de rigor científico
- ✅ Resultados validados (4 hipótesis)
- ✅ Cumplimiento normativo (ISO 42001)

**Objetivos alcanzados:**
- Framework funcionando ✅
- Validación empírica completa ✅
- Documentación exhaustiva ✅
- Open-source disponible ✅
- Publicación preparada ✅

---

**¡TODO LISTO PARA UNA DEFENSA SOBRESALIENTE!** 🎉🎓

---

_Última actualización: $(date '+%Y-%m-%d %H:%M:%S')_
_Commit: b9428c9_
