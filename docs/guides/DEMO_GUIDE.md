# 🎯 MIESC Demo Guide

## Opciones de Demo

### Demo 1: Demo Rápida (Nuevas Características)
**Duración:** 10-15 minutos
**Script:** `./demo.sh`

```bash
./demo.sh
```

**Cubre:**
- ✨ Nuevas características mejoradas
- 📊 Dashboard HTML interactivo
- 📝 Reportes en Markdown
- 🎨 Visualizaciones de dependencias
- 🔍 Detección de vulnerabilidades

---

### Demo 2: Demo Completa (Todas las Capacidades)
**Duración:** 20-30 minutos
**Script:** `./demo_complete.sh`

```bash
./demo_complete.sh
```

**Cubre:**
- 🔧 Todas las herramientas de análisis
- 🤖 IA local y multi-agente
- 📊 Análisis multi-contrato
- 🎯 3 estrategias de análisis
- 🛡️ Detección de exploits reales
- 📈 Código de producción vs vulnerable

---

## Preparación Antes de la Demo

### 1. Verificar Dependencias

```bash
# Verificar herramientas principales
which slither
which ollama
which python3

# Verificar modelos de Ollama
ollama list

# Si no tienes codellama:7b
ollama pull codellama:7b
```

### 2. Limpiar Outputs Previos (Opcional)

```bash
# Limpiar demos anteriores
rm -rf output/demo*

# O mantener para comparación
```

### 3. Probar un Comando Rápido

```bash
# Test rápido (30 segundos)
python main_ai.py examples/reentrancy_simple.sol test --use-slither --use-ollama
```

---

## Estructura de la Demo Completa

### 📋 Parte 1: Análisis de Contrato Único (5 min)

**Qué mostrar:**
- Análisis con múltiples herramientas
- Salida en tiempo real
- Archivos generados

**Puntos clave:**
- "MIESC integra múltiples herramientas en un solo comando"
- "Análisis automático sin configuración manual"

### 📋 Parte 2: IA Local vs Cloud (5 min)

**Qué mostrar:**
- Ollama ejecutándose localmente
- Costo $0 vs GPT-4
- Privacidad de datos

**Puntos clave:**
- "Análisis con IA completamente privado"
- "Sin límites de uso, sin costos"

### 📋 Parte 3: Proyectos Multi-Contrato (8 min)

**Qué mostrar:**
- Análisis de carpeta completa
- Gráfico de dependencias
- Dashboard interactivo

**Puntos clave:**
- "Analiza proyectos completos automáticamente"
- "Visualiza dependencias entre contratos"
- "Dashboard profesional generado automáticamente"

### 📋 Parte 4: Detección de Vulnerabilidades (7 min)

**Qué mostrar:**
- Código intencionalmente vulnerable
- Detección de reentrancy, access control, etc.
- Recomendaciones de corrección

**Puntos clave:**
- "Detecta vulnerabilidades reales"
- "Provee recomendaciones accionables"
- "Referencias a SWC y OWASP"

### 📋 Parte 5: Código de Producción (5 min)

**Qué mostrar:**
- Análisis de Uniswap V2
- Diferencia vs código vulnerable
- Hallazgos informativos vs críticos

**Puntos clave:**
- "Distingue código seguro de inseguro"
- "Minimal false positives en código auditado"

---

## Secuencia de Comandos Manual

Si prefieres ejecutar comandos manualmente en lugar del script:

### 1. Análisis Simple

```bash
python main_ai.py examples/reentrancy_simple.sol demo_simple \
  --use-slither --use-ollama
```

### 2. Proyecto Local

```bash
python main_project.py examples/ demo_local \
  --visualize --use-ollama --quick --max-contracts 3
```

### 3. GitHub Vulnerable

```bash
python main_project.py \
  https://github.com/theredguild/damn-vulnerable-defi demo_vuln \
  --visualize --use-ollama --quick --priority-filter high --max-contracts 2
```

### 4. GitHub Producción

```bash
python main_project.py \
  https://github.com/Uniswap/v2-core demo_uniswap \
  --visualize --use-ollama --quick --priority-filter medium
```

### 5. Ver Dashboard

```bash
open output/demo_local/reports/dashboard.html
open output/demo_vuln/reports/dashboard.html
open output/demo_uniswap/reports/dashboard.html
```

---

## Puntos de Venta Clave

### Para Desarrolladores:
✅ **Integración sin fricción** - Un comando, múltiples herramientas
✅ **Feedback inmediato** - Encuentra bugs antes del deploy
✅ **Aprendizaje continuo** - Explicaciones de cada vulnerabilidad

### Para Auditores:
✅ **Cobertura completa** - Múltiples análisis estáticos + IA
✅ **Priorización automática** - Focus en high-risk issues primero
✅ **Reportes profesionales** - Listos para entregar a clientes

### Para Empresas:
✅ **Costo-efectivo** - $0 con Ollama vs $50k+ auditorías
✅ **Privado y seguro** - Análisis local, sin enviar código a cloud
✅ **Escalable** - De 1 contrato a proyectos completos

---

## Timing Recomendado

### Demo de 10 Minutos (Elevator Pitch)
1. Intro (1 min)
2. Análisis simple (3 min)
3. Dashboard interactivo (3 min)
4. Detección de vulnerabilidad (3 min)

### Demo de 20 Minutos (Completa)
1. Intro (2 min)
2. Análisis simple (4 min)
3. Multi-contrato (5 min)
4. Vulnerabilidades (5 min)
5. Reportes (4 min)

### Demo de 30 Minutos (Detallada)
- Ejecuta `./demo_complete.sh`
- Pausa en cada sección para explicar
- Muestra código y outputs

---

## Preguntas Frecuentes Durante Demos

### "¿Qué tan rápido es?"
- Contrato simple: 30-60 segundos
- Proyecto 10 contratos: 5-10 minutos
- Depende del modelo (7b vs 13b)

### "¿Cuánto cuesta?"
- Ollama local: $0 (ilimitado)
- Herramientas tradicionales: Gratis
- CrewAI/GPT-4: ~$0.50 por contrato
- Auditoría manual: $10k-$100k+

### "¿Qué herramientas incluye?"
- ✅ Slither (gratis)
- ✅ Ollama (gratis, local)
- ✅ Mythril (gratis, opcional)
- ✅ Aderyn (gratis, opcional)
- ✅ CrewAI (pago, opcional)

### "¿Funciona con Foundry/Hardhat?"
- ✅ Sí, automáticamente detecta configuración
- ✅ Soporta ambos frameworks
- ✅ No requiere configuración adicional

### "¿Detecta todos los bugs?"
- ⚠️ No tool es perfecto
- ✅ Combina múltiples herramientas = mejor cobertura
- ✅ IA encuentra patrones que reglas no detectan
- 💡 Complementa, no reemplaza, auditorías manuales

---

## Consejos de Presentación

### ✅ DO:
- Mostrar dashboards en navegador grande
- Preparar ejemplos con vulnerabilidades reales
- Destacar la velocidad (tiempo real)
- Mencionar el aspecto gratuito/open-source
- Comparar con auditorías tradicionales

### ❌ DON'T:
- No confiar en internet en vivo (pre-clonar repos)
- No usar ejemplos muy largos
- No pretender que es 100% infalible
- No esconder limitaciones

### 💡 Tips:
- Tener varios navegadores abiertos con dashboards pre-generados
- Si algo falla, mostrar outputs pre-generados
- Preparar "plan B" con screenshots
- Tener README visible para comandos de referencia

---

## Checklist Pre-Demo

```bash
# 1. Verificar Ollama
ollama list | grep codellama:7b

# 2. Test rápido
python main_ai.py examples/reentrancy_simple.sol test --use-ollama

# 3. Pre-generar demos (si quieres backup)
./demo_complete.sh  # Ejecutar antes y tener outputs listos

# 4. Abrir navegador en tabs
# - Tab 1: Demo dashboard
# - Tab 2: Uniswap dashboard
# - Tab 3: Vulnerable dashboard
# - Tab 4: Dependency graph

# 5. Terminal
# - Font size grande para proyección
# - Color scheme legible
# - Clear history
```

---

## Recursos de Apoyo

### Durante la Demo:
- `docs/ENHANCED_REPORTS.md` - Referencia de reportes
- `QUICK_REFERENCE_MULTI_CONTRACT.md` - Comandos rápidos
- `README.md` - Instalación y setup

### Después de la Demo:
- Compartir repositorio GitHub
- Proveer documentación
- Ofrecer sesión de Q&A
- Demo en vivo en sus contratos

---

## Variantes de Demo

### Demo para Desarrolladores:
Enfoque en: Workflow, velocidad, learning

```bash
# Mostrar integración con desarrollo
python main_ai.py src/MyContract.sol review --use-ollama
# Iterar basado en feedback
# Mostrar fixes
```

### Demo para Auditores:
Enfoque en: Cobertura, reportes, profesionalismo

```bash
# Análisis exhaustivo
python main_project.py project/ audit-2024 --strategy both --visualize

# Mostrar reportes detallados
python generate_reports.py output/audit-2024 "Client XYZ Audit"
```

### Demo para Managers:
Enfoque en: ROI, riesgo, costo

```bash
# Análisis rápido
python main_project.py contracts/ security-check --quick --visualize

# Mostrar dashboard ejecutivo
open output/security-check/reports/dashboard.html
```

---

## Siguientes Pasos Después de la Demo

### Para Interesados:
1. ✅ Clonar el repositorio
2. ✅ Instalar dependencias (`pip install -r requirements.txt`)
3. ✅ Instalar Ollama y descargar modelo
4. ✅ Correr en sus propios contratos
5. ✅ Dar feedback/reportar issues

### Para Colaboradores:
1. ✅ Fork del repositorio
2. ✅ Revisar issues abiertos
3. ✅ Contribuir mejoras
4. ✅ Crear PRs

### Para Empresas:
1. ✅ Evaluar en proyecto piloto
2. ✅ Integrar en CI/CD
3. ✅ Entrenar equipo
4. ✅ Establecer workflow

---

## Script de Apertura Sugerido

> "Hoy les voy a mostrar MIESC, una plataforma que integra múltiples herramientas de análisis de seguridad para smart contracts.
>
> Lo especial de MIESC es que:
> 1. Combina herramientas tradicionales con IA moderna
> 2. Todo corre localmente - es gratis y privado
> 3. Genera reportes profesionales automáticamente
>
> Vamos a ver cómo en menos de 5 minutos podemos analizar un proyecto completo y obtener un dashboard interactivo con todos los hallazgos.
>
> Empecemos con un ejemplo simple..."

---

## Script de Cierre Sugerido

> "Como vimos, MIESC ofrece:
> - Análisis rápido y completo
> - Múltiples herramientas integradas
> - Reportes profesionales automáticos
> - Costo cero con Ollama
>
> Todo el código es open-source en GitHub. Pueden probarlo ahora mismo con sus propios contratos.
>
> ¿Preguntas?"

---

## Contacto y Recursos

**Repositorio:** https://github.com/yourusername/MIESC
**Documentación:** `docs/`
**Issues:** GitHub Issues
**Demos:** `./demo.sh` o `./demo_complete.sh`

---

## ¡Éxito en tu Demo! 🚀

Recuerda:
- ✅ Practica antes
- ✅ Ten backups preparados
- ✅ Conoce los comandos
- ✅ Explica los beneficios
- ✅ Responde preguntas honestamente

**¡Buena suerte! 🎯**
