# Flujo de Trabajo para Auditorías Profesionales

**MIESC v5.1.0** | Guía para Auditores Profesionales

Esta guía proporciona un flujo de trabajo estructurado para realizar auditorías de seguridad profesionales de smart contracts usando MIESC.

---

## Tabla de Contenidos

1. [Descripción General](#descripción-general)
2. [Requisitos Previos](#requisitos-previos)
3. [Fases de Auditoría](#fases-de-auditoría)
4. [Referencia de Comandos](#referencia-de-comandos)
5. [Interpretación de Hallazgos](#interpretación-de-hallazgos)
6. [Gestión de Falsos Positivos](#gestión-de-falsos-positivos)
7. [Generación de Reportes](#generación-de-reportes)
8. [Integración CI/CD](#integración-cicd)
9. [Mejores Prácticas](#mejores-prácticas)
10. [Ejemplos de Flujos de Trabajo](#ejemplos-de-flujos-de-trabajo)

---

## Descripción General

MIESC integra **50 herramientas de seguridad** en **9 capas de defensa** para proporcionar un análisis completo de smart contracts:

| Capa | Enfoque | Herramientas Principales |
|------|---------|--------------------------|
| 1 | Análisis Estático | Slither, Aderyn, Solhint, Semgrep, Wake |
| 2 | Pruebas Dinámicas | Echidna, Medusa, Foundry, Hardhat |
| 3 | Ejecución Simbólica | Mythril, Manticore, Halmos |
| 4 | Verificación Formal | Certora, Scribble, Solc-verify |
| 5 | Análisis Económico | Detectores específicos DeFi |
| 6 | Auditoría de Dependencias | npm-audit, pip-audit, cargo-audit |
| 7 | Análisis con LLM | GPTScan, SmartLLM, GPTLens |
| 8 | Auditorías Especializadas | Monitor de bridges, validador L2 |
| 9 | Meta-Análisis | Correlación entre herramientas, consenso |

---

## Requisitos Previos

### Docker (Recomendado)

```bash
# Imagen estándar (~15 herramientas, rápida)
docker pull ghcr.io/fboiero/miesc:5.1.0

# Imagen completa (~30 herramientas, exhaustiva)
docker pull ghcr.io/fboiero/miesc:5.1.0-full

# Verificar instalación
docker run --rm ghcr.io/fboiero/miesc:5.1.0 --version
```

### Instalación Local

```bash
pip install miesc==5.1.0
miesc doctor  # Verificar disponibilidad de herramientas
```

### Configuración de LLM (Opcional, para reportes con IA)

```bash
# Iniciar Ollama con los modelos requeridos
ollama pull mistral
ollama pull deepseek-coder

# Configurar variable de entorno
export OLLAMA_HOST=http://localhost:11434
```

---

## Fases de Auditoría

### Fase 1: Triaje (5 minutos)

**Objetivo:** Evaluación rápida para identificar problemas obvios y estimar el alcance.

```bash
# Escaneo rápido con 4 herramientas
miesc scan contract.sol

# O con Docker
docker run --rm -v $(pwd):/contracts ghcr.io/fboiero/miesc:5.1.0 \
  scan /contracts/Contract.sol
```

**Salida:** Resumen de hallazgos críticos/altos/medios/bajos.

**Puntos de Decisión:**
- **0 críticos/altos:** Proceder a auditoría completa
- **Muchos críticos:** Notificar inmediatamente al cliente
- **Código complejo:** Considerar enfoque capa por capa

---

### Fase 2: Auditoría Rápida (15-30 minutos)

**Objetivo:** Escaneo rápido y completo usando herramientas principales.

```bash
miesc audit quick ./contracts -o results-quick.json
```

**Herramientas Usadas:** Slither, Aderyn, Solhint, Semgrep

**Cuándo Usar:**
- Engagement inicial con cliente
- Revisiones de PR
- Pipelines CI/CD
- Evaluaciones con tiempo limitado

---

### Fase 3: Auditoría Completa (1-4 horas)

**Objetivo:** Análisis completo de 9 capas con todas las herramientas disponibles.

```bash
# Auditoría completa con todas las capas
miesc audit full ./contracts -o results-full.json

# Saltar herramientas no disponibles (recomendado para Docker)
miesc audit full ./contracts --skip-unavailable -o results-full.json

# Con timeout específico por herramienta
miesc audit full ./contracts --timeout 600 -o results-full.json
```

**Cuándo Usar:**
- Auditorías pre-despliegue
- Contratos de alto valor (DeFi, bridges, governance)
- Requisitos de cumplimiento
- Entregables para clientes

---

### Fase 4: Análisis por Capa (Variable)

**Objetivo:** Profundizar en aspectos específicos de seguridad.

```bash
# Análisis de una sola capa (sintaxis: audit layer NUMERO_CAPA CONTRATO)
miesc audit layer 1 ./contracts  # Solo estático
miesc audit layer 3 ./contracts  # Ejecución simbólica
miesc audit layer 7 ./contracts  # Análisis LLM

# Ejecutar múltiples capas secuencialmente
miesc audit layer 1 ./contracts -o layer1.json
miesc audit layer 3 ./contracts -o layer3.json
miesc audit layer 7 ./contracts -o layer7.json
```

**Guía de Selección de Capas:**

| Preocupación | Capas Recomendadas |
|--------------|-------------------|
| Calidad de código | Capa 1 (Estático) |
| Bugs de lógica | Capa 2 (Dinámico) + Capa 3 (Simbólico) |
| Corrección formal | Capa 4 (Verificación Formal) |
| Vulnerabilidades DeFi | Capa 5 (Económico) + Capa 7 (LLM) |
| Cadena de suministro | Capa 6 (Dependencias) |
| Cross-chain/L2 | Capa 8 (Especializado) |

---

### Fase 5: Generación de Reportes (15-60 minutos)

**Objetivo:** Crear entregable profesional para el cliente.

```bash
# Reporte PDF premium con interpretación LLM
miesc report results-full.json \
  -t premium \
  --llm-interpret \
  -f pdf \
  -o audit-report.pdf

# Resumen ejecutivo (para gerencia)
miesc report results-full.json \
  -t executive \
  -f pdf \
  -o executive-summary.pdf

# Reporte técnico (para desarrolladores)
miesc report results-full.json \
  -t technical \
  -f markdown \
  -o technical-findings.md

# SARIF para GitHub Code Scanning
miesc export results-full.json -f sarif -o results.sarif.json
```

---

## Referencia de Comandos

### Comandos Principales

| Comando | Propósito | Duración Típica |
|---------|-----------|-----------------|
| `miesc scan <archivo>` | Escaneo de triaje | 1-5 min |
| `miesc audit quick <dir>` | Auditoría rápida 4 herramientas | 15-30 min |
| `miesc audit full <dir>` | Auditoría completa 9 capas | 1-4 horas |
| `miesc audit layer N <contrato>` | Análisis de capa específica | Variable |
| `miesc audit smart <dir>` | Auditoría adaptativa con IA | 30-60 min |
| `miesc report <json>` | Generar reporte | 5-60 min |
| `miesc export <json>` | Convertir a SARIF/CSV/HTML | Instantáneo |

### Comandos de Utilidad

| Comando | Propósito |
|---------|-----------|
| `miesc doctor` | Verificar disponibilidad de herramientas |
| `miesc detect <dir>` | Auto-detectar framework (Foundry/Hardhat/Truffle) |
| `miesc tools list` | Listar todas las herramientas disponibles |
| `miesc benchmark <dir>` | Seguimiento de postura de seguridad |
| `miesc watch <dir>` | Monitoreo de archivos en tiempo real |

### Opciones Comunes

| Opción | Descripción |
|--------|-------------|
| `-o, --output <archivo>` | Ruta del archivo de salida |
| `--skip-unavailable` | Saltar herramientas no instaladas |
| `--timeout <segundos>` | Timeout por herramienta (default: 300) |
| `-q, --quiet` | Salida mínima |
| `--ci` | Modo CI (exit 1 en hallazgos críticos/altos) |
| `-t, --template` | Plantilla de reporte (premium, professional, executive, technical) |
| `--llm-interpret` | Agregar análisis con IA a reportes |
| `-f, --format` | Formato de salida (json, pdf, html, markdown, sarif) |

---

## Interpretación de Hallazgos

### Niveles de Severidad

| Nivel | Acción Requerida | Problemas Típicos |
|-------|------------------|-------------------|
| **CRITICAL** | Arreglar inmediatamente, bloquear despliegue | Reentrancy, bypass de control de acceso, drenaje de fondos |
| **HIGH** | Arreglar antes del despliegue | Integer overflow, front-running, manipulación de oráculo |
| **MEDIUM** | Debería arreglarse, revisar cuidadosamente | Optimización de gas, riesgos de centralización |
| **LOW** | Considerar arreglar | Estilo de código, ineficiencias menores de gas |
| **INFO** | Informativo | Mejores prácticas, sugerencias |

### Estructura de un Hallazgo

```json
{
  "tool": "slither",
  "severity": "HIGH",
  "confidence": "HIGH",
  "title": "Vulnerabilidad de reentrancy",
  "description": "Llamada externa seguida de cambio de estado",
  "location": {
    "file": "Contract.sol",
    "line": 45,
    "function": "withdraw()"
  },
  "swc_id": "SWC-107",
  "cwe_id": "CWE-841",
  "recommendation": "Usar patrón checks-effects-interactions"
}
```

### Validación Cruzada

El motor de correlación de MIESC valida hallazgos entre herramientas:

| Nivel de Validación | Significado |
|--------------------|-------------|
| **Confirmado** | Múltiples herramientas reportan el mismo problema |
| **Alta Confianza** | Confianza alta específica de la herramienta |
| **Media Confianza** | Una herramienta, confianza media |
| **Requiere Revisión** | Potencial falso positivo |

---

## Gestión de Falsos Positivos

### Motor de Correlación Integrado

MIESC reduce automáticamente los falsos positivos mediante:

1. **Validación cruzada:** Hallazgos reportados por múltiples herramientas obtienen mayor confianza
2. **Coincidencia de patrones:** Patrones conocidos de falsos positivos son filtrados
3. **Análisis de contexto:** Guards, require statements y patrones CEI son reconocidos

### Filtrado Manual

```bash
# Filtrar por confianza mínima
miesc audit full ./contracts --min-confidence high

# Filtrar por severidad
miesc audit full ./contracts --min-severity medium
```

### Comentarios de Supresión

En tu código Solidity:

```solidity
// slither-disable-next-line reentrancy-eth
// miesc-ignore: razón-del-falso-positivo
function withdraw() external {
    // ...
}
```

### Reporte de Falsos Positivos

Después de la auditoría, documenta los falsos positivos para el cliente:

```markdown
## Falsos Positivos

| Hallazgo | Herramienta | Razón |
|----------|-------------|-------|
| Reentrancy en withdraw() | Slither | Protegido por ReentrancyGuard |
| Integer overflow | Mythril | Solidity 0.8+ tiene checks integrados |
```

---

## Generación de Reportes

### Plantillas Disponibles

| Plantilla | Audiencia | Contenido |
|-----------|-----------|-----------|
| `premium` | Clientes | Scores CVSS, matriz de riesgo, escenarios de ataque, remediación |
| `professional` | Clientes | Formato estándar de auditoría con hallazgos y recomendaciones |
| `executive` | Gerencia | Resumen de alto nivel, evaluación de riesgo, impacto de negocio |
| `technical` | Desarrolladores | Hallazgos detallados, snippets de código, ejemplos de corrección |
| `compliance` | Cumplimiento | Mapeo a ISO 27001, NIST, OWASP, SWC |
| `github-pr` | CI/CD | Formato de comentario para PR |

### Reportes Mejorados con LLM

Con `--llm-interpret`, los reportes incluyen:

- **Resumen Ejecutivo:** Visión general generada por IA de la postura de seguridad
- **Escenarios de Ataque:** Rutas de explotación realistas
- **Guía de Remediación:** Recomendaciones detalladas de corrección
- **Evaluación de Riesgo:** Análisis de impacto de negocio

```bash
# Reporte premium con todas las funciones de IA
miesc report results.json \
  -t premium \
  --llm-interpret \
  --model mistral \
  -f pdf \
  -o premium-audit-report.pdf
```

### Formatos de Salida

| Formato | Caso de Uso | Comando |
|---------|-------------|---------|
| PDF | Entrega a cliente | `-f pdf` |
| HTML | Visualización web | `-f html` |
| Markdown | Documentación | `-f markdown` |
| SARIF | GitHub Code Scanning | `miesc export -f sarif` |
| CSV | Análisis en hoja de cálculo | `miesc export -f csv` |
| JSON | Uso programático | Salida por defecto |

---

## Integración CI/CD

### GitHub Actions

```yaml
name: Auditoría de Seguridad

on:
  pull_request:
    paths:
      - 'contracts/**'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Ejecutar Auditoría MIESC
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/contracts \
            ghcr.io/fboiero/miesc:5.1.0 \
            audit quick /contracts \
            --ci \
            -o /contracts/results.json

      - name: Exportar SARIF
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/contracts \
            ghcr.io/fboiero/miesc:5.1.0 \
            export /contracts/results.json \
            -f sarif \
            -o /contracts/results.sarif.json

      - name: Subir a GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: miesc-scan
        name: MIESC Security Scan
        entry: miesc scan
        language: system
        files: \.sol$
        args: ['--ci']
```

### GitLab CI

```yaml
security-audit:
  image: ghcr.io/fboiero/miesc:5.1.0
  stage: test
  script:
    - miesc audit quick ./contracts --ci -o results.json
  artifacts:
    paths:
      - results.json
    reports:
      sast: results.json
```

---

## Mejores Prácticas

### Antes de la Auditoría

1. **Entender el alcance del proyecto**
   - Cantidad y complejidad de contratos
   - Dependencias y llamadas externas
   - Integraciones DeFi (si las hay)

2. **Configurar el entorno**
   - Usar Docker para resultados consistentes
   - Asegurar que Ollama esté corriendo para funciones LLM
   - Verificar disponibilidad de herramientas con `miesc doctor`

3. **Revisar documentación existente**
   - README y especificaciones del proyecto
   - Reportes de auditorías previas (si existen)
   - Problemas o limitaciones conocidas

### Durante la Auditoría

1. **Empezar con triaje**
   ```bash
   miesc scan contract.sol
   ```

2. **Ejecutar auditoría rápida primero**
   ```bash
   miesc audit quick ./contracts -o results-quick.json
   ```

3. **Revisar hallazgos críticos inmediatamente**
   - No esperar a la auditoría completa para marcar problemas críticos
   - Comunicar al cliente si se encuentran problemas bloqueantes

4. **Ejecutar auditoría completa**
   ```bash
   miesc audit full ./contracts --skip-unavailable -o results-full.json
   ```

5. **Profundización por capas específicas**
   - Usar `audit layer` para preocupaciones específicas
   - Enfocarse en capas relevantes al tipo de contrato

6. **Documentar falsos positivos**
   - Anotar por qué cada falso positivo fue descartado
   - Incluir en el reporte final

### Después de la Auditoría

1. **Generar múltiples reportes**
   - Premium/Professional para cliente
   - Executive para gerencia
   - Technical para desarrolladores

2. **Verificar remediación**
   - Re-ejecutar auditoría después de correcciones
   - Usar `miesc benchmark` para seguir mejoras

3. **Archivar resultados**
   - Guardar resultados JSON para referencia futura
   - Almacenar reportes con documentación del proyecto

---

## Ejemplos de Flujos de Trabajo

### Flujo 1: Revisión Rápida de PR (15 minutos)

```bash
# 1. Escaneo rápido
miesc scan ./contracts/NewFeature.sol

# 2. Si hay problemas, obtener detalles
miesc audit quick ./contracts -o pr-review.json

# 3. Generar comentario de PR
miesc report pr-review.json -t github-pr -f markdown
```

### Flujo 2: Auditoría Pre-Despliegue (4 horas)

```bash
# 1. Triaje
miesc scan ./contracts

# 2. Auditoría completa
miesc audit full ./contracts --skip-unavailable -o full-audit.json

# 3. Generar reportes
miesc report full-audit.json -t premium --llm-interpret -f pdf -o client-report.pdf
miesc report full-audit.json -t executive -f pdf -o executive-summary.pdf
miesc report full-audit.json -t technical -f markdown -o dev-findings.md

# 4. Exportar para CI
miesc export full-audit.json -f sarif -o results.sarif.json
```

### Flujo 3: Auditoría de Protocolo DeFi (1 día)

```bash
# 1. Triaje rápido
miesc scan ./contracts

# 2. Análisis estático (Capa 1)
miesc audit layer 1 ./contracts -o layer1.json

# 3. Ejecución simbólica (Capa 3)
miesc audit layer 3 ./contracts -o layer3.json

# 4. Análisis económico (Capa 5)
miesc audit layer 5 ./contracts -o layer5.json

# 5. Análisis LLM para patrones DeFi (Capa 7)
miesc audit layer 7 ./contracts -o layer7.json

# 6. Auditoría completa para completitud
miesc audit full ./contracts --skip-unavailable -o full-audit.json

# 7. Reporte premium con IA
miesc report full-audit.json -t premium --llm-interpret -f pdf -o defi-audit.pdf
```

### Flujo 4: Monitoreo Continuo

```bash
# 1. Establecer línea base
miesc benchmark ./contracts --save

# 2. Vigilar cambios
miesc watch ./contracts --profile balanced

# 3. Comparar después de cambios
miesc benchmark ./contracts --compare last
```

---

## Referencia Rápida Docker

### Imagen Estándar (Más Común)

```bash
# Auditoría básica
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:5.1.0 \
  audit quick /contracts -o /contracts/results.json

# Con LLM (macOS)
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0 \
  audit full /contracts --skip-unavailable -o /contracts/results.json
```

### Imagen Completa (Exhaustiva)

```bash
# Auditoría completa con todas las herramientas
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0-full \
  audit full /contracts --skip-unavailable -o /contracts/results.json

# Generar reporte premium
docker run --rm -v $(pwd):/contracts \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:5.1.0-full \
  report /contracts/results.json \
  -t premium --llm-interpret -f pdf -o /contracts/report.pdf
```

---

## Soporte y Recursos

- **Documentación:** https://github.com/fboiero/MIESC/tree/main/docs
- **Issues:** https://github.com/fboiero/MIESC/issues
- **Imágenes Docker:** ghcr.io/fboiero/miesc
- **PyPI:** pip install miesc

---

*Versión del documento: 5.1.0 | Última actualización: Febrero 2026*
