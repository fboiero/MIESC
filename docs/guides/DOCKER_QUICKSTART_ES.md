# MIESC Docker - Guía Rápida

Guía rápida para ejecutar auditorías de seguridad usando MIESC con Docker. No requiere instalación.

**[English Version](DOCKER_QUICKSTART.md)**

---

## Requisitos Previos

| Requisito | Detalles |
|-----------|----------|
| **Docker Desktop** | Versión 20+ con 8GB+ RAM |
| **Ollama** | Para análisis con IA (opcional pero recomendado) |
| **Espacio en disco** | ~12GB (imagen Docker ~4GB + modelos LLM ~8GB) |

### Instalar Ollama (para funciones de IA)

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Descargar modelos de IA (una sola vez, ~8GB total)
ollama pull deepseek-coder:6.7b
ollama pull codellama
ollama pull mistral

# Iniciar Ollama (mantener corriendo en segundo plano)
ollama serve
```

---

## 1. Preparar Tus Contratos

Crea una carpeta y coloca tus archivos `.sol` ahí:

```bash
mkdir contracts
cd contracts

# Copia tus contratos aquí
cp /ruta/a/MiToken.sol .
cp /ruta/a/MiVault.sol .
```

> **Nota:** Esta carpeta `contracts/` es donde colocas los contratos que quieres auditar. MIESC analizará todos los archivos `.sol` que encuentre aquí.

### Contratos de Ejemplo para Pruebas

Si quieres probar con contratos vulnerables:

```bash
# Descargar ejemplos reales de contratos vulnerables
curl -O https://raw.githubusercontent.com/crytic/not-so-smart-contracts/master/reentrancy/Reentrancy.sol
curl -O https://raw.githubusercontent.com/crytic/not-so-smart-contracts/master/integer_overflow/integer_overflow_1.sol
```

**Repositorios con contratos vulnerables para demos:**

| Repositorio | Descripción |
|-------------|-------------|
| [crytic/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts) | Ejemplos clásicos de vulnerabilidades |
| [SunWeb3Sec/DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) | Vulnerabilidades DeFi reales |
| [smartbugs/smartbugs](https://github.com/smartbugs/smartbugs) | Dataset de contratos vulnerables |

---

## 2. Escaneo Rápido (~30 segundos)

Análisis rápido con 4 herramientas:

```bash
docker run --rm -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:latest \
  scan /contracts/MiContrato.sol
```

---

## 3. Auditoría Completa con IA (5-8 min)

Auditoría completa de 9 capas con 30+ herramientas:

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MiContrato.sol \
  --skip-unavailable \
  -o /contracts/resultados.json
```

---

## 4. Auditoría por Lotes (Todos los Contratos)

Auditar todos los contratos en la carpeta:

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts \
  -o /contracts/resultados_batch.json
```

---

## 5. Generar Reporte PDF Profesional (2-3 min)

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/resultados.json \
  -t premium -f pdf \
  --llm-interpret \
  --client "Nombre del Cliente" \
  --auditor "Tu Nombre" \
  --contract-name "Nombre del Proyecto" \
  -o /contracts/reporte_auditoria.pdf

# Abrir el PDF
open reporte_auditoria.pdf   # macOS
xdg-open reporte_auditoria.pdf   # Linux
```

---

## 6. Ver Herramientas Disponibles

```bash
# Sin Ollama (solo herramientas estáticas)
docker run --rm ghcr.io/fboiero/miesc:full doctor

# Con Ollama (incluye adaptadores LLM)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  ghcr.io/fboiero/miesc:full doctor
```

---

## Estructura de Carpetas

Después de ejecutar auditorías, tu carpeta se verá así:

```
contracts/                        ← Tu carpeta de contratos
├── MiToken.sol                  ← Tus contratos .sol
├── MiVault.sol
├── resultados.json              ← Resultados de auditoría (generado)
├── resultados_batch.json        ← Resultados por lotes (generado)
└── reporte_auditoria.pdf        ← Reporte PDF (generado)
```

---

## Referencia de Comandos

| Comando | Tiempo | Descripción |
|---------|--------|-------------|
| `scan` | 30s | Análisis rápido 4 herramientas |
| `audit quick` | 1min | Escaneo básico |
| `audit full` | 5-8min | 9 capas, 30+ herramientas, IA |
| `audit batch` | variable | Múltiples contratos |
| `report -t premium` | 2-3min | PDF profesional con IA |
| `doctor` | 10s | Mostrar herramientas disponibles |

---

## Imágenes Docker Disponibles

| Imagen | Tamaño | Contenido |
|--------|--------|-----------|
| `ghcr.io/fboiero/miesc:latest` | ~3GB | Estándar: Slither, Aderyn, Solhint, Foundry (~15 herramientas) |
| `ghcr.io/fboiero/miesc:full` | ~4GB | Completa: + Mythril, Halmos, Semgrep, Wake (~30 herramientas) |

---

## Solución de Problemas

### "Cannot connect to Ollama"

```bash
# Asegúrate de que Ollama esté corriendo
ollama list

# Si no está corriendo, iniciarlo
ollama serve
```

### "Out of memory"

- Aumenta la RAM de Docker Desktop a 10GB+ en Settings → Resources

### Usuarios de Linux

Usa `--network host` en lugar de `host.docker.internal`:

```bash
docker run --rm --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd):/contracts \
  ghcr.io/fboiero/miesc:full \
  audit full /contracts/MiContrato.sol
```

---

## Documentación

- **Guía completa:** [DOCKER_AUDIT_GUIDE_ES.md](DOCKER_AUDIT_GUIDE_ES.md)
- **Sitio web:** https://fboiero.github.io/MIESC
- **Repositorio:** https://github.com/fboiero/MIESC
