# Guia Completa: Auditoria con Docker + LLM

Guia paso a paso para ejecutar una auditoria completa de smart contracts usando Docker y generar un reporte PDF profesional con interpretacion de IA.

**Tiempo estimado de setup**: primera vez ~15 min (descarga de imagenes y modelos). Ejecuciones posteriores: solo pasos 3-5.

---

## Requisitos

| Requisito | Detalle |
|-----------|---------|
| **Docker Desktop** | Version 20+ con **8GB+ de RAM** asignados |
| **Ollama** | Para la interpretacion IA del reporte |
| **Espacio en disco** | ~12GB (imagen Docker ~8GB + modelo LLM ~4GB) |

---

## Paso 1: Instalar y configurar Docker

Descargar Docker Desktop desde https://www.docker.com/products/docker-desktop

**Configurar memoria (obligatorio):**

- Docker Desktop → Settings → Resources → Memory → **8GB** (o mas)
- Apply & Restart

**Descargar la imagen FULL de MIESC** (incluye las 50 herramientas):

```bash
docker pull ghcr.io/fboiero/miesc:full
```

> **ARM / Apple Silicon:** La imagen `:full` del registry es solo amd64. En ARM corre bajo emulacion QEMU (~3-5x mas lento). Para rendimiento nativo, construi localmente con `./scripts/build-images.sh full` o usa el wizard `./scripts/docker-setup.sh`. La imagen `:latest` (standard) es multi-arch y funciona nativamente en ARM.

Verificar que funciona:

```bash
docker run --rm ghcr.io/fboiero/miesc:full --version
# Debe mostrar: MIESC version 5.1.0

docker run --rm ghcr.io/fboiero/miesc:full doctor
# Muestra las ~30 herramientas disponibles
```

---

## Paso 2: Instalar Ollama y descargar el modelo de IA

### macOS

```bash
brew install ollama
```

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Windows

Descargar desde https://ollama.com/download

### Iniciar Ollama y descargar el modelo

```bash
# Iniciar el servicio (dejarlo corriendo en una terminal)
ollama serve

# En otra terminal, descargar el modelo de interpretacion (~4GB)
ollama pull mistral:latest

# Verificar que esta disponible
ollama list
# Debe mostrar: mistral:latest
```

> **Nota:** `ollama serve` debe estar corriendo durante toda la auditoria. Si cerras la terminal, el paso 4 no va a poder generar los insights de IA.

---

## Paso 3: Preparar los contratos

Poner todos los archivos `.sol` que quieras auditar en una carpeta:

```bash
mkdir mis_contratos
cp MiToken.sol MiVault.sol mis_contratos/

# Verificar que estan los archivos
ls mis_contratos/
# MiToken.sol  MiVault.sol
```

---

## Paso 4: Ejecutar la auditoria completa

Esto ejecuta las 9 capas de analisis (estatico, dinamico, simbolico, verificacion formal, IA, ML, etc.) sobre todos los contratos de la carpeta:

```bash
docker run --rm \
  -v $(pwd)/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

**En Windows PowerShell** reemplazar `$(pwd)` por `${PWD}`:

```powershell
docker run --rm `
  -v ${PWD}/mis_contratos:/contracts `
  ghcr.io/fboiero/miesc:full `
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

Al finalizar vas a ver un resumen como este:

```
    Batch Analysis Summary
╭────────────────────┬────────╮
│ Metric             │  Value │
├────────────────────┼────────┤
│ Contracts Analyzed │      9 │
│ CRITICAL           │      0 │
│ HIGH               │      4 │
│ MEDIUM             │      3 │
│ LOW                │     39 │
│ TOTAL FINDINGS     │     73 │
╰────────────────────┴────────╯
OK Report saved to /contracts/results.json
```

---

## Paso 5: Generar el reporte PDF profesional con IA

### macOS / Windows

```bash
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Nombre del Cliente" \
    --auditor "Tu Nombre" \
    --contract-name "Nombre del Proyecto" \
    --network "Ethereum Mainnet" \
    --classification "CONFIDENTIAL" \
    -o /contracts/reporte_auditoria.pdf
```

### Linux

```bash
docker run --rm --network host \
  -e OLLAMA_HOST=http://localhost:11434 \
  -v $(pwd)/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Nombre del Cliente" \
    --auditor "Tu Nombre" \
    --contract-name "Nombre del Proyecto" \
    --network "Ethereum Mainnet" \
    --classification "CONFIDENTIAL" \
    -o /contracts/reporte_auditoria.pdf
```

### Windows PowerShell

```powershell
docker run --rm `
  -e OLLAMA_HOST=http://host.docker.internal:11434 `
  -v ${PWD}/mis_contratos:/contracts `
  ghcr.io/fboiero/miesc:full `
  report /contracts/results.json -t premium -f pdf `
    --llm-interpret `
    --client "Nombre del Cliente" `
    --auditor "Tu Nombre" `
    --contract-name "Nombre del Proyecto" `
    --network "Ethereum Mainnet" `
    --classification "CONFIDENTIAL" `
    -o /contracts/reporte_auditoria.pdf
```

**Personalizar estos campos:**

| Campo | Que poner | Ejemplo |
|-------|-----------|---------|
| `--client` | Nombre del cliente o empresa | `"Acme Corp"` |
| `--auditor` | Nombre del auditor | `"Fernando Boiero"` |
| `--contract-name` | Nombre del contrato o proyecto | `"TokenV2.sol"` |
| `--network` | Red de despliegue | `"Ethereum Mainnet"`, `"Polygon"`, `"BSC"` |
| `--classification` | Clasificacion del reporte | `"CONFIDENTIAL"`, `"PUBLIC"`, `"INTERNAL"` |

---

## Paso 6: Abrir el reporte

El PDF queda en la carpeta de contratos:

```bash
# macOS
open mis_contratos/reporte_auditoria.pdf

# Linux
xdg-open mis_contratos/reporte_auditoria.pdf

# Windows
start mis_contratos\reporte_auditoria.pdf
```

---

## Que incluye el reporte

El reporte PDF profesional (estilo Trail of Bits / OpenZeppelin) incluye:

- **Portada** con clasificacion de confidencialidad
- **Resumen ejecutivo** con analisis de riesgo de negocio generado por IA
- **Recomendacion de despliegue**: GO / NO-GO / CONDICIONAL
- **Matriz de riesgo** con scoring CVSS
- **Hallazgos detallados** con escenarios de ataque paso a paso
- **Sugerencias de remediacion** con diffs de codigo
- **Hoja de ruta de remediacion** priorizada
- **PoC de exploits** para hallazgos criticos/altos
- **Nota de disclosure IA** para transparencia

---

## Solucion de problemas

### "Cannot connect to Ollama" o "LLM interpretation failed"

```bash
# Verificar que Ollama esta corriendo
ollama list

# Si no esta corriendo, iniciarlo
ollama serve
```

### "Out of memory" o Docker se cuelga

- Aumentar la RAM de Docker Desktop a **10GB+** en Settings → Resources
- Cerrar otras aplicaciones pesadas

### El PDF no se genera (solo genera HTML)

La conversion a PDF necesita WeasyPrint. Si falla, el reporte se guarda como HTML. Se puede convertir manualmente:

```bash
# Instalar weasyprint
pip install weasyprint  # o: brew install weasyprint

# Convertir
weasyprint mis_contratos/reporte_auditoria.html mis_contratos/reporte_auditoria.pdf
```

### "Contract file not found"

```bash
# Verificar que el volumen esta bien montado
# El path DENTRO del container debe coincidir con el mount
docker run --rm -v /ruta/completa/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r
```

---

## Referencia rapida (copiar y pegar)

```bash
# === SETUP (solo la primera vez) ===
docker pull ghcr.io/fboiero/miesc:full
ollama pull mistral:latest

# === AUDITORIA (cada vez) ===
# 1. Asegurate de que Ollama este corriendo
ollama serve &

# 2. Poner los .sol en una carpeta
mkdir mis_contratos && cp *.sol mis_contratos/

# 3. Auditoria completa
docker run --rm \
  -v $(pwd)/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  audit batch /contracts -o /contracts/results.json -p thorough -r

# 4. Reporte PDF con IA (macOS/Windows)
docker run --rm \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -v $(pwd)/mis_contratos:/contracts \
  ghcr.io/fboiero/miesc:full \
  report /contracts/results.json -t premium -f pdf \
    --llm-interpret \
    --client "Cliente" \
    --auditor "Auditor" \
    -o /contracts/reporte_auditoria.pdf

# 5. Abrir el PDF
open mis_contratos/reporte_auditoria.pdf
```

---

**Documentacion completa:** https://fboiero.github.io/MIESC
**Repositorio:** https://github.com/fboiero/MIESC
