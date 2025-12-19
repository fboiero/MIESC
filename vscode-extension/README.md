# MIESC Security Auditor - VS Code Extension

<p align="center">
  <img src="media/shield.svg" alt="MIESC Logo" width="128" height="128">
</p>

**Multi-layer Intelligent Evaluation for Smart Contracts**

Extensión de Visual Studio Code para auditoría de seguridad de smart contracts Solidity utilizando el framework MIESC de 7 capas de defensa en profundidad.

## Características

### Análisis Multi-Capa

- **Capa 1**: Análisis estático (Slither, Solhint)
- **Capa 2**: Fuzzing (Echidna, Foundry)
- **Capa 3**: Ejecución simbólica (Mythril, Manticore)
- **Capa 4**: Testing de invariantes (Medusa)
- **Capa 5**: Verificación formal (Certora, SMTChecker)
- **Capa 6**: Property testing (Halmos)
- **Capa 7**: Análisis con IA soberana (Ollama/DeepSeek)

### Funcionalidades

- **Quick Scan**: Análisis rápido solo con Capa 1
- **Full Audit**: Auditoría completa con todas las 7 capas
- **Auto-audit on Save**: Escaneo automático al guardar archivos `.sol`
- **Inline Diagnostics**: Warnings y errores directamente en el editor
- **Sidebar Panel**: Vista de hallazgos organizados por severidad
- **HTML Reports**: Reportes detallados con remediaciones

## Requisitos

- VS Code 1.85.0+
- Python 3.9+
- MIESC instalado (`pip install miesc` o desde fuente)
- Herramientas de análisis (Slither, Mythril, etc.)

## Instalación

### Desde VSIX (Recomendado)

```bash
# En el directorio vscode-extension
npm install
npm run compile
npm run package
code --install-extension miesc-security-auditor-0.1.0.vsix
```

### Desde Código Fuente

```bash
cd vscode-extension
npm install
npm run compile
# Presiona F5 en VS Code para abrir Extension Development Host
```

## Configuración

| Setting | Descripción | Default |
|---------|-------------|---------|
| `miesc.serverUrl` | URL del servidor REST de MIESC | `http://localhost:8000` |
| `miesc.pythonPath` | Path al intérprete Python | `python3` |
| `miesc.miescPath` | Directorio de instalación de MIESC | `` |
| `miesc.defaultLayers` | Capas por defecto | `[1, 2, 3, 7]` |
| `miesc.autoAuditOnSave` | Auto-scan al guardar | `false` |
| `miesc.showInlineWarnings` | Mostrar warnings inline | `true` |
| `miesc.severityThreshold` | Severidad mínima a mostrar | `medium` |
| `miesc.timeout` | Timeout en segundos | `300` |
| `miesc.useLocalLLM` | Usar LLM local (Ollama) | `true` |
| `miesc.ollamaModel` | Modelo de Ollama | `deepseek-coder:6.7b` |

## Comandos

| Comando | Keybinding | Descripción |
|---------|------------|-------------|
| `MIESC: Audit Current File` | `Ctrl+Shift+M` / `Cmd+Shift+M` | Auditar archivo actual |
| `MIESC: Quick Scan` | `Ctrl+Shift+Q` / `Cmd+Shift+Q` | Scan rápido (solo Capa 1) |
| `MIESC: Deep Audit` | - | Auditoría profunda (7 capas) |
| `MIESC: Audit Workspace` | - | Auditar todo el workspace |
| `MIESC: Audit Selection` | - | Auditar código seleccionado |
| `MIESC: Configure Layers` | - | Configurar capas activas |
| `MIESC: Show Report` | - | Mostrar último reporte |
| `MIESC: Start Server` | - | Iniciar servidor MIESC |
| `MIESC: Stop Server` | - | Detener servidor MIESC |

## Uso

### Quick Start

1. Abrir un archivo `.sol` en VS Code
2. Presionar `Ctrl+Shift+M` (o `Cmd+Shift+M` en Mac)
3. Ver resultados en el panel lateral y diagnósticos inline

### Menú Contextual

Click derecho en un archivo `.sol`:
- En el editor: "MIESC: Audit Current File"
- Con texto seleccionado: "MIESC: Audit Selected Code"
- En el explorador: "MIESC: Audit Current File"

### Sidebar

La extensión añade un panel "MIESC Security" en la barra de actividad con:
- **Security Findings**: Hallazgos organizados por severidad
- **Analysis Layers**: Estado de cada capa
- **Audit History**: Historial de auditorías

## Arquitectura

```
┌─────────────────────────────────────────────┐
│           VS Code Extension                  │
│  ┌────────────────────────────────────────┐ │
│  │  Commands → REST Client → MIESC Server │ │
│  └────────────────────────────────────────┘ │
│           ↓                                  │
│  ┌────────────────────────────────────────┐ │
│  │   DiagnosticCollection (Warnings)      │ │
│  │   TreeView (Findings)                  │ │
│  │   WebView (HTML Reports)               │ │
│  └────────────────────────────────────────┘ │
└─────────────────────────────────────────────┘
                    ↓ HTTP
┌─────────────────────────────────────────────┐
│         MIESC REST API Server               │
│  ┌───┬───┬───┬───┬───┬───┬───┐             │
│  │ L1│ L2│ L3│ L4│ L5│ L6│ L7│  7 Capas   │
│  └───┴───┴───┴───┴───┴───┴───┘             │
└─────────────────────────────────────────────┘
```

## Desarrollo

### Setup

```bash
git clone https://github.com/fboiero/MIESC.git
cd MIESC/vscode-extension
npm install
```

### Build

```bash
npm run compile    # Compilar TypeScript
npm run watch      # Watch mode
npm run lint       # Linting
npm run test       # Tests
npm run package    # Crear VSIX
```

### Debug

1. Abrir la carpeta `vscode-extension` en VS Code
2. Presionar `F5` para iniciar Extension Development Host
3. En la nueva ventana, abrir un archivo `.sol`
4. Probar los comandos de MIESC

## Publicación

Para publicar en el Marketplace:

```bash
# Login con token de Azure DevOps
vsce login miesc

# Publicar
vsce publish
```

## Troubleshooting

### "MIESC server not running"

```bash
# Iniciar servidor manualmente
cd /path/to/MIESC
python -m src.miesc_mcp_rest --host localhost --port 8000
```

### "Python not found"

Configurar `miesc.pythonPath` con la ruta correcta al intérprete Python.

### "Timeout during analysis"

Incrementar `miesc.timeout` en la configuración o usar Quick Scan para análisis más rápidos.

## Licencia

GPL-3.0 - Ver [LICENSE](../LICENSE)

## Autor

**Fernando Boiero**
fboiero@undef.edu.ar
Maestría en Ciberdefensa - UNDEF

## Links

- [MIESC Repository](https://github.com/fboiero/MIESC)
- [Documentation](https://github.com/fboiero/MIESC/docs)
- [Issue Tracker](https://github.com/fboiero/MIESC/issues)
