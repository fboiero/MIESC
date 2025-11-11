# Configuración de Clientes MCP para MIESC

Guía completa para conectar MIESC con diferentes clientes MCP open source.

---

## 📋 Tabla de Contenidos

- [Clientes Open Source Disponibles](#clientes-open-source-disponibles)
- [Configuración por Cliente](#configuración-por-cliente)
- [Servidor MCP de MIESC](#servidor-mcp-de-miesc)
- [Testing y Validación](#testing-y-validación)

---

## Clientes Open Source Disponibles

### 🖥️ Desktop AI Assistants

#### 1. **5ire** (Recomendado)
**Descripción**: Cliente cross-platform desktop AI con soporte nativo MCP

**Características**:
- ✅ Open source
- ✅ Cross-platform (Windows, macOS, Linux)
- ✅ MCP servers built-in enable/disable
- ✅ Interface gráfica amigable

**Repository**: GitHub - buscar "5ire AI assistant"

**Ventajas para MIESC**:
- Setup rápido
- No requiere configuración manual compleja
- Ideal para demostraciones

---

#### 2. **AIQL TUUI**
**Descripción**: Native desktop AI chat con multi-provider support

**Características**:
- ✅ Soporte múltiples proveedores (Anthropic, OpenAI, Deepseek, Qwen)
- ✅ Local AI models (vLLM, Ray)
- ✅ Aggregated API platforms (Openrouter)
- ✅ Cross-platform

**Ventajas para MIESC**:
- Flexibilidad de modelos
- Puede usar modelos locales (privacidad)
- Buen para experimentación

---

### 💻 IDE Integration

#### 3. **Amazon Q IDE** (Para desarrollo)
**Descripción**: Agentic coding assistant para IDEs

**IDEs Soportados**:
- VSCode
- JetBrains (PyCharm, IntelliJ)
- Visual Studio
- Eclipse

**Uso en MIESC**:
- Integración directa en workflow de desarrollo
- Auditorías desde el IDE
- Ideal para CI/CD local

---

#### 4. **Amp by Sourcegraph**
**Descripción**: Agentic coding tool con MCP

**IDEs Soportados**:
- VS Code
- Cursor
- Windsurf
- VSCodium
- JetBrains
- Neovim
- CLI

**Ventajas para MIESC**:
- CLI disponible (scripting)
- Multi-IDE support
- Good para workflows automatizados

---

### 🧪 Testing Tools

#### 5. **Apify MCP Tester**
**Descripción**: Standalone tester para MCP servers

**Características**:
- ✅ SSE (Server-Sent Events) support
- ✅ Authorization headers
- ✅ Ideal para testing

**Uso en MIESC**:
- Validar servidor antes de producción
- Testing de tools
- Debugging

---

### 📚 Libraries y SDKs

#### 6. **AgentAI (Rust)**
**Descripción**: Rust library para crear AI agents con MCP

**Uso en MIESC**:
- Crear clientes custom en Rust
- Performance crítico
- Integración en sistemas existentes

---

## Configuración por Cliente

### 🖥️ Configuración 5ire (Recomendado)

**Paso 1: Instalar 5ire**
```bash
# Descargar desde GitHub releases
# https://github.com/5ire-tech/5ire-ai-assistant

# macOS
brew install 5ire

# Linux
sudo apt install 5ire

# Windows
# Descargar installer
```

**Paso 2: Configurar MIESC Server**

Crear archivo de configuración en `~/.5ire/config.json`:

```json
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/xaudit/mcp_server.py", "--stdio"],
      "env": {
        "PYTHONPATH": "/path/to/xaudit"
      },
      "description": "MIESC Smart Contract Security Framework",
      "icon": "🛡️"
    }
  }
}
```

**Paso 3: Iniciar 5ire**
```bash
5ire
```

**Paso 4: Habilitar MIESC Server**
- En interfaz de 5ire: Settings → MCP Servers
- Toggle "miesc" → ON
- Verificar status: verde = conectado

**Paso 5: Usar Tools**
```
Prompt en 5ire:
"Use miesc to audit the contract at examples/vulnerable_bank.sol with balanced priority"
```

---

### 💻 Configuración AIQL TUUI

**Paso 1: Instalar AIQL TUUI**
```bash
# Clonar repositorio
git clone https://github.com/aiql/tuui
cd tuui

# Build
cargo build --release

# Instalar
cargo install --path .
```

**Paso 2: Configurar MCP**

Crear `~/.config/aiql-tuui/mcp.toml`:

```toml
[[servers]]
name = "miesc"
command = "python"
args = ["/path/to/xaudit/mcp_server.py", "--stdio"]
description = "MIESC Smart Contract Auditor"
auto_enable = true

[servers.env]
PYTHONPATH = "/path/to/xaudit"
```

**Paso 3: Ejecutar**
```bash
aiql-tuui
```

**Paso 4: Seleccionar Provider**
- Anthropic (Claude)
- OpenAI (GPT-4)
- Local (Llama, Mistral via vLLM)

**Paso 5: Usar MIESC**
```
Prompt:
"Run a static analysis on examples/voting.sol using miesc"
```

---

### 🧪 Configuración Apify MCP Tester

**Paso 1: Instalar**
```bash
npm install -g @apify/mcp-tester
```

**Paso 2: Test MIESC Server**
```bash
mcp-test --server "python /path/to/xaudit/mcp_server.py --stdio"
```

**Paso 3: Ver Tools Disponibles**
```bash
mcp-test --server "python /path/to/xaudit/mcp_server.py --stdio" --list-tools
```

**Output Esperado**:
```
Available Tools:
✓ audit_contract
✓ static_analysis
✓ ai_triage
✓ compliance_check
✓ get_audit_status
✓ export_audit_trail
```

**Paso 4: Test Individual Tool**
```bash
mcp-test --server "python /path/to/xaudit/mcp_server.py --stdio" \
  --tool audit_contract \
  --args '{"contract_path": "examples/voting.sol", "priority": "fast"}'
```

---

### 💻 Configuración Amazon Q IDE (VSCode)

**Paso 1: Instalar Extension**
```bash
# En VSCode
Ctrl+Shift+X → Buscar "Amazon Q"
```

**Paso 2: Configurar MCP en settings.json**
```json
{
  "amazonq.mcp.servers": {
    "miesc": {
      "command": "python",
      "args": ["/absolute/path/to/xaudit/mcp_server.py", "--stdio"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/xaudit"
      }
    }
  }
}
```

**Paso 3: Usar desde Q Chat**
```
Prompt en Amazon Q:
"Use miesc to run compliance check on the current Solidity file"
```

---

### 🔧 Configuración Amp (CLI)

**Paso 1: Instalar**
```bash
npm install -g @sourcegraph/amp
```

**Paso 2: Configurar MCP**

Crear `~/.amp/config.json`:
```json
{
  "mcp": {
    "servers": {
      "miesc": {
        "command": "python",
        "args": ["/path/to/xaudit/mcp_server.py", "--stdio"]
      }
    }
  }
}
```

**Paso 3: Usar desde CLI**
```bash
amp ask "Audit examples/vulnerable_bank.sol using miesc comprehensive priority"
```

---

## Servidor MCP de MIESC

### Tools Disponibles

| Tool | Descripción | Input | Output |
|------|-------------|-------|--------|
| `audit_contract` | Auditoría completa multiagente | contract_path, priority, layers | audit_summary |
| `static_analysis` | Análisis estático (Layer 1) | contract_path, solc_version | static_findings |
| `ai_triage` | Triage con IA (Layer 6) | contract_path | triaged_findings |
| `compliance_check` | Verificación ISO/NIST/OWASP | contract_path | compliance_report |
| `get_audit_status` | Estado actual de auditoría | - | audit_status |
| `export_audit_trail` | Exportar logs compliance | output_path | audit_trail_path |

### Iniciar Servidor Standalone

```bash
# Modo stdio (para clientes MCP)
python mcp_server.py --stdio

# Ver configuración sugerida
python mcp_server.py --host localhost --port 3000
```

### Verificar Servidor

**Test con Python**:
```python
import subprocess
import json

# Start server
process = subprocess.Popen(
    ["python", "mcp_server.py", "--stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True
)

# Send initialize
init_msg = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {}
}

process.stdin.write(json.dumps(init_msg) + "\n")
process.stdin.flush()

# Read response
response = process.stdout.readline()
print(json.loads(response))
```

---

## Testing y Validación

### Test Suite Completo

**1. Test Conexión**
```bash
# Verificar que servidor arranca
python mcp_server.py --stdio &
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' | nc -U /tmp/mcp.sock
```

**2. Test Tools**
```bash
# Con Apify MCP Tester
mcp-test --server "python mcp_server.py --stdio" --test-all
```

**3. Test E2E**
```bash
# Con cliente real (5ire o AIQL)
# Ejecutar: "Use miesc to audit examples/voting.sol"
# Verificar output
```

### Debugging

**Habilitar logs verbose**:
```python
# En mcp_server.py, cambiar:
logging.basicConfig(level=logging.DEBUG)
```

**Ver mensajes MCP**:
```bash
# Logs del servidor
tail -f /tmp/miesc_mcp.log

# Logs del cliente (5ire)
tail -f ~/.5ire/logs/mcp.log
```

---

## Comparativa de Clientes

| Cliente | Facilidad Setup | Features | Mejor Para |
|---------|-----------------|----------|------------|
| **5ire** | ⭐⭐⭐⭐⭐ | UI, Multi-server | Demos, presentaciones |
| **AIQL TUUI** | ⭐⭐⭐⭐ | Multi-provider, Local models | Experimentación |
| **Amazon Q** | ⭐⭐⭐⭐ | IDE integration | Desarrollo diario |
| **Amp** | ⭐⭐⭐ | CLI, Multi-IDE | Automation |
| **Apify Tester** | ⭐⭐⭐⭐⭐ | Testing only | Validación |

---

## Recomendaciones por Caso de Uso

### 🎓 Defensa de Tesis
**Cliente**: 5ire
**Razón**: Interface visual, setup rápido, impresionante

### 👨‍💻 Desarrollo Diario
**Cliente**: Amazon Q IDE o Amp
**Razón**: Integración en workflow existente

### 🧪 Testing y CI/CD
**Cliente**: Amp (CLI) o Apify Tester
**Razón**: Scripteable, automatizable

### 🔬 Investigación
**Cliente**: AIQL TUUI
**Razón**: Flexibilidad de modelos, local models

---

## Instalación Rápida (Ubuntu/macOS)

```bash
#!/bin/bash
# Quick setup script

# 1. Install 5ire (recommended)
curl -fsSL https://5ire.tech/install.sh | sh

# 2. Configure MIESC
mkdir -p ~/.5ire
cat > ~/.5ire/config.json <<EOF
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["$(pwd)/mcp_server.py", "--stdio"],
      "env": {"PYTHONPATH": "$(pwd)"}
    }
  }
}
EOF

# 3. Test
python mcp_server.py --stdio <<< '{"jsonrpc":"2.0","id":1,"method":"initialize"}'

echo "✅ Setup complete! Run: 5ire"
```

---

## Troubleshooting

### Servidor no arranca
```bash
# Verificar Python
python --version  # Debe ser 3.10+

# Verificar dependencias
pip install -r requirements.txt

# Test directo
python mcp_server.py --stdio
```

### Cliente no ve tools
```bash
# Verificar protocolo MCP
# El servidor debe responder a "initialize"

# Test con curl:
echo '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | \
  python mcp_server.py --stdio
```

### Timeout en audit_contract
```bash
# Aumentar timeout del cliente
# En config: "timeout": 600000  # 10 minutos
```

---

## Referencias

- [MCP Official Docs](https://modelcontextprotocol.io/)
- [MCP GitHub](https://github.com/modelcontextprotocol)
- [Example Clients](https://modelcontextprotocol.io/clients)
- [5ire Repository](https://github.com/5ire-tech/5ire-ai-assistant)
- [AIQL TUUI](https://github.com/aiql/tuui)
- [Amazon Q IDE](https://docs.aws.amazon.com/amazonq/)
- [Apify MCP Tester](https://github.com/apify/mcp-tester)

---

## Próximos Pasos

1. **Instalar cliente recomendado**: 5ire
2. **Configurar MIESC server**: Copiar config
3. **Test con contrato ejemplo**: voting.sol
4. **Documentar en tesis**: Screenshots + resultados

---

**Última Actualización**: Octubre 2025
**Mantenedor**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
**Version MCP**: 1.0
