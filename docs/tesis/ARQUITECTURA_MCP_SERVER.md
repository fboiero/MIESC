# Arquitectura del MCP Server de MIESC

## Model Context Protocol: Integración con Asistentes de IA

---

## 1. Introducción

El Model Context Protocol (MCP) es un estándar abierto desarrollado por Anthropic que permite a modelos de lenguaje (LLMs) como Claude interactuar con herramientas externas de manera estructurada y segura. MIESC v4.0.0 implementa un servidor MCP que expone sus capacidades de auditoría de seguridad a asistentes de IA.

---

## 2. Diagrama de Arquitectura General

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ENTORNO DEL USUARIO                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────┐         ┌───────────────────────────────────────┐    │
│  │                   │         │                                       │    │
│  │   Claude Desktop  │◄───────►│         MCP Protocol (stdio)          │    │
│  │   o Claude.ai     │         │                                       │    │
│  │                   │         └───────────────────┬───────────────────┘    │
│  └───────────────────┘                             │                        │
│                                                    │                        │
│  ┌─────────────────────────────────────────────────▼──────────────────────┐ │
│  │                                                                         │ │
│  │                      MIESC MCP SERVER                                   │ │
│  │                                                                         │ │
│  │  ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                    MCP Handler Layer                             │   │ │
│  │  │                                                                   │   │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │ │
│  │  │  │ Tool        │  │ Resource    │  │     Prompt              │  │   │ │
│  │  │  │ Handler     │  │ Handler     │  │     Handler             │  │   │ │
│  │  │  │             │  │             │  │                         │  │   │ │
│  │  │  │ - analyze   │  │ - contracts │  │ - security_audit_prompt │  │   │ │
│  │  │  │ - quick_scan│  │ - reports   │  │ - vulnerability_explain │  │   │ │
│  │  │  │ - check_*   │  │ - configs   │  │                         │  │   │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │ │
│  │  └─────────────────────────────────────────────────────────────────┘   │ │
│  │                                    │                                    │ │
│  │  ┌─────────────────────────────────▼───────────────────────────────┐   │ │
│  │  │                   MIESC Core Engine                              │   │ │
│  │  │                                                                   │   │ │
│  │  │  ┌────────────────────────────────────────────────────────────┐  │   │ │
│  │  │  │                    Layer Orchestrator                       │  │   │ │
│  │  │  │                                                              │  │   │ │
│  │  │  │   Layer 1    Layer 2    Layer 3    Layer 4    Layer 5       │  │   │ │
│  │  │  │   Static     Fuzzing    Symbolic   Invariant  Formal        │  │   │ │
│  │  │  │   ────────   ────────   ────────   ────────   ────────      │  │   │ │
│  │  │  │   Slither    Echidna    Mythril    Scribble   SMTChecker    │  │   │ │
│  │  │  │   Solhint    Foundry    Manticore  Halmos     Certora       │  │   │ │
│  │  │  │   Securify2  Medusa     Oyente                              │  │   │ │
│  │  │  │   Semgrep    Vertigo                                        │  │   │ │
│  │  │  │                                                              │  │   │ │
│  │  │  │   Layer 6              Layer 7                              │  │   │ │
│  │  │  │   Property             AI Analysis                          │  │   │ │
│  │  │  │   ────────             ────────                             │  │   │ │
│  │  │  │   PropertyGPT          GPTScan                              │  │   │ │
│  │  │  │   Aderyn               SmartLLM                             │  │   │ │
│  │  │  │   Wake                 LLMSmartAudit                        │  │   │ │
│  │  │  │                        ThreatModel                          │  │   │ │
│  │  │  │                        GasGauge                             │  │   │ │
│  │  │  │                        UpgradeGuard                         │  │   │ │
│  │  │  │                        BestPractices                        │  │   │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │   │ │
│  │  │                                                                   │   │ │
│  │  │  ┌────────────────────────────────────────────────────────────┐  │   │ │
│  │  │  │              Normalization & Deduplication                  │  │   │ │
│  │  │  │                                                              │  │   │ │
│  │  │  │    Raw Findings ──► SWC Mapping ──► CWE Mapping            │  │   │ │
│  │  │  │                           │              │                  │  │   │ │
│  │  │  │                           ▼              ▼                  │  │   │ │
│  │  │  │                    ┌─────────────────────────┐              │  │   │ │
│  │  │  │                    │   OWASP Mapping         │              │  │   │ │
│  │  │  │                    └───────────┬─────────────┘              │  │   │ │
│  │  │  │                                │                            │  │   │ │
│  │  │  │                    ┌───────────▼─────────────┐              │  │   │ │
│  │  │  │                    │   Deduplication         │              │  │   │ │
│  │  │  │                    │   (Fellegi-Sunter)      │              │  │   │ │
│  │  │  │                    └─────────────────────────┘              │  │   │ │
│  │  │  └────────────────────────────────────────────────────────────┘  │   │ │
│  │  └───────────────────────────────────────────────────────────────────┘   │ │
│  │                                                                         │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                          EXTERNAL SERVICES                               │ │
│  ├──────────────────┬───────────────────┬───────────────────────────────────┤ │
│  │                  │                   │                                   │ │
│  │  ┌──────────┐    │  ┌────────────┐   │  ┌─────────────────────────────┐ │ │
│  │  │  Ollama  │    │  │   Docker   │   │  │      Solidity Compiler      │ │ │
│  │  │  Server  │    │  │   Engine   │   │  │          (solc)             │ │ │
│  │  │          │    │  │            │   │  │                             │ │ │
│  │  │ codellama│    │  │  Oyente    │   │  │  Compilation & AST          │ │ │
│  │  │ llama2   │    │  │  container │   │  │                             │ │ │
│  │  │ mistral  │    │  │            │   │  │                             │ │ │
│  │  └──────────┘    │  └────────────┘   │  └─────────────────────────────┘ │ │
│  │                  │                   │                                   │ │
│  └──────────────────┴───────────────────┴───────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Componentes del MCP Server

### 3.1 Tool Definitions

El servidor MCP expone las siguientes herramientas a Claude:

```python
# Herramientas disponibles via MCP
TOOLS = {
    "analyze_contract": {
        "description": "Perform comprehensive 7-layer security audit",
        "parameters": {
            "contract_path": "Path to Solidity file",
            "layers": "Optional: layers to run (1-7)",
            "timeout": "Optional: max execution time"
        },
        "returns": "Structured vulnerability report"
    },

    "quick_scan": {
        "description": "Fast Layer 1 static analysis only",
        "parameters": {
            "contract_path": "Path to Solidity file"
        },
        "returns": "Static analysis findings"
    },

    "check_reentrancy": {
        "description": "Specific check for reentrancy vulnerabilities",
        "parameters": {
            "contract_path": "Path to Solidity file"
        },
        "returns": "Reentrancy findings only"
    },

    "check_access_control": {
        "description": "Check for access control vulnerabilities",
        "parameters": {
            "contract_path": "Path to Solidity file"
        },
        "returns": "Access control findings"
    },

    "list_tools": {
        "description": "List available security analysis tools",
        "parameters": {},
        "returns": "List of 25 integrated tools with status"
    },

    "get_tool_status": {
        "description": "Check if specific tool is available",
        "parameters": {
            "tool_name": "Name of tool to check"
        },
        "returns": "Availability status and version"
    },

    "explain_vulnerability": {
        "description": "Get detailed explanation of vulnerability type",
        "parameters": {
            "swc_id": "SWC identifier (e.g., SWC-107)"
        },
        "returns": "Description, impact, and remediation"
    }
}
```

### 3.2 Resource Definitions

```python
# Recursos expuestos via MCP
RESOURCES = {
    "contracts": {
        "uri": "miesc://contracts/{path}",
        "description": "Access to contract files for analysis",
        "mimeType": "text/x-solidity"
    },

    "reports": {
        "uri": "miesc://reports/{analysis_id}",
        "description": "Access to previous analysis reports",
        "mimeType": "application/json"
    },

    "taxonomy": {
        "uri": "miesc://taxonomy/{type}",
        "description": "SWC, CWE, or OWASP taxonomy data",
        "mimeType": "application/json"
    }
}
```

---

## 4. Flujo de Comunicación

### 4.1 Secuencia de Análisis Completo

```
┌──────────┐          ┌──────────────┐          ┌──────────────┐
│  Claude  │          │  MCP Server  │          │ MIESC Engine │
└────┬─────┘          └──────┬───────┘          └──────┬───────┘
     │                       │                         │
     │  1. Tool Call         │                         │
     │  analyze_contract     │                         │
     │ ──────────────────────>                         │
     │                       │                         │
     │                       │  2. Validate Request    │
     │                       │ ─────────────────────────>
     │                       │                         │
     │                       │  3. Execute Layers      │
     │                       │ <─────────────────────────
     │                       │                         │
     │                       │     ┌─────────────────┐ │
     │                       │     │  Layer 1: 3.2s  │ │
     │                       │     │  Layer 2: 18.7s │ │
     │                       │     │  Layer 3: 52.4s │ │
     │                       │     │  Layer 4: 14.1s │ │
     │                       │     │  Layer 5: 9.8s  │ │
     │                       │     │  Layer 6: 21.3s │ │
     │                       │     │  Layer 7: 41.6s │ │
     │                       │     └─────────────────┘ │
     │                       │                         │
     │                       │  4. Normalize + Dedup   │
     │                       │ <─────────────────────────
     │                       │                         │
     │  5. Structured Result │                         │
     │ <──────────────────────                         │
     │                       │                         │
     │  6. Natural Language  │                         │
     │     Response          │                         │
     │                       │                         │
```

### 4.2 Formato de Respuesta MCP

```json
{
  "type": "tool_result",
  "content": [
    {
      "type": "text",
      "text": "## Security Audit Results\n\n### Summary\n- Total vulnerabilities: 16\n- Critical: 2\n- High: 5\n- Medium: 6\n- Low: 3\n\n### Critical Findings\n\n**1. Reentrancy Vulnerability (SWC-107)**\n- Location: VulnerableBank.sol:35\n- Function: withdraw()\n- Description: External call before state update...\n- Recommendation: Apply checks-effects-interactions pattern\n\n..."
    }
  ]
}
```

---

## 5. Configuración del MCP Server

### 5.1 Archivo de Configuración Claude Desktop

```json
// ~/.config/claude/claude_desktop_config.json (macOS/Linux)
// %APPDATA%/Claude/claude_desktop_config.json (Windows)

{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": [
        "-m", "miesc.mcp_server"
      ],
      "env": {
        "MIESC_LAYERS": "1,2,3,7",
        "OLLAMA_HOST": "http://localhost:11434",
        "MIESC_TIMEOUT": "300"
      }
    }
  }
}
```

### 5.2 Variables de Entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `MIESC_LAYERS` | Capas a ejecutar por defecto | `1,2,3,4,5,6,7` |
| `OLLAMA_HOST` | URL del servidor Ollama | `http://localhost:11434` |
| `OLLAMA_MODEL` | Modelo LLM a usar | `codellama:7b` |
| `MIESC_TIMEOUT` | Timeout máximo (segundos) | `300` |
| `MIESC_PARALLEL` | Ejecutar capas en paralelo | `true` |
| `MIESC_LOG_LEVEL` | Nivel de logging | `INFO` |

---

## 6. Implementación del Servidor

### 6.1 Estructura del Código

```
src/
├── mcp/
│   ├── __init__.py
│   ├── server.py           # Punto de entrada MCP
│   ├── tools.py             # Definiciones de herramientas
│   ├── resources.py         # Definiciones de recursos
│   ├── prompts.py           # Prompts predefinidos
│   └── formatters.py        # Formateadores de respuesta
├── adapters/
│   └── ... (25 adapters)
├── core/
│   ├── engine.py            # Motor de análisis
│   ├── normalizer.py        # Normalización
│   └── deduplicator.py      # Deduplicación
└── api/
    └── main.py              # API REST (alternativo)
```

### 6.2 Código del Servidor MCP

```python
# src/mcp/server.py
import asyncio
from mcp.server import Server
from mcp.types import Tool, Resource, TextContent
from typing import List, Dict, Any

from ..core.engine import MIESCEngine
from .tools import TOOL_DEFINITIONS
from .formatters import format_for_claude

# Inicializar servidor MCP
server = Server("miesc-security-audit")
engine = MIESCEngine()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """Lista herramientas disponibles para Claude."""
    return [
        Tool(
            name=name,
            description=info["description"],
            inputSchema={
                "type": "object",
                "properties": info.get("parameters", {}),
                "required": info.get("required", [])
            }
        )
        for name, info in TOOL_DEFINITIONS.items()
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Ejecuta herramienta solicitada por Claude."""

    if name == "analyze_contract":
        result = await engine.analyze_async(
            contract_path=arguments["contract_path"],
            layers=arguments.get("layers", [1, 2, 3, 7]),
            timeout=arguments.get("timeout", 300)
        )
        formatted = format_for_claude(result)
        return [TextContent(type="text", text=formatted)]

    elif name == "quick_scan":
        result = await engine.analyze_async(
            contract_path=arguments["contract_path"],
            layers=[1],  # Solo Layer 1
            timeout=60
        )
        formatted = format_for_claude(result, brief=True)
        return [TextContent(type="text", text=formatted)]

    elif name == "check_reentrancy":
        result = await engine.check_specific(
            contract_path=arguments["contract_path"],
            vulnerability_type="reentrancy"
        )
        formatted = format_for_claude(result)
        return [TextContent(type="text", text=formatted)]

    elif name == "list_tools":
        tools = engine.get_available_tools()
        formatted = format_tools_list(tools)
        return [TextContent(type="text", text=formatted)]

    elif name == "explain_vulnerability":
        explanation = engine.get_vulnerability_info(
            arguments["swc_id"]
        )
        return [TextContent(type="text", text=explanation)]

    else:
        return [TextContent(
            type="text",
            text=f"Unknown tool: {name}"
        )]

@server.list_resources()
async def list_resources() -> List[Resource]:
    """Lista recursos disponibles."""
    return [
        Resource(
            uri="miesc://contracts/",
            name="Contracts",
            description="Access to Solidity contracts for analysis"
        ),
        Resource(
            uri="miesc://reports/",
            name="Reports",
            description="Previous analysis reports"
        )
    ]

async def main():
    """Punto de entrada del servidor MCP."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 7. Ejemplos de Uso con Claude

### 7.1 Análisis Completo

**Usuario:** "Analiza el contrato VulnerableBank.sol para encontrar vulnerabilidades de seguridad"

**Claude (pensamiento interno):**
1. Necesito usar la herramienta de análisis de seguridad MIESC
2. Invocaré `analyze_contract` con el path del contrato

**Claude (invocación MCP):**
```json
{
  "tool": "analyze_contract",
  "arguments": {
    "contract_path": "contracts/audit/VulnerableBank.sol",
    "layers": [1, 2, 3, 7]
  }
}
```

**MIESC (respuesta):**
```markdown
## Security Audit Results for VulnerableBank.sol

### Summary
| Metric | Value |
|--------|-------|
| Total Findings | 16 |
| Critical | 2 |
| High | 5 |
| Medium | 6 |
| Low | 3 |
| Deduplication Rate | 66% |
| Analysis Time | 52.4s |

### Critical Findings

#### 1. Reentrancy (SWC-107)
- **Location:** VulnerableBank.sol:35, function `withdraw()`
- **Severity:** Critical
- **Confidence:** High
- **Detected by:** Slither, Mythril, GPTScan

**Description:**
External call to `msg.sender` at line 35 occurs before state
variable `balances[msg.sender]` is updated at line 39. This allows
an attacker to re-enter the function and drain funds.

**Code:**
```solidity
// Line 35: External call BEFORE state update
(bool success, ) = msg.sender.call{value: balance}("");
require(success, "Transfer failed");

// Line 39: State update AFTER external call
balances[msg.sender] = 0;  // Too late!
```

**Recommendation:**
Apply the Checks-Effects-Interactions pattern:
```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance");

    // 1. Effects: Update state FIRST
    balances[msg.sender] = 0;
    totalDeposits -= balance;

    // 2. Interactions: External call LAST
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
}
```

Alternatively, use OpenZeppelin's `ReentrancyGuard`.

---

#### 2. Unprotected Ether Withdrawal (SWC-105)
...
```

**Claude (respuesta al usuario):**

"He analizado el contrato VulnerableBank.sol y encontré **16 vulnerabilidades** (2 críticas, 5 altas, 6 medias, 3 bajas).

**Hallazgos Críticos:**

1. **Vulnerabilidad de Reentrancy (SWC-107)** en la función `withdraw()` línea 35. El contrato realiza una llamada externa antes de actualizar el estado, permitiendo que un atacante drene todos los fondos.

2. **Retiro de Ether no protegido (SWC-105)** también en `withdraw()`. Cualquier usuario puede retirar fondos sin validación adecuada.

**Recomendación principal:** Aplicar el patrón Checks-Effects-Interactions - actualiza el estado **antes** de hacer llamadas externas:

```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0, "No balance");

    balances[msg.sender] = 0;  // Actualizar estado primero
    totalDeposits -= balance;

    (bool success, ) = msg.sender.call{value: balance}("");
    require(success, "Transfer failed");
}
```

¿Quieres que analice alguna otra función o te explique más sobre alguna vulnerabilidad específica?"

### 7.2 Escaneo Rápido

**Usuario:** "Haz un escaneo rápido de mi token ERC20"

**Claude:** Invoca `quick_scan` (solo Capa 1, análisis estático):

```json
{
  "tool": "quick_scan",
  "arguments": {
    "contract_path": "contracts/MyToken.sol"
  }
}
```

**Respuesta en ~3 segundos** con hallazgos de Slither, Solhint, Securify2, Semgrep.

### 7.3 Verificación Específica

**Usuario:** "¿Este contrato es vulnerable a reentrancy?"

**Claude:** Invoca `check_reentrancy`:

```json
{
  "tool": "check_reentrancy",
  "arguments": {
    "contract_path": "contracts/Vault.sol"
  }
}
```

**Respuesta enfocada** solo en hallazgos de reentrancy de todas las herramientas.

---

## 8. Beneficios de la Integración MCP

### 8.1 Para Desarrolladores

| Beneficio | Descripción |
|-----------|-------------|
| Análisis conversacional | Preguntar sobre vulnerabilidades en lenguaje natural |
| Contexto mantenido | Claude recuerda análisis previos |
| Explicaciones educativas | Aprender sobre seguridad mientras codificas |
| Integración seamless | Sin salir del flujo de desarrollo |

### 8.2 Para Auditores

| Beneficio | Descripción |
|-----------|-------------|
| Asistente inteligente | Claude ayuda a interpretar resultados |
| Documentación automática | Generar reportes en formato deseado |
| Priorización | Claude puede sugerir qué investigar primero |
| Comparación | Analizar cambios entre versiones |

### 8.3 Para Equipos

| Beneficio | Descripción |
|-----------|-------------|
| Conocimiento compartido | Claude puede explicar hallazgos a non-experts |
| Onboarding | Nuevos miembros aprenden con asistente |
| Consistencia | Mismas herramientas, mismos estándares |
| Escalabilidad | Análisis sin bottleneck humano |

---

## 9. Seguridad del MCP Server

### 9.1 Principios de Seguridad

1. **Ejecución local:** Todo análisis ocurre en la máquina del usuario
2. **Sin datos externos:** Los contratos no salen del sistema local
3. **Sandboxing:** Herramientas en Docker cuando es posible
4. **Timeouts:** Límites de ejecución para evitar DoS
5. **Validación de input:** Paths sanitizados contra traversal

### 9.2 Configuración de Seguridad

```python
# Configuración de seguridad del MCP Server
SECURITY_CONFIG = {
    "allowed_paths": [
        "./contracts",
        "./src",
        os.path.expanduser("~/projects")
    ],
    "blocked_paths": [
        "/etc",
        "/var",
        "~/.ssh"
    ],
    "max_file_size_mb": 10,
    "max_execution_time_seconds": 600,
    "require_solidity_extension": True,
    "log_all_requests": True
}
```

---

## 10. Roadmap MCP

### 10.1 Versión Actual (v4.0.0)

- [x] Herramientas básicas de análisis
- [x] Recursos para contratos
- [x] Formateo para Claude

### 10.2 Próximas Versiones

**v4.1.0:**
- [ ] Prompts predefinidos para casos comunes
- [ ] Recursos para historial de auditorías
- [ ] Comparación de versiones de contratos

**v4.2.0:**
- [ ] Streaming de resultados para análisis largos
- [ ] Cache de resultados
- [ ] Integración con GitHub (fetch contracts from PRs)

**v5.0.0:**
- [ ] Multi-chain support via MCP
- [ ] Análisis de transacciones en tiempo real
- [ ] Colaboración multi-usuario

---

## 11. Referencias

Anthropic. (2024). *Model Context Protocol Specification*. https://modelcontextprotocol.io/

Anthropic. (2024). *MCP Python SDK*. https://github.com/anthropics/mcp-python-sdk

---

*Documento técnico para MIESC v4.0.0 MCP Server - Noviembre 2024*
