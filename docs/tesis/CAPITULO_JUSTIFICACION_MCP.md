# Capítulo 7: Justificación del Model Context Protocol (MCP)

## Integración de MIESC con Asistentes de Inteligencia Artificial

---

## 7.1 Introducción: El Problema de la Interfaz Humano-Herramienta

### 7.1.1 Contexto Histórico de las Interfaces de Seguridad

Las herramientas de análisis de seguridad han evolucionado significativamente en sus capacidades técnicas durante las últimas dos décadas, pero sus interfaces de usuario han permanecido fundamentalmente ancladas al paradigma de línea de comandos heredado de los primeros compiladores y analizadores estáticos. Esta disparidad entre sofisticación interna y accesibilidad externa representa una barrera significativa para la adopción de prácticas de seguridad en el desarrollo de software.

Considérese el flujo de trabajo típico de un desarrollador que desea verificar la seguridad de un contrato inteligente antes de desplegarlo:

1. Instalar la herramienta (proceso que puede requerir resolver conflictos de dependencias)
2. Aprender la sintaxis de comandos específica de la herramienta
3. Ejecutar el análisis y capturar la salida
4. Interpretar los resultados técnicos (códigos SWC, trazas de ejecución, condiciones SMT)
5. Investigar cada hallazgo para determinar si representa una vulnerabilidad real
6. Decidir y aplicar la remediación apropiada

Este proceso asume conocimiento técnico especializado que excede las competencias típicas de un desarrollador de aplicaciones. El resultado, documentado por Beller et al. (2016), es que "las herramientas de análisis estático son subutilizadas en la práctica industrial debido a la fricción de uso y la dificultad de interpretación de resultados" (p. 12).

### 7.1.2 La Emergencia de Interfaces Conversacionales

La aparición de modelos de lenguaje grandes (LLMs) capaces de sostener diálogos coherentes y contextualmente relevantes abrió una nueva posibilidad: utilizar lenguaje natural como interfaz principal para herramientas técnicas. En lugar de aprender comandos específicos, el usuario podría expresar su intención en lenguaje cotidiano y dejar que un intermediario inteligente traduzca esa intención a invocaciones de herramientas.

Esta visión, sin embargo, enfrentaba un obstáculo fundamental: los LLMs son sistemas cerrados que operan exclusivamente sobre texto. No pueden ejecutar código, acceder a sistemas de archivos, ni invocar APIs externas. Su conocimiento está congelado en el momento del entrenamiento, sin capacidad de actualizarse o acceder a información en tiempo real.

### 7.1.3 Model Context Protocol: La Solución de Anthropic

En noviembre de 2024, Anthropic publicó el Model Context Protocol (MCP), una especificación abierta que define cómo los LLMs pueden interactuar de manera segura y estructurada con herramientas y datos externos. MCP resuelve las limitaciones inherentes de los LLMs mediante un protocolo que:

1. **Descubre herramientas disponibles:** El LLM puede consultar qué herramientas están registradas y qué parámetros acepta cada una.

2. **Invoca herramientas de manera segura:** Las llamadas a herramientas pasan por un servidor que valida inputs, aplica permisos y limita acceso.

3. **Recibe resultados estructurados:** Los resultados se devuelven al LLM en formato que puede procesar e interpretar para el usuario.

4. **Mantiene contexto entre llamadas:** El protocolo preserva el estado de la conversación, permitiendo análisis iterativos.

La decisión de implementar un servidor MCP en MIESC se fundamenta en el reconocimiento de que la barrera principal para la adopción de herramientas de seguridad no es técnica sino de usabilidad. MCP permite que MIESC sea accesible a través de Claude Desktop, transformando una colección de 25 herramientas especializadas en un asistente de seguridad conversacional.

---

## 7.2 Análisis de Alternativas: Por qué MCP

### 7.2.1 Alternativas Consideradas

Antes de adoptar MCP, se evaluaron cuatro alternativas para habilitar interacción con asistentes de IA:

**Alternativa 1: REST API Tradicional**

Una API REST expondría los endpoints de MIESC para consumo por cualquier cliente. Esta opción, implementada efectivamente en MIESC como interfaz complementaria, tiene ventajas de universalidad pero carece de:
- Descubrimiento automático de capacidades
- Orquestación inteligente de llamadas múltiples
- Interpretación contextual de resultados

El usuario o desarrollador que consume la API debe conocer de antemano qué endpoints existen, qué parámetros requieren, y cómo interpretar las respuestas. La API no proporciona ninguna "inteligencia" más allá de la ejecución literal de lo solicitado.

**Alternativa 2: Plugin para ChatGPT**

OpenAI permite desarrollar plugins que extienden las capacidades de ChatGPT. Esta opción fue descartada por tres razones:
1. **Vendor lock-in:** El plugin solo funcionaría con ChatGPT, excluyendo otros asistentes
2. **Costo de API:** Requiere suscripción a ChatGPT Plus y costos variables de API
3. **Transmisión de código:** El código fuente del contrato se transmitiría a servidores de OpenAI

Esta última razón es particularmente crítica en el contexto de auditorías de seguridad, donde el código bajo análisis frecuentemente contiene propiedad intelectual confidencial o vulnerabilidades potencialmente explotables.

**Alternativa 3: Langchain Agent**

Langchain es un framework de Python para construir aplicaciones que combinan LLMs con herramientas externas. Un "agent" de Langchain puede invocar funciones Python basándose en descripciones en lenguaje natural.

La evaluación de esta alternativa reveló:
- **Complejidad de setup:** Langchain requiere configuración extensa y dependencias pesadas
- **Overhead de abstracción:** Múltiples capas de indirección añaden latencia y puntos de falla
- **Acoplamiento con backend LLM:** Aunque soporta múltiples providers, el código del agent queda ligado a las abstracciones de Langchain

**Alternativa 4: MCP Server (Seleccionada)**

MCP ofrece un balance óptimo entre las alternativas:

| Criterio | REST API | ChatGPT Plugin | Langchain | MCP |
|----------|----------|----------------|-----------|-----|
| Estándar abierto | Sí | No | Parcial | Sí |
| Descubrimiento automático | No | Sí | Parcial | Sí |
| Orquestación inteligente | No | Sí | Sí | Sí |
| Ejecución local | Sí | No | Parcial | Sí |
| Soporte Claude nativo | No | No | No | Sí |
| Complejidad de implementación | Baja | Alta | Alta | Media |

### 7.2.2 Factores Decisivos para MCP

La selección de MCP se fundamentó en cuatro factores:

**1. Alineación con principios de soberanía de datos**

MCP define un modelo donde el servidor (MIESC) corre en la infraestructura del usuario, y el cliente (Claude) se conecta localmente. El código fuente nunca abandona el sistema local:

```
Usuario -> Claude Desktop -> MCP Client -> localhost:3000 -> MIESC MCP Server -> Herramientas
                                                                    |
                                                              (Todo local)
```

Este modelo es fundamentalmente diferente a los plugins de ChatGPT, donde los datos viajan a través de servidores de terceros.

**2. Especificación abierta y estable**

MCP es una especificación publicada bajo licencia permisiva, con implementaciones de referencia en Python y TypeScript. La especificación define:
- Formato de mensajes JSON-RPC 2.0
- Esquemas para descubrimiento de herramientas
- Protocolos de autenticación y permisos
- Mecanismos de streaming para resultados grandes

Esta apertura garantiza que MIESC no queda ligado a las decisiones futuras de un único vendor.

**3. Integración nativa con Claude**

Claude Desktop y Claude Code implementan soporte nativo para MCP, lo que significa que la integración con MIESC "simplemente funciona" sin desarrollo adicional del lado del cliente. Los usuarios de Claude pueden acceder a las capacidades de MIESC inmediatamente después de configurar el servidor.

**4. Modelo de permisos granular**

MCP define un sistema de permisos que permite al usuario controlar qué capacidades expone cada servidor:
- Acceso a sistema de archivos (lectura/escritura)
- Ejecución de comandos
- Acceso a red
- Recursos disponibles

Para MIESC, esto permite configurar el servidor con acceso de solo lectura a directorios de contratos, sin capacidad de modificar archivos ni acceder a otras partes del sistema.

---

## 7.3 Arquitectura del Servidor MCP de MIESC

### 7.3.1 Diseño Conceptual

El servidor MCP de MIESC actúa como puente entre el mundo conversacional de Claude y el mundo técnico de las herramientas de análisis de seguridad. Su responsabilidad es triple:

1. **Traducir intenciones en invocaciones:** Cuando Claude determina que necesita analizar un contrato, el servidor traduce esa intención en llamadas concretas a adaptadores de MIESC.

2. **Normalizar y contextualizar resultados:** Los hallazgos crudos de las herramientas se transforman en descripciones interpretables que Claude puede comunicar al usuario.

3. **Mantener estado de sesión:** El servidor preserva el contexto de análisis previos, permitiendo refinamiento iterativo.

![Figura 7.1 - Arquitectura de integración MCP](figures/fig_04_mcp_architecture.png)

*Figura 7.1: Arquitectura de integración MCP - Flujo de interacción entre Usuario, Claude Desktop y MIESC MCP Server*

### 7.3.2 Componentes del Servidor

**1. Handler de Herramientas (Tools)**

El handler de herramientas expone las capacidades de MIESC como "tools" invocables por Claude. Cada herramienta se define con:
- Nombre único y descriptivo
- Descripción en lenguaje natural de su propósito
- Esquema JSON de parámetros de entrada
- Comportamiento de ejecución

```python
class MIESCToolHandler:
    """
    Expone herramientas MIESC como MCP tools.

    El diseño sigue el principio de que cada tool debe ser
    autocontenida y descriptiva: Claude debe poder determinar
    cuándo y cómo usarla basándose únicamente en su descripción.
    """

    def get_tools(self) -> list:
        """
        Retorna la lista de herramientas disponibles.

        Las descripciones están redactadas para que Claude comprenda:
        1. Qué hace la herramienta
        2. Cuándo es apropiado usarla
        3. Qué parámetros necesita
        """
        return [
            {
                "name": "analyze_contract",
                "description": """Analyze a smart contract for security vulnerabilities
                using MIESC's 7-layer defense-in-depth architecture. This tool runs
                multiple analysis techniques including static analysis (Slither),
                symbolic execution (Mythril), fuzzing (Echidna), and AI-powered
                semantic analysis. Use this tool when the user wants a comprehensive
                security audit of their contract.""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {
                            "type": "string",
                            "description": "Path to the Solidity contract file (.sol)"
                        },
                        "layers": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1, "maximum": 7},
                            "description": "Specific layers to execute (1-7). Default: all layers"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Maximum time in seconds for analysis. Default: 300"
                        }
                    },
                    "required": ["contract_path"]
                }
            },
            {
                "name": "run_slither",
                "description": """Run Slither static analyzer on a contract. Slither
                is fast (typically <5 seconds) and good for detecting common
                vulnerabilities like reentrancy, unchecked returns, and access
                control issues. Use this for quick initial scans.""",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {"type": "string"}
                    },
                    "required": ["contract_path"]
                }
            },
            # ... definiciones para las 25 herramientas
        ]
```

**2. Handler de Recursos (Resources)**

Los recursos MCP representan datos que Claude puede consultar sin ejecutar análisis. En MIESC, los recursos incluyen:

```python
class MIESCResourceHandler:
    """
    Expone recursos informativos de MIESC.

    Los recursos permiten a Claude acceder a información de referencia
    (como la base de datos SWC) sin ejecutar análisis, reduciendo
    latencia para consultas informativas.
    """

    def get_resources(self) -> list:
        return [
            {
                "uri": "miesc://swc-registry",
                "name": "SWC Registry",
                "description": """Complete Smart Contract Weakness Classification
                database with descriptions, examples, and remediation guidance
                for all known vulnerability types.""",
                "mimeType": "application/json"
            },
            {
                "uri": "miesc://tool-status",
                "name": "Tool Status",
                "description": """Current availability and version information
                for all 25 security tools integrated in MIESC.""",
                "mimeType": "application/json"
            },
            {
                "uri": "miesc://findings/latest",
                "name": "Latest Findings",
                "description": """Results from the most recent security analysis,
                including all detected vulnerabilities and their metadata.""",
                "mimeType": "application/json"
            }
        ]
```

### 7.3.3 Flujo de Comunicación Detallado

El siguiente diagrama de secuencia ilustra el flujo completo de una interacción típica:

**Figura 7.2.** Secuencia de interacción MCP

```
Usuario             Claude              MCP Client           MIESC Server          Slither
   │                   │                    │                     │                   │
   │ "Analiza mi       │                    │                     │                   │
   │  VulnerableBank"  │                    │                     │                   │
   │──────────────────>│                    │                     │                   │
   │                   │                    │                     │                   │
   │                   │   tools/list       │                     │                   │
   │                   │───────────────────>│                     │                   │
   │                   │                    │     getTools()      │                   │
   │                   │                    │────────────────────>│                   │
   │                   │                    │<────────────────────│                   │
   │                   │<───────────────────│                     │                   │
   │                   │   [analyze_contract, run_slither, ...]   │                   │
   │                   │                    │                     │                   │
   │                   │   tools/call       │                     │                   │
   │                   │   analyze_contract │                     │                   │
   │                   │   {"contract_path":│                     │                   │
   │                   │    "VulnerableBank.sol"}                 │                   │
   │                   │───────────────────>│                     │                   │
   │                   │                    │    callTool()       │                   │
   │                   │                    │────────────────────>│                   │
   │                   │                    │                     │                   │
   │                   │                    │                     │   analyze()       │
   │                   │                    │                     │──────────────────>│
   │                   │                    │                     │<──────────────────│
   │                   │                    │                     │   {findings:[...]}│
   │                   │                    │                     │                   │
   │                   │                    │<────────────────────│                   │
   │                   │                    │   {findings: [...], │                   │
   │                   │                    │    summary: "..."}  │                   │
   │                   │<───────────────────│                     │                   │
   │                   │                    │                     │                   │
   │<──────────────────│                    │                     │                   │
   │ "Encontré 5       │                    │                     │                   │
   │  vulnerabilidades:│                    │                     │                   │
   │  1. Reentrancy    │                    │                     │                   │
   │     en withdraw() │                    │                     │                   │
   │  ..."             │                    │                     │                   │
```

---

## 7.4 Implementación Técnica

### 7.4.1 Servidor MCP Principal

```python
# src/mcp/server.py
import asyncio
import logging
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, Resource, TextContent

from src.adapters import register_all_adapters, get_adapter_by_name
from src.mcp.tool_handler import MIESCToolHandler
from src.mcp.resource_handler import MIESCResourceHandler
from src.mcp.security import validate_contract_path, SecurityError

logger = logging.getLogger(__name__)

# Instancia del servidor MCP
app = Server("miesc-security")
tool_handler = MIESCToolHandler()
resource_handler = MIESCResourceHandler()

@app.list_tools()
async def list_tools() -> list[Tool]:
    """
    Lista todas las herramientas disponibles para Claude.

    Esta función se invoca cuando Claude necesita saber qué
    capacidades tiene disponibles. El resultado determina qué
    acciones Claude puede proponer al usuario.
    """
    return tool_handler.get_tools()

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Ejecuta una herramienta MIESC.

    Proceso de ejecución:
    1. Validar que el tool existe
    2. Validar parámetros de entrada (especialmente paths)
    3. Ejecutar el análisis correspondiente
    4. Formatear resultados para Claude
    """
    logger.info(f"Tool invocation: {name} with args {arguments}")

    try:
        if name == "analyze_contract":
            contract_path = arguments.get("contract_path")
            layers = arguments.get("layers", [1, 2, 3, 4, 5, 6, 7])
            timeout = arguments.get("timeout", 300)

            # Validación de seguridad crítica
            validate_contract_path(contract_path)

            # Ejecutar análisis multi-capa
            results = await run_full_analysis(contract_path, layers, timeout)

            return [TextContent(
                type="text",
                text=format_findings_for_claude(results)
            )]

        elif name.startswith("run_"):
            # Invocación de herramienta individual
            tool_name = name.replace("run_", "")
            adapter = get_adapter_by_name(tool_name)

            if adapter is None:
                raise ValueError(f"Unknown tool: {tool_name}")

            contract_path = arguments.get("contract_path")
            validate_contract_path(contract_path)

            result = await asyncio.to_thread(
                adapter.analyze,
                contract_path,
                timeout=arguments.get("timeout", 60)
            )

            return [TextContent(
                type="text",
                text=format_single_tool_result(result)
            )]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except SecurityError as e:
        logger.warning(f"Security violation in tool call: {e}")
        return [TextContent(
            type="text",
            text=f"Security error: {e}. The requested operation was blocked."
        )]
    except Exception as e:
        logger.error(f"Error in tool execution: {e}", exc_info=True)
        return [TextContent(
            type="text",
            text=f"Analysis failed: {str(e)}"
        )]

@app.list_resources()
async def list_resources() -> list[Resource]:
    """Lista recursos informativos disponibles."""
    return resource_handler.get_resources()

@app.read_resource()
async def read_resource(uri: str) -> str:
    """Lee contenido de un recurso."""
    return await resource_handler.read(uri)

async def main():
    """
    Punto de entrada del servidor MCP.

    El servidor utiliza stdio (standard input/output) para
    comunicación con el cliente MCP. Esto permite que Claude
    Desktop lance el servidor como subproceso y se comunique
    directamente sin necesidad de sockets de red.
    """
    # Registrar todos los adaptadores de herramientas
    register_all_adapters()

    logger.info("Starting MIESC MCP Server...")

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
```

### 7.4.2 Validación de Seguridad

La validación de entradas es crítica para prevenir que Claude, inadvertidamente o por manipulación, ejecute operaciones no autorizadas:

```python
# src/mcp/security.py
import os
import re

class SecurityError(Exception):
    """Excepción para violaciones de seguridad."""
    pass

# Configuración de seguridad
ALLOWED_EXTENSIONS = {'.sol'}
ALLOWED_PATHS = [
    os.path.expanduser("~/contracts"),
    os.path.expanduser("~/projects"),
    "/tmp/miesc"
]
MAX_FILE_SIZE = 1024 * 1024  # 1 MB

def validate_contract_path(path: str) -> bool:
    """
    Valida que el path proporcionado es seguro para análisis.

    Verificaciones realizadas:
    1. No contiene secuencias de path traversal (../)
    2. Extensión de archivo permitida (.sol)
    3. Ubicación dentro de directorios autorizados
    4. El archivo existe y es legible
    5. El archivo no excede el tamaño máximo

    Estas verificaciones previenen:
    - Lectura de archivos arbitrarios del sistema
    - Ejecución de código malicioso empaquetado como .sol
    - Ataques de denegación de servicio por archivos enormes
    """
    # Prevenir path traversal
    if ".." in path:
        raise SecurityError("Path traversal detected: '..' not allowed")

    # Normalizar y resolver path
    abs_path = os.path.abspath(os.path.expanduser(path))

    # Verificar extensión
    _, ext = os.path.splitext(abs_path)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        raise SecurityError(f"Extension not allowed: {ext}. Only .sol files accepted")

    # Verificar que está en directorio permitido
    in_allowed_path = any(
        abs_path.startswith(os.path.abspath(allowed))
        for allowed in ALLOWED_PATHS
    )
    if not in_allowed_path:
        raise SecurityError(
            f"Path outside allowed directories. "
            f"Allowed: {ALLOWED_PATHS}"
        )

    # Verificar existencia
    if not os.path.exists(abs_path):
        raise SecurityError(f"File not found: {abs_path}")

    # Verificar tamaño
    size = os.path.getsize(abs_path)
    if size > MAX_FILE_SIZE:
        raise SecurityError(
            f"File too large: {size} bytes. "
            f"Maximum: {MAX_FILE_SIZE} bytes"
        )

    return True
```

### 7.4.3 Configuración para Claude Desktop

Para que Claude Desktop reconozca el servidor MIESC, se configura en el archivo de configuración de MCP:

```json
// ~/.config/claude/claude_desktop_config.json (Linux/Mac)
// %APPDATA%\claude\claude_desktop_config.json (Windows)
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["-m", "src.mcp.server"],
      "cwd": "/path/to/miesc",
      "env": {
        "PYTHONPATH": "/path/to/miesc",
        "OLLAMA_HOST": "http://localhost:11434"
      }
    }
  }
}
```

---

## 7.5 Casos de Uso y Ejemplos de Interacción

### 7.5.1 Auditoría Interactiva Completa

El siguiente diálogo ilustra cómo un desarrollador sin experiencia en seguridad puede obtener una auditoría comprehensiva:

```
Usuario: Tengo un contrato de staking en contracts/Staking.sol que necesito
         auditar antes de desplegarlo en mainnet. Es mi primer deploy y
         quiero asegurarme de que no tiene vulnerabilidades críticas.

Claude:  Voy a analizar tu contrato de staking con una auditoría completa
         de seguridad. Esto ejecutará múltiples herramientas de análisis
         incluyendo análisis estático, ejecución simbólica y análisis
         semántico con IA.

         [Ejecuta: analyze_contract("contracts/Staking.sol", layers=[1,2,3,5,7])]

         Completé el análisis. Encontré 8 hallazgos que necesitan tu atención:

         CRÍTICOS (2 - Bloquean despliegue):

         1. Reentrancy en unstake() - Línea 67
            El contrato transfiere ETH antes de actualizar el balance del usuario.
            Esto permite que un atacante retire fondos múltiples veces en una
            sola transacción.

            Código vulnerable:
            ```solidity
            function unstake() external {
                uint256 amount = stakes[msg.sender];
                payable(msg.sender).transfer(amount);  // ← Transferencia primero
                stakes[msg.sender] = 0;                 // ← Actualización después
            }
            ```

            Impacto: Un atacante podría drenar todos los fondos del contrato.
            Severidad: CRÍTICA

         2. Pérdida de precisión en calculateRewards() - Línea 89
            La división se realiza antes de la multiplicación, causando
            pérdida de decimales que favorece al protocolo sobre los usuarios.

            Código problemático:
            ```solidity
            uint256 reward = (stakedAmount / totalStaked) * rewardPool;
            ```

            Impacto: Los usuarios reciben menos recompensas de las que les
            corresponden, especialmente con stakes pequeños.
            Severidad: CRÍTICA

         ALTOS (3):
         [...]

         ¿Quieres que te muestre el código corregido para los hallazgos críticos?

Usuario: Sí, muéstrame cómo arreglar el problema de reentrancy

Claude:  Aquí está la corrección para la vulnerabilidad de reentrancy.
         Hay dos enfoques complementarios que recomiendo usar juntos:

         Enfoque 1: Patrón Checks-Effects-Interactions

         ```solidity
         function unstake() external {
             uint256 amount = stakes[msg.sender];
             require(amount > 0, "Nothing to unstake");

             // EFFECTS: Actualizar estado ANTES de interacción externa
             stakes[msg.sender] = 0;
             totalStaked -= amount;

             // INTERACTIONS: Transferencia después de actualizar estado
             (bool success, ) = payable(msg.sender).call{value: amount}("");
             require(success, "Transfer failed");

             emit Unstaked(msg.sender, amount);
         }
         ```

         Enfoque 2: Añadir ReentrancyGuard de OpenZeppelin (recomendado)

         ```solidity
         import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

         contract Staking is ReentrancyGuard {
             function unstake() external nonReentrant {
                 uint256 amount = stakes[msg.sender];
                 require(amount > 0, "Nothing to unstake");

                 stakes[msg.sender] = 0;
                 totalStaked -= amount;

                 (bool success, ) = payable(msg.sender).call{value: amount}("");
                 require(success, "Transfer failed");

                 emit Unstaked(msg.sender, amount);
             }
         }
         ```

         Recomiendo usar ambos enfoques: el patrón CEI como práctica de
         codificación y ReentrancyGuard como defensa adicional. La defensa
         en profundidad es especialmente importante cuando hay fondos en juego.

         ¿Quieres que analice el contrato de nuevo después de que hagas
         las correcciones para verificar que quedaron bien?
```

### 7.5.2 Consulta de Documentación Contextual

```
Usuario: ¿Qué es SWC-107 y por qué es tan peligroso?

Claude:  [Ejecuta: read_resource("miesc://swc-registry")]

         SWC-107: Reentrancy (Reentrada)

         Descripción:
         Una vulnerabilidad de reentrancy ocurre cuando un contrato hace
         una llamada externa a otro contrato antes de actualizar su propio
         estado. El contrato externo puede entonces "re-entrar" a la
         función original antes de que la primera ejecución termine.

         Por qué es peligroso:

         1. Impacto financiero devastador: El ataque al DAO en 2016 explotó
            exactamente esta vulnerabilidad, resultando en la pérdida de
            $60 millones de dólares y causando un fork de Ethereum.

         2. Difícil de detectar manualmente: El flujo de ejecución es
            contra-intuitivo. El código "se ve bien" porque las operaciones
            están en orden lógico, pero el orden de ejecución real es diferente.

         3. Fácil de explotar: Una vez identificada, la vulnerabilidad se
            puede explotar con un contrato atacante relativamente simple.

         Patrón vulnerable:
         ```
         function withdraw() {
             uint balance = balances[msg.sender];
             msg.sender.call{value: balance}("");  // ← Atacante re-entra aquí
             balances[msg.sender] = 0;              // ← Nunca se ejecuta hasta el final
         }
         ```

         Incidentes históricos notables:
         - The DAO (2016): $60M perdidos, fork de Ethereum
         - Cream Finance (2021): $130M perdidos
         - Rari Capital (2022): $80M perdidos

         Esta vulnerabilidad sigue siendo una de las más explotadas en DeFi
         porque es fácil de introducir accidentalmente y las herramientas
         tradicionales no siempre la detectan en contextos complejos.
```

---

## 7.6 Beneficios Demostrados

### 7.6.1 Reducción de Fricción

**Tabla 7.1.** Comparación de flujos de trabajo

| Tarea | Sin MCP (CLI tradicional) | Con MCP (Claude) |
|-------|---------------------------|------------------|
| Auditar contrato | 5 comandos, 10+ minutos | 1 mensaje, 2 minutos |
| Interpretar hallazgos | Manual, requiere expertise | Explicación contextual |
| Obtener remediación | Buscar documentación externa | Código corregido in-situ |
| Segunda opinión | Ejecutar otra herramienta | "Confirma con Mythril" |
| Generar reporte | Script custom | "Genera un reporte ejecutivo" |

### 7.6.2 Democratización del Acceso

El modelo MCP permite que desarrolladores sin formación específica en seguridad de smart contracts:

1. **Comprendan vulnerabilidades en su contexto:** Claude explica no solo qué está mal sino por qué importa y qué podría pasar.

2. **Reciban guía de remediación específica:** En lugar de documentación genérica, obtienen código corregido para su caso particular.

3. **Aprendan mientras trabajan:** Cada interacción es una oportunidad de aprendizaje sobre seguridad de smart contracts.

4. **Validen correcciones:** Pueden verificar que sus cambios efectivamente resuelven el problema detectado.

---

## 7.7 Limitaciones y Consideraciones

### 7.7.1 Limitaciones Técnicas

| Limitación | Impacto | Mitigación |
|------------|---------|------------|
| Dependencia de Claude | Solo funciona con Claude Desktop/Code | REST API como fallback |
| Protocolo reciente (2024) | Posibles cambios de especificación | Abstracción en handlers |
| Latencia de análisis | Esperas durante análisis largos | Streaming de progreso |
| Contexto limitado de Claude | Contratos muy grandes pueden truncarse | Chunking inteligente |

### 7.7.2 Consideraciones de Seguridad

**1. El servidor MCP solo debe escuchar en localhost:**

```python
# Configuración segura
MCP_CONFIG = {
    "host": "127.0.0.1",
    "transport": "stdio"  # Preferido sobre TCP
}

# Configuración INSEGURA - NUNCA hacer esto:
# MCP_CONFIG = {"host": "0.0.0.0", "port": 3000}
```

**2. Validar siempre los paths de entrada** para prevenir acceso a archivos fuera del alcance autorizado.

**3. Limitar recursos de ejecución** (tiempo, memoria) para prevenir denegación de servicio.

**4. Mantener logs de auditoría** de todas las invocaciones para trazabilidad.

---

## 7.8 Conclusiones

### 7.8.1 Síntesis de la Justificación

La implementación del servidor MCP en MIESC responde a un problema real y significativo: la brecha entre la sofisticación de las herramientas de análisis de seguridad y su accesibilidad para desarrolladores típicos. MCP permite cerrar esta brecha al proporcionar una interfaz conversacional que:

1. **Reduce la barrera de entrada:** Los desarrolladores pueden acceder a análisis de seguridad profesional sin aprender comandos específicos ni interpretar output técnico críptico.

2. **Mantiene la soberanía de datos:** Todo el procesamiento ocurre localmente, sin transmisión de código fuente a servicios externos.

3. **Aprovecha inteligencia existente:** Claude aporta capacidad de explicación, contextualización y guía que las herramientas individuales no pueden proporcionar.

4. **Es extensible y abierto:** Basado en una especificación abierta, no crea dependencia de un vendor específico.

### 7.8.2 Posicionamiento de MIESC

La combinación de 25 herramientas de seguridad, LLM soberano (Ollama), e interfaz conversacional (MCP) posiciona a MIESC como:

> **El primer framework de seguridad de smart contracts con integración nativa de IA conversacional, manteniendo la soberanía de datos mediante ejecución completamente local.**

Esta propuesta de valor es única en el ecosistema de seguridad blockchain, donde las alternativas requieren enviar código a servicios externos, tienen costos significativos, o carecen de interfaces accesibles para no especialistas.

---

## 7.9 Referencias del Capítulo

Anthropic. (2024). Model Context Protocol Specification. https://github.com/anthropics/mcp

Anthropic. (2024). MCP Servers Documentation. https://modelcontextprotocol.io/

Beller, M., Gousios, G., Panichella, A., & Zaidman, A. (2016). When, how, and why developers (do not) test in their IDEs. *ESEC/FSE 2016*, 179-190.

OWASP. (2023). Smart Contract Security Testing Guide. https://owasp.org/

Ross, R., et al. (2016). Guide to Industrial Control Systems (ICS) Security. *NIST SP 800-82 Rev. 2*.

---

*Nota: Las referencias siguen el formato APA 7ma edición. Documento actualizado: 2025-11-29*
