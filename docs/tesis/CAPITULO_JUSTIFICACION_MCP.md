# Capítulo 7: Justificación del Model Context Protocol (MCP)

## Integración de MIESC con Asistentes de Inteligencia Artificial

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

Este proceso asume conocimiento técnico especializado que excede las competencias típicas de un desarrollador de aplicaciones. El resultado, documentado por Beller et al. (2016) en su evaluación a gran escala sobre proyectos de código abierto, es que las herramientas de análisis estático quedan subutilizadas en la práctica por la fricción de uso y la dificultad de interpretar sus resultados.

### 7.1.2 La Emergencia de Interfaces Conversacionales

La aparición de modelos de lenguaje grandes (LLMs) capaces de sostener diálogos coherentes y contextualmente relevantes abrió una nueva posibilidad: utilizar lenguaje natural como interfaz principal para herramientas técnicas. En lugar de aprender comandos específicos, el usuario podría expresar su intención en lenguaje cotidiano y dejar que un intermediario inteligente traduzca esa intención a invocaciones de herramientas.

Esta visión, sin embargo, enfrentaba un obstáculo fundamental: los LLMs son sistemas cerrados que operan exclusivamente sobre texto. No pueden ejecutar código, acceder a sistemas de archivos, ni invocar APIs externas. Su conocimiento está congelado en el momento del entrenamiento, sin capacidad de actualizarse o acceder a información en tiempo real.

### 7.1.3 Model Context Protocol: La Solución de Anthropic

En noviembre de 2024, Anthropic publicó el Model Context Protocol (MCP), una especificación abierta que define cómo los LLMs pueden interactuar de manera segura y estructurada con herramientas y datos externos. El protocolo aborda las limitaciones señaladas en el apartado anterior por cuatro vías complementarias: permite al LLM descubrir qué herramientas están registradas y qué parámetros acepta cada una; canaliza las invocaciones a través de un servidor que valida las entradas, aplica permisos y limita el acceso; devuelve resultados estructurados que el modelo puede procesar e interpretar para el usuario; y preserva el estado de la conversación entre llamadas, lo que habilita análisis iterativos.

La decisión de implementar un servidor MCP en MIESC parte de una constatación: la barrera principal para la adopción de herramientas de seguridad no es técnica sino de usabilidad. MCP permite que MIESC sea accesible desde Claude Desktop y transforma así una colección de 25 herramientas especializadas en un asistente de seguridad conversacional.

## 7.2 Análisis de Alternativas: Por qué MCP

### 7.2.1 Alternativas Consideradas

Antes de adoptar MCP se evaluaron cuatro alternativas para habilitar la interacción con asistentes de IA. La primera, una API REST tradicional, efectivamente implementada en MIESC como interfaz complementaria, ofrece universalidad, pero carece de descubrimiento automático de capacidades, de orquestación inteligente de llamadas múltiples y de interpretación contextual de resultados: quien la consume debe conocer de antemano los endpoints, sus parámetros y el significado de las respuestas, y la API no aporta ninguna inteligencia más allá de la ejecución literal de lo solicitado.

Un plugin para ChatGPT fue descartado por tres razones: el encierro en un proveedor (*vendor lock-in*), ya que solo funcionaría con ChatGPT; el costo, que exige una suscripción a ChatGPT Plus y cargos variables de API; y, sobre todo, la transmisión del código del contrato a servidores de OpenAI. Esta última razón es particularmente crítica en auditorías de seguridad, donde el código analizado suele contener propiedad intelectual confidencial o vulnerabilidades potencialmente explotables.

La tercera opción, un agente de LangChain —framework de Python que combina LLMs con herramientas externas e invoca funciones a partir de descripciones en lenguaje natural—, mostró una configuración extensa con dependencias pesadas, varias capas de indirección que añaden latencia y puntos de falla, y un acoplamiento del código a las abstracciones del propio framework, aun cuando este admite múltiples proveedores.

Frente a estas opciones, un servidor MCP ofreció el mejor equilibrio entre los criterios evaluados, como resume la tabla siguiente.

| Criterio | REST API | ChatGPT Plugin | Langchain | MCP |
|----------|----------|----------------|-----------|-----|
| Estándar abierto | Sí | No | Parcial | Sí |
| Descubrimiento automático | No | Sí | Parcial | Sí |
| Orquestación inteligente | No | Sí | Sí | Sí |
| Ejecución local | Sí | No | Parcial | Sí |
| Soporte Claude nativo | No | No | No | Sí |
| Complejidad de implementación | Baja | Alta | Alta | Media |

### 7.2.2 Factores Decisivos para MCP

La selección de MCP se apoyó en cuatro factores. El primero, y el más relevante para esta tesis, es su alineación con la soberanía de datos: el servidor (MIESC) corre en la infraestructura del usuario y el cliente (Claude) se conecta localmente, de modo que el código fuente y las herramientas permanecen en el sistema local. Lo que sí viaja al proveedor del asistente, cuando el cliente es un servicio alojado como Claude Desktop, es el contenido que el servidor devuelve —hallazgos y fragmentos citados—, un alcance que conviene tener presente al leer el diagrama:

```
Usuario -> Claude Desktop -> MCP Client -> localhost:3000 -> MIESC MCP Server -> Herramientas
                                                                    |
                                                   (Servidor y herramientas locales; respuestas hacia el cliente alojado)
```

Este modelo difiere de los plugins de ChatGPT, en los que el propio contrato viaja a través de servidores de terceros para ser analizado; la diferencia es de grado, no absoluta, y el modo de análisis completamente local sigue siendo el de la línea de comandos (§6.3).

En segundo lugar, MCP es una especificación publicada bajo licencia permisiva, con implementaciones de referencia en Python y TypeScript, que define el formato de mensajes JSON-RPC 2.0, los esquemas de descubrimiento de herramientas, los protocolos de autenticación y permisos y los mecanismos de streaming para resultados extensos; esa apertura reduce el riesgo de que MIESC quede ligado a las decisiones futuras de un único proveedor. Tercero, Claude Desktop y Claude Code implementan soporte nativo para el protocolo, por lo que la integración funciona sin desarrollo adicional del lado del cliente y queda disponible apenas se configura el servidor. Por último, MCP define un modelo de permisos granular —acceso al sistema de archivos en lectura o escritura, ejecución de comandos, acceso a red y recursos disponibles— que, en el caso de MIESC, permite restringir el servidor a lectura sobre los directorios de contratos, sin capacidad de modificar archivos ni de acceder a otras partes del sistema.

## 7.3 Arquitectura del Servidor MCP de MIESC

### 7.3.1 Diseño Conceptual

El servidor MCP de MIESC actúa como puente entre el mundo conversacional de Claude y el mundo técnico de las herramientas de análisis de seguridad, con una responsabilidad triple: traduce las intenciones en invocaciones, de modo que cuando Claude determina que necesita analizar un contrato el servidor convierte esa intención en llamadas concretas a los adaptadores de MIESC; normaliza y contextualiza los resultados, transformando los hallazgos crudos de las herramientas en descripciones que Claude puede comunicar al usuario; y mantiene el estado de la sesión, preservando el contexto de análisis previos para permitir un refinamiento iterativo (Figura 7.1).

**Figura 7.1.** Arquitectura de integración MCP

![Figura 7.1 - Arquitectura de integración MCP](figures/Figura%2023.%20Arquitectura%20de%20integración%20MCP.svg)

### 7.3.2 Componentes del Servidor

El servidor se compone de dos manejadores. El manejador de herramientas expone las capacidades de MIESC como *tools* invocables por Claude; cada una se define con un nombre único y descriptivo, una descripción en lenguaje natural de su propósito, un esquema JSON de sus parámetros de entrada y su comportamiento de ejecución:

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

El manejador de recursos, por su parte, expone datos que Claude puede consultar sin ejecutar un análisis:

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

![Figura 7.2 - Secuencia de interacción MCP](figures/Figura%2024.%20Secuencia%20de%20interacción%20MCP.svg)

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

## 7.5 Casos de Uso y Ejemplos de Interacción

### 7.5.1 Auditoría Interactiva Completa

El siguiente diálogo, construido como ilustración y no como transcripción de una sesión real, muestra cómo un desarrollador sin experiencia en seguridad podría obtener una auditoría exhaustiva:

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

El segundo diálogo, igualmente ilustrativo, muestra la consulta de un recurso informativo:

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

## 7.6 Beneficios Esperados

### 7.6.1 Reducción de Fricción

**Tabla 7.1.** Comparación de flujos de trabajo (estimación cualitativa del autor; no se realizó un estudio formal de usabilidad, §5.8)

| Tarea | Sin MCP (CLI tradicional) | Con MCP (Claude) |
|-------|---------------------------|------------------|
| Auditar contrato | 5 comandos, 10+ minutos | 1 mensaje, 2 minutos |
| Interpretar hallazgos | Manual, requiere expertise | Explicación contextual |
| Obtener remediación | Buscar documentación externa | Código corregido in-situ |
| Segunda opinión | Ejecutar otra herramienta | "Confirma con Mythril" |
| Generar reporte | Script custom | "Genera un reporte ejecutivo" |

### 7.6.2 Democratización del Acceso

El modelo MCP apunta a que desarrolladores sin formación específica en seguridad de smart contracts comprendan las vulnerabilidades en su contexto —no solo qué está mal, sino por qué importa y qué podría ocurrir—, reciban una guía de remediación específica en lugar de documentación genérica, aprendan mientras trabajan y puedan validar que sus correcciones resuelven efectivamente el problema detectado. Estos beneficios se formulan como expectativas de diseño: medirlos requiere un estudio de usabilidad que esta tesis no realizó (§5.8).

## 7.7 Limitaciones y Consideraciones

### 7.7.1 Limitaciones Técnicas

| Limitación | Impacto | Mitigación |
|------------|---------|------------|
| Dependencia de Claude | Solo funciona con Claude Desktop/Code | REST API como fallback |
| Protocolo reciente (2024) | Posibles cambios de especificación | Abstracción en handlers |
| Latencia de análisis | Esperas durante análisis largos | Streaming de progreso |
| Contexto limitado de Claude | Contratos muy grandes pueden truncarse | Chunking inteligente |

### 7.7.2 Consideraciones de Seguridad

Cuatro consideraciones de seguridad acompañan la implementación. La primera es que el servidor MCP solo debe escuchar en localhost:

```python
# Configuración segura
MCP_CONFIG = {
    "host": "127.0.0.1",
    "transport": "stdio"  # Preferido sobre TCP
}

# Configuración INSEGURA - NUNCA hacer esto:
# MCP_CONFIG = {"host": "0.0.0.0", "port": 3000}
```

Las restantes son validar siempre las rutas de entrada para impedir el acceso a archivos fuera del alcance autorizado (§7.4.2), limitar los recursos de ejecución —tiempo y memoria— para prevenir denegaciones de servicio, y mantener registros de auditoría de todas las invocaciones con fines de trazabilidad.

## 7.8 Conclusiones

### 7.8.1 Síntesis de la Justificación

La implementación del servidor MCP responde a una brecha concreta entre la sofisticación de las herramientas de análisis de seguridad y su accesibilidad para los desarrolladores. La interfaz conversacional reduce la barrera de entrada, porque permite acceder a un análisis de nivel profesional sin aprender comandos específicos ni descifrar salidas técnicas; mantiene la ejecución de las herramientas en la infraestructura local, aunque el contenido devuelto a un asistente alojado sigue la política de datos de su proveedor (§7.2.2); aprovecha la capacidad del asistente para explicar, contextualizar y orientar la remediación, algo que las herramientas individuales no ofrecen; y, al apoyarse en una especificación abierta, no ata el diseño a un proveedor en particular, aunque en su estado actual el cliente principal sea Claude (§7.7.1).

### 7.8.2 Posicionamiento de MIESC

La combinación de 25 herramientas de seguridad, LLM soberano (Ollama) e interfaz conversacional (MCP) posiciona a MIESC como un framework de seguridad de smart contracts con integración nativa de IA conversacional, cuyo servidor y herramientas se ejecutan en la infraestructura del usuario y que ofrece un modo de análisis completamente local. Hasta donde alcanza la revisión del Capítulo 3, esta combinación no tiene un equivalente directo en el ecosistema de seguridad blockchain, donde las alternativas requieren enviar el código a servicios externos, implican costos significativos o carecen de interfaces accesibles para no especialistas.

## 7.9 Referencias del Capítulo

Anthropic. (2024). MCP Servers Documentation. https://modelcontextprotocol.io/

Anthropic. (2024). Model Context Protocol Specification. https://modelcontextprotocol.io/

Beller, M., Bholanath, R., McIntosh, S., & Zaidman, A. (2016). Analyzing the state of static analysis: A large-scale evaluation in open source software. En *2016 IEEE 23rd International Conference on Software Analysis, Evolution, and Reengineering (SANER)* (pp. 470-481). IEEE. https://doi.org/10.1109/SANER.2016.105
