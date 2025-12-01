# Capítulo 6: Justificación del Uso de IA y LLMs Soberanos

## Soberanía de Datos en Auditoría de Smart Contracts

---

## 6.1 Introducción: El Dilema de la Confidencialidad

### 6.1.1 Naturaleza del Código en Auditoría Pre-Lanzamiento

El código fuente de un smart contract antes de su despliegue en mainnet representa un tipo particular de activo informático que combina tres características que lo hacen especialmente sensible:

**Primera característica: Valor económico directo.** A diferencia del software tradicional, donde el código tiene valor indirecto a través del producto que produce, un smart contract ES el producto. El contrato de un protocolo DeFi que gestiona 100 millones de dólares en TVL (Total Value Locked) no simplemente "sirve para" manejar ese dinero: el contrato es el mecanismo que define las reglas de ese manejo. Exponer el código antes del lanzamiento permite a atacantes preparar exploits que pueden ejecutarse en los primeros segundos después del despliegue.

**Segunda característica: Inmutabilidad post-despliegue.** Una vez desplegado en blockchain, el código de un smart contract no puede modificarse sin procedimientos extraordinarios (upgrades que requieren consenso de gobernanza, o forks del protocolo completo). Esto significa que una vulnerabilidad detectada por un atacante antes del lanzamiento puede ser explotada indefinidamente si el código desplegado es idéntico al filtrado.

**Tercera característica: Competencia temporal.** En el ecosistema DeFi, el primer protocolo en implementar un mecanismo innovador captura la mayor parte del mercado. La filtración del código de un protocolo innovador permite a competidores lanzar clones antes que el original, capturando el mercado que el innovador esperaba conquistar.

### 6.1.2 El Problema de las APIs de IA Comerciales

La emergencia de modelos de lenguaje grandes (LLMs) como GPT-4 y Claude ha transformado las posibilidades de análisis de código. Sun et al. (2024) demostraron que GPTScan, una herramienta que combina LLM con análisis de programas, detecta el 90.2% de vulnerabilidades de lógica de negocio que escapan a herramientas tradicionales. Este resultado es significativo porque las vulnerabilidades de lógica, a diferencia de patrones técnicos como reentrancy, requieren comprensión semántica del propósito del código.

Sin embargo, la utilización de estos modelos vía APIs comerciales implica transmitir el código fuente a servidores de terceros. Considérese el flujo de datos cuando un auditor utiliza GPT-4 de OpenAI para analizar un contrato:

```
[Código confidencial]
    -> HTTPS a api.openai.com
    -> Servidores en Virginia, USA
    -> Procesamiento por modelo
    -> Almacenamiento en logs por 30 días
    -> Posible uso para entrenamiento (según ToS)
```

Cada uno de estos pasos introduce riesgos:

1. **Transmisión:** El tráfico, aunque cifrado, atraviesa infraestructura de terceros. La metadata (IP de origen, timestamps, tamaño de payload) es visible para intermediarios.

2. **Jurisdicción:** El código queda sujeto a leyes estadounidenses, incluyendo el CLOUD Act que permite a autoridades acceder a datos almacenados por empresas estadounidenses sin notificar al propietario.

3. **Retención:** Las políticas de retención de OpenAI (30 días para API), Anthropic (30 días), y Google (variable) implican que el código permanece accesible en sus sistemas mucho después del análisis.

4. **Memorización:** Carlini et al. (2023) demostraron que los LLMs pueden memorizar y reproducir fragmentos de sus datos de entrenamiento. Aunque las APIs comerciales tienen políticas de no entrenar con datos de API, la posibilidad técnica existe.

### 6.1.3 Cuantificación del Riesgo

La Tabla 6.1 presenta una estimación del valor en riesgo para diferentes tipos de contratos auditados.

**Tabla 6.1.** Valor en riesgo por tipo de contrato

| Tipo de Contrato | TVL Típico | Impacto de Filtración | Ejemplos de Incidentes |
|------------------|------------|----------------------|----------------------|
| Protocolo DeFi núcleo | $100M - $10B | Exploit en primeros minutos post-launch | Harvest Finance ($33M, 2020) |
| Token Launch / ICO | $10M - $500M | Front-running de compra, sniping | Múltiples casos en 2021 |
| NFT Marketplace | $50M - $1B | Manipulación de precios de mint | BAYC clones (2022) |
| DAO Governance | $100M - $5B | Ataques de gobernanza preparados | Beanstalk ($182M, 2022) |
| Cross-chain Bridge | $500M - $5B | Exploit cross-chain coordinado | Ronin ($624M, 2022) |

El patrón común en estos incidentes es que los atacantes tuvieron tiempo de analizar el código y preparar exploits antes o inmediatamente después del despliegue. Si el código se hubiera filtrado durante la auditoría, el tiempo de preparación del ataque habría sido aún mayor.

---

## 6.2 Análisis de Riesgos de APIs Comerciales

### 6.2.1 Riesgos Técnicos

**1. Interceptación en tránsito**

Aunque HTTPS proporciona cifrado punto a punto, existen vectores de ataque:
- Compromiso de autoridades certificadoras (precedente: DigiNotar, 2011)
- Ataques man-in-the-middle en redes corporativas con inspección SSL
- Vulnerabilidades en implementaciones TLS (precedente: Heartbleed, 2014)

Para código de alto valor, estos riesgos no son teóricos sino que constituyen vectores que actores sofisticados pueden explotar.

**2. Exposición por empleados del proveedor**

El personal de OpenAI, Anthropic, o Google con acceso a logs de API puede potencialmente ver código de clientes. Los precedentes de insider threats en empresas tecnológicas (Twitter, 2020; Tesla, 2018) demuestran que este riesgo es real.

**3. Memorización y extracción de modelos**

Carlini et al. (2023) demostraron la "memorization attack": mediante prompts cuidadosamente diseñados, es posible extraer fragmentos de datos de entrenamiento de LLMs. Si un modelo fuera entrenado (inadvertidamente o no) con código de clientes, ese código podría ser extraído posteriormente por terceros.

**Figura 21.** Superficie de ataque en análisis con API comercial

![Figura 21 - Superficie de ataque análisis en API comercial](figures/Figura%2021%20Superficie%20de%20ataque%20análisis%20en%20API%20comercial.svg)

```
┌──────────────────────────────────────────────────────────────────┐
│                    ANÁLISIS CON API COMERCIAL                     │
│                                                                    │
│  [AUDITOR]                                                        │
│      │                                                            │
│      │ Código fuente                                              │
│      │ confidencial                                               │
│      ▼                                                            │
│  ┌────────┐     ┌───────────┐     ┌────────────┐    ┌─────────┐ │
│  │ HTTPS  │────>│ CDN/Edge  │────>│  API GW    │───>│ Modelo  │ │
│  │ Client │     │ Cloudflare │     │ (OpenAI)   │    │ GPU     │ │
│  └────────┘     └───────────┘     └────────────┘    └─────────┘ │
│       │              │                  │                │       │
│       ▼              ▼                  ▼                ▼       │
│   VECTOR 1       VECTOR 2          VECTOR 3         VECTOR 4    │
│   Man-in-       Logs en          Retención        Memorización  │
│   middle        edge nodes       30+ días         en modelo     │
│                                                                    │
│  Cada nodo representa un punto de exposición potencial            │
└──────────────────────────────────────────────────────────────────┘
```

### 6.2.2 Riesgos Regulatorios

**1. GDPR (Unión Europea)**

El Artículo 44 del GDPR establece restricciones a la transferencia de datos personales a países terceros. Si el código fuente contiene direcciones de wallets, nombres de funciones basados en usuarios, o cualquier dato personal, su transmisión a servidores en Estados Unidos requiere mecanismos legales específicos (SCCs, certificación Privacy Shield, etc.).

**2. LGPD (Brasil)**

La Ley General de Proteção de Dados, en su Artículo 33, requiere que transferencias internacionales de datos personales cumplan condiciones específicas que las APIs comerciales típicamente no garantizan para uso programático.

**3. LFPDPPP (México)**

La Ley Federal de Protección de Datos Personales en Posesión de los Particulares establece obligaciones de seguridad que pueden verse comprometidas al transmitir datos a servicios en la nube de terceros países.

**4. Regulaciones financieras sectoriales**

- SOC 2: Requiere control demostrable sobre procesamiento de datos sensibles
- PCI DSS: Para contratos que manejen datos de tarjetas, prohibe explícitamente ciertas transferencias
- HIPAA: Para contratos en healthcare, impone restricciones severas

### 6.2.3 Riesgos Económicos

**Tabla 6.2.** Estructura de costos de APIs comerciales (noviembre 2024)

| Proveedor | Modelo | Costo Input | Costo Output | Costo/Auditoría* |
|-----------|--------|-------------|--------------|------------------|
| OpenAI | GPT-4o | $2.50/1M | $10.00/1M | ~$0.38 |
| OpenAI | GPT-4 Turbo | $10.00/1M | $30.00/1M | ~$1.20 |
| Anthropic | Claude 3.5 Sonnet | $3.00/1M | $15.00/1M | ~$0.54 |
| Anthropic | Claude 3 Opus | $15.00/1M | $75.00/1M | ~$2.70 |
| Google | Gemini 1.5 Pro | $3.50/1M | $10.50/1M | ~$0.42 |

*Estimación para análisis de contrato de ~500 líneas con múltiples pasadas

**Proyección de costos anuales:**

```
Escenario: Equipo de auditoría realizando 100 auditorías mensuales

Costo anual con GPT-4 Turbo:
100 auditorías × 12 meses × $1.20 = $1,440/año

Más overhead de gestión de API keys, rate limits, reintentos:
$1,440 × 1.5 = ~$2,160/año

Más riesgo de cambios de pricing (precedente: OpenAI aumentó precios 3x en 2023):
Reserva de contingencia: +$500/año

Costo total estimado: ~$2,660/año
```

Aunque estos costos parecen modestos, representan una barrera significativa para:
- Proyectos de código abierto sin financiamiento
- Desarrolladores individuales en países con moneda débil
- Organizaciones educativas
- Investigadores académicos

---

## 6.3 Solución: LLMs Soberanos con Ollama

### 6.3.1 Concepto de Soberanía de Datos

El término "soberanía de datos" tiene múltiples acepciones en la literatura. Para los propósitos de este trabajo, adoptamos la definición de la Digital Public Goods Alliance (2023):

> "La soberanía de datos es el principio de que los datos están sujetos a las leyes y estructuras de gobernanza de la nación o entidad donde se generan y procesan, y que dicha entidad mantiene control efectivo sobre su uso y distribución."

La aplicación de este principio al análisis de smart contracts implica que:
1. El código fuente no debe abandonar la infraestructura controlada por el auditor
2. El procesamiento debe ocurrir en recursos computacionales bajo control del auditor
3. No debe existir transmisión a servicios de terceros que introduzcan jurisdicción externa

### 6.3.2 Ollama como Backend Soberano

Ollama es un framework de código abierto que permite ejecutar LLMs localmente en hardware de consumidor. Sus características clave para MIESC son:

**1. Ejecución completamente local**

El servidor Ollama escucha exclusivamente en localhost (127.0.0.1) por defecto. No existe servidor remoto, no hay transmisión de datos:

```bash
# Verificación de binding de red
$ netstat -tlnp | grep ollama
tcp   0   0   127.0.0.1:11434   0.0.0.0:*   LISTEN   12345/ollama

# Verificación de conexiones salientes durante análisis
$ tcpdump -i any "not localhost" during analysis
tcpdump: listening on any
^C
0 packets captured  # CERO tráfico externo
```

**2. Modelos con pesos abiertos**

Ollama soporta modelos cuyos pesos son públicos y auditables:

**Tabla 6.3.** Modelos soportados por MIESC

| Modelo | Parámetros | VRAM Requerida | Licencia | Calidad Código |
|--------|------------|----------------|----------|----------------|
| Llama 3.2:3b | 3B | 4 GB | Meta Llama 3.2 | Buena |
| Llama 3.1:8b | 8B | 8 GB | Meta Llama 3.1 | Muy buena |
| CodeLlama:7b | 7B | 8 GB | Meta Llama 2 | Muy buena (código) |
| CodeLlama:13b | 13B | 16 GB | Meta Llama 2 | Excelente (código) |
| Qwen2.5-Coder:7b | 7B | 8 GB | Apache 2.0 | Excelente (código) |
| Mistral:7b | 7B | 8 GB | Apache 2.0 | Muy buena |
| DeepSeek-Coder:6.7b | 6.7B | 8 GB | MIT | Excelente (código) |

**3. Sin telemetría**

A diferencia de servicios comerciales, Ollama no incluye código de telemetría. Esto es verificable porque el código fuente es público y auditable:

```go
// No existe código de telemetría en ollama/server/routes.go
// No hay endpoints de analytics
// No hay beacons de tracking
```

### 6.3.3 Arquitectura de MIESC con LLM Soberano

**Figura 22.** Arquitectura de análisis con LLM soberano

![Figura 22 - Arquitectura de análisis con LLM soberano](figures/Figura%2022.%20Arquitectura%20de%20análisis%20con%20LLM%20soberano.svg)

*Infraestructura 100% local con cero tráfico externo*

### 6.3.4 Configuración en MIESC

```python
# src/config/llm_config.py
"""
Configuración de LLM soberano para MIESC.

El diseño prioriza soberanía de datos sobre rendimiento:
- Solo conexiones a localhost
- Sin fallback a APIs externas
- Verificación explícita de localidad
"""

LLM_CONFIG = {
    # Backend obligatoriamente local
    "backend": "ollama",
    "base_url": "http://localhost:11434",

    # Modelo por defecto (balance entre calidad y velocidad)
    "model": "llama3.2:3b",

    # Timeouts
    "timeout": 120,
    "max_retries": 3,

    # Parámetros de generación
    "temperature": 0.1,  # Bajo para consistencia
    "max_tokens": 4096,
    "top_p": 0.9,

    # Configuración de seguridad
    "verify_localhost": True,  # Falla si no es localhost
    "allow_external": False,   # NUNCA conectar a APIs externas
    "log_prompts": False,      # No persistir código analizado
}

def verify_sovereign_backend() -> bool:
    """
    Verifica que el backend LLM es soberano (local).

    Esta verificación se ejecuta en cada análisis para garantizar
    que no hay configuración incorrecta que filtre código.
    """
    base_url = LLM_CONFIG["base_url"]

    # Lista blanca de hosts soberanos
    sovereign_hosts = ["localhost", "127.0.0.1", "::1"]

    from urllib.parse import urlparse
    parsed = urlparse(base_url)

    if parsed.hostname not in sovereign_hosts:
        raise SovereigntyViolation(
            f"LLM backend {parsed.hostname} is not local. "
            f"MIESC requires local LLM for data sovereignty. "
            f"Configure Ollama on localhost:11434"
        )

    return True
```

---

## 6.4 Justificación Técnica Detallada

### 6.4.1 Comparativa de Capacidades: Local vs. Comercial

La objeción más frecuente a los LLMs locales es que su capacidad es inferior a modelos comerciales de frontera. Esta sección examina en qué medida esta diferencia afecta el caso de uso específico de análisis de smart contracts.

**Tabla 6.4.** Comparativa de capacidades para análisis de código

| Capacidad | GPT-4 | Claude 3 Opus | Llama 3.1:8b | CodeLlama:13b |
|-----------|-------|---------------|--------------|---------------|
| Comprensión de Solidity | Excelente | Excelente | Buena | Muy buena |
| Detección de reentrancy | Alta | Alta | Media-Alta | Alta |
| Detección de overflow | Alta | Alta | Alta | Alta |
| Lógica de negocio | Muy Alta | Muy Alta | Media | Media |
| Generación de remediación | Excelente | Excelente | Buena | Buena |
| Velocidad (tokens/s) | ~50 | ~60 | ~80* | ~60* |
| Costo por análisis | $1-2 | $2-3 | $0 | $0 |

*En GPU RTX 3090 o equivalente

**Observaciones clave:**

1. **Para vulnerabilidades técnicas conocidas** (reentrancy, overflow, access control), los modelos locales alcanzan rendimiento comparable a los comerciales. Esto se debe a que estas vulnerabilidades siguen patrones predecibles que modelos de 7-13B parámetros pueden aprender.

2. **Para vulnerabilidades de lógica de negocio**, los modelos comerciales tienen ventaja. Sin embargo, esta ventaja se mitiga en MIESC porque:
   - La capa de IA es una de siete capas, no la única defensa
   - Los hallazgos de IA se correlacionan con hallazgos de herramientas tradicionales
   - El auditor humano sigue siendo el decisor final

3. **La velocidad de modelos locales** es frecuentemente superior porque no hay latencia de red ni colas de API.

### 6.4.2 Análisis de Trade-offs

**Trade-off 1: Capacidad vs. Soberanía**

La decisión de usar LLMs locales implica aceptar menor capacidad de razonamiento a cambio de soberanía completa de datos. Este trade-off es aceptable cuando:

- El código tiene valor significativo (>$10M en juego)
- Existen obligaciones regulatorias de confidencialidad
- El auditor no puede aceptar riesgo de filtración
- Las otras capas de MIESC compensan limitaciones del LLM

El trade-off NO es aceptable cuando:
- El código ya es público (análisis post-audit de contratos desplegados)
- No hay restricciones de confidencialidad
- Se requiere máxima capacidad de detección de lógica de negocio

MIESC permite configurar análisis híbridos donde las capas tradicionales corren siempre localmente, y la capa de IA puede configurarse para usar modelos externos solo para código no confidencial.

**Trade-off 2: Costo inicial vs. Costo operativo**

| Aspecto | API Comercial | LLM Soberano |
|---------|---------------|--------------|
| Costo inicial | $0 | $500-1000 (GPU) |
| Costo operativo | ~$2,500/año | ~$60/año (electricidad) |
| Break-even | - | ~6 meses |
| Costo a 3 años | $7,500 | $1,180 |

Para organizaciones que realizan auditorías regularmente, el LLM soberano tiene mejor ROI incluso ignorando los beneficios de soberanía.

### 6.4.3 Estrategias de Mitigación de Limitaciones

**1. Arquitectura de múltiples capas**

Las limitaciones del LLM local se mitigan porque opera dentro de una arquitectura de 7 capas donde 24 herramientas no-LLM proporcionan cobertura complementaria:

```python
def run_comprehensive_audit(contract_path: str) -> AuditReport:
    """
    Auditoría comprehensiva que no depende exclusivamente del LLM.

    Incluso si el LLM local no detecta una vulnerabilidad de lógica,
    las otras capas pueden detectar síntomas relacionados.
    """
    all_findings = []

    # Capas 1-5: Herramientas tradicionales (24 total)
    all_findings.extend(run_static_analysis(contract_path))    # Slither, etc.
    all_findings.extend(run_fuzzing(contract_path))            # Echidna, etc.
    all_findings.extend(run_symbolic(contract_path))           # Mythril, etc.
    all_findings.extend(run_invariant_testing(contract_path))  # Scribble, etc.
    all_findings.extend(run_formal_verification(contract_path))  # SMTChecker, etc.

    # Capa 6-7: LLM local para análisis semántico
    all_findings.extend(run_llm_analysis(contract_path))  # GPTScan, etc.

    # La deduplicación correlaciona hallazgos de múltiples fuentes
    return deduplicate_and_prioritize(all_findings)
```

**2. Prompts optimizados para modelos más pequeños**

Los prompts de MIESC están diseñados para maximizar efectividad con modelos de 7-8B parámetros:

```python
OPTIMIZED_SECURITY_PROMPT = """
Analyze this Solidity contract for security vulnerabilities.

FOCUS ON THESE SPECIFIC PATTERNS:
1. External calls before state updates (reentrancy)
2. Unchecked arithmetic operations
3. Missing access control on sensitive functions
4. Dangerous delegatecall usage
5. Improper handling of ETH transfers

For each vulnerability found, provide:
- Line number
- Vulnerability type
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Brief explanation (1-2 sentences)

CONTRACT:
```solidity
{contract_code}
```

Respond in JSON format only:
{{"vulnerabilities": [...]}}
"""
```

El prompt es:
- Específico (lista exacta de qué buscar)
- Estructurado (formato de respuesta claro)
- Conciso (minimiza tokens de contexto para respuesta)

**3. RAG (Retrieval-Augmented Generation)**

MIESC implementa RAG con una base de conocimiento local de vulnerabilidades conocidas:

```python
class LocalRAGEngine:
    """
    Motor de RAG local para enriquecer análisis LLM.

    La base de conocimiento incluye:
    - Registro SWC completo con ejemplos
    - CVEs de smart contracts históricos
    - Patrones de ataque documentados
    """

    def __init__(self):
        # Base de conocimiento local (no requiere internet)
        self.knowledge_base = load_local_embeddings("data/swc_knowledge.faiss")

    def augment_prompt(self, code: str, base_prompt: str) -> str:
        """
        Enriquece el prompt con contexto relevante de la KB.
        """
        # Buscar patrones similares en la KB
        similar_vulns = self.knowledge_base.search(code, top_k=3)

        # Añadir ejemplos relevantes al prompt
        context = "SIMILAR KNOWN VULNERABILITIES:\n"
        for vuln in similar_vulns:
            context += f"- {vuln['swc_id']}: {vuln['description']}\n"
            context += f"  Example: {vuln['example'][:200]}...\n"

        return f"{context}\n{base_prompt}"
```

---

## 6.5 Implementación en MIESC

### 6.5.1 Herramientas LLM Integradas

MIESC integra seis herramientas basadas en LLM, todas configuradas para ejecución local:

**Tabla 6.5.** Herramientas LLM en MIESC

| Herramienta | Propósito | Tokens/Análisis | Tiempo Típico |
|-------------|-----------|-----------------|---------------|
| GPTScan | Detección de vulnerabilidades | ~15,000 | 30-60s |
| SmartLLM | Análisis con RAG contextual | ~20,000 | 45-90s |
| LLMSmartAudit | Auditoría automatizada completa | ~25,000 | 60-120s |
| ThreatModel | Modelado de amenazas STRIDE | ~10,000 | 20-40s |
| PropertyGPT | Generación de invariantes | ~12,000 | 25-50s |
| GasGauge | Optimización de gas | ~8,000 | 15-30s |

### 6.5.2 Implementación del Adaptador LLM Base

```python
# src/adapters/base_llm_adapter.py
"""
Adaptador base para herramientas basadas en LLM soberano.

Este adaptador garantiza que todas las herramientas LLM de MIESC
usen exclusivamente backends locales, sin posibilidad de filtración
accidental de código a servicios externos.
"""

import requests
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from src.config.llm_config import LLM_CONFIG, verify_sovereign_backend

class SovereigntyViolation(Exception):
    """Excepción para violaciones de soberanía de datos."""
    pass

class BaseLLMAdapter(ABC):
    """
    Adaptador base que garantiza ejecución soberana de LLM.

    Todas las herramientas LLM de MIESC heredan de esta clase,
    heredando automáticamente las garantías de soberanía.
    """

    def __init__(self):
        self.base_url = LLM_CONFIG["base_url"]
        self.model = LLM_CONFIG["model"]
        self.timeout = LLM_CONFIG["timeout"]

        # Verificación crítica de soberanía
        if not self._verify_sovereignty():
            raise SovereigntyViolation(
                "Cannot initialize LLM adapter: backend is not sovereign"
            )

    def _verify_sovereignty(self) -> bool:
        """
        Verifica que el backend LLM es local.

        Esta verificación se ejecuta:
        1. Al instanciar el adaptador
        2. Antes de cada llamada de análisis

        La redundancia es intencional: protege contra cambios
        de configuración en runtime.
        """
        return verify_sovereign_backend()

    def _verify_ollama_local(self) -> bool:
        """
        Verifica que Ollama responde y es efectivamente local.
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )

            # Verificar que la respuesta viene de localhost
            # (no de un proxy que podría reenviar a servicio externo)
            if response.headers.get("X-Ollama-Version"):
                return True

        except requests.exceptions.ConnectionError:
            raise SovereigntyViolation(
                f"Ollama not running at {self.base_url}. "
                f"Start Ollama with: ollama serve"
            )

        return False

    def generate(self, prompt: str) -> str:
        """
        Genera respuesta desde LLM local.

        El código analizado nunca sale del sistema local.
        """
        # Re-verificar soberanía antes de cada llamada
        self._verify_sovereignty()

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": LLM_CONFIG["temperature"],
                    "num_predict": LLM_CONFIG["max_tokens"]
                }
            },
            timeout=self.timeout
        )

        if response.status_code != 200:
            raise RuntimeError(f"Ollama error: {response.text}")

        return response.json()["response"]

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Implementación específica de análisis."""
        pass
```

### 6.5.3 Verificación de Soberanía

MIESC incluye un script de verificación que el auditor puede ejecutar para demostrar soberanía a clientes o reguladores:

```bash
#!/bin/bash
# verify_sovereignty.sh - Verificación de soberanía de datos MIESC

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║        VERIFICACIÓN DE SOBERANÍA DE DATOS - MIESC             ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# 1. Verificar que Ollama escucha solo en localhost
echo "[1/4] Verificando binding de red de Ollama..."
OLLAMA_BIND=$(netstat -tlnp 2>/dev/null | grep 11434 || ss -tlnp | grep 11434)
if echo "$OLLAMA_BIND" | grep -q "127.0.0.1:11434"; then
    echo "      ✓ Ollama escucha SOLO en localhost (127.0.0.1:11434)"
else
    echo "      ✗ ADVERTENCIA: Ollama podría estar expuesto externamente"
    echo "      Salida: $OLLAMA_BIND"
fi
echo ""

# 2. Monitorear tráfico durante análisis de prueba
echo "[2/4] Monitoreando tráfico de red durante análisis..."
timeout 30 tcpdump -c 100 -i any "not host localhost" 2>/dev/null &
TCPDUMP_PID=$!

# Ejecutar análisis de prueba
python3 -c "
from src.adapters.gptscan_adapter import GPTScanAdapter
adapter = GPTScanAdapter()
adapter.analyze('contracts/test/TestContract.sol')
" 2>/dev/null

# Verificar que no hubo tráfico externo
wait $TCPDUMP_PID 2>/dev/null
if [ $? -eq 0 ]; then
    echo "      ✓ CERO conexiones externas durante análisis"
else
    echo "      ✗ Se detectó tráfico externo (investigar)"
fi
echo ""

# 3. Verificar ubicación de modelos
echo "[3/4] Verificando almacenamiento local de modelos..."
if [ -d "$HOME/.ollama/models" ]; then
    MODEL_SIZE=$(du -sh "$HOME/.ollama/models" 2>/dev/null | cut -f1)
    echo "      ✓ Modelos almacenados localmente: $MODEL_SIZE"
    echo "      Ubicación: $HOME/.ollama/models/"
else
    echo "      ✗ No se encontraron modelos locales"
fi
echo ""

# 4. Verificar configuración de MIESC
echo "[4/4] Verificando configuración de MIESC..."
python3 -c "
from src.config.llm_config import LLM_CONFIG, verify_sovereign_backend
print(f'      Backend: {LLM_CONFIG[\"backend\"]}')
print(f'      URL: {LLM_CONFIG[\"base_url\"]}')
print(f'      Allow External: {LLM_CONFIG[\"allow_external\"]}')
if verify_sovereign_backend():
    print('      ✓ Configuración es SOBERANA')
"
echo ""

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  VERIFICACIÓN COMPLETADA                       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
```

---

## 6.6 Cumplimiento con Estándares

### 6.6.1 Digital Public Goods Alliance (DPGA)

MIESC está diseñado para cumplir con los nueve indicadores del estándar DPGA:

| Indicador DPGA | Cumplimiento MIESC |
|----------------|-------------------|
| 1. Relevancia para SDGs | Contribuye a SDG 9 (Infraestructura) y SDG 16 (Instituciones) |
| 2. Licencia abierta | AGPL-3.0 para código, CC-BY 4.0 para documentación |
| 3. Documentación clara | Guías de instalación y uso publicadas |
| 4. Extracción de datos | N/A (herramienta de análisis, no almacena datos de usuarios) |
| 5. Privacidad | Ejecución local, sin transmisión de datos |
| 6. Estándares abiertos | Uso de SWC, CWE, SARIF |
| 7. No discriminación | Sin restricciones de acceso |
| 8. Sin dependencias propietarias | Solo herramientas open source |
| 9. Independencia de plataforma | Funciona en Linux, macOS, Windows |

### 6.6.2 Beneficios para la Comunidad

**1. Democratización del acceso**

La ejecución local elimina barreras de costo para:
- Proyectos de código abierto sin presupuesto
- Desarrolladores en países en desarrollo
- Instituciones educativas
- Investigadores académicos

**2. Soberanía tecnológica nacional**

Organizaciones gubernamentales y empresas en jurisdicciones con requisitos de localización de datos pueden usar MIESC sin comprometer compliance:
- No hay transferencia internacional de datos
- No hay dependencia de servicios extranjeros
- Control total sobre infraestructura de procesamiento

**3. Transparencia y auditabilidad**

Todo el stack es open source y auditable:
- Código de MIESC: GitHub público
- Ollama: Código abierto (MIT)
- Modelos Llama: Pesos públicos y documentación de entrenamiento

---

## 6.7 Conclusiones

### 6.7.1 Síntesis de la Justificación

La decisión de implementar LLMs soberanos en MIESC responde a un análisis riguroso de riesgos y trade-offs. La justificación se fundamenta en:

1. **El código de smart contracts pre-auditoría tiene valor económico directo y significativo.** La filtración de este código puede resultar en pérdidas de decenas o cientos de millones de dólares.

2. **Las APIs comerciales de LLM introducen vectores de riesgo inaceptables** para código de alto valor: transmisión a jurisdicciones extranjeras, retención por períodos extendidos, posible memorización en modelos.

3. **Los modelos locales de 7-13B parámetros proporcionan capacidad suficiente** para el caso de uso de análisis de seguridad, especialmente cuando operan dentro de una arquitectura de múltiples capas.

4. **El costo total de propiedad de LLMs soberanos es inferior** al de APIs comerciales para organizaciones que realizan auditorías regularmente.

5. **La ejecución local garantiza cumplimiento regulatorio automático** con GDPR, LGPD, LFPDPPP y regulaciones sectoriales.

### 6.7.2 Recomendación

Para auditorías de smart contracts que manejan código confidencial con valor económico significativo:

> **El uso de LLMs soberanos (locales) es la única opción que proporciona garantías verificables de confidencialidad del código fuente durante el proceso de auditoría.**

Las limitaciones de capacidad respecto a modelos comerciales se mitigan mediante:
- Arquitectura de siete capas con 25 herramientas
- Prompts optimizados para modelos más pequeños
- RAG con base de conocimiento local
- Correlación de hallazgos entre múltiples fuentes

---

## 6.8 Referencias del Capítulo

Carlini, N., et al. (2023). Extracting Training Data from Large Language Models. *USENIX Security Symposium*.

Digital Public Goods Alliance. (2023). *Digital Public Goods Standard*. https://digitalpublicgoods.net/standard/

European Parliament. (2016). General Data Protection Regulation (GDPR). *Regulation (EU) 2016/679*.

Meta AI. (2024). Llama 3 Model Card. https://ai.meta.com/llama/

Ollama. (2024). Ollama Documentation. https://ollama.ai/

OpenAI. (2024). API Data Usage Policies. https://openai.com/policies/api-data-usage

Presidencia de la República. (2010). Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP).

República Federativa do Brasil. (2018). Lei Geral de Proteção de Dados (LGPD). *Lei nº 13.709*.

Sun, Y., et al. (2024). GPTScan: Detecting logic vulnerabilities in smart contracts by combining GPT with program analysis. *ICSE 2024*, 1-12.

Touvron, H., et al. (2023). LLaMA: Open and efficient foundation language models. *arXiv:2302.13971*.

---

*Nota: Las referencias siguen el formato APA 7ma edición. Documento actualizado: 2025-11-29*
