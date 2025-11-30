# Apéndice E: Código Fuente Representativo

---

## E.1 Introducción

Este apéndice presenta fragmentos representativos del código fuente de MIESC, ilustrando las decisiones de diseño e implementación discutidas en los capítulos anteriores. El código completo está disponible en el repositorio del proyecto bajo licencia MIT.

---

## E.2 Interfaz Base de Adaptadores

El protocolo `ToolAdapter` define la interfaz común que todos los adaptadores deben implementar:

```python
# src/adapters/base_adapter.py
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import logging

class Severity(Enum):
    """Niveles de severidad normalizados."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

@dataclass
class Finding:
    """Estructura normalizada de un hallazgo de seguridad."""
    id: str
    type: str
    severity: Severity
    confidence: str
    title: str
    description: str
    location: Dict[str, Any]
    swc_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = None
    detected_by: str = ""
    raw_output: Optional[str] = None

class ToolAdapter(ABC):
    """
    Clase base abstracta para adaptadores de herramientas de seguridad.

    Implementa el patrón Adapter (Gamma et al., 1994) para unificar
    las interfaces heterogéneas de las herramientas integradas.
    """

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._version: Optional[str] = None
        self._available: Optional[bool] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Nombre identificador de la herramienta."""
        pass

    @property
    @abstractmethod
    def layer(self) -> int:
        """Capa de Defense-in-Depth (1-7)."""
        pass

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta el análisis de seguridad sobre un contrato.

        Args:
            contract_path: Ruta al archivo .sol
            **kwargs: Parámetros específicos de la herramienta

        Returns:
            Dict con estructura normalizada:
            {
                "tool": str,
                "version": str,
                "status": "success" | "error" | "timeout",
                "findings": List[Finding],
                "execution_time": float,
                "raw_output": str
            }
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Verifica si la herramienta está instalada y operativa."""
        pass

    def get_version(self) -> Optional[str]:
        """Retorna la versión de la herramienta instalada."""
        return self._version

    def normalize_severity(self, raw_severity: str) -> Severity:
        """
        Normaliza severidades de diferentes herramientas al estándar MIESC.

        Mapeo basado en CVSS v3.1:
        - CRITICAL: CVSS >= 9.0
        - HIGH: 7.0 <= CVSS < 9.0
        - MEDIUM: 4.0 <= CVSS < 7.0
        - LOW: CVSS < 4.0
        """
        severity_map = {
            # Slither
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFORMATIONAL,
            "optimization": Severity.INFORMATIONAL,
            # Mythril
            "critical": Severity.CRITICAL,
            # Semgrep
            "error": Severity.HIGH,
            "warning": Severity.MEDIUM,
            "info": Severity.LOW,
        }
        return severity_map.get(raw_severity.lower(), Severity.MEDIUM)
```

---

## E.3 Implementación del Adaptador de Slither

```python
# src/adapters/slither_adapter.py
import subprocess
import json
import shutil
from typing import Dict, Any, List
from .base_adapter import ToolAdapter, Finding, Severity

class SlitherAdapter(ToolAdapter):
    """
    Adaptador para Slither (Trail of Bits).

    Slither es un framework de análisis estático que utiliza
    SlithIR como representación intermedia para detección de
    vulnerabilidades mediante análisis de flujo de datos.

    Referencias:
        Feist et al. (2019). Slither: A Static Analysis Framework
        for Smart Contracts. WETSEB 2019.
    """

    # Mapeo de detectores Slither a SWC
    DETECTOR_TO_SWC = {
        "reentrancy-eth": "SWC-107",
        "reentrancy-no-eth": "SWC-107",
        "reentrancy-benign": "SWC-107",
        "unprotected-upgrade": "SWC-105",
        "arbitrary-send-eth": "SWC-105",
        "controlled-delegatecall": "SWC-112",
        "suicidal": "SWC-106",
        "tx-origin": "SWC-115",
        "unchecked-lowlevel": "SWC-104",
        "unchecked-send": "SWC-104",
        "weak-prng": "SWC-120",
        "timestamp": "SWC-116",
        "locked-ether": "SWC-132",
        "shadowing-state": "SWC-119",
        "uninitialized-state": "SWC-109",
        "uninitialized-storage": "SWC-109",
    }

    # Mapeo SWC a CWE
    SWC_TO_CWE = {
        "SWC-107": "CWE-841",  # Improper Enforcement of Behavioral Workflow
        "SWC-105": "CWE-284",  # Improper Access Control
        "SWC-112": "CWE-829",  # Inclusion of Untrusted Functionality
        "SWC-106": "CWE-284",  # Improper Access Control
        "SWC-115": "CWE-477",  # Use of Obsolete Function
        "SWC-104": "CWE-252",  # Unchecked Return Value
        "SWC-120": "CWE-330",  # Use of Insufficiently Random Values
        "SWC-116": "CWE-829",  # Block Timestamp Dependence
        "SWC-132": "CWE-667",  # Improper Locking
        "SWC-119": "CWE-710",  # Improper Adherence to Coding Standards
        "SWC-109": "CWE-824",  # Access of Uninitialized Pointer
    }

    @property
    def name(self) -> str:
        return "slither"

    @property
    def layer(self) -> int:
        return 1  # Capa de Análisis Estático

    def is_available(self) -> bool:
        """Verifica disponibilidad de Slither."""
        if self._available is None:
            self._available = shutil.which("slither") is not None
            if self._available:
                try:
                    result = subprocess.run(
                        ["slither", "--version"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    self._version = result.stdout.strip()
                except Exception:
                    self._available = False
        return self._available

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta análisis Slither sobre un contrato.

        Args:
            contract_path: Ruta al archivo .sol
            timeout: Tiempo máximo de ejecución (default: 300s)
            exclude_dependencies: Excluir dependencias (default: True)

        Returns:
            Dict con hallazgos normalizados
        """
        import time
        start_time = time.time()

        if not self.is_available():
            return {
                "tool": self.name,
                "status": "error",
                "error": "Slither no está instalado",
                "findings": []
            }

        timeout = kwargs.get("timeout", 300)

        try:
            # Ejecutar Slither con salida JSON
            cmd = [
                "slither",
                contract_path,
                "--json", "-",
                "--exclude-dependencies"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parsear JSON de salida
            findings = []
            if result.stdout:
                try:
                    output = json.loads(result.stdout)
                    findings = self._parse_findings(output, contract_path)
                except json.JSONDecodeError:
                    self.logger.warning("Error parseando JSON de Slither")

            execution_time = time.time() - start_time

            return {
                "tool": self.name,
                "version": self._version,
                "status": "success",
                "findings": findings,
                "execution_time": execution_time,
                "raw_output": result.stdout
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": self.name,
                "status": "timeout",
                "error": f"Timeout después de {timeout}s",
                "findings": []
            }
        except Exception as e:
            self.logger.error(f"Error ejecutando Slither: {e}")
            return {
                "tool": self.name,
                "status": "error",
                "error": str(e),
                "findings": []
            }

    def _parse_findings(self, output: Dict, contract_path: str) -> List[Finding]:
        """Parsea y normaliza hallazgos de Slither."""
        findings = []

        for detector in output.get("results", {}).get("detectors", []):
            detector_type = detector.get("check", "unknown")

            # Mapear a SWC
            swc_id = self.DETECTOR_TO_SWC.get(detector_type)
            cwe_id = self.SWC_TO_CWE.get(swc_id) if swc_id else None

            # Extraer ubicación
            elements = detector.get("elements", [])
            location = {}
            if elements:
                first_elem = elements[0]
                location = {
                    "file": first_elem.get("source_mapping", {}).get("filename_relative", ""),
                    "line": first_elem.get("source_mapping", {}).get("lines", [0])[0],
                    "function": first_elem.get("name", ""),
                    "contract": first_elem.get("type_specific_fields", {}).get("parent", {}).get("name", "")
                }

            finding = Finding(
                id=f"SLITHER-{detector_type}-{len(findings)+1}",
                type=detector_type,
                severity=self.normalize_severity(detector.get("impact", "medium")),
                confidence=detector.get("confidence", "medium"),
                title=detector.get("check", "Unknown Issue"),
                description=detector.get("description", ""),
                location=location,
                swc_id=swc_id,
                cwe_id=cwe_id,
                recommendation=detector.get("recommendation", ""),
                detected_by=self.name
            )
            findings.append(finding)

        return findings
```

---

## E.4 Sistema de Normalización

```python
# src/normalizer/finding_normalizer.py
from typing import List, Dict, Any, Set
from dataclasses import asdict
import hashlib
from ..adapters.base_adapter import Finding, Severity

class FindingNormalizer:
    """
    Sistema de normalización y deduplicación de hallazgos.

    Implementa el proceso de normalización descrito en el Capítulo 4,
    mapeando hallazgos de diferentes herramientas a taxonomías
    estándar (SWC, CWE, OWASP) y eliminando duplicados.
    """

    def __init__(self):
        self._swc_registry = self._load_swc_registry()
        self._dedup_hashes: Set[str] = set()

    def normalize_findings(
        self,
        findings: List[Finding],
        deduplicate: bool = True
    ) -> Dict[str, Any]:
        """
        Normaliza y opcionalmente deduplica hallazgos.

        Args:
            findings: Lista de hallazgos de múltiples herramientas
            deduplicate: Si True, elimina duplicados

        Returns:
            Dict con hallazgos normalizados y estadísticas
        """
        normalized = []
        duplicates_removed = 0

        for finding in findings:
            # Enriquecer con información SWC/CWE si falta
            if finding.swc_id and not finding.cwe_id:
                finding.cwe_id = self._swc_to_cwe(finding.swc_id)

            if deduplicate:
                fingerprint = self._compute_fingerprint(finding)
                if fingerprint in self._dedup_hashes:
                    duplicates_removed += 1
                    continue
                self._dedup_hashes.add(fingerprint)

            normalized.append(finding)

        # Ordenar por severidad
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4
        }
        normalized.sort(key=lambda f: severity_order.get(f.severity, 5))

        return {
            "findings": [asdict(f) for f in normalized],
            "total_raw": len(findings),
            "total_unique": len(normalized),
            "duplicates_removed": duplicates_removed,
            "deduplication_rate": duplicates_removed / len(findings) if findings else 0,
            "by_severity": self._count_by_severity(normalized),
            "by_swc": self._count_by_swc(normalized)
        }

    def _compute_fingerprint(self, finding: Finding) -> str:
        """
        Computa fingerprint único para deduplicación.

        Dos hallazgos se consideran duplicados si tienen:
        - Mismo SWC ID (o tipo si no hay SWC)
        - Misma ubicación (archivo + línea)
        """
        components = [
            finding.swc_id or finding.type,
            finding.location.get("file", ""),
            str(finding.location.get("line", 0))
        ]
        fingerprint_str = "|".join(components)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]

    def _swc_to_cwe(self, swc_id: str) -> str:
        """Mapea SWC a CWE."""
        mapping = {
            "SWC-100": "CWE-676",   # Function Default Visibility
            "SWC-101": "CWE-190",   # Integer Overflow
            "SWC-102": "CWE-710",   # Outdated Compiler
            "SWC-103": "CWE-330",   # Floating Pragma
            "SWC-104": "CWE-252",   # Unchecked Return
            "SWC-105": "CWE-284",   # Unprotected Ether
            "SWC-106": "CWE-284",   # Unprotected Selfdestruct
            "SWC-107": "CWE-841",   # Reentrancy
            "SWC-108": "CWE-664",   # State Variable Default
            "SWC-109": "CWE-824",   # Uninitialized Storage
            "SWC-110": "CWE-617",   # Assert Violation
            "SWC-111": "CWE-703",   # Deprecated Functions
            "SWC-112": "CWE-829",   # Delegatecall
            "SWC-113": "CWE-400",   # DoS Gas Limit
            "SWC-114": "CWE-362",   # Transaction Ordering
            "SWC-115": "CWE-477",   # tx.origin
            "SWC-116": "CWE-829",   # Timestamp Dependence
            "SWC-117": "CWE-400",   # Signature Malleability
            "SWC-118": "CWE-697",   # Constructor Mismatch
            "SWC-119": "CWE-710",   # Shadowing State
            "SWC-120": "CWE-330",   # Weak PRNG
            "SWC-121": "CWE-693",   # Missing Protection
            "SWC-122": "CWE-682",   # Lack of Decimals
            "SWC-123": "CWE-617",   # Require Violation
            "SWC-124": "CWE-665",   # Write to Arbitrary
            "SWC-125": "CWE-682",   # Incorrect Inheritance
            "SWC-126": "CWE-672",   # Insufficient Gas
            "SWC-127": "CWE-829",   # Arbitrary Jump
            "SWC-128": "CWE-400",   # DoS Unexpected
            "SWC-129": "CWE-129",   # Typographical Error
            "SWC-130": "CWE-665",   # Right-to-Left
            "SWC-131": "CWE-682",   # Presence of Unused
            "SWC-132": "CWE-667",   # Unexpected Ether
            "SWC-133": "CWE-682",   # Hash Collision
            "SWC-134": "CWE-664",   # Message Call
            "SWC-135": "CWE-682",   # Code With No Effects
            "SWC-136": "CWE-682",   # Unencrypted Private
        }
        return mapping.get(swc_id, "CWE-unknown")

    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Cuenta hallazgos por severidad."""
        counts = {}
        for f in findings:
            sev = f.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_swc(self, findings: List[Finding]) -> Dict[str, int]:
        """Cuenta hallazgos por SWC ID."""
        counts = {}
        for f in findings:
            if f.swc_id:
                counts[f.swc_id] = counts.get(f.swc_id, 0) + 1
        return counts

    def _load_swc_registry(self) -> Dict:
        """Carga el registro SWC."""
        # En producción, cargaría desde archivo o API
        return {}
```

---

## E.5 Orquestador de Pipeline

```python
# src/pipeline/orchestrator.py
import asyncio
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor
import time

from ..adapters import get_all_adapters, get_adapters_by_layer
from ..normalizer.finding_normalizer import FindingNormalizer

class PipelineOrchestrator:
    """
    Orquestador del pipeline de análisis de MIESC.

    Coordina la ejecución de las 7 capas de análisis,
    gestionando paralelismo intra-capa y secuencialidad
    inter-capa según configuración.
    """

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.normalizer = FindingNormalizer()
        self.adapters = get_all_adapters()

    async def run_analysis(
        self,
        contract_path: str,
        layers: Optional[List[int]] = None,
        parallel: bool = True,
        timeout_per_tool: int = 300
    ) -> Dict[str, Any]:
        """
        Ejecuta el pipeline de análisis completo.

        Args:
            contract_path: Ruta al contrato a analizar
            layers: Capas a ejecutar (1-7). None = todas
            parallel: Ejecutar herramientas en paralelo
            timeout_per_tool: Timeout por herramienta

        Returns:
            Dict con resultados consolidados y normalizados
        """
        start_time = time.time()

        if layers is None:
            layers = list(range(1, 8))

        all_findings = []
        layer_results = {}

        for layer_num in sorted(layers):
            layer_start = time.time()
            layer_adapters = get_adapters_by_layer(layer_num)

            if parallel:
                layer_findings = await self._run_layer_parallel(
                    layer_adapters,
                    contract_path,
                    timeout_per_tool
                )
            else:
                layer_findings = await self._run_layer_sequential(
                    layer_adapters,
                    contract_path,
                    timeout_per_tool
                )

            all_findings.extend(layer_findings)
            layer_results[f"layer_{layer_num}"] = {
                "tools_executed": len(layer_adapters),
                "findings_raw": len(layer_findings),
                "execution_time": time.time() - layer_start
            }

        # Normalizar y deduplicar
        normalized = self.normalizer.normalize_findings(all_findings)

        total_time = time.time() - start_time

        return {
            "status": "completed",
            "contract": contract_path,
            "layers_executed": layers,
            "execution_time": total_time,
            "summary": {
                "total_raw_findings": len(all_findings),
                "total_unique_findings": normalized["total_unique"],
                "deduplication_rate": normalized["deduplication_rate"],
                "by_severity": normalized["by_severity"]
            },
            "findings": normalized["findings"],
            "layer_details": layer_results
        }

    async def _run_layer_parallel(
        self,
        adapters: List,
        contract_path: str,
        timeout: int
    ) -> List:
        """Ejecuta herramientas de una capa en paralelo."""
        findings = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(
                    executor,
                    adapter.analyze,
                    contract_path,
                    {"timeout": timeout}
                )
                for adapter in adapters
                if adapter.is_available()
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    continue
                if result.get("status") == "success":
                    findings.extend(result.get("findings", []))

        return findings

    async def _run_layer_sequential(
        self,
        adapters: List,
        contract_path: str,
        timeout: int
    ) -> List:
        """Ejecuta herramientas de una capa secuencialmente."""
        findings = []

        for adapter in adapters:
            if not adapter.is_available():
                continue

            result = adapter.analyze(contract_path, timeout=timeout)
            if result.get("status") == "success":
                findings.extend(result.get("findings", []))

        return findings
```

---

## E.6 Servidor MCP

```python
# src/mcp/server.py
"""
Servidor MCP (Model Context Protocol) de MIESC.

Expone las capacidades de análisis de MIESC como herramientas
que pueden ser invocadas por asistentes de IA como Claude.

Referencias:
    Anthropic (2024). Model Context Protocol Specification.
"""
import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, Resource, TextContent

from ..pipeline.orchestrator import PipelineOrchestrator
from ..adapters import get_all_adapters

app = Server("miesc-security")
orchestrator = PipelineOrchestrator()

@app.list_tools()
async def list_tools() -> list[Tool]:
    """Lista herramientas MCP disponibles."""
    tools = [
        Tool(
            name="analyze_contract",
            description="Analiza un smart contract usando las 7 capas de MIESC",
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_path": {
                        "type": "string",
                        "description": "Ruta al archivo .sol"
                    },
                    "layers": {
                        "type": "array",
                        "items": {"type": "integer", "minimum": 1, "maximum": 7},
                        "description": "Capas a ejecutar (1-7). Default: todas"
                    }
                },
                "required": ["contract_path"]
            }
        ),
        Tool(
            name="get_tool_status",
            description="Obtiene el estado de las 25 herramientas integradas",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="explain_vulnerability",
            description="Explica una vulnerabilidad por su SWC ID",
            inputSchema={
                "type": "object",
                "properties": {
                    "swc_id": {
                        "type": "string",
                        "description": "ID de la vulnerabilidad (ej: SWC-107)"
                    }
                },
                "required": ["swc_id"]
            }
        )
    ]
    return tools

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Ejecuta una herramienta MCP."""

    if name == "analyze_contract":
        contract_path = arguments.get("contract_path")
        layers = arguments.get("layers", list(range(1, 8)))

        # Validar path
        if not contract_path or ".." in contract_path:
            return [TextContent(
                type="text",
                text="Error: Ruta de contrato inválida"
            )]

        # Ejecutar análisis
        result = await orchestrator.run_analysis(
            contract_path=contract_path,
            layers=layers
        )

        return [TextContent(
            type="text",
            text=format_analysis_result(result)
        )]

    elif name == "get_tool_status":
        adapters = get_all_adapters()
        status_lines = []

        for adapter in adapters:
            available = "✓" if adapter.is_available() else "✗"
            version = adapter.get_version() or "N/A"
            status_lines.append(
                f"[{available}] {adapter.name} (Layer {adapter.layer}) - v{version}"
            )

        return [TextContent(
            type="text",
            text="\n".join(status_lines)
        )]

    elif name == "explain_vulnerability":
        swc_id = arguments.get("swc_id", "").upper()
        explanation = get_swc_explanation(swc_id)
        return [TextContent(type="text", text=explanation)]

    return [TextContent(type="text", text=f"Herramienta desconocida: {name}")]

def format_analysis_result(result: dict) -> str:
    """Formatea resultado de análisis para respuesta MCP."""
    lines = [
        f"=== Análisis MIESC Completado ===",
        f"Contrato: {result['contract']}",
        f"Tiempo: {result['execution_time']:.2f}s",
        f"",
        f"Resumen:",
        f"  - Hallazgos brutos: {result['summary']['total_raw_findings']}",
        f"  - Hallazgos únicos: {result['summary']['total_unique_findings']}",
        f"  - Deduplicación: {result['summary']['deduplication_rate']:.1%}",
        f"",
        f"Por severidad:"
    ]

    for severity, count in result['summary']['by_severity'].items():
        lines.append(f"  - {severity.upper()}: {count}")

    lines.append("")
    lines.append("Hallazgos principales:")

    for i, finding in enumerate(result['findings'][:5], 1):
        lines.append(f"")
        lines.append(f"{i}. [{finding['severity']}] {finding['title']}")
        lines.append(f"   Ubicación: {finding['location'].get('file', '')}:{finding['location'].get('line', '')}")
        lines.append(f"   SWC: {finding.get('swc_id', 'N/A')}")
        if finding.get('recommendation'):
            lines.append(f"   Recomendación: {finding['recommendation'][:100]}...")

    return "\n".join(lines)

async def main():
    """Inicia el servidor MCP."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
```

---

## E.7 Integración con Ollama

```python
# src/adapters/base_llm_adapter.py
"""
Adaptador base para integración con LLMs locales via Ollama.

Garantiza soberanía de datos ejecutando análisis de IA
completamente en infraestructura local.
"""
import requests
from typing import Dict, Any, Optional
from abc import abstractmethod
from .base_adapter import ToolAdapter

class BaseLLMAdapter(ToolAdapter):
    """
    Clase base para adaptadores que utilizan LLMs locales.

    Implementa conexión segura con Ollama garantizando:
    1. Solo conexiones a localhost
    2. Sin telemetría externa
    3. Modelos descargados localmente
    """

    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434"
    ):
        super().__init__()
        self.model = model
        self.base_url = base_url
        self._verify_local_only()

    def _verify_local_only(self) -> None:
        """Verifica que solo conectamos a localhost."""
        allowed_hosts = ["localhost", "127.0.0.1", "::1"]
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        if parsed.hostname not in allowed_hosts:
            raise SecurityError(
                f"LLM debe ejecutarse localmente. Host inválido: {parsed.hostname}"
            )

    def is_available(self) -> bool:
        """Verifica que Ollama esté corriendo y el modelo disponible."""
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=5
            )
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                return self.model in model_names
        except Exception:
            pass
        return False

    def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4096
    ) -> str:
        """
        Genera respuesta del LLM local.

        Args:
            prompt: Prompt para el modelo
            temperature: Control de creatividad (0.1 = determinista)
            max_tokens: Máximo de tokens en respuesta

        Returns:
            Respuesta del modelo
        """
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            },
            timeout=120
        )

        if response.status_code == 200:
            return response.json().get("response", "")

        raise RuntimeError(f"Error de Ollama: {response.status_code}")

    @abstractmethod
    def _build_security_prompt(self, code: str) -> str:
        """Construye prompt específico para análisis de seguridad."""
        pass

class SecurityError(Exception):
    """Error de seguridad en configuración de LLM."""
    pass
```

---

## E.8 Estructura del Proyecto

```
MIESC/
├── src/
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base_adapter.py          # Clase base ToolAdapter
│   │   ├── base_llm_adapter.py      # Base para adaptadores LLM
│   │   ├── slither_adapter.py       # Capa 1: Análisis Estático
│   │   ├── solhint_adapter.py
│   │   ├── securify_adapter.py
│   │   ├── echidna_adapter.py       # Capa 2: Fuzzing
│   │   ├── foundry_adapter.py
│   │   ├── medusa_adapter.py
│   │   ├── mythril_adapter.py       # Capa 3: Ejecución Simbólica
│   │   ├── manticore_adapter.py
│   │   ├── oyente_adapter.py
│   │   ├── halmos_adapter.py        # Capa 4: Invariant Testing
│   │   ├── scribble_adapter.py
│   │   ├── smtchecker_adapter.py    # Capa 5: Verificación Formal
│   │   ├── certora_adapter.py
│   │   ├── propertygpt_adapter.py   # Capa 6: Property Testing
│   │   ├── gptscan_adapter.py       # Capa 7: Análisis IA
│   │   ├── smartllm_adapter.py
│   │   └── threat_model_adapter.py
│   │
│   ├── normalizer/
│   │   ├── __init__.py
│   │   ├── finding_normalizer.py    # Normalización y deduplicación
│   │   └── swc_registry.py          # Registro SWC
│   │
│   ├── pipeline/
│   │   ├── __init__.py
│   │   └── orchestrator.py          # Orquestación de capas
│   │
│   ├── mcp/
│   │   ├── __init__.py
│   │   ├── server.py                # Servidor MCP
│   │   ├── tool_handler.py
│   │   └── resource_handler.py
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   └── rest_server.py           # API REST
│   │
│   └── config/
│       ├── __init__.py
│       └── settings.py              # Configuración
│
├── contracts/
│   └── audit/                       # Contratos de prueba
│       ├── VulnerableBank.sol
│       └── UnsafeToken.sol
│
├── tests/
│   ├── test_adapters/
│   ├── test_normalizer/
│   └── test_pipeline/
│
├── docs/
│   └── tesis/                       # Documentación de tesis
│
├── requirements.txt
├── setup.py
└── README.md
```

---

**Total de líneas de código representativo:** ~800

---

*Nota: Este apéndice presenta fragmentos representativos. El código completo está disponible en el repositorio del proyecto.*
