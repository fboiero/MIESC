"""
Tool adapter protocol for heterogeneous security tool integration.

Defines abstract interface that all tool adapters must implement.
Enables loose coupling and avoids vendor lock-in (DPGA requirement).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Tool categories per MIESC 7-layer architecture"""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_TESTING = "dynamic_testing"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    FORMAL_VERIFICATION = "formal_verification"
    AI_ANALYSIS = "ai_analysis"
    COMPLIANCE = "compliance"
    AUDIT_READINESS = "audit_readiness"
    GAS_OPTIMIZATION = "gas_optimization"
    MEV_DETECTION = "mev_detection"
    PRIVACY_ANALYSIS = "privacy_analysis"


class ToolStatus(Enum):
    """Estado de disponibilidad de la herramienta"""
    AVAILABLE = "available"
    NOT_INSTALLED = "not_installed"
    CONFIGURATION_ERROR = "configuration_error"
    LICENSE_REQUIRED = "license_required"
    DEPRECATED = "deprecated"


@dataclass
class ToolCapability:
    """Capacidad específica de una herramienta"""
    name: str
    description: str
    supported_languages: List[str]
    detection_types: List[str]  # e.g., ["reentrancy", "overflow", "access_control"]


@dataclass
class ToolMetadata:
    """Metadatos de una herramienta"""
    name: str
    version: str
    category: ToolCategory
    author: str
    license: str
    homepage: str
    repository: str
    documentation: str
    installation_cmd: str
    capabilities: List[ToolCapability]
    cost: float = 0.0  # 0.0 = free, >0 = paid/API cost
    requires_api_key: bool = False
    is_optional: bool = True  # Por defecto todas son opcionales (no vendor lock-in)


class ToolAdapter(ABC):
    """
    Interfaz base para adaptadores de herramientas.

    Todas las herramientas deben implementar este protocolo para integrarse a MIESC.
    Esto permite:
    - Desacoplar herramientas específicas
    - Intercambiar implementaciones sin cambiar código
    - Agregar nuevas herramientas sin modificar core
    - Cumplir requisitos DPGA

    Ejemplo de uso:

    ```python
    class MyToolAdapter(ToolAdapter):
        def get_metadata(self) -> ToolMetadata:
            return ToolMetadata(
                name="mytool",
                version="1.0.0",
                category=ToolCategory.STATIC_ANALYSIS,
                ...
            )

        def is_available(self) -> ToolStatus:
            # Check if tool is installed
            return ToolStatus.AVAILABLE

        def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
            # Run tool and return normalized results
            return {"findings": [...]}
    ```
    """

    @abstractmethod
    def get_metadata(self) -> ToolMetadata:
        """
        Retorna metadatos de la herramienta.

        OBLIGATORIO: Implementar para que MIESC conozca la herramienta.
        """
        pass

    @abstractmethod
    def is_available(self) -> ToolStatus:
        """
        Verifica si la herramienta está disponible y configurada.

        OBLIGATORIO: Permite a MIESC saber si puede usar la herramienta.

        Returns:
            ToolStatus indicando disponibilidad
        """
        pass

    @abstractmethod
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta análisis con la herramienta.

        OBLIGATORIO: Punto de entrada principal para usar la herramienta.

        Args:
            contract_path: Ruta al contrato Solidity
            **kwargs: Parámetros adicionales específicos de la herramienta

        Returns:
            Diccionario con formato normalizado:
            {
                "tool": str,  # Nombre de la herramienta
                "version": str,
                "status": "success" | "error",
                "findings": List[Dict],  # Findings normalizados
                "metadata": Dict,  # Información adicional
                "execution_time": float,
                "error": Optional[str]  # Si status == "error"
            }
        """
        pass

    @abstractmethod
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normaliza findings de formato específico de la herramienta a formato MIESC.

        OBLIGATORIO: Permite que MIESC procese findings de manera uniforme.

        Args:
            raw_output: Output crudo de la herramienta

        Returns:
            Lista de findings normalizados con estructura:
            {
                "id": str,  # Identificador único
                "type": str,  # Tipo de vulnerabilidad
                "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
                "confidence": float,  # 0.0-1.0
                "location": {
                    "file": str,
                    "line": int,
                    "function": str
                },
                "message": str,
                "description": str,
                "recommendation": str,
                "swc_id": Optional[str],  # SWC-XXX
                "cwe_id": Optional[str],  # CWE-XXX
                "owasp_category": Optional[str]  # OWASP SC Top 10
            }
        """
        pass

    def get_installation_instructions(self) -> str:
        """
        Retorna instrucciones de instalación de la herramienta.

        OPCIONAL: Ayuda a usuarios instalar herramientas opcionales.
        """
        metadata = self.get_metadata()
        return f"""
# Instalación de {metadata.name}

**Licencia**: {metadata.license}
**Costo**: {'Gratuita' if metadata.cost == 0 else f'${metadata.cost}'}

## Comando de instalación

```bash
{metadata.installation_cmd}
```

## Documentación oficial

- Homepage: {metadata.homepage}
- Repositorio: {metadata.repository}
- Docs: {metadata.documentation}

## Verificación

Después de instalar, verifica la disponibilidad:

```python
from src.adapters.{metadata.name}_adapter import {metadata.name.title()}Adapter

adapter = {metadata.name.title()}Adapter()
status = adapter.is_available()
print(f"Estado: {{status}}")
```
"""

    def can_analyze(self, contract_path: str) -> bool:
        """
        Verifica si la herramienta puede analizar el contrato dado.

        OPCIONAL: Permite filtrar herramientas por tipo de contrato.
        Por defecto acepta todos los archivos .sol
        """
        return contract_path.endswith('.sol')

    def get_default_config(self) -> Dict[str, Any]:
        """
        Retorna configuración por defecto de la herramienta.

        OPCIONAL: Permite configurar herramienta sin conocer detalles.
        """
        return {}

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Valida configuración de la herramienta.

        OPCIONAL: Previene errores de configuración.
        """
        return True


class ToolRegistry:
    """
    Registro central de herramientas disponibles.

    Permite descubrimiento dinámico de herramientas sin modificar código core.
    """

    def __init__(self):
        self._tools: Dict[str, ToolAdapter] = {}
        self._initialized = False

    def register(self, adapter: ToolAdapter) -> None:
        """
        Registra una herramienta en el sistema.

        Args:
            adapter: Adaptador que implementa ToolAdapter
        """
        metadata = adapter.get_metadata()
        tool_name = metadata.name

        if tool_name in self._tools:
            logger.warning(f"Herramienta {tool_name} ya registrada, sobrescribiendo")

        self._tools[tool_name] = adapter
        logger.info(f"Herramienta registrada: {tool_name} v{metadata.version}")

    def get_tool(self, name: str) -> Optional[ToolAdapter]:
        """Obtiene adaptador de herramienta por nombre"""
        return self._tools.get(name)

    def get_all_tools(self) -> List[ToolAdapter]:
        """Retorna todas las herramientas registradas"""
        return list(self._tools.values())

    def get_tools_by_category(self, category: ToolCategory) -> List[ToolAdapter]:
        """Retorna herramientas de una categoría específica"""
        return [
            tool for tool in self._tools.values()
            if tool.get_metadata().category == category
        ]

    def get_available_tools(self) -> List[ToolAdapter]:
        """Retorna solo herramientas disponibles (instaladas y configuradas)"""
        available = []
        for tool in self._tools.values():
            status = tool.is_available()
            if status == ToolStatus.AVAILABLE:
                available.append(tool)
        return available

    def get_tool_status_report(self) -> Dict[str, Any]:
        """
        Genera reporte de estado de todas las herramientas.

        Útil para diagnóstico y verificación de instalación.
        """
        report = {
            "total_tools": len(self._tools),
            "available": 0,
            "not_installed": 0,
            "configuration_error": 0,
            "tools": []
        }

        for tool in self._tools.values():
            metadata = tool.get_metadata()
            status = tool.is_available()

            tool_info = {
                "name": metadata.name,
                "version": metadata.version,
                "category": metadata.category.value,
                "status": status.value,
                "cost": metadata.cost,
                "optional": metadata.is_optional
            }

            report["tools"].append(tool_info)

            if status == ToolStatus.AVAILABLE:
                report["available"] += 1
            elif status == ToolStatus.NOT_INSTALLED:
                report["not_installed"] += 1
            elif status == ToolStatus.CONFIGURATION_ERROR:
                report["configuration_error"] += 1

        return report


# Singleton del registro
_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Obtiene instancia singleton del registro de herramientas"""
    return _registry
