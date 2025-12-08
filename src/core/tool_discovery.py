"""
MIESC Tool Discovery
Descubre y carga dinámicamente todos los adaptadores disponibles.
"""

import os
import importlib
import inspect
from pathlib import Path
from typing import Dict, Any, List, Optional, Type
from dataclasses import dataclass, field


@dataclass
class ToolInfo:
    """Información de una herramienta descubierta."""
    name: str
    adapter_class: str
    module_path: str
    layer: str
    category: str
    available: bool
    description: str = ""
    version: Optional[str] = None
    is_optional: bool = True
    requires_api_key: bool = False
    external_deps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'layer': self.layer,
            'category': self.category,
            'available': self.available,
            'description': self.description,
            'version': self.version,
            'is_optional': self.is_optional,
            'requires_api_key': self.requires_api_key,
        }


class ToolDiscovery:
    """
    Descubre dinámicamente todos los adaptadores MIESC disponibles.

    Escanea el directorio de adaptadores y carga información sobre cada uno,
    incluyendo disponibilidad y metadatos.
    """

    # Mapeo de nombres de archivo a nombre canónico
    NAME_MAPPING = {
        'slither_adapter': 'slither',
        'mythril_adapter': 'mythril',
        'aderyn_adapter': 'aderyn',
        'solhint_adapter': 'solhint',
        'echidna_adapter': 'echidna',
        'foundry_adapter': 'foundry',
        'medusa_adapter': 'medusa',
        'dogefuzz_adapter': 'dogefuzz',
        'manticore_adapter': 'manticore',
        'halmos_adapter': 'halmos',
        'smtchecker_adapter': 'smtchecker',
        'certora_adapter': 'certora',
        'wake_adapter': 'wake',
        'propertygpt_adapter': 'propertygpt',
        'smartllm_adapter': 'smartllm',
        'gptscan_adapter': 'gptscan',
        'llmsmartaudit_adapter': 'llmsmartaudit',
        'gas_analyzer_adapter': 'gas_analyzer',
        'mev_detector_adapter': 'mev_detector',
        'threat_model_adapter': 'threat_model',
        'smartbugs_ml_adapter': 'smartbugs_ml',
        'dagnn_adapter': 'dagnn',
        'contract_clone_detector_adapter': 'contract_clone_detector',
        'oyente_adapter': 'oyente',
        'vertigo_adapter': 'vertigo',
    }

    # Categorías por capa
    LAYER_MAPPING = {
        'slither': ('static_analysis', 'Static Analysis'),
        'aderyn': ('static_analysis', 'Static Analysis'),
        'solhint': ('static_analysis', 'Linter'),
        'echidna': ('dynamic_testing', 'Fuzzing'),
        'foundry': ('dynamic_testing', 'Testing Framework'),
        'medusa': ('dynamic_testing', 'Fuzzing'),
        'dogefuzz': ('dynamic_testing', 'Fuzzing'),
        'mythril': ('symbolic_execution', 'Symbolic Execution'),
        'manticore': ('symbolic_execution', 'Symbolic Execution'),
        'halmos': ('symbolic_execution', 'Symbolic Testing'),
        'oyente': ('symbolic_execution', 'Symbolic Execution'),
        'smtchecker': ('formal_verification', 'Formal Verification'),
        'certora': ('formal_verification', 'Formal Verification'),
        'wake': ('formal_verification', 'Testing Framework'),
        'propertygpt': ('property_testing', 'AI Property Generation'),
        'smartllm': ('ai_analysis', 'LLM Analysis'),
        'gptscan': ('ai_analysis', 'LLM Analysis'),
        'llmsmartaudit': ('ai_analysis', 'LLM Audit'),
        'gas_analyzer': ('specialized', 'Gas Optimization'),
        'mev_detector': ('specialized', 'MEV Detection'),
        'threat_model': ('specialized', 'Threat Modeling'),
        'smartbugs_ml': ('ml_detection', 'Machine Learning'),
        'dagnn': ('ml_detection', 'Graph Neural Network'),
        'contract_clone_detector': ('specialized', 'Clone Detection'),
        'vertigo': ('specialized', 'Mutation Testing'),
    }

    def __init__(self, adapters_path: Optional[str] = None):
        self.adapters_path = adapters_path or self._find_adapters_path()
        self._tools: Dict[str, ToolInfo] = {}
        self._discovered = False

    def _find_adapters_path(self) -> str:
        """Encuentra el directorio de adaptadores."""
        # Intentar múltiples ubicaciones
        candidates = [
            Path(__file__).parent.parent / 'adapters',
            Path.cwd() / 'src' / 'adapters',
            Path.cwd() / 'adapters',
        ]

        for path in candidates:
            if path.exists() and path.is_dir():
                return str(path)

        raise RuntimeError("Could not find adapters directory")

    def discover(self, force: bool = False) -> Dict[str, ToolInfo]:
        """
        Descubre todos los adaptadores disponibles.
        """
        if self._discovered and not force:
            return self._tools

        self._tools = {}
        adapters_dir = Path(self.adapters_path)

        for py_file in adapters_dir.glob("*_adapter.py"):
            if py_file.name.startswith('_'):
                continue

            try:
                tool_info = self._load_adapter_info(py_file)
                if tool_info:
                    self._tools[tool_info.name] = tool_info
            except Exception as e:
                # Silenciosamente ignorar adaptadores que no se pueden cargar
                pass

        self._discovered = True
        return self._tools

    def _load_adapter_info(self, py_file: Path) -> Optional[ToolInfo]:
        """Carga información de un adaptador."""
        file_stem = py_file.stem
        tool_name = self.NAME_MAPPING.get(file_stem, file_stem.replace('_adapter', ''))

        # Construir nombre del módulo
        module_name = f"src.adapters.{file_stem}"

        # Determinar capa y categoría
        layer, category = self.LAYER_MAPPING.get(tool_name, ('other', 'Other'))

        try:
            # Intentar importar el módulo
            module = importlib.import_module(module_name)

            # Buscar la clase del adaptador
            adapter_class = None
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if name.endswith('Adapter') and name != 'ToolAdapter':
                    adapter_class = obj
                    break

            if not adapter_class:
                return None

            # Crear instancia para verificar disponibilidad
            try:
                instance = adapter_class()
                available = instance.is_available()

                # Obtener metadatos si están disponibles
                description = ""
                version = None
                is_optional = True
                requires_api_key = False

                try:
                    metadata = instance.get_metadata()
                    description = getattr(metadata, 'description', '')
                    version = getattr(metadata, 'version', None)
                    is_optional = getattr(metadata, 'is_optional', True)
                    requires_api_key = 'api_key' in str(metadata).lower() or 'certora' in tool_name.lower()
                except Exception:
                    pass

            except Exception:
                available = False
                description = ""
                version = None
                is_optional = True
                requires_api_key = False

            return ToolInfo(
                name=tool_name,
                adapter_class=adapter_class.__name__,
                module_path=module_name,
                layer=layer,
                category=category,
                available=available,
                description=description,
                version=version,
                is_optional=is_optional,
                requires_api_key=requires_api_key,
            )

        except ImportError:
            # El módulo no se pudo importar
            return ToolInfo(
                name=tool_name,
                adapter_class=f"{tool_name.title()}Adapter",
                module_path=module_name,
                layer=layer,
                category=category,
                available=False,
                is_optional=True,
            )

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """Obtiene información de una herramienta específica."""
        if not self._discovered:
            self.discover()
        return self._tools.get(name)

    def get_available_tools(self) -> List[ToolInfo]:
        """Obtiene lista de herramientas disponibles."""
        if not self._discovered:
            self.discover()
        return [t for t in self._tools.values() if t.available]

    def get_tools_by_layer(self) -> Dict[str, List[ToolInfo]]:
        """Agrupa herramientas por capa."""
        if not self._discovered:
            self.discover()

        layers: Dict[str, List[ToolInfo]] = {}
        for tool in self._tools.values():
            if tool.layer not in layers:
                layers[tool.layer] = []
            layers[tool.layer].append(tool)

        return layers

    def get_all_tool_names(self) -> List[str]:
        """Obtiene todos los nombres de herramientas."""
        if not self._discovered:
            self.discover()
        return list(self._tools.keys())

    def load_adapter(self, tool_name: str):
        """Carga e instancia un adaptador."""
        tool = self.get_tool(tool_name)
        if not tool:
            raise ValueError(f"Unknown tool: {tool_name}")

        module = importlib.import_module(tool.module_path)
        adapter_class = getattr(module, tool.adapter_class)
        return adapter_class()

    def to_dict(self) -> Dict[str, Any]:
        """Exporta toda la información de herramientas."""
        if not self._discovered:
            self.discover()

        return {
            'total_tools': len(self._tools),
            'available_tools': len(self.get_available_tools()),
            'tools': {name: tool.to_dict() for name, tool in self._tools.items()},
            'by_layer': {
                layer: [t.name for t in tools]
                for layer, tools in self.get_tools_by_layer().items()
            },
        }


# Singleton
_discovery: Optional[ToolDiscovery] = None


def get_tool_discovery() -> ToolDiscovery:
    """Obtiene la instancia singleton de ToolDiscovery."""
    global _discovery
    if _discovery is None:
        _discovery = ToolDiscovery()
    return _discovery
