"""
MIESC Configuration Loader
Carga y gestiona la configuración centralizada desde config/miesc.yaml
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class AdapterConfig:
    """Configuración de un adaptador individual."""
    name: str
    enabled: bool = True
    layer: str = "static_analysis"
    timeout: int = 60
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LayerConfig:
    """Configuración de una capa de análisis."""
    name: str
    enabled: bool = True
    priority: int = 1
    tools: List[str] = field(default_factory=list)


class MIESCConfig:
    """Gestor de configuración centralizada de MIESC."""

    _instance: Optional['MIESCConfig'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _find_config_file(self) -> Path:
        """Encuentra el archivo de configuración."""
        # Buscar en orden de prioridad
        env_config = os.environ.get('MIESC_CONFIG', '')
        search_paths = [
            Path.cwd() / 'config' / 'miesc.yaml',
            Path.cwd() / 'miesc.yaml',
            Path(__file__).parent.parent.parent / 'config' / 'miesc.yaml',
            Path.home() / '.miesc' / 'config.yaml',
        ]

        # Agregar config de env solo si no está vacío
        if env_config:
            search_paths.insert(0, Path(env_config))

        for path in search_paths:
            if path.exists() and path.is_file():
                return path

        # Retornar path default aunque no exista
        return Path(__file__).parent.parent.parent / 'config' / 'miesc.yaml'

    def _load_config(self) -> None:
        """Carga la configuración desde el archivo YAML."""
        config_path = self._find_config_file()

        if config_path.exists():
            with open(config_path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Retorna configuración por defecto."""
        return {
            'version': '4.2.0',
            'global': {
                'log_level': 'INFO',
                'max_workers': 4,
                'cache_enabled': True,
                'cache_ttl_seconds': 3600,
            },
            'chains': {
                'default': 'ethereum',
                'ethereum': {'name': 'Ethereum', 'chain_id': 1, 'enabled': True},
            },
            'adapters': {},
            'layers': {},
        }

    def reload(self) -> None:
        """Recarga la configuración desde disco."""
        self._load_config()

    @property
    def version(self) -> str:
        """Versión de la configuración."""
        return self._config.get('version', '4.0.0')

    @property
    def global_config(self) -> Dict[str, Any]:
        """Configuración global."""
        return self._config.get('global', {})

    @property
    def max_workers(self) -> int:
        """Número máximo de workers para paralelismo."""
        return self.global_config.get('max_workers', 4)

    @property
    def cache_enabled(self) -> bool:
        """Si el caché está habilitado."""
        return self.global_config.get('cache_enabled', True)

    @property
    def log_level(self) -> str:
        """Nivel de logging."""
        return self.global_config.get('log_level', 'INFO')

    def get_adapter_config(self, adapter_name: str) -> AdapterConfig:
        """Obtiene la configuración de un adaptador específico."""
        adapters = self._config.get('adapters', {})
        adapter_data = adapters.get(adapter_name, {})

        return AdapterConfig(
            name=adapter_name,
            enabled=adapter_data.get('enabled', True),
            layer=adapter_data.get('layer', 'static_analysis'),
            timeout=adapter_data.get('timeout', 60),
            options=adapter_data.get('options', {}),
        )

    def get_layer_config(self, layer_name: str) -> LayerConfig:
        """Obtiene la configuración de una capa."""
        layers = self._config.get('layers', {})
        layer_data = layers.get(layer_name, {})

        return LayerConfig(
            name=layer_name,
            enabled=layer_data.get('enabled', True),
            priority=layer_data.get('priority', 1),
            tools=layer_data.get('tools', []),
        )

    def get_enabled_adapters(self) -> List[str]:
        """Obtiene lista de adaptadores habilitados."""
        adapters = self._config.get('adapters', {})
        return [
            name for name, config in adapters.items()
            if config.get('enabled', True)
        ]

    def get_adapters_by_layer(self, layer_name: str) -> List[str]:
        """Obtiene adaptadores de una capa específica."""
        adapters = self._config.get('adapters', {})
        return [
            name for name, config in adapters.items()
            if config.get('layer') == layer_name and config.get('enabled', True)
        ]

    def get_all_layers(self) -> List[LayerConfig]:
        """Obtiene todas las capas ordenadas por prioridad."""
        layers = self._config.get('layers', {})
        layer_configs = []

        for name, data in layers.items():
            layer_configs.append(LayerConfig(
                name=name,
                enabled=data.get('enabled', True),
                priority=data.get('priority', 99),
                tools=data.get('tools', []),
            ))

        return sorted(layer_configs, key=lambda x: x.priority)

    def get_llm_config(self) -> Dict[str, Any]:
        """Obtiene configuración de LLM."""
        return self._config.get('llm', {
            'provider': 'ollama',
            'host': 'http://localhost:11434',
            'default_model': 'deepseek-coder',
        })

    def get_results_config(self) -> Dict[str, Any]:
        """Obtiene configuración de resultados."""
        return self._config.get('results', {
            'deduplication': {'enabled': True, 'similarity_threshold': 0.85},
            'cross_validation': {'enabled': True, 'min_confirmations': 2},
        })

    def get_compliance_frameworks(self) -> List[str]:
        """Obtiene frameworks de compliance habilitados."""
        compliance = self._config.get('compliance', {})
        if compliance.get('enabled', True):
            return compliance.get('frameworks', ['ISO27001', 'NIST', 'OWASP', 'CWE', 'SWC'])
        return []

    def get_chain_config(self, chain_name: Optional[str] = None) -> Dict[str, Any]:
        """Obtiene configuración de una blockchain específica."""
        chains = self._config.get('chains', {})
        target_chain = chain_name or chains.get('default', 'ethereum')
        return chains.get(target_chain, {
            'name': 'Ethereum',
            'evm_version': 'shanghai',
            'solc_version': '0.8.19',
            'chain_id': 1,
            'enabled': True,
        })

    def get_enabled_chains(self) -> List[str]:
        """Obtiene lista de blockchains habilitadas."""
        chains = self._config.get('chains', {})
        return [
            name for name, config in chains.items()
            if isinstance(config, dict) and config.get('enabled', True)
        ]

    def get_license_plan_config(self, plan_name: str) -> Dict[str, Any]:
        """Obtiene configuración de un plan de licencia."""
        plans = self._config.get('license_plans', {})
        return plans.get(plan_name.upper(), {})

    def to_dict(self) -> Dict[str, Any]:
        """Exporta toda la configuración como diccionario."""
        return self._config.copy()


# Singleton instance
def get_config() -> MIESCConfig:
    """Obtiene la instancia singleton de configuración."""
    return MIESCConfig()
