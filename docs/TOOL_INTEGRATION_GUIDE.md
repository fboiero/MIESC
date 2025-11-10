# Guía de Integración de Herramientas - MIESC

**Versión**: 1.0.0
**Autor**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
**Fecha**: 9 de Enero, 2025
**Propósito**: Documentar cómo integrar nuevas herramientas de análisis a MIESC

---

## 🎯 Objetivo

Esta guía explica cómo **cualquier desarrollador puede integrar nuevas herramientas** de análisis de smart contracts a MIESC sin modificar el código core.

Esto permite:
- ✅ **Evitar vendor lock-in** - No estar atado a herramientas específicas
- ✅ **Cumplir requisitos DPGA** - Modularidad, extensibilidad, open source
- ✅ **Escalabilidad** - Agregar herramientas sin romper el sistema
- ✅ **Comunidad** - Cualquiera puede contribuir con adaptadores

---

## 📋 Requisitos DPGA (Digital Public Goods Alliance)

MIESC está diseñado para cumplir con los estándares DPGA:

| Requisito | Cumplimiento | Cómo |
|-----------|--------------|------|
| **Open Source** | ✅ | Licencia AGPL-3.0 |
| **Sin dependencias propietarias obligatorias** | ✅ | Todas las tools son opcionales |
| **Modular y extensible** | ✅ | Tool Adapter Protocol |
| **Documentación clara** | ✅ | Este documento |
| **Community-driven** | ✅ | Protoc

olo abierto para contribuciones |

---

## 🔌 Tool Adapter Protocol

### Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                     MIESC Core                              │
│  (No conoce herramientas específicas, solo el protocolo)   │
└────────────────────┬────────────────────────────────────────┘
                     │
          ┌──────────┼──────────┐
          │          │          │
          ▼          ▼          ▼
    ┌─────────┐ ┌─────────┐ ┌─────────┐
    │ Adapter │ │ Adapter │ │ Adapter │
    │   A     │ │   B     │ │   C     │
    └────┬────┘ └────┬────┘ └────┬────┘
         │           │           │
         ▼           ▼           ▼
    ┌─────────┐ ┌─────────┐ ┌─────────┐
    │ Tool A  │ │ Tool B  │ │ Tool C  │
    │(Slither)│ │(Mythril)│ │(Custom) │
    └─────────┘ └─────────┘ └─────────┘
```

**Ventajas**:
- Core nunca depende de herramientas específicas
- Herramientas se pueden agregar/quitar dinámicamente
- Errores en una herramienta no afectan al sistema
- Permite herramientas propietarias opcionales

### Contrato del Protocolo

Toda herramienta debe implementar 4 métodos obligatorios:

```python
from src.core.tool_protocol import ToolAdapter, ToolMetadata, ToolStatus

class MiHerramientaAdapter(ToolAdapter):

    # 1. OBLIGATORIO: Describir la herramienta
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="mi_herramienta",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Tu Nombre",
            license="MIT",
            homepage="https://...",
            repository="https://github.com/...",
            documentation="https://docs...",
            installation_cmd="pip install mi-herramienta",
            capabilities=[...],
            is_optional=True  # ⚠️ Siempre True para evitar vendor lock-in
        )

    # 2. OBLIGATORIO: Verificar disponibilidad
    def is_available(self) -> ToolStatus:
        try:
            import mi_herramienta
            return ToolStatus.AVAILABLE
        except ImportError:
            return ToolStatus.NOT_INSTALLED

    # 3. OBLIGATORIO: Ejecutar análisis
    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        # Ejecutar tu herramienta
        output = mi_herramienta.analyze(contract_path)

        # Normalizar resultados
        findings = self.normalize_findings(output)

        return {
            "tool": "mi_herramienta",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "execution_time": 1.23
        }

    # 4. OBLIGATORIO: Normalizar findings
    def normalize_findings(self, raw_output: Any) -> List[Dict]:
        findings = []
        for item in raw_output:
            findings.append({
                "id": item.id,
                "type": item.vuln_type,
                "severity": self._map_severity(item.severity),
                "confidence": 0.85,
                "location": {
                    "file": item.file,
                    "line": item.line,
                    "function": item.function
                },
                "message": item.message,
                "description": item.description,
                "recommendation": item.fix,
                "swc_id": item.swc_id,
                "cwe_id": item.cwe_id,
                "owasp_category": item.owasp
            })
        return findings
```

---

## 🚀 Tutorial: Integrar una Nueva Herramienta

### Ejemplo Práctico: Integrar "solgraph" (Gas Optimizer)

#### Paso 1: Crear el Adapter

```bash
# Crear archivo del adapter
touch src/adapters/solgraph_adapter.py
```

```python
"""
Solgraph Adapter - Gas Optimization Tool
=========================================

Integra solgraph a MIESC para análisis de optimización de gas.
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List
import subprocess
import json

class SolgraphAdapter(ToolAdapter):

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="solgraph",
            version="1.0.0",
            category=ToolCategory.GAS_OPTIMIZATION,
            author="raineorshine",
            license="MIT",
            homepage="https://github.com/raineorshine/solgraph",
            repository="https://github.com/raineorshine/solgraph",
            documentation="https://github.com/raineorshine/solgraph#readme",
            installation_cmd="npm install -g solgraph",
            capabilities=[
                ToolCapability(
                    name="gas_optimization",
                    description="Detecta patrones que consumen gas innecesario",
                    supported_languages=["solidity"],
                    detection_types=["expensive_operations", "storage_waste", "loop_optimization"]
                )
            ],
            cost=0.0,  # Gratuita
            requires_api_key=False,
            is_optional=True  # ⚠️ Siempre True
        )

    def is_available(self) -> ToolStatus:
        """Verifica si solgraph está instalado"""
        try:
            result = subprocess.run(
                ["solgraph", "--version"],
                capture_output=True,
                timeout=5
            )
            return ToolStatus.AVAILABLE if result.returncode == 0 else ToolStatus.NOT_INSTALLED
        except FileNotFoundError:
            return ToolStatus.NOT_INSTALLED
        except Exception:
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """Ejecuta solgraph en el contrato"""
        import time
        start = time.time()

        try:
            # Ejecutar solgraph
            result = subprocess.run(
                ["solgraph", contract_path, "--json"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                return {
                    "tool": "solgraph",
                    "status": "error",
                    "error": result.stderr,
                    "findings": []
                }

            # Parsear output
            raw_output = json.loads(result.stdout)
            findings = self.normalize_findings(raw_output)

            return {
                "tool": "solgraph",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": time.time() - start
            }

        except Exception as e:
            return {
                "tool": "solgraph",
                "status": "error",
                "error": str(e),
                "findings": []
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict]:
        """Normaliza findings de solgraph a formato MIESC"""
        findings = []

        for issue in raw_output.get("issues", []):
            findings.append({
                "id": f"GAS-{issue['id']}",
                "type": "gas_optimization",
                "severity": "Info",  # Optimizaciones son informativas
                "confidence": 0.90,
                "location": {
                    "file": issue["file"],
                    "line": issue["line"],
                    "function": issue.get("function", "unknown")
                },
                "message": issue["message"],
                "description": f"Gas optimization opportunity: {issue['description']}",
                "recommendation": issue.get("fix", "Review and optimize"),
                "swc_id": None,  # No aplica para gas optimization
                "cwe_id": None,
                "owasp_category": None,
                "gas_saved": issue.get("gas_saved", 0)  # Campo custom
            })

        return findings
```

#### Paso 2: Registrar el Adapter

```python
# En src/adapters/__init__.py

from src.core.tool_protocol import get_tool_registry
from src.adapters.solgraph_adapter import SolgraphAdapter

def register_all_adapters():
    """Registra todos los adapters disponibles"""
    registry = get_tool_registry()

    # Registrar solgraph
    registry.register(SolgraphAdapter())

    # Agregar más adapters aquí...
    # registry.register(MyOtherAdapter())
```

#### Paso 3: Usar el Adapter

```python
from src.core.tool_protocol import get_tool_registry

# Obtener registry
registry = get_tool_registry()

# Obtener adapter
solgraph = registry.get_tool("solgraph")

# Verificar disponibilidad
status = solgraph.is_available()
if status == ToolStatus.AVAILABLE:
    # Ejecutar análisis
    result = solgraph.analyze("MyContract.sol")
    print(f"Findings: {len(result['findings'])}")
else:
    print(f"Solgraph no disponible: {status}")
    print(solgraph.get_installation_instructions())
```

---

## 📚 Ejemplos de Integración

### 1. Herramienta de Línea de Comandos (CLI)

```python
class CLIToolAdapter(ToolAdapter):
    def analyze(self, contract_path: str, **kwargs) -> Dict:
        # Ejecutar comando
        result = subprocess.run(
            ["mi-tool", contract_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parsear JSON output
        data = json.loads(result.stdout)
        findings = self.normalize_findings(data)

        return {"tool": "mi-tool", "findings": findings}
```

### 2. Librería Python

```python
class PythonLibAdapter(ToolAdapter):
    def analyze(self, contract_path: str, **kwargs) -> Dict:
        import mi_libreria

        # Usar API de la librería
        analyzer = mi_libreria.Analyzer()
        results = analyzer.analyze_file(contract_path)

        findings = self.normalize_findings(results)
        return {"tool": "mi_libreria", "findings": findings}
```

### 3. API REST

```python
class APIToolAdapter(ToolAdapter):
    def __init__(self, api_key: str):
        self.api_key = api_key

    def analyze(self, contract_path: str, **kwargs) -> Dict:
        import requests

        # Leer contrato
        with open(contract_path, 'r') as f:
            code = f.read()

        # Llamar API
        response = requests.post(
            "https://api.herramienta.com/analyze",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"code": code}
        )

        data = response.json()
        findings = self.normalize_findings(data)

        return {"tool": "api_tool", "findings": findings}
```

---

## 🔒 Manejo de Herramientas Propietarias

Algunas herramientas requieren licencias o API keys. Esto es ACEPTABLE siempre que:

1. **La herramienta sea OPCIONAL** (`is_optional=True`)
2. **MIESC funcione sin ella** (graceful degradation)
3. **Se documente claramente** el costo y requisitos

```python
class PropietaryToolAdapter(ToolAdapter):
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="proprietary_tool",
            version="1.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            license="Commercial",
            cost=99.0,  # $99/mes
            requires_api_key=True,
            is_optional=True  # ⚠️ OBLIGATORIO
        )

    def is_available(self) -> ToolStatus:
        # Verificar API key
        api_key = os.getenv("PROPRIETARY_TOOL_API_KEY")
        if not api_key:
            return ToolStatus.LICENSE_REQUIRED

        # Verificar validez
        if self._verify_api_key(api_key):
            return ToolStatus.AVAILABLE
        else:
            return ToolStatus.CONFIGURATION_ERROR
```

**Comportamiento de MIESC**:
- Si la herramienta NO está disponible → Continúa con otras herramientas
- Si TODAS las herramientas de una capa fallan → Advierte al usuario pero no falla
- Genera reporte indicando herramientas faltantes

---

## ✅ Checklist de Integración

Antes de contribuir un nuevo adapter, verifica:

- [ ] Implementa `ToolAdapter` completo (4 métodos obligatorios)
- [ ] `is_optional=True` en metadata
- [ ] Maneja errores gracefully (no lanza excepciones al core)
- [ ] Normaliza findings al formato MIESC
- [ ] Incluye tests unitarios
- [ ] Documenta requisitos de instalación
- [ ] Agrega ejemplo de uso
- [ ] Actualiza `src/adapters/__init__.py` para registrar
- [ ] Cumple licencia open source compatible (MIT, Apache, GPL, AGPL)

---

## 📊 Verificación de Cumplimiento DPGA

Ejecuta este comando para verificar cumplimiento:

```python
from src.core.tool_protocol import get_tool_registry

registry = get_tool_registry()
report = registry.get_tool_status_report()

print(f"Total tools: {report['total_tools']}")
print(f"Available: {report['available']}")
print(f"Optional: {sum(1 for t in report['tools'] if t['optional'])}")

# Verificar: TODAS las tools deben ser opcionales
assert all(t['optional'] for t in report['tools']), "❌ Vendor lock-in detectado!"
print("✅ Cumple requisitos DPGA")
```

---

## 🤝 Contribuciones

Para contribuir un nuevo adapter:

1. Fork del repositorio
2. Crea adapter siguiendo este protocolo
3. Agrega tests en `tests/adapters/test_mi_adapter.py`
4. Actualiza documentación
5. Pull request con descripción detallada

**Revisaremos**:
- Cumplimiento del protocolo
- Requisitos DPGA
- Tests passing
- Documentación completa

---

## 📖 Referencias

- **Tool Adapter Protocol**: `src/core/tool_protocol.py`
- **Ejemplos de Adapters**: `src/adapters/`
- **Tests**: `tests/adapters/`
- **DPGA Guidelines**: https://digitalpublicgoods.net/standard/

---

**Versión del Documento**: 1.0.0
**Última Actualización**: 2025-01-09
**Autor**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
