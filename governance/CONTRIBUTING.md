# Guía de Contribución a MIESC

¡Gracias por tu interés en contribuir a MIESC (Marco Integrado de Evaluación de Seguridad en Smart Contracts)! Este documento proporciona lineamientos para contribuir al proyecto.

---

## 📋 Tabla de Contenidos

- [Código de Conducta](#código-de-conducta)
- [Cómo Puedo Contribuir](#cómo-puedo-contribuir)
- [Configuración del Entorno de Desarrollo](#configuración-del-entorno-de-desarrollo)
- [Proceso de Contribución](#proceso-de-contribución)
- [Estándares de Código](#estándares-de-código)
- [Testing](#testing)
- [Documentación](#documentación)
- [Comunicación](#comunicación)

---

## Código de Conducta

Este proyecto adhiere al [Código de Conducta de Contributor Covenant](CODE_OF_CONDUCT.md). Al participar, te comprometes a respetar este código. Por favor reporta comportamientos inaceptables a fboiero@frvm.utn.edu.ar.

---

## Cómo Puedo Contribuir

### 🐛 Reportar Bugs

Si encuentras un bug, por favor:

1. **Verifica** que no haya un issue existente en [GitHub Issues](https://github.com/fboiero/xaudit/issues)
2. **Crea un nuevo issue** usando la plantilla de bug report
3. **Incluye**:
   - Descripción clara del problema
   - Pasos para reproducir
   - Comportamiento esperado vs actual
   - Versión de MIESC, Python, SO
   - Logs relevantes

**Plantilla de Bug Report**:
```markdown
**Descripción del Bug**
[Descripción clara y concisa]

**Pasos para Reproducir**
1. Ejecutar '...'
2. Ver '...'
3. Error '...'

**Comportamiento Esperado**
[Qué debería pasar]

**Capturas de Pantalla/Logs**
[Si aplica]

**Entorno**
- MIESC Version: [2.0.1]
- Python: [3.10.x]
- SO: [Ubuntu 22.04]
- Herramientas: [Slither 0.9.x, Foundry]
```

### 💡 Proponer Nuevas Funcionalidades

Para proponer nuevas features:

1. **Abre un issue** con la etiqueta `enhancement`
2. **Describe**:
   - Problema que resuelve
   - Solución propuesta
   - Alternativas consideradas
   - Impacto en compliance (ISO/NIST/OWASP)
3. **Discute** con los mantenedores antes de implementar

### 📖 Mejorar Documentación

La documentación es crítica. Contribuciones bienvenidas en:

- Correcciones de typos/gramática
- Clarificación de instrucciones
- Traducción a otros idiomas
- Ejemplos adicionales
- Tutoriales y guías

### 🔧 Contribuir Código

Ver sección [Proceso de Contribución](#proceso-de-contribución) para detalles.

---

## Configuración del Entorno de Desarrollo

### Prerrequisitos

- **Python 3.10+** ([python.org](https://www.python.org/))
- **Git** ([git-scm.com](https://git-scm.com/))
- **Node.js 18+** (para Solhint/Surya)
- **Foundry** ([getfoundry.sh](https://getfoundry.sh/))

### Instalación

#### 1. Fork y Clone

```bash
# Fork en GitHub primero, luego:
git clone https://github.com/TU_USUARIO/xaudit.git
cd xaudit

# Agregar remote upstream
git remote add upstream https://github.com/fboiero/xaudit.git
```

#### 2. Crear Entorno Virtual

```bash
python -m venv venv

# Activar
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
```

#### 3. Instalar Dependencias

```bash
# Dependencias core
pip install -r requirements.txt

# Dependencias de desarrollo
pip install -r requirements_dev.txt  # Si existe

# Herramientas de análisis
pip install slither-analyzer solc-select
npm install -g solhint surya

# Solidity compiler
solc-select install 0.8.0
solc-select use 0.8.0
```

#### 4. Instalar Pre-commit Hooks (Recomendado)

```bash
pip install pre-commit
pre-commit install
```

#### 5. Verificar Instalación

```bash
# Test básico
python -c "from agents.static_agent import StaticAgent; print('✅ OK')"

# Test E2E
python test_mcp_e2e.py
```

---

## Proceso de Contribución

### Workflow Git

```bash
# 1. Actualizar tu fork
git checkout main
git fetch upstream
git merge upstream/main

# 2. Crear rama de feature
git checkout -b feature/nombre-descriptivo
# O para bugs: bugfix/nombre-descriptivo

# 3. Hacer cambios y commits
git add .
git commit -m "Descripción clara del cambio"

# 4. Push a tu fork
git push origin feature/nombre-descriptivo

# 5. Crear Pull Request en GitHub
```

### Convenciones de Nombres de Ramas

- `feature/descripcion` - Nuevas funcionalidades
- `bugfix/descripcion` - Correcciones de bugs
- `docs/descripcion` - Cambios en documentación
- `refactor/descripcion` - Refactorización de código
- `test/descripcion` - Agregar/modificar tests

### Commits

**Formato de Mensajes de Commit**:

```
<tipo>: <descripción corta>

<descripción detallada opcional>

<footer opcional con referencias a issues>
```

**Tipos**:
- `feat`: Nueva funcionalidad
- `fix`: Corrección de bug
- `docs`: Cambios en documentación
- `style`: Formateo, puntos y comas, etc (sin cambio de lógica)
- `refactor`: Refactorización de código
- `test`: Agregar o modificar tests
- `chore`: Mantenimiento (dependencias, build, etc)

**Ejemplos**:
```bash
feat: Agregar soporte para Solidity 0.8.20

Implementar compatibilidad con nuevas opciones del compilador
en StaticAgent y SymbolicAgent.

Closes #123

---

fix: Corregir reentrancy false positive en AIAgent

El triage de IA marcaba incorrectamente patrones CEI seguros
como vulnerables. Ajustado el prompt de clasificación.

Fixes #456
```

### Pull Requests

#### Antes de Crear el PR

- [ ] Código sigue el estilo del proyecto (PEP 8)
- [ ] Tests pasan: `python test_mcp_e2e.py`
- [ ] Documentación actualizada si aplica
- [ ] Commits son claros y atómicos
- [ ] Sin merge commits (usar rebase)

#### Crear el PR

1. **Título claro**: Resumen del cambio
2. **Descripción completa**:
   ```markdown
   ## Descripción
   [Qué cambia y por qué]

   ## Tipo de Cambio
   - [ ] Bug fix
   - [ ] Nueva funcionalidad
   - [ ] Breaking change
   - [ ] Documentación

   ## Testing
   [Cómo se probó]

   ## Checklist
   - [ ] Tests pasan
   - [ ] Docs actualizadas
   - [ ] Código sigue estilo
   - [ ] Sin conflictos con main
   ```

3. **Vincular issues**: `Closes #123`, `Fixes #456`

#### Revisión del PR

- Los mantenedores revisarán tu PR
- Puede haber solicitud de cambios
- Discusión constructiva esperada
- Una vez aprobado, se hará merge

---

## Estándares de Código

### Python Style (PEP 8)

```python
# BIEN: Nombres descriptivos, docstrings, type hints
def analyze_contract(contract_path: str, solc_version: str = "0.8.0") -> Dict[str, Any]:
    """
    Analyze Solidity contract for vulnerabilities.

    Args:
        contract_path: Absolute path to .sol file
        solc_version: Solidity compiler version

    Returns:
        Dict with findings and metadata

    Raises:
        FileNotFoundError: If contract doesn't exist
    """
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contract not found: {contract_path}")

    # Implementation
    return results

# MAL: Nombres crípticos, sin documentación
def ac(p, v="0.8.0"):
    if not os.path.exists(p):
        raise FileNotFoundError(f"Not found: {p}")
    return r
```

### Imports

```python
# Orden: stdlib → third-party → local
import os
import sys
from pathlib import Path
from typing import Dict, List, Any

import requests
from langchain.llms import OpenAI

from mcp.context_bus import get_context_bus
from agents.base_agent import BaseAgent
```

### Docstrings

Usar Google style docstrings:

```python
def process_findings(findings: List[Dict], severity_filter: str = "all") -> List[Dict]:
    """
    Process and filter security findings.

    Long description explaining the function's purpose,
    behavior, and any important implementation details.

    Args:
        findings: List of finding dictionaries from analysis tools
        severity_filter: Filter by severity ('critical', 'high', 'medium', 'low', 'all')

    Returns:
        Filtered list of findings sorted by severity

    Raises:
        ValueError: If severity_filter is invalid

    Example:
        >>> findings = [{"severity": "high", "title": "Reentrancy"}]
        >>> process_findings(findings, severity_filter="high")
        [{"severity": "high", "title": "Reentrancy"}]
    """
    pass
```

### Type Hints

Usar type hints en todas las funciones públicas:

```python
from typing import Dict, List, Optional, Union, Any

def aggregate_results(
    static_findings: List[Dict[str, Any]],
    dynamic_findings: Optional[List[Dict[str, Any]]] = None,
    timeout: int = 300
) -> Dict[str, Union[List[Dict], int, str]]:
    """Type hints make code self-documenting."""
    pass
```

### Error Handling

```python
# BIEN: Específico, informativo
try:
    result = subprocess.run(["slither", contract_path],
                          capture_output=True,
                          timeout=timeout,
                          check=True)
except subprocess.TimeoutExpired:
    logger.error(f"Slither timeout after {timeout}s on {contract_path}")
    raise AnalysisTimeoutError(f"Analysis exceeded {timeout}s")
except subprocess.CalledProcessError as e:
    logger.error(f"Slither failed: {e.stderr.decode()}")
    raise AnalysisFailedError(f"Slither error: {e.stderr.decode()}")

# MAL: Genérico, silencioso
try:
    result = subprocess.run(["slither", contract_path])
except:
    pass  # ❌ Nunca hacer esto
```

---

## Testing

### Ejecutar Tests

```bash
# Todos los tests
python test_mcp_e2e.py

# Tests específicos (si hay unittest/pytest)
pytest tests/test_static_agent.py
pytest tests/test_coordinator.py -v
```

### Escribir Tests

```python
# tests/test_static_agent.py
import unittest
from agents.static_agent import StaticAgent

class TestStaticAgent(unittest.TestCase):
    def setUp(self):
        """Setup antes de cada test."""
        self.agent = StaticAgent()
        self.test_contract = "examples/voting.sol"

    def test_initialization(self):
        """Test que el agente se inicializa correctamente."""
        self.assertEqual(self.agent.agent_name, "StaticAgent")
        self.assertIn("static_analysis", self.agent.capabilities)

    def test_analyze_voting_contract(self):
        """Test análisis de contrato de ejemplo."""
        results = self.agent.run(self.test_contract)

        self.assertIn("static_findings", results)
        self.assertIsInstance(results["static_findings"], list)
        self.assertGreater(len(results["static_findings"]), 0)

    def tearDown(self):
        """Cleanup después de cada test."""
        pass

if __name__ == "__main__":
    unittest.main()
```

### Coverage

Apuntar a >80% de cobertura en código nuevo:

```bash
pip install coverage
coverage run -m pytest tests/
coverage report
coverage html  # Genera reporte HTML en htmlcov/
```

---

## Documentación

### Documentar Nuevos Agentes

Si agregas un nuevo agente, actualizar:

1. **docs/agents_usage.md** - Agregar sección completa
2. **docs/MIESC_framework.md** - Actualizar arquitectura
3. **README.md** - Mencionar en overview

**Estructura**:
```markdown
### NuevoAgent

**Descripción**: [Qué hace este agente]

**Capabilities**:
- `capability_1`: Descripción
- `capability_2`: Descripción

**Context Types Published**:
- `context_type_1`: Formato JSON

**Ejemplo de Uso**:
```python
from agents.nuevo_agent import NuevoAgent

agent = NuevoAgent()
results = agent.run("examples/contract.sol")
print(results)
```

**Output Esperado**:
```json
{
  "findings": [...]
}
```
```

### Documentar Herramientas

Si integras una nueva herramienta:

1. **requirements.txt** - Agregar dependencia
2. **docs/deployment_guide.md** - Instrucciones de instalación
3. **Comentarios en código** - Explicar integración

---

## Comunicación

### GitHub Issues

- Para bugs, features, preguntas
- Usa etiquetas apropiadas
- Sé claro y conciso

### Email

Para consultas directas:
**Email**: fboiero@frvm.utn.edu.ar
**Respuesta típica**: 48-72 horas

### Discusiones

GitHub Discussions (si está habilitado):
- Preguntas generales
- Ideas de features
- Ayuda con implementación

---

## Áreas que Necesitan Contribución

### 🔴 Alta Prioridad

- [ ] Implementar DynamicAgent con Medusa
- [ ] Mejorar detección de false positives en AIAgent
- [ ] Agregar soporte para Vyper
- [ ] Dashboard real-time conectado a Context Bus

### 🟡 Media Prioridad

- [ ] Más contratos de ejemplo en `examples/`
- [ ] Traducciones de documentación (inglés)
- [ ] Integración con más clientes MCP
- [ ] Performance optimization en CoordinatorAgent

### 🟢 Baja Prioridad

- [ ] Logo y branding
- [ ] Videos tutoriales
- [ ] Blog posts técnicos
- [ ] Presentaciones para conferencias

---

## Licencia

Al contribuir a MIESC, aceptas que tus contribuciones serán licenciadas bajo la misma [GPL-3.0 License](LICENSE) que el proyecto.

---

## Reconocimientos

Todos los contribuyentes serán reconocidos en:

- **README.md** - Sección de contribuyentes
- **Release notes** - Menciones específicas
- **Commits** - Atribución en git log

---

## Recursos Adicionales

### Documentación del Proyecto

- [README Principal](README.md)
- [Guía de Deployment](docs/deployment_guide.md)
- [Guía de Agentes](docs/agents_usage.md)
- [Framework MIESC](docs/MIESC_framework.md)

### Estándares de Referencia

- [ISO/IEC 27001 Controls](standards/iso27001_controls.md)
- [NIST SSDF Mapping](standards/nist_ssdf_mapping.md)
- [OWASP SC Top 10](standards/owasp_sc_top10_mapping.md)

### Herramientas

- [Slither Documentation](https://github.com/crytic/slither/wiki)
- [Foundry Book](https://book.getfoundry.sh/)
- [MCP Protocol](https://modelcontextprotocol.io/)

### Python Best Practices

- [PEP 8 Style Guide](https://peps.python.org/pep-0008/)
- [Google Python Style](https://google.github.io/styleguide/pyguide.html)
- [Type Hints (PEP 484)](https://peps.python.org/pep-0484/)

---

## Preguntas Frecuentes

**P: ¿Puedo contribuir si soy principiante?**
R: ¡Absolutamente! Issues etiquetados con `good-first-issue` son ideales para empezar.

**P: ¿Necesito firmar un CLA (Contributor License Agreement)?**
R: No, actualmente no requerimos CLA. Tu contribución bajo GPL-3.0 es suficiente.

**P: ¿Cuánto tiempo toma la revisión de un PR?**
R: Típicamente 3-7 días para PRs pequeños, hasta 2 semanas para cambios grandes.

**P: ¿Puedo usar MIESC en mi tesis/investigación?**
R: Sí, por favor cítanos. Ver README.md para información de citación.

**P: ¿Aceptan contribuciones en inglés?**
R: Sí, aunque el proyecto está en español, contribuciones en inglés son bienvenidas (se traducirán si es necesario).

---

## Contacto

**Mantenedor Principal**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institución**: Universidad Tecnológica Nacional - FRVM
**GitHub**: [@fboiero](https://github.com/fboiero)

---

**Gracias por contribuir a MIESC y ayudar a mejorar la seguridad de smart contracts como un bien público digital!** 🛡️🌍

---

**Última Actualización**: Octubre 2025
**Versión**: 1.0
