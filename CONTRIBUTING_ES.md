# Contribuir a MIESC

**[English Version](CONTRIBUTING.md)**

¡Gracias por tu interés en contribuir a MIESC! Este documento proporciona guías e instrucciones para contribuir.

---

## Tabla de Contenidos

- [Código de Conducta](#código-de-conducta)
- [Primeros Pasos](#primeros-pasos)
- [Cómo Contribuir](#cómo-contribuir)
- [Configuración del Desarrollo](#configuración-del-desarrollo)
- [Estándares de Código](#estándares-de-código)
- [Pruebas](#pruebas)
- [Proceso de Pull Request](#proceso-de-pull-request)
- [Documentación](#documentación)
- [Comunidad](#comunidad)

---

## Código de Conducta

Este proyecto se adhiere al [Código de Conducta del Pacto del Colaborador](./CODE_OF_CONDUCT_ES.md). Al participar, se espera que respetes este código. Por favor reporta comportamiento inaceptable a fboiero@frvm.utn.edu.ar.

---

## Primeros Pasos

### Prerrequisitos

- Python 3.12 o superior
- Git
- Entorno virtual (recomendado)
- Compilador de Solidity (solc) para pruebas

### Configuración Rápida

```bash
# Fork y clona el repositorio
git clone https://github.com/TU_USUARIO/MIESC.git
cd MIESC

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
pip install -r requirements_dev.txt

# Ejecutar pruebas para verificar la configuración
pytest tests/
```

---

## Cómo Contribuir

### Tipos de Contribuciones

| Tipo | Descripción | Etiqueta |
|------|-------------|----------|
| Corrección de Bug | Corregir un error en el código existente | `bug` |
| Característica | Agregar nueva funcionalidad | `enhancement` |
| Documentación | Mejorar o agregar documentación | `documentation` |
| Pruebas | Agregar o mejorar pruebas | `testing` |
| Refactorización | Mejoras de código sin cambiar comportamiento | `refactor` |
| Traducción | Agregar traducciones de idiomas | `i18n` |

### Encontrar Issues

- Busca issues etiquetados [`good first issue`](https://github.com/fboiero/MIESC/labels/good%20first%20issue)
- Revisa [`help wanted`](https://github.com/fboiero/MIESC/labels/help%20wanted) para elementos prioritarios
- Revisa la [hoja de ruta del proyecto](./docs/ROADMAP.md)

### Proponer Cambios

1. **Verifica issues existentes** para evitar duplicados
2. **Abre un issue** para discutir cambios significativos antes de codificar
3. **Obtén retroalimentación** de los mantenedores sobre tu enfoque

---

## Configuración del Desarrollo

### Configuración del Entorno

```bash
# Crear y activar entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar todas las dependencias (incluyendo dev)
pip install -r requirements.txt
pip install -r requirements_dev.txt

# Instalar hooks de pre-commit
pre-commit install

# Verificar instalación
python scripts/verify_installation.py
```

### Herramientas Requeridas

| Herramienta | Propósito | Instalación |
|-------------|-----------|-------------|
| pytest | Pruebas | `pip install pytest pytest-cov` |
| black | Formateo de código | `pip install black` |
| ruff | Linting | `pip install ruff` |
| mypy | Verificación de tipos | `pip install mypy` |
| pre-commit | Hooks de Git | `pip install pre-commit` |

### Estructura del Proyecto

```
MIESC/
├── src/                    # Código fuente principal
│   ├── adapters/          # Adaptadores de herramientas
│   ├── core/              # Framework core
│   ├── ml/                # Componentes de machine learning
│   └── mcp/               # Implementación del protocolo MCP
├── tests/                  # Suite de pruebas
│   ├── unit/              # Pruebas unitarias
│   ├── integration/       # Pruebas de integración
│   └── fixtures/          # Datos de prueba
├── docs/                   # Documentación
├── examples/               # Scripts de ejemplo
└── contracts/              # Contratos de prueba
```

---

## Estándares de Código

### Guía de Estilo Python

Seguimos [PEP 8](https://peps.python.org/pep-0008/) con estas adiciones:

| Regla | Configuración |
|-------|---------------|
| Longitud de línea | 100 caracteres máximo |
| Formateador | Black |
| Ordenamiento de imports | isort |
| Docstrings | Estilo Google |

### Formateo de Código

```bash
# Formatear código
black src/ tests/

# Ordenar imports
isort src/ tests/

# Linting de código
ruff check src/ tests/

# Verificación de tipos
mypy src/
```

### Ejemplo de Estilo de Código

```python
"""Docstring del módulo describiendo su propósito.

Este módulo proporciona funcionalidad para...
"""

from typing import Dict, List, Optional

from miesc.core import BaseAdapter


class MyAdapter(BaseAdapter):
    """Adaptador para el escáner de seguridad MyTool.

    Este adaptador envuelve el CLI de MyTool y normaliza
    su salida al formato de hallazgos de MIESC.

    Attributes:
        name: Identificador de la herramienta.
        category: Categoría de la herramienta (STATIC, DYNAMIC, etc.).
    """

    def __init__(self, config: Optional[Dict] = None) -> None:
        """Inicializa el adaptador.

        Args:
            config: Diccionario de configuración opcional.
        """
        super().__init__(config)
        self.name = "mytool"
        self.category = "STATIC"

    def analyze(self, contract_path: str, timeout: int = 300) -> Dict:
        """Analiza un contrato inteligente.

        Args:
            contract_path: Ruta al archivo Solidity.
            timeout: Tiempo máximo de ejecución en segundos.

        Returns:
            Diccionario conteniendo resultados del análisis con claves:
                - status: "success" o "error"
                - findings: Lista de hallazgos de vulnerabilidades
                - metadata: Metadatos de ejecución

        Raises:
            FileNotFoundError: Si el archivo del contrato no existe.
            TimeoutError: Si el análisis excede el timeout.
        """
        # Implementación
        pass
```

---

## Pruebas

Para documentación completa de pruebas, consulta la [Guía de Pruebas](./docs/guides/TESTING.md).

### Referencia Rápida

```bash
# Ejecutar todas las pruebas con cobertura
make test

# Ejecutar pruebas sin cobertura (más rápido)
make test-quick

# Ejecutar solo pruebas de integración
pytest -m integration --no-cov

# Ejecutar archivo de prueba específico
pytest tests/test_integration_pipeline.py -v --no-cov
```

### Escribir Pruebas

```python
"""Pruebas para SlitherAdapter."""

import pytest
from src.adapters.slither_adapter import SlitherAdapter


class TestSlitherAdapter:
    """Suite de pruebas para SlitherAdapter."""

    @pytest.fixture
    def adapter(self):
        """Crea instancia del adaptador para pruebas."""
        return SlitherAdapter()

    @pytest.fixture
    def sample_contract(self, tmp_path):
        """Crea un contrato de ejemplo para pruebas."""
        contract = tmp_path / "test.sol"
        contract.write_text("""
            pragma solidity ^0.8.0;
            contract Test {
                function foo() public {}
            }
        """)
        return str(contract)

    def test_analyze_valid_contract(self, adapter, sample_contract):
        """Prueba el análisis de un contrato válido."""
        result = adapter.analyze(sample_contract)

        assert result["status"] == "success"
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_analyze_invalid_path(self, adapter):
        """Prueba el análisis con ruta de archivo inválida."""
        with pytest.raises(FileNotFoundError):
            adapter.analyze("/nonexistent/path.sol")
```

### Requisitos de Cobertura de Pruebas

- Cobertura mínima: 80%
- Nuevas características deben incluir pruebas
- Correcciones de bugs deben incluir pruebas de regresión

---

## Proceso de Pull Request

### Antes de Enviar

1. **Crea una rama**
   ```bash
   git checkout -b feature/nombre-de-tu-caracteristica
   ```

2. **Realiza tus cambios**
   - Sigue los estándares de código
   - Agrega/actualiza pruebas
   - Actualiza documentación

3. **Ejecuta verificaciones localmente**
   ```bash
   # Formatear código
   black src/ tests/

   # Ejecutar linter
   ruff check src/ tests/

   # Ejecutar pruebas
   pytest tests/

   # Verificar tipos
   mypy src/
   ```

4. **Haz commit con mensajes claros**
   ```bash
   git commit -m "feat: agregar soporte para nueva herramienta X

   - Implementar clase XAdapter
   - Agregar pruebas unitarias para integración de X
   - Actualizar documentación

   Closes #123"
   ```

### Formato del Mensaje de Commit

Seguimos [Conventional Commits](https://www.conventionalcommits.org/):

```
<tipo>(<alcance>): <descripción>

[cuerpo opcional]

[pie opcional]
```

**Tipos**:
- `feat`: Nueva característica
- `fix`: Corrección de bug
- `docs`: Documentación
- `style`: Formateo
- `refactor`: Reestructuración de código
- `test`: Agregar pruebas
- `chore`: Mantenimiento

### Enviar el PR

1. Push de tu rama
   ```bash
   git push origin feature/nombre-de-tu-caracteristica
   ```

2. Crea Pull Request en GitHub

3. Completa la plantilla del PR:
   - Descripción de cambios
   - Issue(s) relacionado(s)
   - Pruebas realizadas
   - Actualizaciones de documentación

4. Solicita revisión de los mantenedores

### Checklist de Revisión de PR

- [ ] El código sigue las guías de estilo
- [ ] Las pruebas pasan y se mantiene la cobertura
- [ ] Documentación actualizada
- [ ] No se introducen vulnerabilidades de seguridad
- [ ] Los mensajes de commit siguen la convención
- [ ] La descripción del PR está completa

---

## Documentación

### Tipos de Documentación

| Tipo | Ubicación | Formato |
|------|-----------|---------|
| Docs de código | En archivos fuente | Docstrings |
| Guía de usuario | `docs/` | Markdown |
| Referencia API | `docs/api/` | Auto-generada |
| Ejemplos | `examples/` | Scripts Python |

### Construir Documentación

```bash
# Instalar dependencias de documentación
pip install mkdocs mkdocs-material

# Servir docs localmente
mkdocs serve

# Construir sitio estático
mkdocs build
```

### Estándares de Documentación

- Usa lenguaje claro y conciso
- Incluye ejemplos de código
- Mantén la documentación actualizada con los cambios de código
- Agrega capturas de pantalla/diagramas donde sea útil

---

## Comunidad

### Obtener Ayuda

- **GitHub Issues**: Reportes de bugs, solicitudes de características
- **GitHub Discussions**: Preguntas, ideas, comunidad
- **Email**: fboiero@frvm.utn.edu.ar

### Reconocimiento

Los colaboradores son reconocidos en:
- [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Notas de lanzamiento
- Documentación del proyecto

### Convertirse en Mantenedor

Los colaboradores regulares pueden ser invitados a convertirse en mantenedores. Criterios:
- Contribuciones de calidad sostenidas
- Entendimiento de los objetivos del proyecto
- Interacciones positivas con la comunidad
- Compromiso con el proyecto

---

## Licencia

Al contribuir a MIESC, aceptas que tus contribuciones serán licenciadas bajo la [Licencia AGPL-3.0](./LICENSE).

---

## ¿Preguntas?

¡No dudes en hacer preguntas! Abre un issue o contáctanos por email.

¡Gracias por contribuir a MIESC!
