# MIESC - Plan de Mejoras v5.1.0

**Fecha**: Febrero 2026
**Versión actual**: 5.0.3
**Objetivo**: 5.1.0

---

## Resumen Ejecutivo

El proyecto MIESC está **bien estructurado y listo para producción** con 50+ adaptadores, 3,469 casos de test, y CI/CD profesional. Este plan identifica mejoras incrementales para llevar el proyecto al siguiente nivel de madurez.

---

## 1. Quick Wins (1-2 semanas)

### 1.1 Aumentar Cobertura de Tests
**Prioridad**: ALTA | **Esfuerzo**: Bajo

```toml
# pyproject.toml - cambiar de 55% a 70%
[tool.coverage.report]
fail_under = 70
```

**Acción**: Agregar tests para adaptadores críticos (Slither, Aderyn).

### 1.2 Habilitar Type Hints Estrictos
**Prioridad**: ALTA | **Esfuerzo**: Bajo

```toml
# pyproject.toml
[tool.mypy]
disallow_untyped_defs = true
```

### 1.3 Crear .env.example Completo
**Prioridad**: MEDIA | **Esfuerzo**: Bajo

```bash
# config/.env.example
MIESC_DEBUG=false
MIESC_LOG_LEVEL=INFO
OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=...
CERTORA_KEY=...
```

### 1.4 Agregar Markdown Link Checker al CI
**Prioridad**: BAJA | **Esfuerzo**: Bajo

```yaml
# .github/workflows/ci.yml
- name: Check documentation links
  run: |
    npm install -g markdown-link-check
    find docs -name "*.md" -exec markdown-link-check {} \;
```

### 1.5 Limpiar TODOs Críticos
**Prioridad**: MEDIA | **Esfuerzo**: Bajo

- [ ] `src/adapters/exploit_synthesizer_adapter.py:148`
- [ ] `src/adapters/gptlens_adapter.py:295` - SWC-XXX placeholder
- [ ] `src/poc/poc_generator.py:556`

---

## 2. Corto Plazo (1 mes)

### 2.1 Mejorar Manejo de Excepciones
**Prioridad**: MEDIA | **Esfuerzo**: Medio

**Problema**: 10+ instancias de `except Exception:` demasiado genérico.

**Solución**:
```python
# Antes
except Exception as e:
    logger.error(f"Analysis failed: {e}")

# Después
except (TimeoutError, subprocess.TimeoutExpired) as e:
    logger.error(f"Tool timeout: {e}")
except FileNotFoundError as e:
    logger.error(f"Contract not found: {e}")
except subprocess.CalledProcessError as e:
    logger.error(f"Tool execution failed: {e}")
```

### 2.2 Reemplazar Print por Logging
**Prioridad**: BAJA | **Esfuerzo**: Medio

**Problema**: 718 `print()` en lugar de logging estructurado.

**Script de migración**:
```bash
# Identificar archivos
grep -r "print(" src/ --include="*.py" | wc -l
```

### 2.3 Documentación de API
**Prioridad**: MEDIA | **Esfuerzo**: Medio

- [ ] Generar docs con Sphinx desde docstrings
- [ ] Crear OpenAPI schema para REST API
- [ ] Agregar `.pyi` stubs para módulos críticos

### 2.4 Agregar Trivy al CI (Docker Security)
**Prioridad**: MEDIA | **Esfuerzo**: Bajo

```yaml
# .github/workflows/docker.yml
- name: Scan Docker image for vulnerabilities
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ghcr.io/fboiero/miesc:${{ github.sha }}
    format: 'sarif'
    output: 'trivy-results.sarif'
```

### 2.5 Expandir Fixtures de Tests
**Prioridad**: MEDIA | **Esfuerzo**: Medio

Agregar contratos de prueba para:
- [ ] Reentrancy (SWC-107)
- [ ] Integer Overflow (SWC-101)
- [ ] Access Control (SWC-105)
- [ ] Flash Loan attacks
- [ ] Oracle manipulation

---

## 3. Mediano Plazo (2-3 meses)

### 3.1 Refactorizar Archivos Grandes
**Prioridad**: MEDIA | **Esfuerzo**: Alto

| Archivo | Líneas | Acción |
|---------|--------|--------|
| `miesc/cli/main.py` | 6,710 | Dividir en subcomandos Click |
| `src/llm/vulnerability_rag.py` | 2,839 | Extraer lógica común |
| `src/llm/embedding_rag.py` | 2,575 | Crear módulo base_rag.py |
| `src/adapters/gptlens_adapter.py` | 2,266 | Separar prompts de lógica |

### 3.2 Consolidar Estructura de Paquetes
**Prioridad**: MEDIA | **Esfuerzo**: Alto

**Problema**: Estructura dual `src/` y `miesc/` causa confusión.

**Opciones**:
1. Documentar claramente la razón (lazy imports, backwards compat)
2. Migrar todo a `miesc/` en v6.0.0
3. Marcar `src/` como deprecated con DeprecationWarning

### 3.3 Implementar Lock de Dependencias
**Prioridad**: MEDIA | **Esfuerzo**: Bajo

```bash
# Usar pip-compile para builds reproducibles
pip install pip-tools
pip-compile pyproject.toml -o requirements-lock.txt
```

### 3.4 Crear BaseToolAdapter Mejorado
**Prioridad**: BAJA | **Esfuerzo**: Medio

```python
class BaseToolAdapter(ToolAdapter):
    """Base con patrones reutilizables"""

    def execute_with_timeout(self, cmd: list, timeout: int = 30) -> str:
        """Wrapper de timeout reutilizable"""
        pass

    def parse_json_output(self, output: str) -> dict:
        """Parser JSON con manejo de errores"""
        pass

    def handle_missing_tool(self, tool_name: str) -> None:
        """Manejo consistente de herramienta faltante"""
        pass
```

### 3.5 Documentar ADRs (Architecture Decision Records)
**Prioridad**: BAJA | **Esfuerzo**: Medio

- [ ] ADR-001: Estructura dual src/miesc
- [ ] ADR-002: RAG con ChromaDB vs alternativas
- [ ] ADR-003: Adaptadores vs Agentes
- [ ] ADR-004: Soporte multi-plataforma ARM/x86

---

## 4. Largo Plazo (3-6 meses)

### 4.1 Pipeline de Performance
**Prioridad**: BAJA | **Esfuerzo**: Medio

- [ ] Agregar benchmarks de tiempo al CI
- [ ] Monitorear regresiones de performance
- [ ] Documentar requisitos de recursos por herramienta

### 4.2 Plugin Marketplace
**Prioridad**: BAJA | **Esfuerzo**: Alto

- [ ] Crear registro de adaptadores de terceros
- [ ] Sistema de discovery dinámico
- [ ] Documentación para desarrolladores de plugins

### 4.3 Modernizar Web UI
**Prioridad**: BAJA | **Esfuerzo**: Alto

- [ ] Evaluar migración Streamlit → React/Vue
- [ ] Dashboard de métricas en tiempo real
- [ ] Visualización interactiva de findings

### 4.4 Release Automation
**Prioridad**: MEDIA | **Esfuerzo**: Medio

- [ ] Semantic versioning automático
- [ ] Changelog auto-generado
- [ ] Verificación de consistencia de versiones

---

## 5. Seguridad

### 5.1 Validación de Inputs
**Prioridad**: ALTA | **Esfuerzo**: Medio

```python
# src/security/input_validator.py
class InputValidator:
    @staticmethod
    def validate_path(path: str) -> Path:
        """Prevenir path traversal"""
        resolved = Path(path).resolve()
        if ".." in str(resolved):
            raise SecurityError("Path traversal detected")
        return resolved

    @staticmethod
    def validate_env_var(name: str, value: str) -> str:
        """Validar variables de entorno"""
        # Sanitizar según tipo esperado
        pass
```

### 5.2 Auditoría de Dependencias
**Prioridad**: ALTA | **Esfuerzo**: Bajo

```yaml
# Quitar continue-on-error de pip-audit
- name: Audit dependencies
  run: pip-audit --desc
  # Sin continue-on-error para bloquear en vulnerabilidades
```

---

## 6. Métricas de Éxito

| Métrica | Actual | Objetivo |
|---------|--------|----------|
| Test Coverage | 55% | 70% |
| Type Hints | ~60% | 90% |
| TODOs Críticos | 23 | 0 |
| Print statements | 718 | 0 |
| Archivos >2000 líneas | 4 | 0 |
| Broad exceptions | 10+ | 0 |

---

## 7. Cronograma Propuesto

```
Semana 1-2:   Quick Wins (1.1-1.5)
Semana 3-4:   Exception handling + Logging (2.1-2.2)
Mes 2:        API Docs + CI Security (2.3-2.5)
Mes 3:        Refactoring archivos grandes (3.1)
Mes 4-5:      Consolidación paquetes (3.2-3.4)
Mes 6:        ADRs + Performance (3.5, 4.1)
```

---

## 8. Siguientes Pasos Inmediatos

1. **Crear issues en GitHub** para cada tarea del plan
2. **Priorizar** según impacto vs esfuerzo
3. **Asignar** a milestones (v5.1.0, v5.2.0, v6.0.0)
4. **Comenzar** con Quick Wins esta semana

---

*Generado: Febrero 2026*
*Próxima revisión: Marzo 2026*
