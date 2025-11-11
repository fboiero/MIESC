# Capa 7 (Audit Readiness) - Análisis y Hoja de Ruta

**Autor**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
**Fecha**: 8 de Noviembre, 2025
**Versión MIESC**: 3.3.0
**Estado**: ANÁLISIS PROFUNDO Y PLAN DE MEJORA

---

## Tabla de Contenidos

1. [Estado Actual](#estado-actual)
2. [Gap Analysis vs OpenZeppelin Guide](#gap-analysis-vs-openzeppelin-guide)
3. [Implementación Propuesta](#implementación-propuesta)
4. [Integración LLM para Análisis Cualitativo](#integración-llm-para-análisis-cualitativo)
5. [Roadmap de Implementación](#roadmap-de-implementación)

---

## Estado Actual

### Código Implementado

**Ubicación**: `src/agents/policy_agent.py` (Líneas 873-1613)

#### Funcionalidad Existente

| Componente | Líneas | Estado | Funcionalidad |
|------------|--------|--------|---------------|
| **`_audit_checklist_score()`** | 891-998 | ⚠️ PARCIAL | Trail of Bits checklist (solo cuenta findings) |
| **`_assess_audit_readiness()`** | 1591-1613 | ⚠️ MUY BÁSICO | Solo evalúa severidad de findings |
| **Integración en reporte** | 1436-1447 | ✅ COMPLETO | Añade datos al compliance report |

### Evaluación Detallada

#### 1. `_audit_checklist_score()` - Trail of Bits Checklist

**Código Actual**:
```python
def _audit_checklist_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    checklist_categories = {
        "access_control": {"items_total": 8, "items_checked": 0},
        "arithmetic": {"items_total": 6, "items_checked": 0},
        "reentrancy": {"items_total": 4, "items_checked": 0},
        "gas_optimization": {"items_total": 5, "items_checked": 0},
        "code_quality": {"items_total": 7, "items_checked": 0},
        "external_calls": {"items_total": 5, "items_checked": 0},
        "cryptography": {"items_total": 4, "items_checked": 0},
        "upgradability": {"items_total": 3, "items_checked": 0}
    }

    # Mapea findings a categorías
    for finding in findings:
        if "access" in finding.get("description", "").lower():
            checklist_categories["access_control"]["items_checked"] += 1

    completion_score = total_checked / total_items
    return {"completion_score": completion_score}
```

**Problemas**:
- ❌ Solo cuenta findings, no verifica checklist items reales
- ❌ No valida si el contrato cumple cada item específico
- ❌ No tiene lista detallada de verificaciones Trail of Bits
- ❌ No analiza código directamente

**Ejemplo**:
Si un contrato tiene 0 findings, `completion_score = 0`, pero debería ser 100% si todo está implementado correctamente.

#### 2. `_assess_audit_readiness()` - Evaluación de Preparación

**Código Actual**:
```python
def _assess_audit_readiness(self, findings: List[Dict[str, Any]]) -> str:
    critical = len([f for f in findings if f.get("severity") == "Critical"])
    high = len([f for f in findings if f.get("severity") == "High"])

    if critical > 0:
        return "not_ready"
    elif high > 5:
        return "needs_review"
    elif high > 0:
        return "ready_with_notes"
    else:
        return "ready"
```

**Problemas**:
- ❌ Solo considera cantidad de findings
- ❌ No evalúa documentación
- ❌ No evalúa test coverage
- ❌ No evalúa madurez del código
- ❌ No evalúa prácticas de seguridad

---

## Gap Analysis vs OpenZeppelin Guide

### Checklist Completo de OpenZeppelin Audit Readiness Guide

#### Categoría 1: Documentation (Peso: 25%)

| Item | Estado | Prioridad |
|------|--------|-----------|
| **NatSpec coverage ≥ 90%** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **README comprehensivo** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Architecture diagram** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **Deployment process documented** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **Known issues documented** | ⚠️ PARCIAL (findings) | 🟡 MEDIA |
| **API documentation** | ❌ NO IMPLEMENTADO | 🟢 BAJA |

#### Categoría 2: Testing (Peso: 30%)

| Item | Estado | Prioridad |
|------|--------|-----------|
| **Line coverage ≥ 85%** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Branch coverage ≥ 80%** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Property tests defined** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Invariants documented** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Integration tests** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **Fuzzing campaign** | ⚠️ PARCIAL (Capa 2) | 🟡 MEDIA |

#### Categoría 3: Code Maturity (Peso: 20%)

| Item | Estado | Prioridad |
|------|--------|-----------|
| **Code age ≥ 3 months** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Active development** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **Git history clean** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **No major changes recently** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **Multiple contributors** | ❌ NO IMPLEMENTADO | 🟢 BAJA |
| **Audit history** | ❌ NO IMPLEMENTADO | 🟢 BAJA |

#### Categoría 4: Security Practices (Peso: 25%)

| Item | Estado | Prioridad |
|------|--------|-----------|
| **Access controls implemented** | ⚠️ PARCIAL (findings) | 🔴 ALTA |
| **Upgrade mechanism present** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Emergency pause exists** | ❌ NO IMPLEMENTADO | 🔴 ALTA |
| **Reentrancy guards used** | ⚠️ PARCIAL (findings) | 🟡 MEDIA |
| **SafeMath or Solidity 0.8+** | ❌ NO IMPLEMENTADO | 🟡 MEDIA |
| **No hardcoded addresses** | ❌ NO IMPLEMENTADO | 🟢 BAJA |

### Resumen de Gaps

| Categoría | Items Totales | Implementados | Parciales | Faltantes | Completitud |
|-----------|---------------|---------------|-----------|-----------|-------------|
| Documentation | 6 | 0 | 1 | 5 | **8%** |
| Testing | 6 | 0 | 1 | 5 | **8%** |
| Code Maturity | 6 | 0 | 0 | 6 | **0%** |
| Security Practices | 6 | 0 | 2 | 4 | **17%** |
| **TOTAL** | **24** | **0** | **4** | **20** | **~10%** |

**Conclusión**: La Capa 7 está implementada al **~10%** vs OpenZeppelin Audit Readiness Guide.

---

## Implementación Propuesta

### Arquitectura Mejorada de Capa 7

```python
class AuditReadinessAnalyzer:
    """
    Implementación completa de Layer 7 según OpenZeppelin Guide

    Components:
    1. DocumentationAnalyzer - NatSpec, README, diagrams
    2. TestingAnalyzer - Coverage, property tests, invariants
    3. MaturityAnalyzer - Git metrics, stability, history
    4. SecurityPracticesAnalyzer - Patterns, guards, upgrades
    5. LLMEnhancedAnalyzer - Qualitative analysis (opcional)
    """

    def analyze_full_audit_readiness(self, contract_path: str) -> dict:
        """
        Análisis completo de preparación para auditoría

        Returns:
            {
                'documentation': {...},  # 25% weight
                'testing': {...},        # 30% weight
                'maturity': {...},       # 20% weight
                'security_practices': {...},  # 25% weight
                'overall_score': float (0-100),
                'readiness_level': str,
                'recommendations': [...]
            }
        """
        pass
```

### Componente 1: DocumentationAnalyzer

```python
class DocumentationAnalyzer:
    """Analiza calidad y completitud de documentación"""

    def analyze_natspec_coverage(self, contract_path: str) -> dict:
        """
        Calcula cobertura de NatSpec comments

        Checks:
        - @title, @author, @notice en contratos
        - @notice, @dev, @param, @return en funciones
        - @notice en events

        Returns:
            {
                'contracts_documented': int,
                'functions_documented': int,
                'coverage_percentage': float,
                'missing_items': [...]
            }
        """
        from slither.slither import Slither

        slither = Slither(contract_path)
        total_items = 0
        documented_items = 0

        for contract in slither.contracts:
            total_items += 1
            if contract.natspec:
                documented_items += 1

            for function in contract.functions:
                if function.visibility in ['public', 'external']:
                    total_items += 1
                    if function.natspec:
                        documented_items += 1

        coverage = (documented_items / total_items * 100) if total_items > 0 else 0

        return {
            'total_items': total_items,
            'documented_items': documented_items,
            'coverage_percentage': coverage,
            'passes_threshold': coverage >= 90.0
        }

    def analyze_readme_quality(self, project_root: str) -> dict:
        """
        Evalúa calidad del README con LLM

        Checks:
        - Exists
        - Has overview section
        - Has installation instructions
        - Has usage examples
        - Has architecture description
        - Has security considerations

        Returns:
            {
                'exists': bool,
                'word_count': int,
                'sections_present': [...],
                'quality_score': float (0-1)
            }
        """
        readme_path = Path(project_root) / "README.md"

        if not readme_path.exists():
            return {
                'exists': False,
                'quality_score': 0.0,
                'recommendation': 'Create comprehensive README.md'
            }

        content = readme_path.read_text()
        word_count = len(content.split())

        required_sections = [
            'overview', 'installation', 'usage',
            'architecture', 'security', 'testing'
        ]

        sections_found = [
            section for section in required_sections
            if section.lower() in content.lower()
        ]

        quality_score = len(sections_found) / len(required_sections)

        return {
            'exists': True,
            'word_count': word_count,
            'sections_present': sections_found,
            'sections_missing': list(set(required_sections) - set(sections_found)),
            'quality_score': quality_score,
            'passes_threshold': quality_score >= 0.8
        }
```

### Componente 2: TestingAnalyzer

```python
class TestingAnalyzer:
    """Analiza cobertura y calidad de tests"""

    def analyze_test_coverage(self, project_root: str) -> dict:
        """
        Ejecuta pytest-cov para obtener cobertura

        Returns:
            {
                'line_coverage': float,
                'branch_coverage': float,
                'missing_lines': int,
                'passes_threshold': bool
            }
        """
        import subprocess
        import json

        # Ejecutar pytest con coverage
        result = subprocess.run(
            ['pytest', '--cov=contracts', '--cov-report=json'],
            cwd=project_root,
            capture_output=True,
            text=True
        )

        # Parsear JSON de coverage
        coverage_file = Path(project_root) / '.coverage.json'
        if coverage_file.exists():
            with open(coverage_file) as f:
                cov_data = json.load(f)

            line_coverage = cov_data['totals']['percent_covered']

            return {
                'line_coverage': line_coverage,
                'branch_coverage': cov_data['totals'].get('percent_covered_branches', 0),
                'missing_lines': cov_data['totals']['missing_lines'],
                'passes_threshold': line_coverage >= 85.0
            }

        return {
            'line_coverage': 0,
            'error': 'Coverage data not found',
            'passes_threshold': False
        }

    def analyze_property_tests(self, project_root: str) -> dict:
        """
        Verifica presencia de property-based tests (Echidna)

        Checks:
        - Echidna config exists
        - Property tests defined
        - Invariants documented

        Returns:
            {
                'echidna_config_exists': bool,
                'property_tests_count': int,
                'invariants': [...]
            }
        """
        echidna_config = Path(project_root) / 'echidna.yaml'

        if not echidna_config.exists():
            return {
                'echidna_config_exists': False,
                'property_tests_count': 0,
                'recommendation': 'Add property-based tests with Echidna'
            }

        # Buscar archivos de test con prefijo echidna_
        test_files = list(Path(project_root).glob('**/echidna_*.sol'))

        # Contar funciones que empiezan con echidna_
        property_count = 0
        invariants = []

        for test_file in test_files:
            content = test_file.read_text()
            # Buscar funciones echidna_*
            import re
            functions = re.findall(r'function\s+(echidna_\w+)', content)
            property_count += len(functions)
            invariants.extend(functions)

        return {
            'echidna_config_exists': True,
            'property_tests_count': property_count,
            'invariants': invariants,
            'passes_threshold': property_count >= 5
        }
```

### Componente 3: MaturityAnalyzer

```python
class MaturityAnalyzer:
    """Analiza madurez del código via Git metrics"""

    def analyze_code_maturity(self, project_root: str) -> dict:
        """
        Analiza historial Git para evaluar madurez

        Metrics:
        - Age of codebase (first commit to now)
        - Commit frequency
        - Number of contributors
        - Time since last major change
        - Stability (commits per week trend)

        Returns:
            {
                'age_days': int,
                'total_commits': int,
                'contributors': int,
                'days_since_last_major_change': int,
                'maturity_score': float (0-1)
            }
        """
        import subprocess
        from datetime import datetime

        def run_git(cmd):
            result = subprocess.run(
                ['git'] + cmd,
                cwd=project_root,
                capture_output=True,
                text=True
            )
            return result.stdout.strip()

        # Age of codebase
        first_commit_date = run_git(['log', '--reverse', '--format=%ct', '--max-parents=0'])
        if first_commit_date:
            first_commit_ts = int(first_commit_date.split('\n')[0])
            age_days = (datetime.now().timestamp() - first_commit_ts) / 86400
        else:
            age_days = 0

        # Total commits
        total_commits = int(run_git(['rev-list', '--count', 'HEAD']))

        # Contributors
        contributors_output = run_git(['shortlog', '-sn', '--all'])
        contributors = len(contributors_output.split('\n')) if contributors_output else 0

        # Last major change (>100 lines modified)
        last_major_commit = run_git([
            'log', '--oneline', '--shortstat', '--since=6.months.ago'
        ])
        # Parse para encontrar commits grandes

        # Maturity score calculation
        maturity_factors = {
            'age': min(age_days / 90, 1.0),  # 90 days = mature
            'commits': min(total_commits / 50, 1.0),  # 50 commits = active
            'contributors': min(contributors / 3, 1.0)  # 3+ contributors = collaborative
        }

        maturity_score = sum(maturity_factors.values()) / len(maturity_factors)

        return {
            'age_days': int(age_days),
            'total_commits': total_commits,
            'contributors': contributors,
            'maturity_score': maturity_score,
            'passes_threshold': maturity_score >= 0.6
        }
```

### Componente 4: SecurityPracticesAnalyzer

```python
class SecurityPracticesAnalyzer:
    """Analiza prácticas de seguridad implementadas"""

    def analyze_security_practices(self, contract_path: str) -> dict:
        """
        Verifica implementación de security best practices

        Checks:
        - Access control modifiers (onlyOwner, AccessControl)
        - Upgrade mechanisms (UUPS, Transparent Proxy)
        - Emergency pause (Pausable)
        - Reentrancy guards (ReentrancyGuard, nonReentrant)
        - SafeMath or Solidity 0.8+
        - No hardcoded addresses

        Returns:
            {
                'access_control': bool,
                'upgradeable': bool,
                'pausable': bool,
                'reentrancy_guard': bool,
                'safe_arithmetic': bool,
                'security_score': float (0-1)
            }
        """
        from slither.slither import Slither

        slither = Slither(contract_path)

        practices = {
            'access_control': False,
            'upgradeable': False,
            'pausable': False,
            'reentrancy_guard': False,
            'safe_arithmetic': False,
            'no_hardcoded_addresses': True  # Assume true unless found
        }

        for contract in slither.contracts:
            # Check inheritance
            inherited = [c.name for c in contract.inheritance]

            # Access control
            if any(ac in inherited for ac in ['Ownable', 'AccessControl', 'AccessControlEnumerable']):
                practices['access_control'] = True

            # Upgradeable
            if any(up in inherited for up in ['UUPSUpgradeable', 'TransparentUpgradeableProxy']):
                practices['upgradeable'] = True

            # Pausable
            if 'Pausable' in inherited:
                practices['pausable'] = True

            # Reentrancy guard
            if 'ReentrancyGuard' in inherited:
                practices['reentrancy_guard'] = True

            # Safe arithmetic (Solidity >= 0.8.0)
            if contract.compilation_unit.solc_version.startswith('0.8'):
                practices['safe_arithmetic'] = True
            elif 'SafeMath' in inherited:
                practices['safe_arithmetic'] = True

            # Hardcoded addresses (básico)
            for function in contract.functions:
                source = function.source_mapping.get('content', '')
                if '0x' in source and len([addr for addr in source.split('0x') if len(addr) >= 40]) > 0:
                    practices['no_hardcoded_addresses'] = False

        # Calculate security score
        security_score = sum(practices.values()) / len(practices)

        return {
            **practices,
            'security_score': security_score,
            'passes_threshold': security_score >= 0.75
        }
```

---

## Integración LLM para Análisis Cualitativo

### Uso de OpenLLaMA / Ollama para Evaluación de Calidad

```python
class LLMEnhancedAnalyzer:
    """
    Análisis cualitativo usando LLM local (OpenLLaMA via Ollama)

    Proporciona evaluaciones subjetivas de:
    - Calidad de documentación
    - Legibilidad del código
    - Complejidad percibida
    - Riesgos potenciales no detectados por análisis estático
    """

    def __init__(self, use_local_llm=True):
        """
        Args:
            use_local_llm: Si True, usa Ollama local (OpenLLaMA).
                          Si False, usa OpenAI API (requiere key).
        """
        self.use_local_llm = use_local_llm

        if use_local_llm:
            # Verificar que Ollama está corriendo
            import subprocess
            try:
                subprocess.run(['ollama', 'list'], check=True, capture_output=True)
                self.llm_available = True
            except:
                self.llm_available = False
                logger.warning("Ollama not available. LLM analysis will be skipped.")
        else:
            # OpenAI API
            import openai
            self.llm_available = bool(os.getenv('OPENAI_API_KEY'))

    def analyze_documentation_quality(self, readme_content: str) -> dict:
        """
        Evalúa calidad de README con LLM

        Returns:
            {
                'clarity_score': float (0-1),
                'completeness_score': float (0-1),
                'recommendations': [...],
                'summary': str
            }
        """
        if not self.llm_available:
            return {'error': 'LLM not available'}

        prompt = f"""
Analyze the following smart contract README documentation and evaluate its quality.

README Content:
{readme_content[:2000]}  # Limit to 2000 chars

Evaluate:
1. Clarity (0-1): Is the documentation easy to understand?
2. Completeness (0-1): Does it cover all necessary topics?
3. Recommendations: List 3 improvements

Respond in JSON format:
{{
  "clarity_score": float,
  "completeness_score": float,
  "recommendations": [str, str, str],
  "summary": str (1-2 sentences)
}}
"""

        if self.use_local_llm:
            response = self._call_ollama(prompt, model='openllama')
        else:
            response = self._call_openai(prompt)

        return json.loads(response)

    def analyze_code_complexity(self, contract_code: str) -> dict:
        """
        Evalúa complejidad del código con LLM

        Returns:
            {
                'complexity_score': float (0-1),
                'readability_score': float (0-1),
                'suggestions': [...]
            }
        """
        if not self.llm_available:
            return {'error': 'LLM not available'}

        prompt = f"""
Analyze the following Solidity smart contract code for complexity and readability.

Contract Code:
```solidity
{contract_code[:1500]}
```

Evaluate:
1. Complexity (0-1): 0 = very simple, 1 = very complex
2. Readability (0-1): 0 = hard to read, 1 = easy to read
3. Suggestions: List 3 ways to improve code quality

Respond in JSON format:
{{
  "complexity_score": float,
  "readability_score": float,
  "suggestions": [str, str, str]
}}
"""

        if self.use_local_llm:
            response = self._call_ollama(prompt, model='openllama')
        else:
            response = self._call_openai(prompt)

        return json.loads(response)

    def _call_ollama(self, prompt: str, model: str = 'openllama') -> str:
        """Llama a Ollama API local"""
        import subprocess

        result = subprocess.run(
            ['ollama', 'run', model, prompt],
            capture_output=True,
            text=True,
            timeout=60
        )

        return result.stdout

    def _call_openai(self, prompt: str) -> str:
        """Llama a OpenAI API"""
        import openai

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",  # Más barato
            messages=[
                {"role": "system", "content": "You are a smart contract auditor."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )

        return response.choices[0].message.content
```

---

## Roadmap de Implementación

### Fase 1: Core Functionality (2-3 días)

**Prioridad**: 🔴 ALTA

1. **Implementar DocumentationAnalyzer**
   - [x] NatSpec coverage calculator
   - [x] README quality analyzer
   - [ ] Architecture diagram checker

2. **Implementar TestingAnalyzer**
   - [ ] pytest-cov integration
   - [ ] Property test counter
   - [ ] Invariant extractor

3. **Implementar MaturityAnalyzer**
   - [ ] Git metrics extractor
   - [ ] Stability calculator
   - [ ] Contributor analyzer

4. **Implementar SecurityPracticesAnalyzer**
   - [ ] Access control detector
   - [ ] Upgrade mechanism detector
   - [ ] Pausable/ReentrancyGuard detector

### Fase 2: LLM Integration (1-2 días)

**Prioridad**: 🟡 MEDIA

1. **Setup Ollama + OpenLLaMA**
   - [ ] Install Ollama
   - [ ] Download OpenLLaMA model
   - [ ] Test API calls

2. **Implementar LLMEnhancedAnalyzer**
   - [ ] README quality evaluator
   - [ ] Code complexity evaluator
   - [ ] Integration with main analyzer

### Fase 3: Integration & Testing (1 día)

**Prioridad**: 🔴 ALTA

1. **Integrar con PolicyAgent**
   - [ ] Reemplazar `_assess_audit_readiness()` actual
   - [ ] Añadir al compliance report
   - [ ] Publicar a MCP Context Bus

2. **Testing**
   - [ ] Unit tests para cada analyzer
   - [ ] Integration test completo
   - [ ] Validar con test suite contracts

### Fase 4: Documentation (1 día)

**Prioridad**: 🟢 BAJA

1. **Documentar nueva funcionalidad**
   - [ ] Actualizar LAYER_TECHNICAL_DETAILS.md
   - [ ] Añadir ejemplos de uso
   - [ ] Crear guía de configuración

---

## Ejemplo de Output Esperado

```json
{
  "audit_readiness": {
    "overall_score": 87.5,
    "ready_for_audit": true,
    "breakdown": {
      "documentation": {
        "score": 92.0,
        "weight": 0.25,
        "details": {
          "natspec_coverage": "95%",
          "readme_quality": 0.9,
          "architecture_diagram": true,
          "llm_clarity_score": 0.91
        }
      },
      "testing": {
        "score": 88.0,
        "weight": 0.30,
        "details": {
          "line_coverage": "91%",
          "branch_coverage": "87%",
          "property_tests": 12,
          "invariants_defined": ["echidna_total_supply", "..."]
        }
      },
      "maturity": {
        "score": 85.0,
        "weight": 0.20,
        "details": {
          "age_days": 180,
          "total_commits": 127,
          "contributors": 3,
          "stability_score": 0.82
        }
      },
      "security_practices": {
        "score": 86.0,
        "weight": 0.25,
        "details": {
          "access_control": true,
          "upgradeable": true,
          "pausable": true,
          "reentrancy_guard": true,
          "safe_arithmetic": true,
          "no_hardcoded_addresses": false
        }
      }
    },
    "recommendations": [
      "Remove hardcoded address at Contract.sol:42",
      "Add architecture diagram to README",
      "Increase branch coverage to ≥90%"
    ],
    "methodology": "OpenZeppelin Audit Readiness Guide v2.0 + LLM Enhancement"
  }
}
```

---

## Próximos Pasos Inmediatos

1. **Decisión sobre LLM**:
   - ¿Usar OpenLLaMA local via Ollama? (privacy-first, gratis)
   - ¿O usar OpenAI GPT-4o-mini? (mejor calidad, costo por API call)

2. **Priorizar Features**:
   - Core analyzers primero (NatSpec, coverage, git metrics)
   - LLM enhancement como opcional

3. **Validación**:
   - Probar con contratos del test suite
   - Comparar con auditorías reales conocidas

---

**Autor**: Fernando Boiero <fboiero@frvm.utn.edu.ar>
**Estado**: DOCUMENTO VIVO - Se actualizará con progreso de implementación
**Versión**: 1.0
**Licencia**: AGPL v3.0
