# MIESC v4.2.0 - Roadmap de Desarrollo

**Fecha:** 2025-12-13
**Version Actual:** 4.1.0
**Version Target:** 4.2.0
**Codename:** "Fortress"

---

## Estado Actual (v4.1.0)

### Completado Recientemente

| Feature | Archivo | Estado |
|---------|---------|--------|
| CI/CD PyPI Release | `.github/workflows/release.yml` | Completado |
| LLM Orchestrator Multi-Backend | `src/llm/llm_orchestrator.py` | Completado |
| WebSocket Real-Time API | `src/core/websocket_api.py` | Completado |
| Rich CLI Interactivo | `src/core/rich_cli.py` | Completado |
| Metricas Prometheus | `src/core/metrics.py` | Completado |
| Exportadores SARIF/SonarQube | `src/core/exporters.py` | Completado |
| Persistence SQLite | `src/core/persistence.py` | Completado |
| ML Orchestrator | `src/core/ml_orchestrator.py` | Completado |

### Modulos Core Estables

```
src/core/
├── __init__.py              # 117 exports
├── config_loader.py         # Configuracion YAML
├── optimized_orchestrator.py # Ejecucion paralela
├── result_aggregator.py     # Agregacion de hallazgos
├── health_checker.py        # Health checks
├── tool_discovery.py        # Auto-descubrimiento
├── correlation_api.py       # Correlacion de hallazgos
├── agent_protocol.py        # Protocolo de agentes
├── agent_registry.py        # Registro de agentes
├── tool_protocol.py         # Protocolo de herramientas
├── metrics.py               # [NEW] Prometheus metrics
├── exporters.py             # [NEW] Multi-format export
├── websocket_api.py         # [NEW] Real-time API
├── rich_cli.py              # [NEW] Rich terminal UI
├── persistence.py           # [NEW] SQLite storage
└── ml_orchestrator.py       # [NEW] ML pipeline
```

---

## Plan v4.2.0 "Fortress"

### Fase 1: Limpieza y Consolidacion

**Duracion Estimada:** 1-2 sprints
**Prioridad:** CRITICA

#### 1.1 Eliminar Codigo Legacy (P0.2)

**Archivos a eliminar de `src/`:**

```bash
# Herramientas standalone (reemplazadas por adapters)
rm src/gptlens_tool.py
rm src/llama2_tool.py
rm src/mythril_tool.py
rm src/manticore_tool.py
rm src/slither_tool.py
rm src/halmos_tool.py
rm src/wake_tool.py
rm src/echidna_tool.py
rm src/medusa_tool.py
rm src/foundry_tool.py
rm src/smartllm_tool.py
rm src/gptscan_tool.py
rm src/llmsmartaudit_tool.py

# CLI y Core legacy (reemplazados por miesc/)
rm src/miesc_cli.py
rm src/miesc_core.py
rm src/miesc_ai_layer.py
rm src/miesc_mcp_adapter.py
rm src/miesc_mcp_rest.py
rm src/miesc_websocket_api.py
rm src/miesc_ml_cli.py
rm src/miesc_policy_agent.py
rm src/miesc_policy_mapper.py
rm src/miesc_risk_engine.py
rm src/miesc_security_checks.py

# Analizadores legacy
rm src/orchestrator.py
rm src/project_analyzer.py
rm src/audit_generator.py
rm src/report_formatter.py
rm src/graph_visualizer.py

# Utilidades legacy
rm src/main.py
rm src/utils.py
rm src/GPTLens_prompts.py
rm src/summarize_information.py
rm src/test_generator.py
rm src/text_generator.py

# Backup accidental
rm "src/agents/symbolic_agent 2.py"
```

**Total:** ~35 archivos a eliminar

#### 1.2 Completar __init__.py Faltantes (P0.3)

```python
# src/dashboard/__init__.py
"""MIESC Dashboard Module - Streamlit and Flask UIs."""
from webapp.app import main as run_streamlit
from webapp.dashboard_enhanced import main as run_enhanced

# src/utils/__init__.py
"""MIESC Utility Functions."""
# Consolidar utilidades comunes

# src/knowledge_base/__init__.py
"""MIESC Vulnerability Knowledge Base."""
from .vulnerability_db import VulnerabilityDB
```

#### 1.3 Input Validators (P0.4)

**Nuevo archivo:** `src/security/input_validator.py`

```python
class InputValidator:
    """Validates and sanitizes all user inputs."""

    def validate_contract_path(self, path: str) -> ValidatedPath
    def validate_solidity_code(self, code: str) -> ValidatedCode
    def validate_layers(self, layers: List[int]) -> ValidatedLayers
    def validate_tools(self, tools: List[str]) -> ValidatedTools
    def sanitize_output(self, output: str) -> str
```

---

### Fase 2: Tests y Documentacion

**Duracion Estimada:** 2 sprints
**Prioridad:** ALTA

#### 2.1 Aumentar Cobertura de Tests (P1.9)

**Target:** 80% cobertura global

| Modulo | Actual | Target | Tests Nuevos |
|--------|--------|--------|--------------|
| `core/metrics.py` | 0% | 90% | test_metrics.py |
| `core/exporters.py` | 0% | 90% | test_exporters.py |
| `core/websocket_api.py` | 0% | 85% | test_websocket.py |
| `core/rich_cli.py` | 0% | 80% | test_rich_cli.py |
| `ml/correlation_engine.py` | 60% | 85% | Ampliar |
| `core/optimized_orchestrator.py` | 55% | 80% | Ampliar |

**Nuevos archivos de tests:**

```
tests/
├── test_metrics.py           # [NEW]
├── test_exporters.py         # [NEW]
├── test_websocket_api.py     # [NEW]
├── test_rich_cli.py          # [NEW]
├── test_input_validator.py   # [NEW]
└── integration/
    ├── test_full_audit.py    # [NEW]
    └── test_realtime_flow.py # [NEW]
```

#### 2.2 Documentacion OpenAPI 3.1 (P1.10)

**Archivo:** `docs/openapi.yaml`

```yaml
openapi: 3.1.0
info:
  title: MIESC Security API
  version: 4.2.0
  description: Multi-layer Intelligent Evaluation for Smart Contracts

servers:
  - url: http://localhost:8000/api/v1
    description: Local development
  - url: https://api.miesc.io/v1
    description: Production

paths:
  /audit:
    post:
      operationId: createAudit
      summary: Create new security audit

  /audit/{auditId}:
    get:
      operationId: getAudit
      summary: Get audit results

  /audit/{auditId}/stream:
    get:
      operationId: streamAudit
      summary: Stream audit progress (SSE)

  /tools:
    get:
      operationId: listTools
      summary: List available security tools

  /health:
    get:
      operationId: healthCheck
      summary: System health status
```

---

### Fase 3: Features de Produccion

**Duracion Estimada:** 3-4 sprints
**Prioridad:** ALTA

#### 3.1 VS Code Extension Completa (P1.6)

**Estructura:**

```
vscode-extension/
├── src/
│   ├── extension.ts              # [EXISTE] Entry point
│   ├── providers/
│   │   ├── diagnosticProvider.ts # [NEW] Inline warnings
│   │   ├── codeActionProvider.ts # [NEW] Quick fixes
│   │   ├── hoverProvider.ts      # [NEW] Vulnerability info
│   │   └── completionProvider.ts # [NEW] Secure patterns
│   ├── views/
│   │   ├── findingsTreeView.ts   # [NEW] Findings explorer
│   │   ├── layersTreeView.ts     # [NEW] Layer status
│   │   └── historyTreeView.ts    # [NEW] Audit history
│   ├── services/
│   │   ├── miescClient.ts        # [NEW] API client
│   │   ├── websocketService.ts   # [NEW] Real-time
│   │   └── configService.ts      # [NEW] Settings
│   ├── commands/
│   │   ├── auditCommand.ts       # [NEW] Run audit
│   │   ├── exportCommand.ts      # [NEW] Export report
│   │   └── configCommand.ts      # [NEW] Configure
│   └── test/
│       ├── extension.test.ts     # [NEW] Unit tests
│       └── integration.test.ts   # [NEW] E2E tests
├── package.json
├── tsconfig.json
└── README.md
```

**Funcionalidades:**

1. **Diagnostics:** Mostrar vulnerabilidades inline
2. **Code Actions:** Sugerencias de fix automaticas
3. **Tree Views:** Panel lateral con hallazgos
4. **Commands:** Palette commands para auditorias
5. **WebSocket:** Actualizaciones en tiempo real

#### 3.2 Sistema de Plugins (P1.12)

**Nuevo modulo:** `src/plugins/`

```python
# src/plugins/__init__.py
from .plugin_manager import PluginManager, Plugin
from .plugin_loader import PluginLoader
from .plugin_protocol import PluginProtocol

# src/plugins/plugin_manager.py
class PluginManager:
    """Manages third-party analysis plugins."""

    def __init__(self):
        self.plugins: Dict[str, Plugin] = {}
        self.loader = PluginLoader()

    def discover_plugins(self) -> List[Plugin]:
        """Auto-discover plugins from entry points."""

    def register_adapter(self, adapter: ToolAdapter) -> None:
        """Register custom adapter from plugin."""

    def register_detector(self, detector: VulnerabilityDetector) -> None:
        """Register custom vulnerability detector."""

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get plugin by name."""

# Plugin entry point (pyproject.toml de plugins externos)
[project.entry-points."miesc.plugins"]
my_plugin = "my_package:MIESCPlugin"
```

#### 3.3 Cache de Resultados (P2.15)

**Nuevo archivo:** `src/core/cache.py`

```python
class AuditCache:
    """Intelligent cache for audit results."""

    def __init__(self, cache_dir: Path = None, ttl: int = 3600):
        self.cache_dir = cache_dir or Path.home() / ".miesc" / "cache"
        self.ttl = ttl

    def get_cached(self, contract_hash: str, tools: List[str]) -> Optional[CachedResult]:
        """Get cached result if valid."""

    def cache_result(self, contract_hash: str, tools: List[str], result: AuditResult):
        """Cache audit result."""

    def invalidate(self, contract_path: str):
        """Invalidate cache for modified contract."""

    def clean_expired(self):
        """Remove expired cache entries."""

    def get_stats(self) -> CacheStats:
        """Get cache hit/miss statistics."""
```

#### 3.4 Comparacion de Auditorias (P2.17)

**Nuevo archivo:** `src/core/diff_engine.py`

```python
class AuditDiffEngine:
    """Compare audits to track security improvements."""

    def compare(self, audit1: AuditResult, audit2: AuditResult) -> DiffReport:
        """Generate comprehensive diff between audits."""
        return DiffReport(
            new_findings=self._find_new(audit1, audit2),
            resolved_findings=self._find_resolved(audit1, audit2),
            severity_changes=self._find_severity_changes(audit1, audit2),
            coverage_diff=self._compare_coverage(audit1, audit2),
            tool_diff=self._compare_tools(audit1, audit2)
        )

    def generate_changelog(self, diffs: List[DiffReport]) -> str:
        """Generate security changelog from diffs."""

@dataclass
class DiffReport:
    new_findings: List[Finding]
    resolved_findings: List[Finding]
    severity_changes: List[SeverityChange]
    coverage_diff: CoverageDiff
    tool_diff: ToolDiff
```

---

### Fase 4: Integraciones

**Duracion Estimada:** 2-3 sprints
**Prioridad:** MEDIA

#### 4.1 Integracion GitHub/GitLab (P2.18)

**Nuevo modulo:** `src/integrations/`

```python
# src/integrations/github.py
class GitHubIntegration:
    """GitHub PR comments and checks integration."""

    async def create_check_run(
        self,
        repo: str,
        sha: str,
        results: AuditResult
    ) -> CheckRun:
        """Create GitHub check run with findings."""

    async def comment_on_pr(
        self,
        pr_number: int,
        findings: List[Finding]
    ) -> Comment:
        """Add inline comments on affected lines."""

    async def upload_sarif(self, repo: str, sarif: str) -> None:
        """Upload SARIF to GitHub Code Scanning."""

# src/integrations/gitlab.py
class GitLabIntegration:
    """GitLab MR and pipeline integration."""

    async def create_pipeline_job(self, project_id: int, results: AuditResult)
    async def comment_on_mr(self, mr_iid: int, findings: List[Finding])
```

#### 4.2 Knowledge Base Estructurada (P2.13)

**Expandir:** `src/knowledge_base/`

```
src/knowledge_base/
├── __init__.py
├── vulnerability_db.py        # SQLite-based vuln DB
├── pattern_matcher.py         # Pattern matching engine
├── remediation_engine.py      # Auto-remediation suggestions
├── data/
│   ├── vulnerabilities/
│   │   ├── reentrancy.json
│   │   ├── overflow.json
│   │   ├── access_control.json
│   │   ├── front_running.json
│   │   ├── flash_loan.json
│   │   └── oracle_manipulation.json
│   ├── patterns/
│   │   ├── defi_patterns.json
│   │   ├── nft_patterns.json
│   │   ├── governance_patterns.json
│   │   └── proxy_patterns.json
│   ├── remediations/
│   │   └── templates.json
│   └── cwe_swc_mapping.json
```

---

### Fase 5: Innovacion (v5.0 Preview)

**Duracion Estimada:** Ongoing
**Prioridad:** FUTURA

#### 5.1 Analisis Multi-Chain (P3.19)

```
src/chains/
├── __init__.py
├── chain_factory.py
├── ethereum/
│   ├── adapter.py       # EVM/Solidity
│   └── analyzer.py
├── solana/
│   ├── adapter.py       # Rust/Anchor
│   └── analyzer.py
├── near/
│   ├── adapter.py       # Rust/AssemblyScript
│   └── analyzer.py
├── polkadot/
│   ├── adapter.py       # Ink!/Rust
│   └── analyzer.py
└── move/
    ├── adapter.py       # Aptos/Sui
    └── analyzer.py
```

#### 5.2 ML: Sintesis de Invariantes (P3.20)

```python
class InvariantSynthesizer:
    """ML-powered automatic invariant generation."""

    def synthesize(self, contract: Contract) -> List[Invariant]:
        """Generate invariants from contract behavior."""
        # 1. Analyze state transitions
        # 2. Infer pre/post conditions
        # 3. Generate Solidity asserts
        # 4. Validate with symbolic execution
```

#### 5.3 Auditoria Continua (P3.21)

```python
class ContinuousAuditor:
    """Monitor deployed contracts in real-time."""

    async def monitor_contract(self, address: str, chain: str):
        """Real-time transaction monitoring."""
        # Integration with Forta
        # Integration with OpenZeppelin Defender
        # Custom anomaly detection
```

#### 5.4 Generacion de Tests (P3.22)

```python
class TestGenerator:
    """Generate PoC tests from findings."""

    def generate_foundry_test(self, finding: Finding) -> str:
        """Generate Foundry test for vulnerability."""

    def generate_hardhat_test(self, finding: Finding) -> str:
        """Generate Hardhat test for vulnerability."""
```

---

## Metricas de Exito v4.2.0

| Metrica | v4.1.0 | Target v4.2.0 |
|---------|--------|---------------|
| Cobertura Tests | 50% | 80% |
| Archivos Legacy | ~35 | 0 |
| VS Code Features | 1 | 10+ |
| Export Formats | 5 | 5 |
| Plugins Oficiales | 0 | 3 |
| GitHub Stars | - | 100 |
| PyPI Downloads | - | 1000/mes |
| Documentacion | Parcial | 100% API |

---

## Cronograma Propuesto

```
Semana 1-2:   Fase 1 - Limpieza (P0.2, P0.3, P0.4)
Semana 3-4:   Fase 2 - Tests (P1.9)
Semana 5-6:   Fase 2 - Documentacion (P1.10)
Semana 7-10:  Fase 3 - VS Code Extension (P1.6)
Semana 11-12: Fase 3 - Plugins y Cache (P1.12, P2.15)
Semana 13-14: Fase 4 - Integraciones (P2.17, P2.18)
Semana 15-16: QA y Release v4.2.0
```

---

## Dependencias y Riesgos

### Dependencias

- **VS Code Extension:** Requiere conocimiento de VS Code API
- **GitHub Integration:** Requiere GitHub App o PAT
- **Multi-Chain:** Requiere tooling especifico de cada chain

### Riesgos

| Riesgo | Probabilidad | Impacto | Mitigacion |
|--------|--------------|---------|------------|
| Breaking changes en adapters | Media | Alto | Tests exhaustivos |
| Incompatibilidad VS Code | Baja | Medio | Version pinning |
| Performance en cache | Media | Medio | Benchmarks |

---

## Siguiente Paso Inmediato

1. **Crear branch** `feature/v4.2-cleanup`
2. **Ejecutar script** de limpieza de legacy
3. **Actualizar** coverage tests
4. **Merge** a main con version bump

---

*Plan generado: 2025-12-13*
*Version: MIESC v4.2.0 "Fortress"*
*Autor: Claude Opus 4.5 + Fernando Boiero*
