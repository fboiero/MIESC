# MIESC Open Core Boundary

This document defines the repository boundary for the open-source MIESC core and
the commercial platform/workflow layer.

## Repositories

| Repository | Scope | Distribution |
| --- | --- | --- |
| `MIESC` | Reproducible research core, CLI, adapters, benchmark evidence, local APIs, MCP interfaces, Docker packaging, and paper artifacts. | FOSS |
| `git@gitlab.com:xcapit/miesc_platform.git` | Product platform, commercial workflow, hosted/team experience, licensing, dashboards, IDE/product integrations, and customer-specific orchestration. | Commercial |

## Core Principles

1. The public core must remain sufficient to reproduce the published papers.
2. Paper metrics must come only from the public core, pinned commits/tags, and
   versioned evidence artifacts.
3. The commercial platform may orchestrate the core, but it must not be required
   to reproduce paper claims.
4. Any change that affects paper metrics, benchmark selection, adapter behavior,
   or remediation claims belongs in the public core first, with reproducible
   evidence.
5. Product workflow, team operations, customer policy, hosted services, and
   licensing belong in the platform repository.

## Keep In The FOSS Core

| Area | Paths | Rationale |
| --- | --- | --- |
| Paper artifacts | `paper/`, `benchmarks/results/`, reproducibility notes | Canonical scientific record and reviewer evidence. |
| Analysis engine | `miesc/core/`, `src/adapters/`, `src/agents/`, `src/ml/`, `src/llm/` | Implements the evaluated security pipeline. |
| CLI and reports | `miesc/cli/`, `src/utils/enhanced_reporter.py`, report templates | Required for local reproducible use. |
| Local integration interfaces | `miesc/api/`, `miesc/mcp_server.py`, `src/mcp_core/`, `docs/openapi.yaml` | Local automation surfaces used by researchers and developers. |
| Packaging and reproducibility | `Dockerfile*`, `docker/`, `scripts/`, `requirements/`, `pyproject.toml` core extras | Needed to run the same toolchain outside the platform. |
| Security/research documentation | `docs/guides/`, `docs/policies/`, `docs/TOOL_DIAGNOSTIC_REPORT.md` | Documents how claims are reproduced and audited. |

## Move To The Commercial Platform

| Area | Candidate Paths | Notes |
| --- | --- | --- |
| Web product UI | `webapp/`, `.streamlit/` | Product-facing experience and deployment workflow. |
| Commercial licensing | `src/licensing/` | License keys, quotas, plans, and admin APIs are product concerns. |
| Product dashboards | `src/dashboard/`, `src/utils/web_dashboard.py`, `src/utils/metrics_dashboard.py` | Keep only static report generation in core if needed for reproducibility. |
| IDE/product client | `vscode-extension/` | Best maintained as a platform client consuming the core CLI/API. |
| Hosted workflow glue | future platform CI, queues, storage, tenancy, RBAC, billing | Must consume released core versions rather than modifying benchmark behavior. |

## Review Before Moving

| Path | Decision Rule |
| --- | --- |
| `miesc/api/rest.py` | Keep local/public API if it is used for reproducibility or local automation; move hosted-only endpoints to platform. |
| `miesc/cli/commands/server.py` | Keep commands that expose the local core; move SaaS or tenant-aware commands. |
| `src/core/websocket_api.py` | Keep only if used by local researcher workflows; otherwise export to platform. |
| `docs/evidence/web/` | Preserve paper/research evidence in core; move product demo evidence to platform. |
| `paper/INSTRUCCIONES_RELEASE.md` | Update only if it references deployment of moved product UI; do not alter paper claims. |

## Non-Impact Rule For Papers

The platform split does not invalidate Paper 1 or Paper 2 when these conditions
hold:

1. The core repository keeps the paper PDFs, source, benchmark manifests, and
   claim matrices.
2. Reproduction commands continue to run without the platform repository.
3. Platform-only files are not referenced by the benchmark scripts used for paper
   claims.
4. Any future experiment that uses the platform is labeled as platform evidence,
   not as a replacement for the published paper evidence.

## Dependency Direction

The platform depends on the core. The core must not import platform modules.

Recommended platform consumption modes:

1. Python package dependency pinned to a core release tag.
2. Docker image pinned to a core image digest or release tag.
3. CLI invocation against a checked-out core version for local developer flows.
4. MCP or local API integration against released core interfaces.

The platform may add workflow value, but the security results must remain
traceable to a public core version.
