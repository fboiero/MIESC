# MIESC v4.0.0 - Evidence Report
Generated: 2025-12-08 12:43:19

## Summary

This document contains evidence of MIESC tool functionality for thesis documentation.

## Evidence Categories

### 1. CLI Evidence (docs/evidence/cli/)

| Test | Status |
|------|--------|
| miesc --version | ✓ |
| miesc --help | ✓ |
| miesc doctor | ✓ |
| miesc scan | ✓ |
| project structure | ✓ |

### 2. API Evidence (docs/evidence/api/)

| Endpoint | Status |
|----------|--------|
| GET / | ✓ |
| GET /mcp/capabilities | ✓ |
| GET /mcp/status | ✓ |
| GET /mcp/get_metrics | ✓ |
| POST /mcp/run_audit | ✓ |

### 3. ML Pipeline Evidence (docs/evidence/ml/)

| Component | Status |
|-----------|--------|
| ML Pipeline | ✓ |
| FP Filter | ✓ |
| ML Report | ✓ |
| ML Summary | ✓ |

### 4. Test Evidence (docs/evidence/tests/)

| Test Suite | Status |
|------------|--------|
| pytest | ✓ |
| test summary | ✓ |

### 5. Web Dashboard Evidence (docs/evidence/web/)

| Screenshot | Status |
|------------|--------|
| Main dashboard view | ✓ |
| Dashboard after load | ✓ |
| Dashboard scrolled | ✓ |


## Files Generated

### cli/
- 01_miesc_version.txt
- 02_miesc_help.txt
- 03_miesc_doctor.txt
- 04_miesc_scan.txt
- 05_project_structure.txt

### api/
- 01_api_root.json
- 02_api_capabilities.json
- 03_api_status.json
- 04_api_metrics.json
- 05_api_run_audit.json

### ml/
- 01_ml_pipeline_output.json
- 02_fp_filter_stats.json
- 03_ml_report.json
- 04_ml_summary.txt

### tests/
- 01_test_results.txt
- 02_test_summary.txt

### web/
- 01_dashboard_main.png
- 02_dashboard_loaded.png
- 03_dashboard_scrolled.png


## Validation Metrics

| Metric | Value |
|--------|-------|
| Precision | 89.47% |
| Recall | 86.20% |
| F1-Score | 87.81% |
| Cohen's Kappa | 0.847 |
| FP Reduction | 43% |
| Test Coverage | 87.5% |
| Tests Passing | 204 |

---
*Evidence generated automatically by MIESC capture script*
