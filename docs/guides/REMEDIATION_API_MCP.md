# Remediation API and MCP Examples

This guide shows the platform remediation workflow exposed outside the CLI. The
schema is shared with `miesc remediate`, `benchmarks/fix_eval.py`, and the Paper
2 evidence bundle.

## REST API

Apply patch candidates without validation:

```bash
curl -sS -X POST http://localhost:8000/api/v1/remediate/ \
  -H 'Content-Type: application/json' \
  -d '{
    "results_json": "results.json",
    "contract_path": "contracts/Vulnerable.sol",
    "output_path": "build/remediation/Vulnerable.patched.sol"
  }'
```

Apply patch candidates with compile and re-scan validation:

```bash
curl -sS -X POST http://localhost:8000/api/v1/validate-remediation/ \
  -H 'Content-Type: application/json' \
  -d '{
    "results_json": "results.json",
    "contract_path": "contracts/Vulnerable.sol",
    "output_path": "build/remediation/Vulnerable.patched.sol",
    "compile": true,
    "rescan": true,
    "no_regression_bound": 2
  }'
```

The response includes the source hash, patched hash, patch application status,
optional compile evidence, optional re-scan evidence, and bounded no-regression
status.

## MCP Tools

Use `miesc_apply_fix` when the caller only needs a patched artifact and hash
evidence:

```json
{
  "tool": "miesc_apply_fix",
  "arguments": {
    "results_json": "results.json",
    "contract_path": "contracts/Vulnerable.sol",
    "output_path": "build/remediation/Vulnerable.patched.sol"
  }
}
```

Use `miesc_validate_remediation` or `miesc_remediation_evidence_bundle` when the
caller needs Paper 2 style evidence:

```json
{
  "tool": "miesc_validate_remediation",
  "arguments": {
    "results_json": "results.json",
    "contract_path": "contracts/Vulnerable.sol",
    "output_path": "build/remediation/Vulnerable.patched.sol",
    "compile_check": true,
    "rescan_check": true,
    "no_regression_bound": 2
  }
}
```

## Evidence Contract

The remediation evidence contract is:

- `source_path`, `patched_path`
- `source_sha256`, `patched_sha256`
- `fix_applied`, `patched_changed`
- `patches`
- `compile`
- `rescan`
- `no_regression`
- `errors`

REST, MCP, CLI, and benchmark code should preserve this contract so paper
evidence and platform output stay comparable.
