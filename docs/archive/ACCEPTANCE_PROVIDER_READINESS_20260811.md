# Acceptance-Pattern Provider Readiness

Date: 2026-08-11
Owner/Lane: Codex
Status: integration runbook for `bench/v6.0.0-smartbugs`

## Purpose

This runbook records how the acceptance-pattern intelligence feature is wired in
the current branch and how to validate it before using the v6 benchmark evidence
in a release note, PR, or demo.

The feature is intentionally **provider-neutral** and **recall-safe**:

- Provider-neutral: MIESC defines a port in `miesc/core/acceptance_contracts.py`
  and adapters in `miesc/core/acceptance_providers.py`.
- Local-first: the default provider is `LocalAcceptancePatternProvider`, backed
  by `miesc/knowledge_base/acceptance_patterns.json`.
- Remote-off-by-default: `BugBountyIntelligenceProvider` is unavailable unless
  config enables it, policy allows remote traffic, and the API-key environment
  variable is present.
- Recall-safe: acceptance probability may reorder findings only. It must not
  drop findings, lower detector recall, or feed a confidence filter.

## Runtime Wiring

Primary entrypoints:

- `miesc.core.acceptance_contracts.AcceptancePatternProvider`
- `miesc.core.acceptance_contracts.AcceptancePolicy`
- `miesc.core.acceptance_providers.LocalAcceptancePatternProvider`
- `miesc.core.acceptance_providers.BugBountyIntelligenceProvider`
- `miesc.core.acceptance_providers.auto_acceptance_provider`
- `miesc.ml.triage_ranker.apply_acceptance_ordering`
- `miesc.cli.commands.scan._apply_acceptance_ordering`

CLI surface:

```bash
miesc scan <target> --acceptance-provider local
miesc scan <target> --acceptance-provider external
miesc scan <target> --acceptance-provider none
```

Expected behavior:

- `none`: no acceptance ordering.
- `local`: annotate known classes with `acceptance_prob` and reorder findings by
  acceptance probability.
- `external`: use the external adapter only when explicitly configured and
  available; otherwise fall back gracefully through the local provider path.

## Validation Commands

Run these before claiming that the feature is integrated:

```bash
python3 -m py_compile \
  miesc/core/acceptance_contracts.py \
  miesc/core/acceptance_providers.py \
  miesc/ml/triage_ranker.py \
  miesc/cli/commands/scan.py

python3 -m pytest tests/test_acceptance_patterns.py -q

python3 - <<'PY'
from miesc.core.acceptance_providers import LocalAcceptancePatternProvider
from miesc.ml.triage_ranker import apply_acceptance_ordering

results = [{
    "tool": "unit",
    "findings": [
        {"type": "front-running", "description": "low acceptance stays visible"},
        {"type": "reentrancy-eth", "description": "higher acceptance rises"},
    ],
}]

before = sum(len(r["findings"]) for r in results)
annotated = apply_acceptance_ordering(
    results,
    provider=LocalAcceptancePatternProvider(),
)
after = sum(len(r["findings"]) for r in results)
assert annotated == before == after == 2
assert results[0]["findings"][0]["type"] == "reentrancy-eth"
print("acceptance-ordering-recall-safe")
PY

git diff --check -- \
  docs/ACCEPTANCE_PROVIDER_READINESS_20260811.md \
  miesc/core/acceptance_contracts.py \
  miesc/core/acceptance_providers.py \
  miesc/ml/triage_ranker.py \
  miesc/cli/commands/scan.py \
  tests/test_acceptance_patterns.py
```

## Evidence Expectations

Acceptable claims after the validation above:

- The provider abstraction is present.
- The local default is functional and offline.
- The external adapter is opt-in and guarded.
- Acceptance ordering is recall-safe on the focused test and smoke snippet.
- The v6 benchmark branch can discuss acceptance ordering as integrated
  functionality, not as a measured SmartBugs precision uplift unless a separate
  benchmark run wires it into that harness.

Do not claim:

- Benchmark TPR/FPR improvement from acceptance ordering without a dated
  non-canonical run.
- Any remote provider availability unless configuration and credentials were
  explicitly present during validation.
- Any finding suppression from acceptance probability. Suppression belongs to
  confidence/FP filtering, not this feature.

## Release/PR Checklist

- `tests/test_acceptance_patterns.py` passes.
- `acceptance_patterns.json` is present and parseable.
- CLI help exposes `--acceptance-provider`.
- `apply_acceptance_ordering` preserves finding count.
- External provider paths are remote-off-by-default.
- SSRF guard coverage remains in the external adapter tests.
- Benchmark reports label acceptance ordering as recall-safe ordering unless a
  separate measured run proves metric movement.
