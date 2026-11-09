# Verify-gate multi-provider — change note & evidence (2026-10-23)

## Context

MIESC detection on SmartBugs-curated is **recall-first**: recall is maxed (143/143,
lenient 1.0) but precision is the hard gap — the most recent static-detector runs measured
**28.9%–31.9% precision with 300–352 false positives** on 143 contracts.

The recall-safe FP-verification gate already existed (`--verify-fp` /`--verify-model`,
engine `miesc/ml/benign_context_verifier.py`, recall 1.0 validated on six sources), but its
advisory LLM pass could only reach a **local Ollama model plus a DeepSeek failover**. This
change opens that pass to a **configurable set of providers** so the gate can be driven by
stronger reasoners when a team has them, while staying free/local and reproducible by
default.

## What changed

`BenignContextVerifier._query` now routes the advisory prompt by provider, derived from the
`--verify-model` string via `_parse_verifier_model`:

| `--verify-model` | Provider | Transport | Key |
|---|---|---|---|
| `ollama:<m>` / bare name | local Ollama | `/api/generate` | — |
| `deepseek[:<m>]` | DeepSeek | OpenAI-compatible | `DEEPSEEK_API_KEY` |
| `gpt` / `openai[:<m>]` | OpenAI | OpenAI chat/completions | `OPENAI_API_KEY` |
| `claude` / `anthropic[:<m>]` | Anthropic | Messages API | `ANTHROPIC_API_KEY` |
| `kimi` / `moonshot[:<m>]` | Moonshot | OpenAI-compatible | `KIMI_API_KEY` / `MOONSHOT_API_KEY` |

Base URL and model are env-overridable per provider (e.g. `OPENAI_BASE_URL`,
`MIESC_VERIFY_OPENAI_MODEL`). The Ollama host is now resolved via `get_ollama_host()`
(`OLLAMA_HOST` env / config) instead of a hard-coded `localhost`, so Docker and remote
daemons are reached rather than silently skipped.

**Invariants preserved (by construction):**
- Opt-in and **local-first**: no `--verify-model` → rule-only; API providers only fire with
  an explicit provider and its key present.
- **Recall-safe**: a missing key or any transport error returns `''`, which the caller
  treats as KEEP. The LLM is advisory — it only FLAGS `needs_review`, never drops. Recall
  stays 1.0.
- **CI / reproducible baseline need no key** (`env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY …`
  still produces the rule-only result).

## Verification

### Plumbing (unit, no network, no keys)
`tests/test_benign_context_verifier.py` — 56 tests pass under `env -u` of all provider keys.
New coverage: `_parse_verifier_model` for every form; per-provider mocked-transport tests
asserting the **exact endpoint and headers** (OpenAI/GPT Bearer → `…/v1/chat/completions`,
Anthropic `x-api-key` → `…/v1/messages`, Kimi via `MOONSHOT_API_KEY`); missing-key →
recall-safe `''`; `OLLAMA_HOST` honored; and the end-to-end contract that an LLM
`false_positive` through an API provider only FLAGS `needs_review`, never drops.
`ruff` + `black` (26.1.0, line-length 100) clean.

### End-to-end smoke (1 contract — directional, NOT a precision claim)
`benchmarks/datasets/smartbugs-curated/dataset/arithmetic/BECToken.sol` (the historical
batchOverflow contract), via `miesc scan`:

| Variant | Findings | Verdicts |
|---|---|---|
| baseline (no gate) | 12 | — |
| `--verify-fp` (rule-only) | 11 | 11 confirmed (1 type-deterministic FP dropped) |
| `--verify-fp --verify-model ollama:qwen2.5-coder:14b` | 11 | 9 needs_review + 2 confirmed, **0 dropped** (~61 s) |

This exercises the full path, including the new multi-provider routing to a local model, and
shows the recall-safe behavior: the LLM pass demoted 9 findings to `needs_review` for triage
and surfaced 2 as most-likely-real, **without dropping anything** below the rule-only set.

### Full measurement (left to a maintainer/CI run)
A corpus-wide precision/recall measurement is intentionally **not** bundled here (it runs the
full pipeline over 143 contracts and writes into `benchmarks/results/`). Canonical command:

```bash
# baseline (no gate) — expect ~29–32% precision, recall 143/143
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY \
  python benchmarks/smartbugs_evaluation.py --max 143
# gated: re-run with the verify pass applied (rule-only, then --verify-model ollama:...)
```

The claim this change makes is about **plumbing** (provider-configurable advisory pass),
proven by the mocked-transport tests; the gate's recall-safety is the pre-existing
"recall 1.0 on six sources" property, unchanged.

## Files
- `miesc/ml/benign_context_verifier.py` — provider table + routing in `_query`; host via `get_ollama_host()`.
- `miesc/cli/commands/scan.py`, `miesc/cli/commands/audit.py` — `--verify-model` help.
- `tests/test_benign_context_verifier.py` — parser + per-provider mocked-transport tests.

No frozen paper/benchmark artifacts were modified.

## Update (same PR, after #204): the verifier reads the shared provider registry

The provider table and `_parse_verifier_model` alias list that this document describes
were replaced by `miesc.core.llm_providers` (landed in #204), so `--verify-model` and
`scan --model` accept the same forms (`provider[:model]`, the historical aliases, bare
Ollama tags, bare model ids by prefix) and read the same endpoints and key variables
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `MOONSHOT_API_KEY` /
`KIMI_API_KEY`, `<NAME>_BASE_URL`, plus anything under `llm.providers`). What is specific
to the verifier: a cheaper default tier for the per-finding advisory call (`gpt-4o-mini`,
`claude-haiku-4-5-20251001`, `deepseek-chat`), `MIESC_VERIFY_<NAME>_MODEL` to override it,
the pre-registry `DEEPSEEK_MODEL` kept for the failover, and the recall-safe behaviour on
any failure. An unknown provider prefix disables the pass instead of guessing an endpoint.
See `docs/guides/LLM_PROVIDERS.md`.
