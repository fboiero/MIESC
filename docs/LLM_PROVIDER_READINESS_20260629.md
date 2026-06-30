# LLM Provider Readiness - 2026-06-29

This is a non-frozen readiness note for MIESC's LLM provider surface. It does
not contain API keys, live provider outputs, paper claims, or benchmark baseline
changes.

## Executive State

MIESC has four usable provider families in code:

- local Ollama / OpenLLaMA helper
- OpenAI
- Anthropic
- DeepSeek through an OpenAI-compatible API

The implementation is ready for operational use, but scientific claims should
stay narrower than the configuration surface. A provider being configured or
available does not prove that a multi-provider ensemble improves Paper 1 or
Paper 2 metrics. Any claim such as "best with all providers together" requires
a dated benchmark artifact with fixed corpus, provider list, model list, prompt
profile, and aggregation strategy.

## Provider Matrix

| Provider | Runtime path | Health/readiness behavior | Current evidence | Claim status |
| --- | --- | --- | --- | --- |
| Ollama | `src/llm/llm_orchestrator.py`, `src/llm/ensemble_detector.py`, `src/llm/openllama_helper.py` | Checks local Ollama `/api/tags`; local-first default in `.env.example`. | Unit coverage for helper availability and ensemble availability. | Operationally ready when local model is installed. |
| OpenAI | `OpenAIBackend`, ensemble `_query_openai` | Orchestrator health only checks API key presence; ensemble assumes configured provider models when key is present. | Mocked query/fallback tests. | Configured, but availability is not model-list verified. |
| Anthropic | `AnthropicBackend`, ensemble `_query_anthropic` | Orchestrator health only checks API key presence; ensemble assumes configured provider models when key is present. | Mocked query/fallback tests. | Configured, but availability is not model-list verified. |
| DeepSeek | `DeepSeekBackend`, ensemble `_query_deepseek`, `doctor` | Verifies `/v1/models` and only marks configured models available if listed. | Mocked model-list, model-missing, connection-error tests; doctor status tests. | Best health-check rigor among cloud providers. |

## Current Defaults

`.env.example` currently sets:

- `OLLAMA_HOST=http://localhost:11434`
- `MIESC_LLM_MODEL=deepseek-coder`
- `MIESC_LLM_PROVIDER=ollama`

Optional cloud variables are documented but commented:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `DEEPSEEK_API_KEY`
- `DEEPSEEK_BASE_URL=https://api.deepseek.com`

This is a reasonable default posture: local-first, cloud optional, no real
secrets committed.

## Evidence-Backed Strengths

- DeepSeek is integrated in the orchestrator, ensemble detector, doctor command,
  and provider-health helper.
- DeepSeek readiness checks `/v1/models`; it is not treated as available merely
  because a key exists.
- Doctor reports DeepSeek as not set, configured, model missing, unavailable, or
  ready without exposing secrets.
- LLM parsing paths already have tests for malformed JSON and provider fallback
  behavior.
- The project has explicit tests for provider priority order and fallback after
  runtime errors.

## Gaps And Non-Claims

Do not claim:

- "OpenAI/Anthropic are live-ready" from key presence alone.
- "DeepSeek improves benchmark results" without a dated benchmark artifact.
- "All providers together are best" unless an ensemble run records corpus,
  prompts, model versions, provider order, voting strategy, and raw/filtered
  findings.
- "No regressions from provider updates" without fixed prompt/model versions.

Known gaps:

- OpenAI and Anthropic health checks do not verify model listing or a lightweight
  model-specific probe.
- `.env.example` uses `MIESC_LLM_MODEL=deepseek-coder` with
  `MIESC_LLM_PROVIDER=ollama`; this is coherent for local Ollama only. Users who
  switch to `deepseek` should set a DeepSeek API model such as
  `deepseek-v4-flash`.
- Provider-specific benchmark claims are scattered in older docs; they should
  be treated as historical unless backed by current artifacts.

## Recommended Next Engineering Loop

The safest implementation improvement is to align cloud provider readiness
semantics:

1. Add lightweight model-aware readiness for OpenAI where practical.
2. Add lightweight model-aware readiness for Anthropic where practical.
3. Keep failures non-fatal and secret-safe.
4. Add tests matching the DeepSeek pattern: ready, model missing, unavailable,
   no key.

If provider APIs do not expose stable model-list endpoints or if live calls are
not wanted in local tests, keep key-presence checks but label them as
`configured`, not `ready`.

## Recommended Benchmark Loop

For a scientific ensemble claim, create a dated non-canonical artifact first:

```bash
MIESC_LLM_PROVIDER=ollama python3 <benchmark> --provider-profile local
MIESC_LLM_PROVIDER=deepseek python3 <benchmark> --provider-profile deepseek
python3 <benchmark> --provider-profile ensemble-openai-anthropic-deepseek-ollama
```

The artifact should record:

- corpus and commit SHA
- provider list and order
- model names
- prompt/profile version
- voting strategy and threshold
- raw findings and filtered findings
- recall/precision or remediation metrics, depending on the paper surface

Until that exists, provider integration should be described as an operational
capability, not as a measured scientific improvement.

## Closeout Decision

Provider readiness is good enough for continued tool development. The next
high-value work is either:

- implement model-aware readiness parity for OpenAI/Anthropic, or
- run a dated provider/ensemble benchmark to replace historical claims with
  current evidence.
