# LLM detection path on any registry provider, and what EVMBench says about it (2026-10-23)

## Context

The LLM detection path (`FrontierLLMAdapter`, `miesc scan --model`, `benchmarks/evmbench_eval.py`)
measured **gpt-5 88.2 % vs qwen2.5-coder:32b 41.2 %** recall on the 10 smallest EVMBench
audits (`EVMBENCH_FRONTIER_RUN_2026-10.md`), but each entry point carried its own provider
table and only Anthropic/OpenAI (DeepSeek as a special case; no Kimi). #204 replaced those
tables with one registry, `miesc/core/llm_providers.py`; #203 put the recall-safe `--verify-fp`
pass on it. This note records the EVMBench harness moving onto the same registry and the
provider comparison that was run on the way (it was first drafted for a branch that carried
a second registry, which was dropped in favour of the one on `main`).

## What changed in the harness

`benchmarks/evmbench_eval.py --model` accepts any registry provider as `provider[:model]`:
`claude`, `gpt-5`, `deepseek`, `kimi`, `ollama:qwen2.5-coder:14b`, or an endpoint declared under
`llm.providers`. The three hardcoded `provider_map` / `model_map` tables are gone; the direct
adapter path and the CLI subprocess receive the same canonical `provider:model`. Two spellings
keep the meaning they had in earlier runs so numbers stay comparable: `deepseek` is
`deepseek-chat` (the registry default elsewhere is `deepseek-v4-flash`) and `ollama` is the
benchmarked 32B local model (`scan --model ollama` is the 14B quick model). An unknown provider
prefix stops the run before any API call.

Invariants: `--model` is opt-in; without a key the provider reports not available and the run
degrades; the paper profile is LLM-free and nothing frozen was touched.

## Evidence

### Plumbing (unit, no network, no keys)

`tests/test_frontier_llm_adapter.py::TestRegistryProviders` (Kimi available with
`KIMI_API_KEY` or `MOONSHOT_API_KEY`, configuration error without, auto-detect order
anthropic → openai → deepseek → kimi), `tests/test_llm_providers.py` (client construction
with the provider's base URL and key against fake SDK modules), and
`tests/test_evmbench_model_resolution.py` (harness aliases and registry forms).

### Real API smoke (run 2026-10-23 by the sibling session, with keys)

`evmbench_eval.py --max-audits 1 --model gpt` (gpt-4o) on `2024-01-canto`: 2/2 detected,
recall 100 %, 1 API call, 11,749 in / 676 out tokens, $0.04.

### Provider comparison (EVMBench, 5 smallest audits by SLOC, 11 ground-truth findings)

Directional, not a coverage claim: a small subset with the selection bias described in
`EVMBENCH_FRONTIER_RUN_2026-10.md`. Run before the registry port; the call path is unchanged.

| Provider | Recall | Precision | $/audit | Note |
|---|---|---|---|---|
| gpt-4o (`--model gpt`) | 72.7 % | 53.3 % (TP 8 / FP 7) | $0.037 | OpenAI API |
| deepseek-chat (`--model deepseek`) | **100.0 %** | 18.3 % (TP 11 / FP 49) | not priced by the harness* | OpenAI-compatible |
| qwen2.5-coder:14b (`--model qwen14b`) | 54.5 % | 27.3 % (TP 6 / FP 16) | $0 | local baseline |
| Kimi (Moonshot) | — | — | — | plumbing and mocked tests only, no key available |

\* 5 calls, 64.7k in / 36.1k out tokens: a real, low cost, not zero.

Reading: the API providers cover more than the local model on this subset (deepseek 100 %,
gpt-4o 72.7 %, qwen14b 54.5 %), and deepseek pays for it with false positives (18.3 %
precision), which is the shape the recall-safe `--verify-fp` gate (#203) exists to triage.
Coverage and precision are two different levers; this run moves the first.

### Canonical comparison (maintainer, with credit)

For the number comparable to the earlier 88 % / 41 %, on the 10 smallest audits:

```bash
python benchmarks/evmbench_eval.py --max-audits 10 --model gpt-5
python benchmarks/evmbench_eval.py --max-audits 10 --model claude
python benchmarks/evmbench_eval.py --max-audits 10 --model deepseek
python benchmarks/evmbench_eval.py --max-audits 10 --model kimi      # needs MOONSHOT_API_KEY
python benchmarks/evmbench_eval.py --max-audits 10 --model qwen32b   # local, free
```

Results land in `benchmarks/results/evmbench/`; the frozen paper artifacts are not written.
