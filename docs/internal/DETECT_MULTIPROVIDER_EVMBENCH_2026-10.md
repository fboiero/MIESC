# EVMBench multi-provider coverage — evidence (2026-10-23)

## Context

The business-logic detection path (`FrontierLLMAdapter` + `miesc scan --model` +
`benchmarks/evmbench_eval.py`) now resolves any configured provider through the shared
registry `miesc/core/llm_providers.py` — anthropic/openai/deepseek/kimi — landed in main via
PRs #203/#204. This note records an **independent EVMBench run comparing providers** and wires
**Kimi/Moonshot into the EVMBench harness** (the only piece the registry work left out).

The purpose is to answer, with numbers: does routing the detector through an API provider
actually improve coverage over the free local model? The prior frontier run
(`EVMBENCH_FRONTIER_RUN_2026-10.md`) measured gpt-5 at 88.2% vs qwen32b 41.2%; this run adds a
same-corpus, multi-provider comparison at a smaller, bounded scale.

## Change in this PR

- `benchmarks/evmbench_eval.py`: add `kimi`/`moonshot` to the `provider_map` and both
  `model_map`s (default model `kimi-k2-turbo-preview`), so `--model kimi` reaches the
  registry-configured Moonshot endpoint like the other providers. Additive, dict-only.

## Measurement

Bounded run over the **5 smallest EVMBench audits by SLOC** (11 ground-truth vulns; same
selection criterion as the prior 10-audit run), via `evmbench_eval.py --max-audits 5 --model
<p>`, with API keys supplied in the environment. Models: `gpt` → gpt-4o, `deepseek` →
deepseek-chat, `qwen14b` → qwen2.5-coder:14b (local). Directional — a small subset, not a
definitive coverage claim (selection bias toward small audits; see the prior doc).

| Provider | Recall | Precision | $/audit | Notes |
|---|---|---|---|---|
| gpt-4o (`--model gpt`) | 72.7% | 53.3% (TP8/FP7) | $0.037 | API (OpenAI) |
| deepseek (`--model deepseek`) | **100.0%** | 18.3% (TP11/FP49) | ~$0* | API (OpenAI-compatible) |
| qwen2.5-coder:14b (`--model qwen14b`) | 54.5% | 27.3% (TP6/FP16) | $0 | local baseline |
| Kimi/Moonshot (`--model kimi`) | not run | — | — | no API key available here; wiring verified by the registry + `miesc scan --model kimi` availability |

*deepseek: the harness cost table does not price it (reported $0; 5 calls, 64.7k in / 36.1k
out tokens) — real cost is low but **not** zero.

### Reading

- **An API provider covers more than the free local model.** deepseek 100% and gpt-4o 72.7%
  recall vs qwen2.5-coder:14b 54.5% on the same 5 audits. So a researcher after maximum
  coverage benefits from a frontier/API provider — the local model trades recall for $0.
- **deepseek floods false positives** (18.3% precision, 49 FP): high recall, low precision —
  exactly the input the recall-safe `--verify-fp` gate (also in main) is built to triage.
  Coverage and precision are complementary levers: pick a strong provider for recall, then let
  the verifier demote the FPs to `needs_review` without dropping anything.

### Canonical full run (maintainer/CI, with credit)
Comparable to the prior 88%/41%, over the 10 smallest audits:
```bash
# OPENAI/ANTHROPIC/DEEPSEEK/KIMI_API_KEY in the environment
python benchmarks/evmbench_eval.py --max-audits 10 --model gpt-5
python benchmarks/evmbench_eval.py --max-audits 10 --model claude
python benchmarks/evmbench_eval.py --max-audits 10 --model deepseek
python benchmarks/evmbench_eval.py --max-audits 10 --model kimi      # needs KIMI_API_KEY
python benchmarks/evmbench_eval.py --max-audits 10 --model qwen32b   # local, free
```

No frozen paper/benchmark artifacts were modified.
