# MIESC — Independent EVMBench frontier run (gpt-5) + "do researchers need paid APIs?"

**Date:** 2026-10-20
**Base:** `origin/main` @ `8f872577` (miesc 6.1.0), ARM64 macOS.
**Goal:** Independently run MIESC's own EVMBench harness with a frontier model
(GPT-5) and, together with the papers' evidence, judge whether a researcher
needs paid APIs.

> **Additive, not a paper claim.** This does not modify any frozen artifact
> (`benchmarks/results/*`, claims matrices, PDFs). Outputs went to a scratch dir.
> EVMBench data was cloned fresh (`paradigmxyz/evmbench` + its public
> `openai/frontier-evals` submodule, 298 MB; per-audit source from
> `evmbench-org/<id>`). Run on the **10 smallest audits by SLOC** — see the
> selection-bias caveat below; these numbers are **indicative**, not a 40-audit claim.

## What I ran

`benchmarks/evmbench_eval.py --max-audits 10 --model gpt-5` with the `[llm]` extra
installed (`openai`), a single-provider env (only `OPENAI_API_KEY`, so the adapter
routes to OpenAI), and keys sourced from `apik.sh` without ever printing them.

### A harness bug I had to fix first
The Strategy A2 fallback (`evmbench_eval.py:523`, "scan top files individually when
the concat yields 0 findings") had a `model_map` missing `gpt-5`, so
`model_map.get("gpt-5", "claude-sonnet-4-6")` fell back to **claude-sonnet-4-6** and
sent it to the **OpenAI** endpoint → `404 model_not_found`. Fixed by matching it to
Strategy A's full map. (Not a frozen artifact; the fix only affects the fallback path.)

## Result (GPT-5, 10 smallest EVMBench audits)

| Metric | Value |
|--------|-------|
| Audits | 10/10, 0 errors |
| Vulns detected | **15 / 17** |
| **Recall** | **88.2%** |
| **Precision** | **78.9%** (TP=15, FP=4) |
| **F1** | **83.3%** |
| API calls | 10 (1 concat call/audit) |
| Tokens | 130,754 in / 47,828 out (37,120 reasoning) |
| **Cost** | **$0.64 total (~$0.064/audit)** → ~$2.6 for all 40 |

Per-audit recall was 100% on 8 of 10; `2024-07-munchables` 4/5 (80%) and
`2024-05-loop` 0/1 were the only misses.

### Honest caveats (why this is not the paper's 77.5%)
1. **Selection bias:** these are the 10 **smallest** audits (sorted by SLOC), which
   are easier. The paper's **77.5% recall / 42.7% precision / 0.550 F1** is over **all
   40**, so my higher numbers are optimistic, not a contradiction.
2. **Lenient matcher:** EVMBench recall here uses keyword matching; the paper's own
   null control credits ~50% to a contract-agnostic matcher, so absolute recall is
   inflated. The *relative* static-vs-frontier gap is the reliable signal.

## Combined picture (my run + the papers' frozen numbers)

**EVMBench (business-logic / semantic bugs):**

| Config | Recall | Precision | F1 | Cost | Source |
|--------|:------:|:---------:|:--:|:----:|--------|
| static-only | 18.3% | 14.5% | 0.162 | $0 | paper (40) |
| Ollama qwen32b (local) | 59.2% | 30.1% | 0.399 | **$0** | paper (40) |
| GPT-4o | 73.7% | 20.0% | 0.315 | $$ | paper (40) |
| GPT-5 | 77.5% | 42.7% | 0.550 | $$ | paper (40) |
| **GPT-5 (my independent run)** | **88.2%** | **78.9%** | **83.3%** | **$0.064/audit** | this doc (10 smallest) |
| ensemble (union) | 92.5% | — | — | $$$ | paper (40) |

**SmartBugs (common vulns):** static+own layers 95.8%, +local Ollama 97.9%. Frontier
adds nothing here.

## Answer: does a researcher need paid APIs?

**No for common-vulnerability detection.** SmartBugs recall is 95.8–97.9% with the
free static + local-Ollama stack. Paying adds nothing.

**For business-logic / semantic bugs, it depends — and the cost is trivial.**
- Static alone is weak (18%). **Local Ollama ($0) already reaches ~59%** and, notably,
  beats GPT-4o on F1 (0.40 vs 0.32) — so a free local model is a legitimate baseline.
- A frontier model buys a real single-run recall jump (paper 77.5% for GPT-5 over 40;
  my independent run 88.2% on the 10 easiest) at **~$0.06/audit** — a few dollars for
  the whole 40-audit suite. GPT-5 also gives the best precision/F1 of the frontier set.
- Maximum recall (92.5%) needs the multi-provider ensemble.

**Bottom line:** a researcher can get strong results for free (local-first), and should
reach for paid frontier only when chasing business-logic/semantic recall — where the
spend is a few dollars, not a barrier. This matches the papers' thesis ("frontier buys
single-run recall, not better precision/F1"), with the nuance that GPT-5 *does* improve
precision/F1 over the other frontier models and over local.

## Reproduce

```bash
git clone --depth 1 --recurse-submodules --shallow-submodules \
  https://github.com/paradigmxyz/evmbench /tmp/evmbench
pip install -e '.[llm]'                 # openai/anthropic clients
# only one provider key in env so the adapter routes correctly:
env -u ANTHROPIC_API_KEY -u DEEPSEEK_API_KEY \
  python benchmarks/evmbench_eval.py --max-audits 10 --model gpt-5 --output /scratch/gpt5_10.json
# read the harness's own "Token / cost report" block for cost; recall/precision/F1 in the summary.
```

> Gotcha: the harness tracks cost in its **own** end-of-run report, not in
> `MIESC_FRONTIER_USAGE_LOG` (the adapter ledger, which this in-process path does not
> populate). Judge success by the harness report, not the ledger.
