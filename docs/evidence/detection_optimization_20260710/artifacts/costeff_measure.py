"""Cost-efficiency experiment: can an open-source model (DeepSeek) reach
comparable detection to frontier models (GPT-5, Fable, ...) at N x less cost?

Head-to-head on the corrected 29-vuln DeFi corpus (L112/L125 dropped as
mislabelled -> 27 real vulns). Each model runs K times in its cost-reasonable
DEFAULT config (DeepSeek/GPT-5 reason; GPT-4o/Claude/Fable standard). Captures
REAL token usage per call -> measured cost, not estimated. Reports per-model
single-run recall distribution, ensemble (union) recall, total cost, and
recall-per-dollar. Additive dated artifact.
"""
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "benchmarks/results/detection_optimization_20260710")
from s3_deepseek_measure import GT, CORPUS, LEVER_PROMPT, matched  # reuse GT + matcher

# Corrected ground truth: drop the two mislabelled share-vault vulns.
PHANTOM = {("FlashLoanVault.sol", 112), ("FlashLoanVault.sol", 125)}
GT_CORR = {n: [(ln, kw) for (ln, kw) in v if (n, ln) not in PHANTOM] for n, v in GT.items()}
TOTAL = sum(len(v) for v in GT_CORR.values())

# (provider, model, n_runs, rate_in $/MTok, rate_out $/MTok, tokenizer_mult)
MODELS = [
    ("ollama", "qwen3-coder:30b", 5, 0.0, 0.0, 1.0),      # LOCAL, $0 API (runs on GPU)
    ("deepseek", "deepseek-reasoner", 5, 0.55, 2.19, 1.0),
    ("openai", "gpt-5", 3, 1.25, 10.0, 1.0),
    ("openai", "gpt-4o", 2, 2.5, 10.0, 1.0),
    ("anthropic", "claude-sonnet-4-6", 2, 3.0, 15.0, 1.0),
    ("anthropic", "claude-fable-5", 2, 10.0, 50.0, 1.0),  # tokenizer +30% shows in usage
]


def call_model(provider, model, prompt):
    """Return (text, in_tokens, out_tokens)."""
    if provider == "ollama":
        # Native Ollama API (host GPU via localhost). The OpenAI-compat /v1
        # endpoint hung on large prompts; the native /api/chat is reliable.
        import requests
        r = requests.post("http://localhost:11434/api/chat", json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"num_predict": 2048},
        }, timeout=300)
        d = r.json()
        return d["message"]["content"], d.get("prompt_eval_count", 0), d.get("eval_count", 0)
    if provider == "deepseek":
        import openai
        c = openai.OpenAI(base_url="https://api.deepseek.com",
                          api_key=os.environ["DEEPSEEK_API_KEY"], timeout=300)
        r = c.chat.completions.create(model=model, max_tokens=32768,
                                      messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content, r.usage.prompt_tokens, r.usage.completion_tokens
    if provider == "openai":
        import openai
        c = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"], timeout=300)
        if model.startswith("gpt-5"):
            r = c.chat.completions.create(model=model, max_completion_tokens=32768,
                                          reasoning_effort="low",
                                          messages=[{"role": "user", "content": prompt}])
        else:
            r = c.chat.completions.create(model=model, max_tokens=8192,
                                          messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content, r.usage.prompt_tokens, r.usage.completion_tokens
    if provider == "anthropic":
        import anthropic
        c = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], timeout=300)
        r = c.messages.create(model=model, max_tokens=8192,
                              messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        return text, r.usage.input_tokens, r.usage.output_tokens
    raise ValueError(provider)


def extract(text):
    m = re.search(r"\[.*\]", text or "", re.DOTALL)
    if not m:
        return []
    try:
        return json.loads(m.group(0))
    except Exception:
        return []


def detected_set(findings_by_contract):
    found = set()
    for name, vulns in GT_CORR.items():
        fs = findings_by_contract.get(name, [])
        for (ln, kws) in vulns:
            if matched(ln, kws, fs):
                found.add((name, ln))
    return found


def main():
    out = {}
    for provider, model, n_runs, ri, ro, _ in MODELS:
        run_sets, cost = [], 0.0
        for k in range(n_runs):
            fbc = {}
            for name in GT_CORR:
                code = (CORPUS / name).read_text()
                prompt = LEVER_PROMPT.format(name=name, code=code)
                for attempt in range(2):
                    try:
                        text, it, ot = call_model(provider, model, prompt)
                        break
                    except Exception as e:
                        print(f"    [{model} run{k} {name}] retry: {str(e)[:70]}")
                        time.sleep(3)
                else:
                    text, it, ot = "[]", 0, 0
                fbc[name] = extract(text)
                cost += it / 1e6 * ri + ot / 1e6 * ro
            ds = detected_set(fbc)
            run_sets.append(ds)
            print(f"  {model:20} run{k+1}/{n_runs}: {len(ds)}/{TOTAL} = {len(ds)/TOTAL:.0%}  (acum ${cost:.2f})")
        singles = [len(s) for s in run_sets]
        ens = set().union(*run_sets) if run_sets else set()
        out[model] = {
            "provider": provider, "n_runs": n_runs,
            "single_recalls": [round(s / TOTAL, 4) for s in singles],
            "single_mean": round(sum(singles) / len(singles) / TOTAL, 4),
            "single_min": round(min(singles) / TOTAL, 4),
            "single_max": round(max(singles) / TOTAL, 4),
            "ensemble_recall": round(len(ens) / TOTAL, 4),
            "ensemble_detected": len(ens),
            "total_cost_usd": round(cost, 4),
            "recall_per_dollar": round(len(ens) / TOTAL / cost, 3) if cost else None,
            "detected_vulns": sorted(map(list, ens)),
        }
        print(f"  >>> {model}: ensemble {len(ens)}/{TOTAL}={len(ens)/TOTAL:.1%} | cost ${cost:.2f} | "
              f"recall/$ {out[model]['recall_per_dollar']}")
    Path("benchmarks/results/detection_optimization_20260710/costeff_headtohead.json").write_text(
        json.dumps({"total_vulns": TOTAL, "corpus": "29-vuln corrected (27)", "models": out}, indent=2))
    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
