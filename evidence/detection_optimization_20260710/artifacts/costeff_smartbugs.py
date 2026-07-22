"""Cost-efficiency at SmartBugs scale (n=143 contracts) for tight CIs.

Per-contract type-aware recall: a contract counts as detected if the model
reports a finding whose normalized type matches the contract's ground-truth
category (its SmartBugs directory). Reuses call_model (multi-provider, real
cost capture) and the harness category normalizer. Time-aware run counts (large
n reduces single-run variance, so fewer runs suffice). Additive dated artifact.
"""
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "benchmarks/results/detection_optimization_20260710")
from concurrent.futures import ThreadPoolExecutor, as_completed
from costeff_measure import robust_call  # retrying multi-provider router
from miesc.cli.commands.evaluate import _normalize_category

DATASET = Path("benchmarks/datasets/smartbugs-curated/dataset")

# (provider, model, n_runs, rate_in $/MTok, rate_out $/MTok)
PER_CAT = int(os.environ.get("PER_CAT", "4"))  # stratified subset per category

MODELS = [
    ("ollama", "qwen3-coder:30b", 2, 0.0, 0.0),
    ("deepseek", "deepseek-reasoner", 1, 0.55, 2.19),
    ("anthropic", "claude-sonnet-4-6", 2, 3.0, 15.0),
    ("openai", "gpt-5", 1, 1.25, 10.0),
    ("openai", "gpt-4o", 1, 2.5, 10.0),
]

PROMPT = (
    "You are a smart-contract security auditor performing a DEFENSIVE review to help "
    "developers fix weaknesses before deployment. Report every security weakness. "
    "Respond ONLY with a JSON array; each item: {{\"line\": <int>, \"type\": \"<short "
    "type>\", \"swc\": \"<SWC-id or ''>\", \"severity\": \"<critical|high|medium|low>\"}}."
    "\n\nContract {name}:\n```solidity\n{code}\n```"
)

CATS = ["access_control", "arithmetic", "bad_randomness", "denial_of_service",
        "front_running", "other", "reentrancy", "short_addresses",
        "time_manipulation", "unchecked_low_level_calls"]


def load_corpus():
    items = []  # (path, category)
    for cat in CATS:
        sols = sorted((DATASET / cat).glob("*.sol"))
        items.extend((sol, cat) for sol in sols[:PER_CAT])  # stratified subset
    return items


def extract(text):
    m = re.search(r"\[.*\]", text or "", re.DOTALL)
    if not m:
        return []
    try:
        return json.loads(m.group(0))
    except Exception:
        return []


def detected_category(findings, gt_cat):
    for f in findings:
        c = _normalize_category(str(f.get("type", "")), str(f.get("type", "")),
                                str(f.get("swc", "")))
        if c == gt_cat:
            return True
    return False


def main():
    corpus = load_corpus()
    n = len(corpus)
    print(f"Corpus: {n} contracts across {len(CATS)} categories")
    def work(provider, model, sol, cat):
        """One contract -> (name, detected_bool, in_tok, out_tok, refused_bool)."""
        code = sol.read_text(errors="ignore")
        text, it, ot = robust_call(provider, model, PROMPT.format(name=sol.name, code=code[:12000]))
        refused = (text is not None and text.strip() == "" and ot <= 5)
        det = (text is not None) and detected_category(extract(text), cat)
        return sol.name, det, it, ot, refused

    out = {}
    for provider, model, n_runs, ri, ro in MODELS:
        conc = 1 if provider == "ollama" else 4  # local GPU serial; APIs concurrent
        run_hits, cost, refused = [], 0.0, 0
        for k in range(n_runs):
            hits, done = set(), 0
            with ThreadPoolExecutor(max_workers=conc) as ex:
                futs = [ex.submit(work, provider, model, sol, cat) for sol, cat in corpus]
                for fut in as_completed(futs):
                    name, det, it, ot, ref = fut.result()
                    cost += it / 1e6 * ri + ot / 1e6 * ro
                    if det:
                        hits.add(name)
                    if ref:
                        refused += 1
                    done += 1
                    if done % 20 == 0:
                        print(f"  {model} run{k+1}/{n_runs}: {done}/{n} done, {len(hits)} hits, ${cost:.2f}", flush=True)
            run_hits.append(hits)
            print(f"  {model} run{k+1}/{n_runs}: {len(hits)}/{n} = {len(hits)/n:.1%}  (${cost:.2f})", flush=True)
        ens = set().union(*run_hits) if run_hits else set()
        out[model] = {
            "provider": provider, "n_runs": n_runs, "n_contracts": n,
            "single_recalls": [round(len(h) / n, 4) for h in run_hits],
            "ensemble_hits": len(ens), "ensemble_recall": round(len(ens) / n, 4),
            "total_cost_usd": round(cost, 4),
            "recall_per_dollar": round(len(ens) / n / cost, 3) if cost else None,
            "refusals": refused,
        }
        print(f"  >>> {model}: ensemble {len(ens)}/{n}={len(ens)/n:.1%} | ${cost:.2f} | "
              f"refusals={refused}", flush=True)
        Path("benchmarks/results/detection_optimization_20260710/costeff_smartbugs.json").write_text(
            json.dumps({"n_contracts": n, "models": out}, indent=2))
    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
