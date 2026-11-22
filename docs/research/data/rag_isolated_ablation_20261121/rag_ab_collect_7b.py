"""Isolated EmbeddingRAG A/B — 7B follow-up (off-ceiling test). COLLECTION only.

Same harness as the 32B run (rag_ab_collect.py), weaker backend. Hypothesis:
a 7B model that does NOT encode the canonical vuln patterns internally is the
regime where semantic retrieval can actually contribute recall — unlike the 32B,
which sat at ceiling. Everything else identical: same corpus, same toggle, same
scorer, same pairing, 3 runs/arm, cache off, atomic per-contract checkpoint.
"""

import json
import os
import sys
import time
from pathlib import Path

REPO = Path(os.environ.get("MIESC_REPO", Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(REPO))

MODEL = "qwen2.5-coder:7b"
os.environ["MIESC_LLM_MODEL"] = MODEL
os.environ["MIESC_DISABLE_LLM_CACHE"] = "1"  # fresh model call every time

RUNS = 3
TIMEOUT = 180  # ceiling; 7B finishes faster, a slow call is still not a false miss
CATEGORIES = ["reentrancy", "access_control", "arithmetic"]
DATASET = REPO / "benchmarks/datasets/smartbugs-curated/dataset"
OUT = Path(__file__).parent / "rag_ab_raw_7b_20261121.json"

META = {
    "experiment": "isolated EmbeddingRAG A/B (mechanism 1) — 7B off-ceiling follow-up",
    "git_sha": "deea9b7d",  # main post-#372; toggle harness unchanged since #370
    "model": MODEL,
    "model_digest": "dae161e27b0e",
    "kb_version": "2026-11-15-chain-provenance-v5",
    "embedding_model": "all-MiniLM-L6-v2 (EmbeddingRAG default)",
    "adapter": "smartllm",
    "arms": {"on": "RAG on (default)", "off": "MIESC_DISABLE_RAG=1"},
    "runs_per_arm": RUNS,
    "timeout_s": TIMEOUT,
    "cache_disabled": True,
    "categories": CATEGORIES,
    "dataset": "SmartBugs-curated",
    "scorer": "category-level (classify_finding); contract is a hit if its true "
    "category is among detected categories",
    "note": "Companion to the 32B run (rag_ab_raw_20261121.json). Inline "
    "@vulnerable_at_lines annotations are present in both arms and cancel in the "
    "on-vs-off delta. The comparison of interest is delta_7B vs delta_32B.",
    "companion_32b": "rag_ab_raw_20261121.json",
}


def build_corpus():
    corpus = []
    for cat in CATEGORIES:
        for sol in sorted((DATASET / cat).glob("*.sol")):
            corpus.append((str(sol), cat))
    return corpus


def main():
    from benchmarks.reproduce_benchmark import classify_finding
    from miesc.adapters.smartllm_adapter import SmartLLMAdapter

    adapter = SmartLLMAdapter()
    adapter._model = MODEL

    hit_counter = {"n": 0}
    if adapter._embedding_rag is not None:
        _orig_search = adapter._embedding_rag.search

        def counting_search(*a, **k):
            res = _orig_search(*a, **k)
            try:
                hit_counter["n"] += len(res)
            except Exception:
                pass
            return res

        adapter._embedding_rag.search = counting_search

    corpus = build_corpus()
    if os.environ.get("RAG_AB_SMOKE") == "1":
        corpus = corpus[:1]
        globals()["RUNS"] = 1
    META["total_contracts"] = len(corpus)
    META["started"] = time.strftime("%Y-%m-%d %H:%M:%S")
    results = []
    t_start = time.time()

    def checkpoint():
        payload = {"meta": META, "results": results}
        tmp = OUT.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(OUT)

    def one_call(path, true_cat, run, arm):
        if arm == "off":
            os.environ["MIESC_DISABLE_RAG"] = "1"
        else:
            os.environ.pop("MIESC_DISABLE_RAG", None)
        hit_counter["n"] = 0
        t0 = time.time()
        try:
            res = adapter.analyze(path, timeout=TIMEOUT)
            dt = time.time() - t0
            md = res.get("metadata", {}) or {}
            findings = res.get("findings", []) or []
            detected = sorted({classify_finding(f) for f in findings})
            return {
                "contract": path,
                "true_category": true_cat,
                "run": run,
                "arm": arm,
                "status": res.get("status"),
                "from_cache": res.get("from_cache"),
                "model": md.get("model"),
                "rag_enhanced": md.get("rag_enhanced"),
                "rag_hits": hit_counter["n"],
                "n_findings": len(findings),
                "detected_categories": detected,
                "hit": true_cat in detected,
                "time_s": round(dt, 1),
            }
        except Exception as e:
            return {
                "contract": path,
                "true_category": true_cat,
                "run": run,
                "arm": arm,
                "status": "exception",
                "error": repr(e),
                "time_s": round(time.time() - t0, 1),
            }

    total = len(corpus)
    for i, (path, true_cat) in enumerate(corpus, 1):
        name = Path(path).name
        for run in range(1, RUNS + 1):
            for arm in ("on", "off"):
                r = one_call(path, true_cat, run, arm)
                results.append(r)
                print(
                    f"[{i}/{total} {true_cat}/{name}] run{run} {arm}: "
                    f"status={r.get('status')} rag={r.get('rag_enhanced')} "
                    f"hits={r.get('rag_hits')} hit={r.get('hit')} {r.get('time_s')}s",
                    flush=True,
                )
        checkpoint()
        elapsed = time.time() - t_start
        print(
            f"  -- checkpoint {i}/{total} | elapsed {elapsed/60:.1f}min | "
            f"eta {elapsed/i*(total-i)/60:.0f}min left",
            flush=True,
        )

    META["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    META["elapsed_min"] = round((time.time() - t_start) / 60, 1)
    checkpoint()
    print(f"\nDONE. {len(results)} calls in {META['elapsed_min']}min -> {OUT}")


if __name__ == "__main__":
    main()
