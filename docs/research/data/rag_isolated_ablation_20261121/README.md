# Isolated EmbeddingRAG ablation — raw data & scripts

Reproducibility bundle for the two research notes:

- `docs/research/RAG_ISOLATED_ABLATION_20261121.md` (32B)
- `docs/research/RAG_ISOLATED_ABLATION_7B_FOLLOWUP_20261122.md` (7B follow-up + cross-model comparison)

## Files

| File | What |
|---|---|
| `rag_ab_collect.py` | Collection driver, 32B (`qwen2.5-coder:32b`). |
| `rag_ab_collect_7b.py` | Same harness, 7B (`qwen2.5-coder:7b`). |
| `rag_ab_compare.py` | Loads both raw datasets, prints the paired analysis (Wilson CIs, McNemar, spray, flip rate) side by side. |
| `rag_ab_probe_7b.py` | Instrumented probe: for the 11 discordant access_control contracts, dumps pre/post-verificator finding titles + retrieved hits in both arms (the detection-vs-attribution check). |
| `rag_ab_raw_20261121.json` | 32B raw: 384 calls (64×3×2). |
| `rag_ab_raw_7b_20261121.json` | 7B raw: 384 calls. |
| `rag_ab_compare_20261122.json` | Machine-readable comparison output. |
| `rag_ab_probe_7b_20261122.json` | Probe output (finding titles per arm). |

Contract paths in the raw JSON are repo-relative (`benchmarks/datasets/...`).

## Reproduce

Requires a local Ollama with the two models pulled, and the optional RAG deps
(`chromadb`, `sentence-transformers`). From the repo root:

```bash
export MIESC_REPO="$(pwd)"
python docs/research/data/rag_isolated_ablation_20261121/rag_ab_collect.py      # 32B (~14h)
python docs/research/data/rag_isolated_ablation_20261121/rag_ab_collect_7b.py   # 7B  (~3h)
python docs/research/data/rag_isolated_ablation_20261121/rag_ab_compare.py      # analysis
```

Determinism caveat: within a single process the 3 runs are identical replicates
(0 flips). Across process restarts there is minor run-to-run variability (see the
7B note), so an exact re-run may differ on one or two borderline contracts.

## Provenance

- SHA `deea9b7d` (main post-#372); toggle harness unchanged since #370.
- Models: `qwen2.5-coder:32b` (`b92d6a0bd47e`), `qwen2.5-coder:7b` (`dae161e27b0e`).
- Embedding: `all-MiniLM-L6-v2`. KB: `2026-11-15-chain-provenance-v5`.
- Corpus: SmartBugs-curated (reentrancy / access_control / arithmetic).
