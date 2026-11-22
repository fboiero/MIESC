"""Decisive probe: is the 7B access_control +50pp genuine DETECTION or a scorer
artifact? For the 11 discordant access_control contracts, both arms, capture the
actual finding TITLES (pre- and post-verificator) and the retrieved KB hits, so a
human can read whether OFF names the real access-control bug or genuinely misses it,
and whether ON substantively identifies it or only echoes the KB label.
"""

import json
import os
import sys
from pathlib import Path

REPO = Path(os.environ.get("MIESC_REPO", Path(__file__).resolve().parents[4]))
sys.path.insert(0, str(REPO))
os.environ["MIESC_LLM_MODEL"] = "qwen2.5-coder:7b"
os.environ["MIESC_DISABLE_LLM_CACHE"] = "1"

AC = REPO / "benchmarks/datasets/smartbugs-curated/dataset/access_control"
CONTRACTS = [
    "incorrect_constructor_name3.sol", "mapping_write.sol", "multiowned_vulnerable.sol",
    "parity_wallet_bug_2.sol", "phishable.sol", "proxy.sol", "rubixi.sol",
    "unprotected0.sol", "wallet_02_refund_nosub.sol", "wallet_04_confused_sign.sol",
    "simple_suicide.sol",  # the lone OFF-only win, for symmetry
]
OUT = Path(__file__).parent / "rag_ab_probe_7b_20261122.json"


def short(f):
    return {
        "title": str(f.get("title", ""))[:140],
        "swc": f.get("swc_id") or f.get("swc") or (f.get("metadata", {}) or {}).get("swc_id"),
        "severity": f.get("severity"),
        "desc": str(f.get("description", ""))[:200],
    }


def main():
    from miesc.adapters.smartllm_adapter import SmartLLMAdapter

    adapter = SmartLLMAdapter()
    adapter._model = "qwen2.5-coder:7b"

    cap = {"hits": [], "pre": None}
    if adapter._embedding_rag is not None:
        _os = adapter._embedding_rag.search

        def csearch(*a, **k):
            res = _os(*a, **k)
            for h in (res or []):
                try:
                    cap["hits"].append({
                        "title": str(getattr(h, "title", None) or (isinstance(h, dict) and h.get("title")) or "")[:120],
                        "id": str(getattr(h, "id", None) or getattr(h, "source", None) or (isinstance(h, dict) and (h.get("id") or h.get("source"))) or "")[:80],
                    })
                except Exception:
                    pass
            return res
        adapter._embedding_rag.search = csearch

    _ov = adapter._verificator_stage

    def cver(code, initial):
        cap["pre"] = [short(f) for f in (initial or [])]
        return _ov(code, initial)
    adapter._verificator_stage = cver

    out = []
    for name in CONTRACTS:
        path = str(AC / name)
        row = {"contract": name}
        for arm in ("on", "off"):
            if arm == "off":
                os.environ["MIESC_DISABLE_RAG"] = "1"
            else:
                os.environ.pop("MIESC_DISABLE_RAG", None)
            cap["hits"], cap["pre"] = [], None
            res = adapter.analyze(path, timeout=180)
            post = [short(f) for f in (res.get("findings") or [])]
            row[arm] = {
                "status": res.get("status"),
                "rag_enhanced": (res.get("metadata") or {}).get("rag_enhanced"),
                "retrieved_hits": cap["hits"],
                "pre_verificator": cap["pre"],
                "post_verificator": post,
            }
        out.append(row)
        print(f"[done] {name}", flush=True)
        OUT.write_text(json.dumps(out, indent=2))
    print(f"\nWROTE {OUT}")


if __name__ == "__main__":
    main()
