import json
from pathlib import Path

import benchmarks.generate_paper1_artifacts as paper1


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _provider_result(recall: float) -> dict:
    return {
        "audits_evaluated": 1,
        "total_vulns": 1,
        "total_detected": 1,
        "total_findings": 2,
        "recall": recall,
    }


def test_generate_paper1_claims_preserves_smartbugs_958_claim(monkeypatch, tmp_path: Path):
    results = tmp_path / "benchmarks" / "results"
    evmbench = results / "evmbench"
    smartbugs_latest = results / "paper1_smartbugs_eval_layers_1_6_7.json"
    evmbench_static = evmbench / "evmbench_static_40.json"
    provider_paths = {
        "claude_sonnet_4_6": evmbench / "evmbench_claude46_40_FINAL.json",
        "gpt_5": evmbench / "evmbench_gpt5_40.json",
        "gpt_4o": evmbench / "evmbench_gpt4o_40.json",
        "ollama_qwen2_5_coder_32b": evmbench / "evmbench_ollama_qwen32b_40_FINAL.json",
    }

    _write_json(
        smartbugs_latest,
        {
            "aggregate": {
                "contracts_evaluated": 143,
                "tp": 137,
                "fp": 481,
                "fn": 6,
                "precision": 0.2219,
                "recall": 0.958,
                "f1": 0.3604,
            }
        },
    )
    _write_json(evmbench_static, _provider_result(0.183))
    for path in provider_paths.values():
        _write_json(path, _provider_result(0.5))

    monkeypatch.setattr(paper1, "ROOT", tmp_path)
    monkeypatch.setattr(paper1, "RESULTS", results)
    monkeypatch.setattr(paper1, "EVMBENCH", evmbench)
    monkeypatch.setattr(paper1, "SMARTBUGS_LATEST", smartbugs_latest)
    monkeypatch.setattr(paper1, "EVMBENCH_STATIC", evmbench_static)
    monkeypatch.setattr(paper1, "PROVIDERS", provider_paths)

    ensemble = {
        "provider_summary": {
            provider: {"recall": 0.5, "source": str(path.relative_to(tmp_path))}
            for provider, path in provider_paths.items()
        },
        "audits_evaluated": 40,
        "total_vulns": 120,
        "total_detected": 111,
        "recall": 0.925,
        "missed": 9,
        "detected_by_provider_count": {"1": 13, "2": 16, "3": 23, "4": 59},
    }

    matrix = paper1.generate_claims_matrix(ensemble)
    claims = {claim["claim_id"]: claim for claim in matrix["claims"]}

    assert matrix["generated_at"] == "1970-01-01T00:00:00+00:00"
    latest = claims["smartbugs_latest_reproducible"]
    assert "95.8%" in latest["paper_claim"]
    assert "93.7%" not in latest["paper_claim"]
    assert latest["value"]["recall"] == 0.958
    assert latest["value"]["precision"] == 0.2219
    assert latest["value"]["f1"] == 0.3604
    assert latest["value"]["layers_evaluated"] == [1, 6, 7]

    followup = claims["smartbugs_local_ollama_followup"]
    assert followup["value"]["recall"] == 0.979
    assert followup["status"] == "supported_with_note"
