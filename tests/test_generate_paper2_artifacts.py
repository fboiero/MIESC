import json
from pathlib import Path

import benchmarks.generate_paper2_artifacts as paper2


def test_generate_paper2_artifacts_preserves_claim_schema(monkeypatch, tmp_path: Path, capsys):
    results_dir = tmp_path / "benchmarks" / "results"
    results_dir.mkdir(parents=True)
    fix_eval = results_dir / "fix_eval_results.json"
    claims = results_dir / "paper2_claims_matrix.json"
    transforms = results_dir / "paper2_patch_quality_by_transform.json"
    compile_failures = results_dir / "paper2_compile_failure_by_category.json"

    fix_eval.write_text(
        json.dumps(
            {
                "totals": {
                    "contracts": 2,
                    "fix_applied": 2,
                    "fix_compiles": 1,
                    "vuln_eliminated": 1,
                    "no_regression": 1,
                    "fix_failed": 0,
                },
                "by_category": {
                    "reentrancy": {
                        "contracts": 1,
                        "fix_applied": 1,
                        "fix_compiles": 1,
                        "vuln_eliminated": 1,
                        "no_regression": 1,
                        "fix_failed": 0,
                    },
                    "unchecked_low_level_calls": {
                        "contracts": 1,
                        "fix_applied": 1,
                        "fix_compiles": 0,
                        "vuln_eliminated": 0,
                        "no_regression": 0,
                        "fix_failed": 0,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(paper2, "ROOT", tmp_path)
    monkeypatch.setattr(paper2, "FIX_EVAL", fix_eval)
    monkeypatch.setattr(paper2, "OUT", claims)
    monkeypatch.setattr(paper2, "PATCH_TRANSFORMS_OUT", transforms)
    monkeypatch.setattr(paper2, "COMPILE_FAILURES_OUT", compile_failures)
    monkeypatch.setattr(paper2, "COMPILE_TAXONOMY", results_dir / "missing_taxonomy.json")
    monkeypatch.setattr(paper2, "EXPERIMENT_AUDIT", results_dir / "missing_audit.json")

    paper2.main()

    generated_claims = json.loads(claims.read_text(encoding="utf-8"))
    claim_ids = {claim["claim_id"] for claim in generated_claims["claims"]}

    assert generated_claims["artifact"] == "paper2_claims_matrix"
    assert "fix_application_rate" in claim_ids
    assert "paper1_detection_input" in claim_ids
    assert "no_semantic_equivalence_claim" in claim_ids
    assert generated_claims["paper1_compatibility_rule"].startswith("Paper 2 may inherit")

    generated_transforms = json.loads(transforms.read_text(encoding="utf-8"))
    assert set(generated_transforms["transforms"]) == {
        "reentrancy_guard_injection",
        "require_success_wrapper",
    }

    generated_compile_failures = json.loads(compile_failures.read_text(encoding="utf-8"))
    assert generated_compile_failures["totals"]["compile_failures"] == 1

    output = capsys.readouterr().out
    assert "Paper 2 fix claims: 2/2 applied, 1/2 compiled, 1/2 eliminated" in output
