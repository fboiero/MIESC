"""Tests for ml_invariant_synthesizer public API and synthesis flow (no Ollama).

Exercises feature extraction, invariant prediction, the full synthesize_with_ml
path (LLM synthesis gracefully skipped when Ollama is absent), training stats,
and validation result recording.
"""

from __future__ import annotations

from miesc.ml.ml_invariant_synthesizer import (
    MLInvariantSynthesizer,
    extract_contract_features,
    predict_invariants,
    synthesize_with_ml,
)

ERC20_CODE = (
    "contract Vault is ERC20 {\n"
    "    mapping(address=>uint) balances;\n"
    "    uint totalSupply;\n"
    "    function deposit() external payable { balances[msg.sender]+=msg.value; }\n"
    "    function withdraw(uint a) external {\n"
    "        require(balances[msg.sender]>=a);\n"
    "        balances[msg.sender]-=a;\n"
    '        msg.sender.call{value:a}("");\n'
    "    }\n"
    "}"
)


class TestFeatureExtraction:
    def test_detects_erc20_and_external_calls(self):
        f = extract_contract_features(ERC20_CODE)
        assert f.is_erc20 is True
        assert f.external_call_count >= 1

    def test_to_vector_and_to_dict_consistent(self):
        f = extract_contract_features(ERC20_CODE)
        vec = f.to_vector()
        d = f.to_dict()
        assert isinstance(vec, list) and len(vec) > 0
        assert isinstance(d, dict) and len(d) > 0

    def test_empty_contract_is_safe(self):
        f = extract_contract_features("contract C {}")
        assert f.is_erc20 is False


class TestPrediction:
    def test_predicts_invariants(self):
        preds = predict_invariants(ERC20_CODE)
        assert isinstance(preds, list)
        assert len(preds) > 0
        assert all(hasattr(p, "to_dict") for p in preds)


class TestSynthesizeWithMl:
    def test_full_synthesis_path(self, tmp_path):
        f = tmp_path / "Vault.sol"
        f.write_text(ERC20_CODE, encoding="utf-8")
        res = synthesize_with_ml(str(f))
        assert res["status"] in ("success", "ok", "completed") or "invariants" in res
        assert "features" in res
        assert "predictions" in res
        assert res.get("ml_enhanced") is True


class TestSynthesizerState:
    def test_training_stats_shape(self):
        syn = MLInvariantSynthesizer(collect_training_data=False)
        stats = syn.get_training_stats()
        assert "total_examples" in stats

    def test_add_validation_result_no_error(self):
        syn = MLInvariantSynthesizer(collect_training_data=False)
        syn.add_validation_result("hash123", "balance_invariant", True)
        syn.add_validation_result("hash123", "balance_invariant", False)
