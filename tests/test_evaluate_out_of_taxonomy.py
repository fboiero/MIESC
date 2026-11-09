"""The benchmark scorer must not read a finding's remediation text as its diagnosis.

``_normalize_category`` falls back to keyword matching on title/description when
the type is unknown. Two MIESC finding kinds that are not SmartBugs-curated
categories used to be coerced into one through that fallback:

- the ``hardcoded_gas`` gap-filler (SWC-134) says "use call{value:}() with
  reentrancy guard" and scored as ``reentrancy`` (36 FP / 0 TP on the corpus);
- the DeFi adapter's ``mev_exposure`` rule ("Public withdrawal - can be
  front-run") ships ``category`` but no ``type`` and scored as ``front_running``
  (14 FP / 0 TP).

A third quirk: an empty type is a substring of every alias, so a finding with
neither ``type`` nor ``title`` was classified as the first category in the table.
"""

from pathlib import Path
from unittest.mock import patch

from miesc.cli.commands.evaluate import (
    OUT_OF_TAXONOMY_TYPES,
    _evaluate_contract,
    _normalize_category,
)
from miesc.core.intelligence import ZERO_RECALL_PATTERNS

HARDCODED_GAS_MESSAGE = ZERO_RECALL_PATTERNS["hardcoded_gas"]["message"]
MEV_DESCRIPTION = "Public withdrawal - can be front-run. Found at line 12."


class TestOutOfTaxonomyTypes:
    def test_hardcoded_gas_is_not_reentrancy(self):
        assert "reentrancy guard" in HARDCODED_GAS_MESSAGE  # the text that misled the fallback
        assert _normalize_category("hardcoded_gas", description=HARDCODED_GAS_MESSAGE) is None

    def test_defi_mev_exposure_is_not_front_running(self):
        # The DeFi adapter sets ``category`` and a title, no ``type``; evaluate
        # passes the title as the type.
        assert (
            _normalize_category(
                "MEV Exposure Detected",
                title="MEV Exposure Detected",
                description=MEV_DESCRIPTION,
                category="mev_exposure",
            )
            is None
        )

    def test_out_of_taxonomy_type_wins_over_keywords(self):
        for kind in sorted(OUT_OF_TAXONOMY_TYPES):
            assert _normalize_category(kind, description="classic reentrancy attack") is None
            assert _normalize_category("", category=kind, description="front-run") is None

    def test_real_transaction_order_dependence_still_maps(self):
        # mev_detector's balance-dependent require IS SWC-114; keep it.
        assert (
            _normalize_category(
                "mev_vulnerability",
                description="Logic depends on contract balance (transaction order dependent)",
            )
            == "front_running"
        )

    def test_keyword_fallback_unchanged_for_unknown_types(self):
        assert (
            _normalize_category("SWC-107", description="A classic reentrancy attack vector")
            == "reentrancy"
        )
        assert _normalize_category("reentrancy-eth", category="whatever") == "reentrancy"


class TestEmptyType:
    def test_empty_type_without_text_is_unclassified(self):
        assert _normalize_category("") is None
        assert _normalize_category("", title="", description="") is None

    def test_empty_type_still_uses_title_keywords(self):
        assert _normalize_category("", title="Reentrancy in withdraw()") == "reentrancy"
        assert _normalize_category("", description="integer overflow in add") == "arithmetic"


def _fake_run_layer(findings):
    def run_layer(layer_num, contract_path, timeout, exclude_tools=None):
        return [{"tool": "defi", "status": "success", "findings": list(findings)}]

    return run_layer


class TestEvaluateContractScoring:
    def _evaluate(self, tmp_path: Path, findings, source: str):
        contract = tmp_path / "x.sol"
        contract.write_text(source, encoding="utf-8")
        with patch("miesc.cli.commands.evaluate.run_layer", side_effect=_fake_run_layer(findings)):
            return _evaluate_contract(
                contract,
                {"access_control"},
                layers=[7],
                timeout=5,
                skip_unavailable=True,
                use_intelligence=False,
            )

    def test_defi_mev_finding_does_not_score_front_running(self, tmp_path: Path):
        mev = {
            "title": "MEV Exposure Detected",
            "description": MEV_DESCRIPTION,
            "category": "mev_exposure",
            "severity": "High",
        }
        result = self._evaluate(tmp_path, [mev], "pragma solidity ^0.4.24;\ncontract A {}\n")
        assert "front_running" not in result["aggregate"]["detected_categories"]
        assert result["match"]["fp"] == []

    def test_typeless_titleless_finding_does_not_score_reentrancy(self, tmp_path: Path):
        blank = {"description": "", "severity": "Low"}
        result = self._evaluate(tmp_path, [blank], "pragma solidity ^0.4.24;\ncontract A {}\n")
        assert result["aggregate"]["detected_categories"] == []
