"""Tests for CardanoAdapter global pattern checks, language detection, and
the Plutus/Aiken vulnerability detectors (pure logic, no Cardano tooling)."""

from __future__ import annotations

from pathlib import Path

from src.adapters.cardano_adapter import (
    CardanoAnalyzer,
    CardanoContract,
    CardanoPatternDetector,
)


def _empty_contract(language="plutus"):
    return CardanoContract(
        name="C",
        language=language,
        validators=[],
        minting_policies=[],
        data_types=[],
        imports=[],
        metadata={},
    )


class TestGlobalPatterns:
    def test_unbounded_and_missing_context(self):
        out = CardanoPatternDetector._check_global_patterns("foldr f (all inputs)")
        types = {f["type"] for f in out}
        assert "unbounded_computation" in types
        assert "missing_context_check" in types

    def test_script_context_present_no_missing(self):
        out = CardanoPatternDetector._check_global_patterns("module F where\nf = ScriptContext")
        assert out == []

    def test_missing_context_only(self):
        out = CardanoPatternDetector._check_global_patterns("module F where\nf = 1")
        assert {f["type"] for f in out} == {"missing_context_check"}


class TestLanguageDetection:
    def test_by_extension(self):
        a = CardanoAnalyzer()
        assert a._detect_language(Path("x.ak"), "") == "aiken"
        assert a._detect_language(Path("x.hs"), "") == "plutus"

    def test_by_content(self):
        a = CardanoAnalyzer()
        assert a._detect_language(Path("x.txt"), "use aiken/foo") == "aiken"
        assert a._detect_language(Path("x.txt"), "module Foo where") == "plutus"

    def test_default_is_plutus(self):
        a = CardanoAnalyzer()
        assert a._detect_language(Path("x.txt"), "nothing recognizable") == "plutus"


class TestDetectors:
    def test_plutus_detector_includes_global(self):
        d = CardanoPatternDetector()
        out = d.detect_plutus_vulnerabilities(_empty_contract("plutus"), "foldr f (all inputs)")
        assert any(f["type"] == "unbounded_computation" for f in out)

    def test_aiken_detector_runs(self):
        d = CardanoPatternDetector()
        out = d.detect_aiken_vulnerabilities(_empty_contract("aiken"), "foldr f (all inputs)")
        assert isinstance(out, list)  # validator loop + checks execute without error
