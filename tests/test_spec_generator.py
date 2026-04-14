"""Tests for src.formal.spec_generator — auto spec generation from findings."""


import pytest

from src.formal import GeneratedSpec, SpecFormat, SpecGenerator


@pytest.fixture
def gen():
    return SpecGenerator()


@pytest.fixture
def reentrancy_finding():
    return {
        "id": "F1",
        "type": "reentrancy-eth",
        "location": {"function": "withdraw"},
        "severity": "high",
    }


@pytest.fixture
def access_control_finding():
    return {
        "id": "F2",
        "type": "selfdestruct-identifier",
        "location": {"function": "kill"},
        "severity": "critical",
    }


class TestSpecFormat:
    def test_enum_values(self):
        assert SpecFormat.CVL.value == "cvl"
        assert SpecFormat.SCRIBBLE.value == "scribble"
        assert SpecFormat.SMTCHECKER.value == "smtchecker"

    def test_from_string(self):
        assert SpecFormat("cvl") == SpecFormat.CVL
        assert SpecFormat("scribble") == SpecFormat.SCRIBBLE


class TestGeneratedSpec:
    def test_to_dict(self):
        spec = GeneratedSpec(
            finding_id="F1",
            finding_type="reentrancy",
            format=SpecFormat.CVL,
            spec_code="rule noReentrancy() { assert true; }",
            description="Test",
        )
        d = spec.to_dict()
        assert d["format"] == "cvl"
        assert d["finding_id"] == "F1"
        assert "spec_code" in d


class TestSpecGenerator:
    def test_generate_reentrancy_cvl(self, gen, reentrancy_finding):
        spec = gen.generate(reentrancy_finding, format=SpecFormat.CVL)
        assert spec is not None
        assert spec.format == SpecFormat.CVL
        assert "noReentrancy_withdraw" in spec.spec_code
        assert "Reentrancy detected" in spec.spec_code

    def test_generate_access_control_cvl(self, gen, access_control_finding):
        spec = gen.generate(access_control_finding, format=SpecFormat.CVL)
        assert spec is not None
        assert "onlyOwnerCanCall_kill" in spec.spec_code
        assert "Unauthorized" in spec.spec_code

    def test_generate_overflow_cvl(self, gen):
        finding = {"id": "F3", "type": "integer-overflow", "location": {"function": "mint"}}
        spec = gen.generate(finding)
        assert spec is not None
        assert "noOverflow_mint" in spec.spec_code
        assert "totalSupply" in spec.spec_code

    def test_generate_scribble(self, gen, reentrancy_finding):
        spec = gen.generate(reentrancy_finding, format=SpecFormat.SCRIBBLE)
        assert spec is not None
        assert spec.format == SpecFormat.SCRIBBLE
        assert "#if_succeeds" in spec.spec_code

    def test_generate_smtchecker(self, gen):
        finding = {"id": "F4", "type": "overflow"}
        spec = gen.generate(finding, format=SpecFormat.SMTCHECKER)
        assert spec is not None
        assert "assert" in spec.spec_code

    def test_unknown_type_returns_none(self, gen):
        finding = {"id": "F5", "type": "unknown-xyz-123"}
        spec = gen.generate(finding)
        assert spec is None

    def test_generate_batch(self, gen, reentrancy_finding, access_control_finding):
        findings = [reentrancy_finding, access_control_finding]
        specs = gen.generate_batch(findings)
        assert len(specs) == 2
        assert all(isinstance(s, GeneratedSpec) for s in specs)

    def test_batch_filters_unknown_types(self, gen, reentrancy_finding):
        findings = [reentrancy_finding, {"id": "X", "type": "unknown-type"}]
        specs = gen.generate_batch(findings)
        assert len(specs) == 1  # unknown filtered out

    def test_function_extraction_from_message(self, gen):
        finding = {
            "id": "F6",
            "type": "reentrancy",
            "message": "Reentrancy in function withdraw",
        }
        spec = gen.generate(finding)
        assert spec is not None
        assert "withdraw" in spec.spec_code

    def test_generate_spec_file_cvl(self, gen, tmp_path, reentrancy_finding):
        output = tmp_path / "out.spec"
        count = gen.generate_spec_file(
            [reentrancy_finding], output, contract_name="TestC"
        )
        assert count == 1
        assert output.exists()
        content = output.read_text()
        assert "TestC" in content
        assert "methods {" in content
        assert "noReentrancy_withdraw" in content

    def test_generate_spec_file_scribble(self, gen, tmp_path, reentrancy_finding):
        output = tmp_path / "annotations.sol"
        count = gen.generate_spec_file(
            [reentrancy_finding], output, format=SpecFormat.SCRIBBLE
        )
        assert count == 1
        assert "#if_succeeds" in output.read_text()

    def test_type_normalization(self, gen):
        # Different vendor names should map to same canonical type
        f1 = {"id": "A", "type": "reentrancy-eth", "location": {"function": "f"}}
        f2 = {"id": "B", "type": "reentrant", "location": {"function": "f"}}
        f3 = {"id": "C", "type": "Reentrancy", "location": {"function": "f"}}
        s1 = gen.generate(f1)
        s2 = gen.generate(f2)
        s3 = gen.generate(f3)
        assert s1 and s2 and s3
        assert s1.finding_type == s2.finding_type == s3.finding_type == "reentrancy"

    def test_access_control_variants(self, gen):
        """Various access-control finding types should all generate specs."""
        for vuln_type in [
            "access-control",
            "selfdestruct-identifier",
            "suicidal",
            "unprotected-initializer",
            "tx-origin",
        ]:
            finding = {"id": "X", "type": vuln_type, "location": {"function": "admin"}}
            spec = gen.generate(finding)
            assert spec is not None, f"Failed for type: {vuln_type}"
            assert spec.finding_type == "access-control"

    def test_confidence_in_range(self, gen, reentrancy_finding):
        spec = gen.generate(reentrancy_finding)
        assert spec is not None
        assert 0.0 <= spec.confidence <= 1.0

    def test_references_populated(self, gen, reentrancy_finding):
        spec = gen.generate(reentrancy_finding, format=SpecFormat.CVL)
        assert spec is not None
        assert any("certora" in r.lower() for r in spec.references)
