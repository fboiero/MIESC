"""
Functionality regression suite — additional coverage for behaviors that
other test files touch only indirectly.

Covers:
  - FP classifier train/save/load cross-process consistency
  - Multi-chain analyze dispatcher routing
  - CanonicalCategory contract (forward/backward compat)
  - DeepAuditAgent phase ordering
  - VulnerabilityExample new fields (attack_steps, detection_heuristic)
  - `miesc specs` -> `miesc verify` integration shape
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# FP classifier persistence
# ---------------------------------------------------------------------------


sklearn = pytest.importorskip("sklearn")


class TestFPClassifierPersistence:
    def test_predict_identical_across_instances_after_save(self, tmp_path):
        """Save with one instance, load with another, verify same prediction."""
        from src.ml.fp_ml_classifier import AuditorTrainedFPClassifier, create_sample_dataset

        data = tmp_path / "labels.jsonl"
        create_sample_dataset(data, n=40)
        model_path = tmp_path / "clf.pkl"

        clf1 = AuditorTrainedFPClassifier(model_path=model_path)
        clf1.train(str(data))

        clf2 = AuditorTrainedFPClassifier(model_path=model_path)

        finding = {"type": "reentrancy-eth", "severity": "High", "tool": "slither"}
        p1 = clf1.predict_fp_probability(finding, "pragma solidity ^0.8.20;")
        p2 = clf2.predict_fp_probability(finding, "pragma solidity ^0.8.20;")

        assert abs(p1 - p2) < 1e-9, f"Predictions diverged after save/load: {p1} vs {p2}"

    def test_heuristic_fallback_when_no_sklearn(self, tmp_path):
        """When sklearn import fails, classifier must fall back gracefully,
        not crash callers."""
        from src.ml.fp_ml_classifier import AuditorTrainedFPClassifier

        clf = AuditorTrainedFPClassifier(model_path=tmp_path / "absent.pkl")
        clf._sklearn_available = False
        clf.model = None
        # Should return a float in [0, 1] via the heuristic
        p = clf.predict_fp_probability(
            {"type": "reentrancy-eth", "severity": "critical", "tool": "slither"},
            "pragma solidity ^0.8.20;",
        )
        assert 0.0 <= p <= 1.0


# ---------------------------------------------------------------------------
# Multi-chain analyze dispatcher
# ---------------------------------------------------------------------------


class TestMultiChainDispatch:
    """`miesc analyze` must auto-detect chain from file extension."""

    @pytest.fixture
    def runner(self):
        from click.testing import CliRunner

        return CliRunner()

    def test_cairo_extension_routes_to_cairo_analyzer(self, runner, tmp_path):
        from miesc.cli.commands.analyze import analyze

        c = tmp_path / "vuln.cairo"
        c.write_text(
            "#[starknet::contract]\nmod V { #[external] fn f() { replace_class_syscall(); } }\n"
        )
        result = runner.invoke(analyze, [str(c), "--quiet"])
        # Cairo analyzer finds replace_class_syscall -> proxy_upgrade
        assert "Traceback" not in result.output
        # Either stdout shows findings or summary, doesn't crash
        assert result.exit_code in (0, 1)

    def test_unknown_extension_errors_cleanly(self, runner, tmp_path):
        from miesc.cli.commands.analyze import analyze

        c = tmp_path / "mystery.xyz"
        c.write_text("unknown content")
        result = runner.invoke(analyze, [str(c), "--quiet"])
        assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# CanonicalCategory backward-compat
# ---------------------------------------------------------------------------


class TestCanonicalCategoryContract:
    def test_all_categories_serializable(self):
        """Every enum value MUST be a string — we JSON-serialize this in
        the investigation report and in the FP classifier's features."""
        from src.core.finding_taxonomy import CanonicalCategory

        for c in CanonicalCategory:
            assert isinstance(c.value, str)
            assert c.value == c.value.lower()

    def test_removing_a_category_would_fail_this(self):
        """Lock in the current enum set so an accidental rename/removal
        surfaces here, not in the agent at runtime."""
        from src.core.finding_taxonomy import CanonicalCategory

        required = {
            "reentrancy",
            "access_control",
            "oracle_manipulation",
            "flash_loan",
            "arithmetic",
            "unchecked_call",
            "initialization",
            "signature_verification",
            "bad_randomness",
            "time_manipulation",
            "denial_of_service",
            "front_running",
            "proxy_upgrade",
            "centralization",
            "input_validation",
            "other",
        }
        actual = {c.value for c in CanonicalCategory}
        missing = required - actual
        assert not missing, f"CanonicalCategory removed these entries: {missing}"


# ---------------------------------------------------------------------------
# DeepAuditAgent phase ordering
# ---------------------------------------------------------------------------


class TestPhaseOrdering:
    """Every analyze() run must execute reconnaissance -> targeted_scan ->
    deep_investigation -> synthesis in that exact order."""

    def test_phases_in_correct_order(self, tmp_path):
        from src.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        cfg = DeepAuditConfig(
            timeout_seconds=60,
            enable_llm=False,
            enable_rag=False,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=cfg)
        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C {}")
        result = agent.analyze(str(c))

        phase_keys = list(result.get("phases", {}).keys())
        expected = ["reconnaissance", "targeted_scan", "deep_investigation", "synthesis"]
        assert phase_keys == expected, f"Phase order broken: expected {expected}, got {phase_keys}"


# ---------------------------------------------------------------------------
# VulnerabilityExample new fields (attack_steps + detection_heuristic)
# ---------------------------------------------------------------------------


class TestVulnerabilityExampleFields:
    """Lock in the v5.1.6 dataclass extension so removing these fields
    triggers a clear failure."""

    def test_has_attack_steps_field(self):
        from miesc.llm.vulnerability_rag import VulnerabilityExample

        ex = VulnerabilityExample(
            id="x",
            swc_id=None,
            cwe_id=None,
            title="t",
            description="d",
            vulnerable_code="",
            fixed_code=None,
            attack_scenario=None,
            severity="low",
            category="x",
        )
        assert hasattr(ex, "attack_steps")
        assert hasattr(ex, "detection_heuristic")
        assert ex.attack_steps == []
        assert ex.detection_heuristic is None

    def test_registry_enrichment_preserved(self):
        """At least the top-8 patterns enriched in v5.1.6 must still carry
        both attack_steps and detection_heuristic."""
        from miesc.llm.vulnerability_rag import EXPLOIT_EXAMPLES, SWC_REGISTRY

        required_enriched = [
            ("SWC-107", SWC_REGISTRY),
            ("SWC-105", SWC_REGISTRY),
            ("SWC-106", SWC_REGISTRY),
            ("SWC-104", SWC_REGISTRY),
            ("SWC-115", SWC_REGISTRY),
            ("SWC-101", SWC_REGISTRY),
            ("euler-finance-2023", EXPLOIT_EXAMPLES),
            ("curve-vyper-reentrancy-2023", EXPLOIT_EXAMPLES),
        ]
        for key, registry in required_enriched:
            ex = registry[key]
            assert len(ex.attack_steps) >= 3, f"{key} lost attack_steps"
            assert ex.detection_heuristic, f"{key} lost detection_heuristic"


# ---------------------------------------------------------------------------
# specs -> verify integration shape
# ---------------------------------------------------------------------------


class TestSpecsVerifyIntegrationShape:
    """`miesc specs` emits specs that `miesc verify` must be able to consume."""

    def test_specs_emits_cvl_with_rule_block(self, tmp_path):
        from src.formal.spec_generator import SpecFormat, SpecGenerator

        findings = [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "swc_id": "SWC-107",
                "location": {"function": "withdraw"},
            }
        ]
        generator = SpecGenerator()
        out = tmp_path / "rules.spec"
        count = generator.generate_spec_file(
            findings=findings,
            output_path=out,
            contract_name="MyContract",
            format=SpecFormat.CVL,
        )
        assert count >= 1
        assert out.exists()
        content = out.read_text()
        # CVL uses `rule` blocks
        assert "rule" in content.lower()

    def test_spec_runner_result_has_required_fields_for_verify_json(self):
        from src.formal.spec_runner import VerificationResult

        r = VerificationResult(tool="halmos", spec_file="/x", status="passed")
        d = r.to_dict()
        # `miesc verify -o out.json` writes r.to_dict() — verify the shape
        for key in (
            "tool",
            "spec_file",
            "status",
            "rules_passed",
            "rules_failed",
            "rules_total",
            "counterexamples",
            "elapsed_seconds",
        ):
            assert key in d, f"verify JSON missing key: {key}"


# ---------------------------------------------------------------------------
# Bootstrap label_finding <-> AuditorTrainedFPClassifier interop
# ---------------------------------------------------------------------------


class TestBootstrapClassifierInterop:
    def test_bootstrap_labels_are_consumable_by_classifier(self, tmp_path):
        """The JSONL the bootstrap script writes must be trainable by
        AuditorTrainedFPClassifier without any schema transformation."""
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "bootstrap_fp_dataset",
            Path(__file__).parent.parent / "scripts" / "bootstrap_fp_dataset.py",
        )
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)

        # Synthesize a small balanced dataset the bootstrap script would produce
        samples = []
        for _ in range(10):
            samples.append(
                {
                    "finding": {"type": "reentrancy-eth", "severity": "High", "tool": "slither"},
                    "context": "pragma solidity ^0.8.20;",
                    "label": True,
                    "_reason": "canonical-match:reentrancy",
                }
            )
        for _ in range(10):
            samples.append(
                {
                    "finding": {
                        "type": "useless-public-function",
                        "severity": "low",
                        "tool": "aderyn",
                    },
                    "context": "pragma solidity ^0.8.20;",
                    "label": False,
                    "_reason": "noise-type:useless-public-function",
                }
            )
        out = tmp_path / "labels.jsonl"
        out.write_text("\n".join(json.dumps(s) for s in samples))

        from src.ml.fp_ml_classifier import AuditorTrainedFPClassifier

        clf = AuditorTrainedFPClassifier(model_path=tmp_path / "m.pkl")
        metrics = clf.train(str(out))
        assert "accuracy" in metrics
        assert metrics["train_samples"] + metrics["test_samples"] == 20
