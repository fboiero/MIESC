"""
Tests for honest fuzzing-campaign classification (P1-3).

A coverage-guided fuzzer that never exercises the contract (no harness, an
unsupported CLI flag, a compile failure) must NOT report "0 findings" as a
clean pass. These tests pin:

  * the pure classifier / verdict helper, and
  * the three coverage-guided adapters (medusa, echidna, dogefuzz) against the
    REAL degenerate output each tool produces on this host — so a regression
    that re-introduces the false-clean is caught.
"""

from unittest.mock import MagicMock, patch

from miesc.adapters._fuzz_result import (
    FUZZ_INCONCLUSIVE,
    FUZZ_SUCCESS,
    apply_fuzz_verdict,
    classify_fuzz_campaign,
)
from miesc.core.tool_protocol import ToolStatus

# --- Real degenerate output captured on this host (do not synthesize) --------

# medusa 1.3.1 rejects the adapter's `--assertion-mode` flag and exits 1 before
# fuzzing anything.
MEDUSA_UNKNOWN_FLAG_STDOUT = "unknown flag: --assertion-mode\n"

# echidna on a contract with no fuzzable ABI: compiles, analyzes, then bails.
ECHIDNA_EMPTY_ABI_OUTPUT = (
    "[2026-11-09 14:08:02.99] Compiling `Empty.sol`... Done! (0.581037s)\n"
    "Analyzing contract: /tmp/empty_target/Empty.sol:Empty\n"
    "echidna: ABI is empty, are you sure your constructor is right?\n"
)


class TestClassifyFuzzCampaign:
    """The pure verdict function."""

    def test_findings_present_is_success(self):
        status, warning = classify_fuzz_campaign(
            tool="medusa", findings=[{"type": "reentrancy"}], exercised=False
        )
        assert status == FUZZ_SUCCESS
        assert warning is None

    def test_exercised_without_findings_is_success(self):
        status, warning = classify_fuzz_campaign(tool="echidna", findings=[], exercised=True)
        assert status == FUZZ_SUCCESS
        assert warning is None

    def test_no_findings_and_not_exercised_is_inconclusive(self):
        status, warning = classify_fuzz_campaign(tool="medusa", findings=[], exercised=False)
        assert status == FUZZ_INCONCLUSIVE
        assert warning is not None
        assert "inconclusive" in warning.lower()
        assert "medusa" in warning.lower()
        # Never claims a clean pass.
        assert "clean pass" in warning.lower()

    def test_diagnostic_is_folded_into_message(self):
        _, warning = classify_fuzz_campaign(
            tool="medusa",
            findings=[],
            exercised=False,
            diagnostic="unknown flag: --assertion-mode",
        )
        assert "unknown flag: --assertion-mode" in warning

    def test_long_diagnostic_is_truncated(self):
        _, warning = classify_fuzz_campaign(
            tool="medusa", findings=[], exercised=False, diagnostic="x" * 5000
        )
        # Message stays bounded; truncation marker present.
        assert len(warning) < 1000
        assert "…" in warning


class TestApplyFuzzVerdict:
    """The in-place result stamper used by adapters."""

    def test_inconclusive_result_is_stamped(self):
        result = {"tool": "medusa", "status": "success", "findings": [], "metadata": {}}
        apply_fuzz_verdict(result, tool="medusa", exercised=False, diagnostic="boom")
        assert result["status"] == FUZZ_INCONCLUSIVE
        assert result["warning"]
        # Downstream renderers key off `error` for the non-success branch.
        assert result["error"] == result["warning"]
        assert result["metadata"]["campaign_exercised"] is False
        assert result["metadata"]["campaign_diagnostic"] == "boom"

    def test_exercised_result_keeps_success(self):
        result = {"tool": "medusa", "status": "success", "findings": [], "metadata": {}}
        apply_fuzz_verdict(result, tool="medusa", exercised=True)
        assert result["status"] == FUZZ_SUCCESS
        assert result["metadata"]["campaign_exercised"] is True
        assert "warning" not in result

    def test_findings_force_success_even_if_not_exercised(self):
        result = {"tool": "medusa", "status": "success", "findings": [{"x": 1}]}
        apply_fuzz_verdict(result, tool="medusa", exercised=False)
        assert result["status"] == FUZZ_SUCCESS

    def test_missing_metadata_is_created(self):
        result = {"tool": "echidna", "status": "success", "findings": []}
        apply_fuzz_verdict(result, tool="echidna", exercised=False, diagnostic="d")
        assert result["metadata"]["campaign_exercised"] is False


class TestMedusaHonestStatus:
    """MedusaAdapter honest verdict on real medusa 1.3.x output."""

    def _adapter(self):
        from miesc.adapters.medusa_adapter import MedusaAdapter

        return MedusaAdapter()

    def test_run_that_never_fuzzed_is_inconclusive_not_success(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0; contract C {}")
        adapter = self._adapter()

        # medusa aborted before fuzzing (no deployable target): no calls.
        abort = "error Failed to initialize the test chain\nspecify target contract(s)\n"

        def fake_run(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="medusa 1.3.1", stderr="")
            return MagicMock(returncode=6, stdout=abort, stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            result = adapter.analyze(str(contract))

        assert result["status"] == FUZZ_INCONCLUSIVE
        assert result["findings"] == []
        assert result["metadata"]["campaign_exercised"] is False

    def test_real_coverage_run_is_success(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0; contract C {}")
        adapter = self._adapter()

        def fake_run(cmd, **kwargs):
            if "--version" in cmd:
                return MagicMock(returncode=0, stdout="medusa 1.3.1", stderr="")
            # Real medusa 1.3.x progress + summary format (calls / branches / corpus).
            return MagicMock(
                returncode=0,
                stdout=(
                    "fuzz: elapsed: 3s, calls: 140003 (46667/sec), seq/s: 466, "
                    "branches hit: 81, corpus: 2, failures: 0/1399\n"
                    "Test summary: 1 test(s) passed, 0 test(s) failed\n"
                ),
                stderr="",
            )

        with patch("subprocess.run", side_effect=fake_run):
            result = adapter.analyze(str(contract))

        assert result["status"] == FUZZ_SUCCESS
        assert result["metadata"]["campaign_exercised"] is True


class TestEchidnaHonestStatus:
    """EchidnaAdapter against the real empty-ABI output."""

    def _adapter(self):
        from miesc.adapters.echidna_adapter import EchidnaAdapter

        return EchidnaAdapter()

    def test_empty_abi_run_is_inconclusive_not_success(self, tmp_path):
        contract = tmp_path / "Empty.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Empty { uint256 x; }")
        adapter = self._adapter()

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch(
                "miesc.adapters.echidna_adapter._run_capturing_pty",
                return_value=(1, ECHIDNA_EMPTY_ABI_OUTPUT),
            ),
        ):
            result = adapter.analyze(str(contract))

        assert result["status"] == FUZZ_INCONCLUSIVE
        assert result["findings"] == []
        assert result["metadata"]["campaign_exercised"] is False

    def test_run_with_evaluated_property_is_success(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0; contract C {}")
        adapter = self._adapter()

        output = (
            "Analyzing contract: C.sol:C\n"
            "echidna_balance_under_cap: passing\n"
            "Unique instructions: 412\n"
            "Total calls: 50000\n"
        )
        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch(
                "miesc.adapters.echidna_adapter._run_capturing_pty",
                return_value=(0, output),
            ),
        ):
            result = adapter.analyze(str(contract))

        assert result["status"] == FUZZ_SUCCESS
        assert result["metadata"]["campaign_exercised"] is True


class TestDogeFuzzHonestStatus:
    """DogeFuzzAdapter when the campaign instruments/covers nothing."""

    def test_zero_coverage_campaign_is_inconclusive(self, tmp_path):
        from miesc.adapters.dogefuzz_adapter import DogeFuzzAdapter

        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0; contract C { uint256 x; }")
        adapter = DogeFuzzAdapter()

        with (
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch.object(adapter, "_run_fuzzing_campaign", return_value=[]),
        ):
            # Global coverage stays at its empty init state (no statements
            # instrumented) -> nothing was exercised.
            result = adapter.analyze(str(contract))

        assert result["status"] == FUZZ_INCONCLUSIVE
        assert result["findings"] == []
        assert result["metadata"]["campaign_exercised"] is False
