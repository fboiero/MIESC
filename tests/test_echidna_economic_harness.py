"""
Tests for the opt-in economic-invariant harness in the Echidna adapter (P1-3a,
echidna half).

When ``generate_harness`` is enabled, EchidnaAdapter generates an ERC-4626 /
Compound-V2 harness (via ``economic_harness``) and fuzzes its ``echidna_*``
properties instead of a bare run. Off by default. The recursion guard lives in
``run_economic_fuzz``, so it cannot loop regardless of the adapter passed.
"""

from unittest.mock import patch

from miesc.adapters.echidna_adapter import EchidnaAdapter
from miesc.core.tool_protocol import ToolStatus
from miesc.formal import economic_harness as eh


class TestConfigAndClasses:
    def test_generate_harness_off_by_default(self):
        assert EchidnaAdapter().generate_harness is False
        assert EchidnaAdapter(config={"generate_harness": True}).generate_harness is True

    def test_invariant_classes_split(self):
        classes = eh.invariant_classes()
        assert set(classes) == {"erc4626", "compound"}
        # Every listed name is a real runnable invariant, and the union matches.
        union = set().union(*classes.values())
        assert union == eh.supported_invariants()


class TestRecursionGuard:
    def test_run_economic_fuzz_forces_adapter_bare(self):
        # The helper drives the adapter on a GENERATED harness; it must flip the
        # adapter's generate_harness off so analyze() never re-enters harness-gen.
        adapter = EchidnaAdapter(config={"generate_harness": True})
        assert adapter.generate_harness is True
        with patch.object(EchidnaAdapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            eh.run_economic_fuzz("/does/not/exist.sol", ["vault_solvency"], adapter=adapter)
        assert adapter.generate_harness is False


def _eco(status, findings=None, properties=None):
    return {
        "status": status,
        "findings": findings or [],
        "properties": properties or ["echidna_vault_solvent"],
        "target_contract": "MiniVault",
        "echidna": {"execution_time": 1.2, "tests_run": 3},
    }


class TestTryEconomicHarness:
    def _adapter(self):
        a = EchidnaAdapter(config={"generate_harness": True})
        return a

    def test_detected_maps_to_success_with_findings(self, tmp_path):
        target = tmp_path / "V.sol"
        target.write_text("contract V { function deposit(uint256 a, address r) public {} }")
        finding = {"type": "economic_invariant_violation", "property": "echidna_vault_solvent"}
        with patch.object(
            eh, "run_economic_fuzz", return_value=_eco("detected", findings=[finding])
        ):
            r = self._adapter()._try_economic_harness(str(target))
        assert r["status"] == "success"
        assert len(r["findings"]) == 1
        assert r["metadata"]["harness_generated"] is True
        assert r["metadata"]["campaign_exercised"] is True
        assert r["metadata"]["economic_status"] == "detected"

    def test_clean_maps_to_success_with_properties(self, tmp_path):
        target = tmp_path / "V.sol"
        target.write_text("contract V {}")
        props = ["echidna_vault_solvent", "echidna_share_price_non_decreasing"]
        with patch.object(eh, "run_economic_fuzz", return_value=_eco("clean", properties=props)):
            r = self._adapter()._try_economic_harness(str(target))
        assert r["status"] == "success"
        assert r["findings"] == []
        # "clean" means these named invariants held — list them, don't imply safety.
        assert r["metadata"]["economic_properties"] == props
        assert r["metadata"]["campaign_exercised"] is True

    def test_nothing_binds_falls_through(self, tmp_path):
        target = tmp_path / "V.sol"
        target.write_text("contract V {}")
        with patch.object(eh, "run_economic_fuzz", return_value=_eco("skipped")):
            r = self._adapter()._try_economic_harness(str(target))
        assert r is None  # -> bare run

    def test_tries_each_class_until_one_binds(self, tmp_path):
        target = tmp_path / "V.sol"
        target.write_text("contract V {}")
        calls = []

        def fake(contract_path, inv_names, **kwargs):
            calls.append(tuple(inv_names))
            # first class (erc4626) skips, second (compound) binds.
            cls = eh.invariant_classes()
            if inv_names == cls["erc4626"]:
                return _eco("skipped")
            return _eco("detected", findings=[{"type": "x"}])

        with patch.object(eh, "run_economic_fuzz", side_effect=fake):
            r = self._adapter()._try_economic_harness(str(target))
        assert r is not None and r["status"] == "success"
        assert len(calls) == 2  # tried erc4626, then compound

    def test_non_sol_file_returns_none(self, tmp_path):
        d = tmp_path / "proj"
        d.mkdir()
        assert self._adapter()._try_economic_harness(str(d)) is None
        txt = tmp_path / "x.txt"
        txt.write_text("nope")
        assert self._adapter()._try_economic_harness(str(txt)) is None

    def test_harness_gen_is_bounded_inner_analyze_is_bare(self, tmp_path):
        # Behavioural recursion proof: when run_economic_fuzz drives the adapter
        # on the GENERATED harness (its L785 call), the inner analyze must NOT
        # re-enter harness generation — so _try_economic_harness runs exactly once.
        target = tmp_path / "V.sol"
        target.write_text("contract V {}")
        harness = tmp_path / "H.sol"
        harness.write_text("contract H {}")
        adapter = EchidnaAdapter(config={"generate_harness": True})

        entries = []
        original = type(adapter)._try_economic_harness

        def counting(self, cp, **kw):
            entries.append(cp)
            return original(self, cp, **kw)

        def fake_run_economic_fuzz(contract_path, inv_names, **kwargs):
            # Faithful to run_economic_fuzz: flip the guard, then run the adapter
            # on the generated harness. The inner analyze must go bare.
            adapter.generate_harness = False
            adapter.analyze(str(harness))
            return _eco("clean")

        with (
            patch.object(type(adapter), "_try_economic_harness", counting),
            patch.object(eh, "run_economic_fuzz", side_effect=fake_run_economic_fuzz),
            patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE),
            patch("miesc.adapters.echidna_adapter._run_capturing_pty", return_value=(1, "")),
        ):
            adapter.analyze(str(target))

        assert entries == [str(target)]  # exactly once; the harness run went bare
