"""
Tests for the pluggable acceptance-pattern intelligence provider.

Covers the ports-and-adapters design (miesc.core.acceptance_contracts /
acceptance_providers) plus the recall-safe ordering integration in
miesc.ml.triage_ranker and the scan CLI wiring. All network is mocked — no
test touches the real internet.

Key guarantees under test:
  * Protocol conformance for both adapters.
  * Local provider returns real probabilities for known classes, None otherwise.
  * Finding -> vuln-class mapping goes through normalize_finding_type.
  * RECALL-SAFE: acceptance reordering never drops a finding (count in == out).
  * External adapter is opt-in (off by default), SSRF-guarded, and its paid
    scan path is unimplemented; allow_remote=False blocks remote calls.
  * Factory returns the local provider by default.
"""

from __future__ import annotations

import json

import pytest

from miesc.core.acceptance_contracts import (
    AcceptancePatternProvider,
    AcceptancePolicy,
    AcceptanceSignal,
    finding_to_vuln_class,
)
from miesc.core.acceptance_providers import (
    _DEFAULT_DATA_PATH,
    BugBountyIntelligenceProvider,
    LocalAcceptancePatternProvider,
    auto_acceptance_provider,
)
from miesc.ml.triage_ranker import apply_acceptance_ordering


def _finding(vtype: str, severity: str = "high") -> dict:
    return {"type": vtype, "check": vtype, "severity": severity}


# --------------------------------------------------------------------------- #
# Port / protocol conformance
# --------------------------------------------------------------------------- #
class TestProtocolConformance:
    def test_local_provider_satisfies_protocol(self):
        provider = LocalAcceptancePatternProvider()
        assert isinstance(provider, AcceptancePatternProvider)
        assert isinstance(provider.name, str) and provider.name

    def test_external_provider_satisfies_protocol(self):
        provider = BugBountyIntelligenceProvider()
        assert isinstance(provider, AcceptancePatternProvider)
        assert isinstance(provider.name, str) and provider.name

    def test_policy_defaults_are_local_first_remote_off(self):
        policy = AcceptancePolicy()
        assert policy.local_first is True
        assert policy.allow_remote is False
        assert policy.to_dict() == {"local_first": True, "allow_remote": False}

    def test_acceptance_signal_clamps_probability(self):
        assert AcceptanceSignal("reentrancy", 1.5).to_dict()["acceptance_prob"] == 1.0
        assert AcceptanceSignal("reentrancy", -0.2).to_dict()["acceptance_prob"] == 0.0


# --------------------------------------------------------------------------- #
# Finding -> vuln class mapping (via normalize_finding_type)
# --------------------------------------------------------------------------- #
class TestFindingMapping:
    def test_known_type_maps_to_canonical_class(self):
        assert finding_to_vuln_class(_finding("reentrancy-eth")) == "reentrancy"
        assert finding_to_vuln_class({"swc_id": "SWC-105"}) == "access_control"

    def test_unknown_type_returns_none(self):
        assert finding_to_vuln_class(_finding("totally-made-up-xyz")) is None


# --------------------------------------------------------------------------- #
# Local provider — real probs for known classes, None for unknown
# --------------------------------------------------------------------------- #
class TestLocalProvider:
    def test_is_available_and_lists_patterns(self):
        provider = LocalAcceptancePatternProvider()
        assert provider.is_available() is True
        patterns = provider.list_vulnerability_patterns()
        assert "reentrancy" in patterns
        assert all(0.0 <= v <= 1.0 for v in patterns.values())

    def test_known_class_returns_real_probability(self):
        provider = LocalAcceptancePatternProvider()
        prob = provider.acceptance_probability(_finding("reentrancy-eth"))
        assert prob is not None
        assert 0.0 <= prob <= 1.0

    def test_unknown_class_returns_none(self):
        provider = LocalAcceptancePatternProvider()
        assert provider.acceptance_probability(_finding("nonexistent-check")) is None

    def test_missing_data_file_degrades_gracefully(self, tmp_path):
        provider = LocalAcceptancePatternProvider(data_path=str(tmp_path / "nope.json"))
        assert provider.is_available() is False
        assert provider.acceptance_probability(_finding("reentrancy-eth")) is None


# --------------------------------------------------------------------------- #
# Curated JSON data loads + validates
# --------------------------------------------------------------------------- #
class TestCuratedData:
    def test_data_file_is_valid_and_well_formed(self):
        with open(_DEFAULT_DATA_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
        assert "_meta" in data and "provenance" in data["_meta"]
        patterns = data["patterns"]
        assert patterns
        for key, entry in patterns.items():
            assert isinstance(key, str)
            prob = entry["acceptance_prob"]
            assert 0.0 <= float(prob) <= 1.0, f"{key} prob out of range"


# --------------------------------------------------------------------------- #
# RECALL-SAFE proof: reorder-only, never drops (count in == count out)
# --------------------------------------------------------------------------- #
class TestRecallSafeOrdering:
    def test_low_acceptance_finding_reordered_lower_but_never_removed(self):
        # front_running has low acceptance; reentrancy has high acceptance.
        results = [
            {
                "tool": "t",
                "findings": [
                    _finding("front-running"),  # low acceptance -> should sink
                    _finding("reentrancy-eth"),  # high acceptance -> should rise
                ],
            }
        ]
        count_in = sum(len(r["findings"]) for r in results)
        total = apply_acceptance_ordering(results, provider=LocalAcceptancePatternProvider())
        count_out = sum(len(r["findings"]) for r in results)

        # Nothing dropped — recall preserved.
        assert count_in == count_out == 2
        assert total == 2
        ordered = results[0]["findings"]
        # High-acceptance finding rose to the top; low-acceptance is still present.
        assert ordered[0]["type"] == "reentrancy-eth"
        assert ordered[1]["type"] == "front-running"
        # Signal annotated on the finding, NOT removed from output.
        assert "acceptance_prob" in ordered[0]
        assert "acceptance_prob" in ordered[1]
        assert ordered[0]["acceptance_prob"] > ordered[1]["acceptance_prob"]

    def test_unknown_class_findings_kept_visible(self):
        results = [
            {
                "tool": "t",
                "findings": [
                    _finding("reentrancy-eth"),
                    _finding("totally-unknown-xyz"),  # unknown class -> no prob
                ],
            }
        ]
        apply_acceptance_ordering(results, provider=LocalAcceptancePatternProvider())
        types = {f["type"] for f in results[0]["findings"]}
        assert types == {"reentrancy-eth", "totally-unknown-xyz"}  # nothing dropped
        # Unknown-class finding has no acceptance annotation.
        unknown = next(f for f in results[0]["findings"] if f["type"] == "totally-unknown-xyz")
        assert "acceptance_prob" not in unknown

    def test_unavailable_provider_is_noop(self):
        class _Down:
            name = "down"

            def is_available(self) -> bool:
                return False

            def list_vulnerability_patterns(self):
                return {}

            def acceptance_probability(self, finding, protocol_type=None):
                return None

        results = [{"tool": "t", "findings": [_finding("reentrancy-eth")]}]
        total = apply_acceptance_ordering(results, provider=_Down())
        assert total == -1
        assert len(results[0]["findings"]) == 1  # untouched


# --------------------------------------------------------------------------- #
# External adapter — opt-in, SSRF-guarded, paid scan unimplemented
# --------------------------------------------------------------------------- #
class TestBugBountyProvider:
    def test_unavailable_by_default(self, monkeypatch):
        monkeypatch.delenv("MIESC_BUGBOUNTY_API_KEY", raising=False)
        assert BugBountyIntelligenceProvider().is_available() is False

    def test_allow_remote_false_blocks_even_when_configured(self, monkeypatch):
        monkeypatch.setenv("MIESC_BUGBOUNTY_API_KEY", "secret")
        provider = BugBountyIntelligenceProvider(
            config={"enabled": True}, policy=AcceptancePolicy(allow_remote=False)
        )
        assert provider.is_available() is False

    def test_available_when_env_and_config_and_remote_set(self, monkeypatch):
        monkeypatch.setenv("MIESC_BUGBOUNTY_API_KEY", "secret")
        provider = BugBountyIntelligenceProvider(
            config={"enabled": True}, policy=AcceptancePolicy(allow_remote=True)
        )
        assert provider.is_available() is True

    def test_network_call_goes_through_ssrf_guard_rejecting_localhost(self, monkeypatch):
        monkeypatch.setenv("MIESC_BUGBOUNTY_API_KEY", "secret")
        # Point the provider at a localhost/private URL — the SSRF guard must reject it,
        # so no request is made and we get {} back (never raises).
        provider = BugBountyIntelligenceProvider(
            config={"enabled": True, "base_url": "http://127.0.0.1:9000"},
            policy=AcceptancePolicy(allow_remote=True),
        )

        def _boom(*_a, **_k):  # pragma: no cover - must never be reached
            raise AssertionError("urlopen called despite SSRF-blocked URL")

        provider._opener = _boom
        assert provider.list_vulnerability_patterns() == {}

    def test_guarded_success_path_with_mocked_opener(self, monkeypatch):
        monkeypatch.setenv("MIESC_BUGBOUNTY_API_KEY", "secret")
        # Public HTTPS host that passes the guard; mock the opener so no real DNS/network.
        provider = BugBountyIntelligenceProvider(
            config={"enabled": True, "base_url": "https://intel.example.com"},
            policy=AcceptancePolicy(allow_remote=True),
        )
        payload = json.dumps({"patterns": {"reentrancy": 0.9, "front_running": 0.1}}).encode()

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def read(self):
                return payload

        # Guard resolves DNS for non-allowlisted hosts; the base_url host IS allowlisted
        # by the adapter, so no real DNS occurs. Opener is fully mocked.
        provider._opener = lambda *_a, **_k: _Resp()
        patterns = provider.list_vulnerability_patterns()
        assert patterns["reentrancy"] == 0.9
        prob = provider.acceptance_probability(_finding("reentrancy-eth"))
        assert prob == 0.9

    def test_paid_scan_is_not_implemented(self):
        provider = BugBountyIntelligenceProvider()
        with pytest.raises(NotImplementedError, match="opt-in extension point"):
            provider.scan_contract("contract.sol")

    def test_remote_disabled_returns_empty_without_calling(self):
        provider = BugBountyIntelligenceProvider(
            config={"enabled": True}, policy=AcceptancePolicy(allow_remote=False)
        )
        assert provider.list_vulnerability_patterns() == {}


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
class TestFactory:
    def test_returns_local_by_default(self):
        provider = auto_acceptance_provider()
        assert isinstance(provider, LocalAcceptancePatternProvider)

    def test_falls_back_to_local_when_external_unavailable(self, monkeypatch):
        monkeypatch.delenv("MIESC_BUGBOUNTY_API_KEY", raising=False)
        provider = auto_acceptance_provider(
            prefer_local=False,
            config={"enabled": True},
            policy=AcceptancePolicy(allow_remote=True),
        )
        # No API key -> external not available -> local fallback.
        assert isinstance(provider, LocalAcceptancePatternProvider)

    def test_returns_external_when_fully_enabled(self, monkeypatch):
        monkeypatch.setenv("MIESC_BUGBOUNTY_API_KEY", "secret")
        provider = auto_acceptance_provider(
            prefer_local=False,
            config={"enabled": True},
            policy=AcceptancePolicy(allow_remote=True),
        )
        assert isinstance(provider, BugBountyIntelligenceProvider)


# --------------------------------------------------------------------------- #
# CLI wiring smoke
# --------------------------------------------------------------------------- #
class TestCliWiring:
    def test_apply_acceptance_ordering_helper_local(self):
        from miesc.cli.commands.scan import _apply_acceptance_ordering

        results = [
            {
                "tool": "t",
                "findings": [_finding("front-running"), _finding("reentrancy-eth")],
            }
        ]
        _apply_acceptance_ordering(results, choice="local", quiet=True)
        # Recall-safe: still two findings, reordered by acceptance.
        assert len(results[0]["findings"]) == 2
        assert results[0]["findings"][0]["type"] == "reentrancy-eth"

    def test_scan_exposes_acceptance_provider_flag(self):
        from miesc.cli.commands.scan import scan

        opts = {p.name for p in scan.params}
        assert "acceptance_provider" in opts
