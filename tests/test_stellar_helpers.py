"""Tests for StellarAdapter Soroban pattern detectors (pure, no Stellar tooling)."""

from __future__ import annotations

from src.adapters.stellar_adapter import StellarPatternDetector as D


class TestDetectors:
    def test_panic_and_unwrap(self):
        out = D.detect_panic_in_contract('fn f() { let x = a.unwrap(); panic!("bad"); }')
        types = {x.get("type") for x in out}
        assert "unwrap_without_check" in types
        assert "panic_in_contract" in types

    def test_storage_ttl(self):
        out = D.detect_storage_issues("fn f(env: Env) { env.storage().instance().set(&k, &v); }")
        assert any(x.get("type") == "ttl_not_extended" for x in out)

    def test_arithmetic_overflow(self):
        out = D.detect_arithmetic_issues("fn f() { let x = a + b; let y = c * d; }")
        assert any(x.get("type") == "arithmetic_overflow" for x in out)

    def test_token_detector_runs(self):
        out = D.detect_token_issues("fn transfer(from: Address, to: Address, amount: i128) {}")
        assert isinstance(out, list)

    def test_cross_contract_detector_runs(self):
        out = D.detect_cross_contract_risks("fn f() { client.invoke(&other); }")
        assert isinstance(out, list)

    def test_missing_auth_runs(self):
        out = D.detect_missing_auth("fn admin_only() { set_admin(); }", [])
        assert isinstance(out, list)


class TestFindPatterns:
    def test_find_patterns_matches(self):
        hits = D.find_patterns("let x = a.unwrap();", {"unwrap": r"\.unwrap\(\)"})
        assert len(hits) >= 1

    def test_find_patterns_no_match(self):
        assert D.find_patterns("clean code", {"unwrap": r"\.unwrap\(\)"}) == []
