"""
Tests for the webhook / Slack notifier sink (T1.3).

Covers:
- payload shaping: generic JSON summary + Slack Block Kit structure
- SSRF guard: localhost / private-IP / metadata URLs are REJECTED (never POSTed);
  a normal https URL is allowed and POSTed
- severity-threshold gating: below threshold => no notification
- network-error handling: a failing POST never raises out of the notifier
- CLI wiring: `miesc scan` / `miesc audit quick` expose --notify / --slack, and
  a dispatched notification POSTs the right payload (network fully mocked)

All network I/O is mocked — no real HTTP request is ever made. IP-literal URLs
are used for the "allowed" cases so the SSRF guard never performs real DNS.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json
from unittest import mock

import pytest
from click.testing import CliRunner

from miesc.core import notifiers
from miesc.core.net_guard import SSRFError, guard_outbound_url, is_url_safe

# =============================================================================
# Helpers
# =============================================================================

# A public IP literal: passes the SSRF guard without any DNS lookup.
PUBLIC_URL = "https://8.8.8.8/webhook"


def _finding(
    severity="high",
    type="reentrancy",
    file="contracts/Bank.sol",
    message="Reentrancy in withdraw()",
):
    return {"severity": severity, "type": type, "file": file, "message": message}


def _results(*findings):
    return [{"tool": "slither", "status": "success", "findings": list(findings)}]


class _FakeResponse:
    """Minimal context-manager stand-in for a urlopen() response."""

    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getcode(self):
        return self.status


def _patch_urlopen(status=200):
    """Patch the notifier's urlopen; returns the mock for assertions."""
    return mock.patch.object(
        notifiers.urllib.request,
        "urlopen",
        return_value=_FakeResponse(status),
    )


# =============================================================================
# Payload shaping
# =============================================================================


class TestPayloadShaping:
    def test_generic_summary_counts_and_status(self):
        results = _results(
            _finding(severity="critical"),
            _finding(severity="high"),
            _finding(severity="low"),
        )
        payload = notifiers.build_summary(results, "contracts/Bank.sol")

        assert payload["tool"] == "MIESC"
        assert payload["contract"] == "contracts/Bank.sol"
        assert payload["total_findings"] == 3
        assert payload["severity_counts"]["critical"] == 1
        assert payload["severity_counts"]["high"] == 1
        assert payload["severity_counts"]["low"] == 1
        # critical/high present => fail
        assert payload["status"] == "fail"
        assert "timestamp" in payload

    def test_generic_status_pass_when_no_critical_high(self):
        results = _results(_finding(severity="low"), _finding(severity="medium"))
        payload = notifiers.build_summary(results, "C.sol")
        assert payload["status"] == "pass"

    def test_top_findings_are_most_severe_first_and_capped(self):
        results = _results(
            _finding(severity="low", type="lint"),
            _finding(severity="critical", type="reentrancy"),
            _finding(severity="medium", type="tx-origin"),
        )
        payload = notifiers.build_summary(results, "C.sol", top_n=2)
        top = payload["top_findings"]
        assert len(top) == 2
        assert top[0]["severity"] == "critical"
        assert top[0]["title"] == "reentrancy"

    def test_explicit_ci_failed_overrides_status(self):
        results = _results(_finding(severity="low"))
        payload = notifiers.build_summary(results, "C.sol", ci_failed=True)
        assert payload["status"] == "fail"

    def test_slack_block_structure(self):
        results = _results(_finding(severity="critical", type="reentrancy"))
        payload = notifiers.build_slack_payload(results, "contracts/Bank.sol")

        assert "blocks" in payload
        blocks = payload["blocks"]
        # header + summary section + findings section
        assert blocks[0]["type"] == "header"
        assert "MIESC scan: contracts/Bank.sol" in blocks[0]["text"]["text"]
        assert blocks[1]["type"] == "section"
        assert blocks[1]["text"]["type"] == "mrkdwn"
        assert "FAIL" in blocks[1]["text"]["text"]
        # a findings section referencing the finding title
        findings_block = blocks[2]
        assert findings_block["type"] == "section"
        assert "reentrancy" in findings_block["text"]["text"]

    def test_slack_no_findings_section_when_empty(self):
        payload = notifiers.build_slack_payload(_results(), "C.sol")
        # header + summary only (no findings section)
        assert len(payload["blocks"]) == 2
        assert "PASS" in payload["blocks"][1]["text"]["text"]


# =============================================================================
# SSRF guard
# =============================================================================


class TestSSRFGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "https://127.0.0.1/hook",  # loopback
            "http://localhost/hook",  # loopback + plain http
            "https://10.0.0.5/hook",  # private
            "https://192.168.1.10/hook",  # private
            "https://169.254.169.254/latest",  # link-local / AWS metadata
            "https://metadata.google.internal/x",  # GCP metadata host
            "http://8.8.8.8/hook",  # plain http (non-local) rejected
            "ftp://8.8.8.8/hook",  # bad scheme
        ],
    )
    def test_guard_rejects_internal_targets(self, url):
        with pytest.raises(SSRFError):
            guard_outbound_url(url)
        assert is_url_safe(url) is False

    def test_guard_allows_public_https(self):
        assert guard_outbound_url(PUBLIC_URL) == PUBLIC_URL
        assert is_url_safe(PUBLIC_URL) is True

    def test_guard_allows_localhost_when_opted_in(self):
        assert guard_outbound_url("http://127.0.0.1/hook", allow_localhost=True)

    def test_notify_does_not_post_to_blocked_url(self):
        results = _results(_finding(severity="critical"))
        with _patch_urlopen() as m:
            ok = notifiers.notify_webhook("https://169.254.169.254/x", results, "C.sol")
        assert ok is False
        m.assert_not_called()

    def test_notify_posts_to_public_url(self):
        results = _results(_finding(severity="critical"))
        with _patch_urlopen() as m:
            ok = notifiers.notify_webhook(PUBLIC_URL, results, "C.sol")
        assert ok is True
        m.assert_called_once()
        # the posted body is our JSON summary
        request = m.call_args[0][0]
        body = json.loads(request.data.decode("utf-8"))
        assert body["tool"] == "MIESC"
        assert body["severity_counts"]["critical"] == 1
        assert request.get_method() == "POST"


# =============================================================================
# Severity-threshold gating
# =============================================================================


class TestThresholdGating:
    def test_meets_threshold(self):
        low_only = _results(_finding(severity="low"))
        assert notifiers.meets_threshold([_finding(severity="low")], "low") is True
        assert notifiers.meets_threshold(low_only[0]["findings"], "high") is False

    def test_below_threshold_skips_webhook(self):
        results = _results(_finding(severity="low"))
        with _patch_urlopen() as m:
            ok = notifiers.notify_webhook(PUBLIC_URL, results, "C.sol", min_severity="high")
        assert ok is False
        m.assert_not_called()

    def test_below_threshold_skips_slack(self):
        results = _results(_finding(severity="medium"))
        with _patch_urlopen() as m:
            ok = notifiers.notify_slack(PUBLIC_URL, results, "C.sol", min_severity="critical")
        assert ok is False
        m.assert_not_called()

    def test_at_threshold_sends(self):
        results = _results(_finding(severity="high"))
        with _patch_urlopen() as m:
            ok = notifiers.notify_slack(PUBLIC_URL, results, "C.sol", min_severity="high")
        assert ok is True
        m.assert_called_once()


# =============================================================================
# Network-error handling
# =============================================================================


class TestNetworkErrors:
    def test_urlerror_does_not_raise(self):
        import urllib.error

        results = _results(_finding(severity="critical"))
        with mock.patch.object(
            notifiers.urllib.request,
            "urlopen",
            side_effect=urllib.error.URLError("boom"),
        ):
            ok = notifiers.notify_webhook(PUBLIC_URL, results, "C.sol")
        assert ok is False

    def test_timeout_does_not_raise(self):
        results = _results(_finding(severity="critical"))
        with mock.patch.object(notifiers.urllib.request, "urlopen", side_effect=TimeoutError()):
            ok = notifiers.notify_slack(PUBLIC_URL, results, "C.sol")
        assert ok is False

    def test_non_2xx_returns_false(self):
        results = _results(_finding(severity="critical"))
        with _patch_urlopen(status=500):
            ok = notifiers.notify_webhook(PUBLIC_URL, results, "C.sol")
        assert ok is False


# =============================================================================
# dispatch + CLI wiring
# =============================================================================


class TestDispatchAndCLI:
    def test_dispatch_fans_out_to_both_sinks(self):
        results = _results(_finding(severity="critical"))
        with _patch_urlopen() as m:
            delivered = notifiers.dispatch_notifications(
                results,
                "contracts/Bank.sol",
                webhook_url=PUBLIC_URL,
                slack_url=PUBLIC_URL,
            )
        assert delivered == {"webhook": True, "slack": True}
        assert m.call_count == 2

    def test_dispatch_noop_without_urls(self):
        with _patch_urlopen() as m:
            delivered = notifiers.dispatch_notifications(_results(), "C.sol")
        assert delivered == {}
        m.assert_not_called()

    def test_scan_help_shows_notify_options(self):
        from miesc.cli.commands.scan import scan

        result = CliRunner().invoke(scan, ["--help"])
        assert result.exit_code == 0
        assert "--notify" in result.output
        assert "--slack" in result.output
        assert "--notify-min-severity" in result.output

    def test_audit_quick_help_shows_notify_options(self):
        from miesc.cli.commands.audit import audit_quick

        result = CliRunner().invoke(audit_quick, ["--help"])
        assert result.exit_code == 0
        assert "--notify" in result.output
        assert "--slack" in result.output
