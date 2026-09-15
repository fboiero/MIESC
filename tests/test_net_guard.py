"""Tests for the outbound SSRF guard (miesc.core.net_guard).

net_guard.guard_outbound_url() already had indirect coverage via
tests/test_notifiers.py (IP-literal / scheme rejection cases), but the
module's own docstring names DNS-rebinding as a specific threat it defends
against -- a hostname that *resolves* to a private/reserved address -- and
that resolution path, the allowed_hosts trust-list bypass, and the DNS
failure fallback were never exercised. This file covers those directly with
socket.getaddrinfo mocked (no real DNS lookups).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import socket
from unittest import mock

import pytest

from miesc.core.net_guard import SSRFError, guard_outbound_url, is_url_safe

URL = "https://evil.example.com/hook"


def _resolved(*ips):
    """Build a socket.getaddrinfo()-shaped return value for the given IPs."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


class TestDnsRebinding:
    def test_hostname_resolving_to_private_ip_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolved("10.0.0.5")):
            with pytest.raises(SSRFError):
                guard_outbound_url(URL)

    def test_hostname_resolving_to_metadata_ip_is_blocked(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolved("169.254.169.254")):
            with pytest.raises(SSRFError):
                guard_outbound_url(URL)

    def test_hostname_resolving_to_public_ip_is_allowed(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolved("8.8.8.8")) as m:
            assert guard_outbound_url(URL) == URL
            m.assert_called_once()

    def test_is_url_safe_reflects_dns_rebinding(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolved("10.0.0.5")):
            assert is_url_safe(URL) is False
        with mock.patch("socket.getaddrinfo", return_value=_resolved("8.8.8.8")):
            assert is_url_safe(URL) is True

    def test_one_private_address_among_several_blocks(self):
        """A hostname with multiple A/AAAA records is blocked if ANY resolves internally."""
        with mock.patch("socket.getaddrinfo", return_value=_resolved("8.8.8.8", "10.0.0.5")):
            with pytest.raises(SSRFError):
                guard_outbound_url(URL)


class TestAllowedHostsBypassesDnsCheck:
    def test_allowed_host_skips_resolution_entirely(self):
        with mock.patch("socket.getaddrinfo") as m:
            assert guard_outbound_url(URL, allowed_hosts=["evil.example.com"]) == URL
            m.assert_not_called()

    def test_host_not_in_allowed_list_still_goes_through_full_guard(self):
        with mock.patch("socket.getaddrinfo", return_value=_resolved("10.0.0.5")):
            with pytest.raises(SSRFError):
                guard_outbound_url(URL, allowed_hosts=["other.example.com"])

    def test_allowed_hosts_matching_is_case_insensitive(self):
        with mock.patch("socket.getaddrinfo") as m:
            assert guard_outbound_url(URL, allowed_hosts=["EVIL.EXAMPLE.COM"]) == URL
            m.assert_not_called()


class TestResolveDnsFlag:
    def test_resolve_dns_false_skips_the_lookup(self):
        with mock.patch("socket.getaddrinfo") as m:
            assert guard_outbound_url(URL, resolve_dns=False) == URL
            m.assert_not_called()


class TestDnsFailureFallsOpen:
    def test_gaierror_lets_the_url_through(self):
        """A DNS failure isn't an SSRF signal -- let the real request surface it."""
        with mock.patch(
            "socket.getaddrinfo", side_effect=socket.gaierror("name resolution failed")
        ):
            assert guard_outbound_url(URL) == URL


class TestMalformedAndIpv6:
    def test_no_hostname_raises(self):
        with pytest.raises(SSRFError):
            guard_outbound_url("https:///no-host")

    def test_ipv6_loopback_is_blocked(self):
        with pytest.raises(SSRFError):
            guard_outbound_url("https://[::1]/hook")

    def test_ipv6_loopback_allowed_when_opted_in(self):
        assert guard_outbound_url("https://[::1]/hook", allow_localhost=True)
