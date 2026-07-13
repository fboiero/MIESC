"""
Outbound URL SSRF guard
=======================

Shared server-side request forgery (SSRF) protection for any MIESC feature
that makes an outbound HTTP request to a *user-configured* URL (plugin
marketplace, webhook / Slack notifiers, ...).

The guard rejects requests that could reach internal infrastructure:

- Non-HTTPS schemes (plain ``http`` only tolerated for explicit localhost dev).
- Private / reserved / loopback / link-local / multicast IP literals.
- Cloud metadata endpoints (``169.254.169.254``, ``metadata.google.internal``).
- Hostnames that *resolve* to a private / reserved / loopback address
  (DNS-rebinding style bypass).

This logic was originally embedded in ``miesc.plugins.marketplace`` and is
factored out here so every outbound sink reuses one audited implementation
instead of hand-rolling ``urlopen``.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Hostnames that expose cloud instance credentials / metadata — never reachable.
METADATA_HOSTS: Set[str] = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}

_LOCAL_HOSTNAMES: Set[str] = {"localhost", "127.0.0.1", "::1"}


class SSRFError(ValueError):
    """Raised when a URL fails SSRF validation and must not be requested."""


def _ip_is_blocked(ip: ipaddress._BaseAddress, *, allow_loopback: bool) -> bool:
    """Return True if ``ip`` points at internal / reserved space."""
    if allow_loopback and ip.is_loopback:
        return False
    return bool(
        ip.is_private
        or ip.is_reserved
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def guard_outbound_url(
    url: str,
    *,
    allow_localhost: bool = False,
    allowed_hosts: Optional[Iterable[str]] = None,
    resolve_dns: bool = True,
) -> str:
    """Validate ``url`` for outbound requests, blocking SSRF targets.

    Args:
        url: The user-supplied URL to validate.
        allow_localhost: When True, tolerate ``http://localhost`` /
            ``127.0.0.1`` (local development / testing only).
        allowed_hosts: Optional trust list. If the URL's hostname is in this
            set it is accepted without the DNS-resolution check (the host is
            operator-curated). Hosts *not* in the list still go through the
            full guard rather than being rejected outright.
        resolve_dns: When True, resolve hostnames and reject any that map to a
            private / reserved address. Disable only in tests that must not
            touch the network (IP-literal URLs never resolve regardless).

    Returns:
        The validated URL, unchanged.

    Raises:
        SSRFError: If the URL is malformed or targets internal infrastructure.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname

    if not hostname:
        raise SSRFError(f"Invalid URL: no hostname in {url!r}")

    host_l = hostname.lower()

    # --- scheme ------------------------------------------------------------
    if scheme == "http":
        if not (allow_localhost and host_l in _LOCAL_HOSTNAMES):
            raise SSRFError(
                f"Only HTTPS URLs are allowed for outbound requests, got {scheme!r}"
            )
    elif scheme != "https":
        raise SSRFError(f"Unsupported URL scheme {scheme!r}; use https")

    # --- metadata endpoints (always blocked) -------------------------------
    if host_l in METADATA_HOSTS:
        raise SSRFError(f"Access to cloud metadata endpoint blocked: {hostname}")

    # --- IP-literal hosts --------------------------------------------------
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if _ip_is_blocked(ip, allow_loopback=allow_localhost):
            raise SSRFError(f"Access to private/reserved IP address blocked: {ip}")
        return url

    # --- named hosts -------------------------------------------------------
    allow_set = {h.lower() for h in allowed_hosts} if allowed_hosts else set()
    if host_l in allow_set:
        # Operator-curated host; trusted, skip DNS re-check.
        return url

    if allow_localhost and host_l in _LOCAL_HOSTNAMES:
        return url

    if resolve_dns:
        try:
            resolved = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            # DNS failure — let the real request surface the connection error.
            return url
        for _family, _type, _proto, _canon, sockaddr in resolved:
            try:
                resolved_ip = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            if _ip_is_blocked(resolved_ip, allow_loopback=allow_localhost):
                raise SSRFError(
                    f"Hostname {hostname} resolves to private/reserved IP {resolved_ip}"
                )

    return url


def is_url_safe(url: str, **kwargs: object) -> bool:
    """Boolean convenience wrapper around :func:`guard_outbound_url`."""
    try:
        guard_outbound_url(url, **kwargs)  # type: ignore[arg-type]
        return True
    except SSRFError:
        return False
