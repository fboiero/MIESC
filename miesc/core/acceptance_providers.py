"""
Adapters for the acceptance-pattern intelligence port.

Two implementations of *different nature* prove the abstraction defined in
:mod:`miesc.core.acceptance_contracts` is genuinely provider-neutral:

* :class:`LocalAcceptancePatternProvider` — the DEFAULT. Offline, deterministic,
  always available. Reads the curated open table shipped at
  ``miesc/knowledge_base/acceptance_patterns.json``. Real and functional.

* :class:`BugBountyIntelligenceProvider` — an OPT-IN external adapter for a
  third-party "bug bounty intelligence" service. It is unavailable unless the
  operator explicitly enables it (config ``enabled: true`` + an API-key env var)
  AND the acceptance policy allows remote traffic. Its network calls pass the
  SSRF guard (:func:`miesc.core.net_guard.guard_outbound_url`) with a host
  allowlist. The service's paid, on-chain-charged ``scan_contract`` path is a
  documented extension point that raises ``NotImplementedError`` — the public
  core ships no payment integration.

Mirrors ``miesc.llm.reasoning_provider_adapter``: a local-heuristic default, a
configured/remote implementation guarded by an ``allow_remote`` policy, and an
``auto_*`` factory that returns local unless remote is explicitly wired.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from miesc.core.acceptance_contracts import (
    AcceptancePatternProvider,
    AcceptancePolicy,
    finding_to_vuln_class,
)
from miesc.core.net_guard import SSRFError, guard_outbound_url

logger = logging.getLogger(__name__)

#: Default location of the curated local acceptance table.
_DEFAULT_DATA_PATH = (
    Path(__file__).resolve().parent.parent / "knowledge_base" / "acceptance_patterns.json"
)

#: Outbound request timeout for the external adapter (seconds).
_REQUEST_TIMEOUT_SECONDS = 10

#: Environment variable holding the external service API key (opt-in).
_BUGBOUNTY_API_KEY_ENV = "MIESC_BUGBOUNTY_API_KEY"


def _clamp(value: Any) -> Optional[float]:
    """Return ``value`` clamped into ``[0, 1]``, or ``None`` if non-numeric/NaN."""
    try:
        prob = float(value)
    except (TypeError, ValueError):
        return None
    if prob != prob:  # NaN
        return None
    return max(0.0, min(1.0, prob))


class LocalAcceptancePatternProvider(AcceptancePatternProvider):
    """Offline, always-available default backed by a curated JSON table."""

    name = "local-acceptance-patterns"

    def __init__(self, data_path: Optional[str] = None) -> None:
        self._data_path = Path(data_path) if data_path else _DEFAULT_DATA_PATH
        self._patterns: Dict[str, float] = {}
        self._raw: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(self._data_path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:  # missing/corrupt table -> degrade
            logger.warning("Acceptance: could not load local table %s: %s", self._data_path, exc)
            return
        patterns = data.get("patterns") if isinstance(data, Mapping) else None
        if not isinstance(patterns, Mapping):
            logger.warning("Acceptance: local table has no 'patterns' object")
            return
        for key, entry in patterns.items():
            if not isinstance(entry, Mapping):
                continue
            prob = _clamp(entry.get("acceptance_prob"))
            if prob is None:
                continue
            self._patterns[str(key)] = prob
        self._raw = dict(patterns)

    def is_available(self) -> bool:
        return bool(self._patterns)

    def list_vulnerability_patterns(self) -> Dict[str, float]:
        return dict(self._patterns)

    def acceptance_probability(
        self,
        finding: Dict[str, Any],
        protocol_type: Optional[str] = None,
    ) -> Optional[float]:
        del protocol_type  # local table is protocol-agnostic
        vuln_class = finding_to_vuln_class(finding)
        if vuln_class is None:
            return None
        return self._patterns.get(vuln_class)


class BugBountyIntelligenceProvider(AcceptancePatternProvider):
    """Opt-in adapter for a third-party bug-bounty-intelligence service.

    Availability is gated by three independent conditions (all required):

    1. The acceptance policy allows remote traffic (``allow_remote=True``).
    2. Config enablement (``enabled=True`` passed via ``config``).
    3. An API key present in the ``MIESC_BUGBOUNTY_API_KEY`` environment
       variable (env var name mirrors the certora ``api_key_env`` convention).

    All outbound requests pass :func:`guard_outbound_url` with a host allowlist,
    so localhost / private / reserved targets are rejected (SSRF-safe).
    """

    name = "bugbounty-intelligence"

    #: The vendor's FREE, cheap "list patterns" endpoint (illustrative host).
    #: Overridable via config ``base_url``; must be HTTPS and pass the guard.
    _DEFAULT_BASE_URL = "https://api.bugbounty-intelligence.example"

    def __init__(
        self,
        *,
        config: Optional[Mapping[str, Any]] = None,
        policy: Optional[AcceptancePolicy] = None,
        opener: Optional[Any] = None,
    ) -> None:
        cfg = dict(config or {})
        self._policy = policy or AcceptancePolicy()
        self._enabled = bool(cfg.get("enabled", False))
        self._api_key_env = str(cfg.get("api_key_env") or _BUGBOUNTY_API_KEY_ENV)
        self._base_url = str(cfg.get("base_url") or self._DEFAULT_BASE_URL).rstrip("/")
        # Injectable opener keeps tests fully offline (no real network).
        self._opener = opener

    # -- opt-in gating ------------------------------------------------------

    def _api_key(self) -> str:
        return os.environ.get(self._api_key_env, "").strip()

    def is_available(self) -> bool:
        if not self._policy.allow_remote:
            return False
        if not self._enabled:
            return False
        return bool(self._api_key())

    # -- port surface -------------------------------------------------------

    def list_vulnerability_patterns(self) -> Dict[str, float]:
        """Call the vendor's FREE list endpoint. Returns ``{}`` on any failure."""
        if not self.is_available():
            return {}
        url = f"{self._base_url}/v1/vulnerability-patterns"
        payload = self._get_json(url)
        if not isinstance(payload, Mapping):
            return {}
        raw = payload.get("patterns", payload)
        result: Dict[str, float] = {}
        if isinstance(raw, Mapping):
            for key, value in raw.items():
                prob = _clamp(
                    value if not isinstance(value, Mapping) else value.get("acceptance_prob")
                )
                if prob is not None:
                    result[str(key)] = prob
        return result

    def acceptance_probability(
        self,
        finding: Dict[str, Any],
        protocol_type: Optional[str] = None,
    ) -> Optional[float]:
        del protocol_type
        if not self.is_available():
            return None
        vuln_class = finding_to_vuln_class(finding)
        if vuln_class is None:
            return None
        return self.list_vulnerability_patterns().get(vuln_class)

    def scan_contract(self, *args: Any, **kwargs: Any) -> Any:
        """Paid, x402-metered per-contract scan — an opt-in extension point.

        Deliberately unimplemented in the public core: it would require an
        on-chain payment integration we do not ship.
        """
        raise NotImplementedError(
            "paid x402 scan is an opt-in extension point; not shipped in core"
        )

    # -- guarded transport --------------------------------------------------

    def _get_json(self, url: str) -> Optional[Any]:
        """HTTPS GET ``url`` after SSRF validation. Never raises; ``None`` on error."""
        if not self._policy.allow_remote:
            logger.info("Acceptance: remote disabled by policy, not calling %s", url)
            return None
        try:
            allowed_host = self._host_of(self._base_url)
            guard_outbound_url(url, allowed_hosts=[allowed_host] if allowed_host else None)
        except SSRFError as exc:
            logger.warning("Acceptance: URL rejected by SSRF guard, not calling: %s", exc)
            return None
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key()}",
                "User-Agent": "MIESC-acceptance",
            },
            method="GET",
        )
        try:
            opener = self._opener or urllib.request.urlopen
            with opener(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                body = response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            logger.warning("Acceptance: failed to reach service: %s", exc)
            return None
        try:
            return json.loads(body)
        except (ValueError, TypeError) as exc:
            logger.warning("Acceptance: invalid JSON from service: %s", exc)
            return None

    @staticmethod
    def _host_of(base_url: str) -> str:
        from urllib.parse import urlparse

        return (urlparse(base_url).hostname or "").lower()


def auto_acceptance_provider(
    prefer_local: bool = True,
    *,
    config: Optional[Mapping[str, Any]] = None,
    policy: Optional[AcceptancePolicy] = None,
) -> AcceptancePatternProvider:
    """Return an acceptance provider suitable for DPG local-first workflows.

    Returns the offline :class:`LocalAcceptancePatternProvider` by default. The
    external :class:`BugBountyIntelligenceProvider` is returned only when the
    caller explicitly opts in (``prefer_local=False`` with an enabled config and
    a remote-allowing policy) AND that provider reports itself available;
    otherwise it falls back to local.
    """
    if prefer_local or config is None:
        return LocalAcceptancePatternProvider()

    effective_policy = policy or AcceptancePolicy(allow_remote=True)
    external = BugBountyIntelligenceProvider(config=config, policy=effective_policy)
    if external.is_available():
        return external
    return LocalAcceptancePatternProvider()


__all__ = [
    "LocalAcceptancePatternProvider",
    "BugBountyIntelligenceProvider",
    "auto_acceptance_provider",
]
