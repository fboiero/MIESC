"""
Plugin API Versioning - Stable, Versioned Plugin Contract
=========================================================

Defines the explicit, versioned MIESC Plugin API contract and the
compatibility rules used to decide whether a community plugin built
against one API version can be loaded by the current host.

The Plugin API is **versioned, not frozen**. It evolves under semantic
versioning so the community can build on a stable surface:

- **MAJOR** bump  -> breaking change to the plugin protocol (methods
  removed/renamed, required signatures changed). Plugins built for a
  different MAJOR are rejected.
- **MINOR** bump  -> backward-compatible additions (new optional hooks,
  new services). A plugin that targets a *newer* MINOR than the host
  provides needs features the host lacks and is rejected; a plugin that
  targets an *older or equal* MINOR is accepted (the host is backward
  compatible within a MAJOR line).
- **PATCH** bump  -> internal fixes, always compatible. Ignored for the
  compatibility decision.

Usage:
    from miesc.plugins.version import (
        PLUGIN_API_VERSION,
        check_api_compatibility,
        ApiCompatStatus,
    )

    result = check_api_compatibility("1.0.0")
    if not result.compatible:
        raise RuntimeError(result.message)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: July 2026
Version: 1.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# The current, stable Plugin API version exposed by this host.
#
# Bump this using semantic versioning when the plugin protocol changes:
#   - MAJOR: breaking change to MIESCPlugin / specialized base classes
#   - MINOR: backward-compatible additions (new optional hooks/services)
#   - PATCH: internal fixes with no protocol impact
# ---------------------------------------------------------------------------
PLUGIN_API_VERSION = "1.0.0"

_SEMVER_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)")


class ApiCompatStatus(Enum):
    """Outcome of a plugin-API compatibility check."""

    COMPATIBLE = "compatible"
    # Plugin targets a different MAJOR than the host -> breaking mismatch.
    INCOMPATIBLE_MAJOR = "incompatible_major"
    # Plugin targets a newer MINOR than the host provides -> host too old.
    INCOMPATIBLE_MINOR = "incompatible_minor"
    # The declared version could not be parsed as semver.
    INVALID = "invalid"


@dataclass(frozen=True)
class ApiCompatResult:
    """Structured result of a compatibility check."""

    status: ApiCompatStatus
    plugin_api_version: str
    host_api_version: str
    message: str

    @property
    def compatible(self) -> bool:
        """True only when the plugin can be safely loaded."""
        return self.status == ApiCompatStatus.COMPATIBLE

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "compatible": self.compatible,
            "plugin_api_version": self.plugin_api_version,
            "host_api_version": self.host_api_version,
            "message": self.message,
        }


def parse_api_version(version: str) -> Optional[Tuple[int, int, int]]:
    """Parse a semver string into a (major, minor, patch) tuple.

    Args:
        version: Version string such as ``"1.2.3"`` (trailing pre-release /
            build metadata is ignored).

    Returns:
        A ``(major, minor, patch)`` tuple, or ``None`` if the string is not a
        valid semantic version.
    """
    if not isinstance(version, str):
        return None
    match = _SEMVER_RE.match(version)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def check_api_compatibility(
    plugin_api_version: str,
    host_api_version: str = PLUGIN_API_VERSION,
) -> ApiCompatResult:
    """Decide whether a plugin's declared API version is loadable.

    Compatibility rule (semantic versioning):

    * ``MAJOR`` must match exactly. A different MAJOR means the protocol
      changed in a breaking way -> ``INCOMPATIBLE_MAJOR``.
    * Within the same MAJOR, the plugin's ``MINOR`` must be ``<=`` the host's
      MINOR. A newer MINOR means the plugin expects API additions the host
      does not provide -> ``INCOMPATIBLE_MINOR``.
    * ``PATCH`` is ignored for the decision.

    Args:
        plugin_api_version: API version the plugin was built against.
        host_api_version: API version provided by this host (defaults to the
            current :data:`PLUGIN_API_VERSION`).

    Returns:
        An :class:`ApiCompatResult` describing the outcome with an actionable
        message.
    """
    plugin_parts = parse_api_version(plugin_api_version)
    host_parts = parse_api_version(host_api_version)

    if plugin_parts is None:
        return ApiCompatResult(
            status=ApiCompatStatus.INVALID,
            plugin_api_version=str(plugin_api_version),
            host_api_version=host_api_version,
            message=(
                f"Plugin declares an invalid API version "
                f"{plugin_api_version!r}; expected semantic version "
                f"'MAJOR.MINOR.PATCH' (host API {host_api_version})."
            ),
        )

    if host_parts is None:  # pragma: no cover - host constant is always valid
        return ApiCompatResult(
            status=ApiCompatStatus.INVALID,
            plugin_api_version=plugin_api_version,
            host_api_version=str(host_api_version),
            message=f"Host API version {host_api_version!r} is not valid semver.",
        )

    p_major, p_minor, _ = plugin_parts
    h_major, h_minor, _ = host_parts

    if p_major != h_major:
        return ApiCompatResult(
            status=ApiCompatStatus.INCOMPATIBLE_MAJOR,
            plugin_api_version=plugin_api_version,
            host_api_version=host_api_version,
            message=(
                f"Plugin targets Plugin API v{plugin_api_version} but this "
                f"host provides v{host_api_version}. MAJOR versions differ "
                f"({p_major} vs {h_major}); the plugin protocol is "
                f"incompatible. "
                + (
                    "Upgrade MIESC to a host that provides this API major."
                    if p_major > h_major
                    else "Update the plugin to target the current Plugin API."
                )
            ),
        )

    if p_minor > h_minor:
        return ApiCompatResult(
            status=ApiCompatStatus.INCOMPATIBLE_MINOR,
            plugin_api_version=plugin_api_version,
            host_api_version=host_api_version,
            message=(
                f"Plugin targets Plugin API v{plugin_api_version} which needs "
                f"MINOR {p_minor}, but this host only provides "
                f"v{host_api_version} (MINOR {h_minor}). Upgrade MIESC to a "
                f"host that provides Plugin API >= {p_major}.{p_minor}."
            ),
        )

    return ApiCompatResult(
        status=ApiCompatStatus.COMPATIBLE,
        plugin_api_version=plugin_api_version,
        host_api_version=host_api_version,
        message=(
            f"Plugin API v{plugin_api_version} is compatible with host "
            f"v{host_api_version}."
        ),
    )


__all__ = [
    "PLUGIN_API_VERSION",
    "ApiCompatStatus",
    "ApiCompatResult",
    "parse_api_version",
    "check_api_compatibility",
]
