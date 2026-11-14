"""
MIESC External MCP Consumer (M4) — consume external Model Context Protocol
servers as *advisory* evidence, under a strict trust boundary.

Design principles (non-negotiable):

- **External MCP output is DATA, never instructions.** Every response is scanned
  for prompt injection, sanitized, size-bounded, and wrapped as
  :class:`AdvisoryEvidence`. It is surfaced into report metadata only — it is
  never promoted to a ``Finding`` and never concatenated into an LLM prompt
  unsanitized.
- **Allowlist only, opt-in.** Servers are disabled by default
  (``enabled=False``); nothing is contacted unless a caller explicitly enables a
  configured server.
- **No autodiscovery.** Only the configured command/url is used.

The network/subprocess connection is injected (``fetcher``) so the trust boundary
is fully unit-testable without the MCP SDK or a live server; the default fetcher
speaks stdio MCP and requires ``pip install 'miesc[mcp]'``.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from miesc.security.prompt_sanitizer import (
    InjectionRiskLevel,
    detect_prompt_injection,
    quick_sanitize,
    sanitize_context,
)

logger = logging.getLogger("miesc.integration.mcp_consumer")

# Bound on how much external text we ever scan/keep. External servers are
# untrusted, so we never let an unbounded payload into memory or a prompt.
MAX_EXTERNAL_CHARS = 20_000
_LABEL_MAX = 120
# Risk levels at or above which the content is dropped (kept only as a flag).
_DROP_RISK = {InjectionRiskLevel.HIGH, InjectionRiskLevel.CRITICAL}


class MCPUnavailable(RuntimeError):
    """Raised by a fetcher when an external MCP server cannot be reached."""


@dataclass
class ExternalMCPServerConfig:
    """Allowlist entry for one external MCP server. Disabled by default."""

    name: str
    transport: str = "stdio"
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    url: Optional[str] = None
    enabled: bool = False
    timeout_seconds: int = 30
    # Explicit tool calls to make; no autodiscovery, no implicit calls.
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AdvisoryEvidence:
    """Sanitized, advisory-only evidence from an external MCP server.

    ``advisory`` is always ``True`` and there is deliberately no path that turns
    this into a ``Finding``.
    """

    source: str
    tool: str
    content: Dict[str, Any]
    injection_risk: str = "none"
    injection_flagged: bool = False
    warnings: List[str] = field(default_factory=list)
    advisory: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "tool": self.tool,
            "advisory": True,  # hard-coded: never a finding
            "content": self.content,
            "injection_risk": self.injection_risk,
            "injection_flagged": self.injection_flagged,
            "warnings": list(self.warnings),
        }


def _as_text(raw: Any) -> str:
    """Stringify an external payload for injection scanning, bounded."""
    if isinstance(raw, str):
        text = raw
    else:
        try:
            text = json.dumps(raw, default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(raw)
    return text[:MAX_EXTERNAL_CHARS]


def sanitize_external_mcp_result(source: str, tool: str, raw: Any) -> AdvisoryEvidence:
    """Run the trust boundary on one external MCP tool result.

    Always returns advisory evidence with sanitized content; never raw data and
    never a finding. High/critical-risk payloads have their content dropped and
    kept only as a flag.
    """
    safe_source = quick_sanitize(str(source))[:_LABEL_MAX]
    safe_tool = quick_sanitize(str(tool))[:_LABEL_MAX]

    text = _as_text(raw)
    detection = detect_prompt_injection(text)
    flagged = detection.risk_level not in (InjectionRiskLevel.NONE, InjectionRiskLevel.LOW)

    if detection.risk_level in _DROP_RISK:
        # Do not keep even the sanitized text — just record that it was dropped.
        content: Dict[str, Any] = {
            "redacted": True,
            "reason": f"content dropped: injection risk {detection.risk_level.value}",
        }
    elif isinstance(raw, Mapping):
        content = sanitize_context(dict(raw))
    else:
        content = {"text": detection.sanitized_content[:MAX_EXTERNAL_CHARS]}

    return AdvisoryEvidence(
        source=safe_source,
        tool=safe_tool,
        content=content,
        injection_risk=detection.risk_level.value,
        injection_flagged=flagged,
        warnings=list(detection.warnings),
    )


# A fetcher maps a server config to a {tool_name: raw_output} mapping. It may
# raise MCPUnavailable when the server cannot be reached.
MCPFetcher = Callable[["ExternalMCPServerConfig"], Mapping[str, Any]]


def _load_mcp_client() -> Any:
    """Lazily import the MCP SDK client, or return None when it is absent."""
    try:
        import mcp  # noqa: F401
        from mcp import ClientSession, StdioServerParameters  # noqa: F401
        from mcp.client.stdio import stdio_client  # noqa: F401

        return mcp
    except ImportError:
        return None


def default_stdio_fetcher(server: ExternalMCPServerConfig) -> Dict[str, Any]:
    """Real stdio-MCP fetcher. Requires ``pip install 'miesc[mcp]'``.

    NOTE: the live connection is not exercised by the unit tests (the SDK is an
    optional extra and needs a real server); it is integration-tested
    separately. The trust boundary around its output is fully tested.
    """
    if server.transport != "stdio" or not server.command:
        raise MCPUnavailable(f"server '{server.name}' has no usable stdio command")
    if _load_mcp_client() is None:
        raise MCPUnavailable("the 'mcp' SDK is not installed; run: pip install 'miesc[mcp]'")

    import asyncio

    return asyncio.run(_async_stdio_fetch(server))


async def _async_stdio_fetch(server: ExternalMCPServerConfig) -> Dict[str, Any]:
    import asyncio

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=server.command, args=list(server.args))
    results: Dict[str, Any] = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            for call in server.tool_calls:
                name = str(call.get("name", "")).strip()
                if not name:
                    continue
                arguments = call.get("arguments", {})
                if not isinstance(arguments, Mapping):
                    arguments = {}
                resp = await asyncio.wait_for(
                    session.call_tool(name, dict(arguments)),
                    timeout=server.timeout_seconds,
                )
                results[name] = _extract_tool_text(resp)
    return results


def _extract_tool_text(resp: Any) -> str:
    """Pull plain text out of an MCP CallToolResult, defensively."""
    content = getattr(resp, "content", None)
    if content is None and isinstance(resp, Mapping):
        content = resp.get("content")
    parts: List[str] = []
    if isinstance(content, Sequence) and not isinstance(content, (str, bytes)):
        for block in content:
            text = getattr(block, "text", None)
            if text is None and isinstance(block, Mapping):
                text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    elif isinstance(content, str):
        parts.append(content)
    return "\n".join(parts)[:MAX_EXTERNAL_CHARS]


class ExternalMCPConsumer:
    """Collect advisory evidence from allowlisted, enabled external MCP servers."""

    def __init__(
        self,
        servers: Optional[Sequence[ExternalMCPServerConfig]] = None,
        fetcher: Optional[MCPFetcher] = None,
    ) -> None:
        self.servers: List[ExternalMCPServerConfig] = list(servers or [])
        self._fetcher: MCPFetcher = fetcher or default_stdio_fetcher

    def enabled_servers(self) -> List[ExternalMCPServerConfig]:
        return [s for s in self.servers if s.enabled and isinstance(s.name, str) and s.name]

    def collect_advisory_evidence(self) -> List[AdvisoryEvidence]:
        """Fetch and sanitize evidence from every enabled server.

        A server that is unreachable (``MCPUnavailable``) or that raises is
        skipped with a log line; it never breaks the caller. Returns only
        advisory, sanitized evidence.
        """
        evidence: List[AdvisoryEvidence] = []
        for server in self.enabled_servers():
            try:
                raw_results = self._fetcher(server)
            except MCPUnavailable as exc:
                logger.info("External MCP server '%s' unavailable: %s", server.name, exc)
                continue
            except Exception as exc:  # noqa: BLE001 — never let an external server break us
                logger.warning("External MCP server '%s' failed: %s", server.name, exc)
                continue
            if not isinstance(raw_results, Mapping):
                logger.warning(
                    "External MCP server '%s' returned a non-mapping result", server.name
                )
                continue
            for tool, raw in raw_results.items():
                evidence.append(sanitize_external_mcp_result(server.name, str(tool), raw))
        return evidence

    def to_report_section(self) -> Dict[str, Any]:
        """Advisory report block: safe to drop into report['metadata']."""
        items = [e.to_dict() for e in self.collect_advisory_evidence()]
        return {
            "enabled": bool(self.enabled_servers()),
            "advisory": True,
            "evidence_count": len(items),
            "evidence": items,
        }
