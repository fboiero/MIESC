"""
Notifier sinks (webhook / Slack)
================================

Post a compact scan summary to an external sink so CI can alert a channel on
findings. Two sinks are supported:

- **Generic webhook**: POSTs a JSON summary (severity counts, pass/fail, the
  top findings) to an arbitrary URL.
- **Slack**: POSTs a Slack *Block Kit* payload (header + summary + a few
  findings) to a Slack Incoming Webhook URL.

Security
--------
Both sinks make an outbound HTTP request to a **user-configured URL**, which is
a classic SSRF vector. Every URL is validated with the shared
:func:`miesc.core.net_guard.guard_outbound_url` guard (blocks localhost,
private / reserved / link-local IPs and cloud metadata endpoints) *before* any
socket is opened. Network failures never propagate: a notifier that cannot
reach its sink logs a warning and returns ``False`` so the scan still completes.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from miesc.core.baseline import normalize_finding
from miesc.core.net_guard import SSRFError, guard_outbound_url

logger = logging.getLogger(__name__)

#: Outbound request timeout (seconds).
REQUEST_TIMEOUT_SECONDS = 10

#: Default number of findings embedded in a notification payload.
DEFAULT_TOP_N = 5

#: Severity ordering (higher = more severe). Unknown severities rank at INFO.
SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

_SLACK_EMOJI: Dict[str, str] = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_yellow_circle:",
    "info": ":white_circle:",
}


# ---------------------------------------------------------------------------
# Payload shaping
# ---------------------------------------------------------------------------


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get((severity or "info").lower(), 0)


def _iter_findings(results: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for result in results:
        for finding in result.get("findings", []) or []:
            findings.append(finding)
    return findings


def _severity_counts(findings: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = normalize_finding(finding).get("severity", "") or "info"
        sev = sev.lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def _top_findings(
    findings: Sequence[Dict[str, Any]], top_n: int = DEFAULT_TOP_N
) -> List[Dict[str, Any]]:
    """Return the ``top_n`` most-severe findings as compact dicts."""
    ordered = sorted(
        findings,
        key=lambda f: _severity_rank(normalize_finding(f).get("severity", "")),
        reverse=True,
    )
    top: List[Dict[str, Any]] = []
    for finding in ordered[: max(0, top_n)]:
        norm = normalize_finding(finding)
        top.append(
            {
                "severity": norm.get("severity", "") or "info",
                "title": norm.get("rule_id", "") or "finding",
                "file": norm.get("file", "") or "",
                "message": norm.get("message", "") or "",
            }
        )
    return top


def meets_threshold(findings: Sequence[Dict[str, Any]], min_severity: str = "low") -> bool:
    """True if any finding is at least as severe as ``min_severity``."""
    floor = _severity_rank(min_severity)
    return any(_severity_rank(normalize_finding(f).get("severity", "")) >= floor for f in findings)


def build_summary(
    results: Sequence[Dict[str, Any]],
    contract: str,
    *,
    min_severity: str = "low",
    ci_failed: Optional[bool] = None,
    top_n: int = DEFAULT_TOP_N,
) -> Dict[str, Any]:
    """Build the generic JSON summary payload for a webhook sink.

    Args:
        results: Per-tool result dicts (each with a ``findings`` list).
        contract: The scanned contract / path label.
        min_severity: Threshold recorded in the payload (see ``meets_threshold``).
        ci_failed: Explicit pass/fail; when None, fails if any critical/high.
        top_n: Number of findings to embed.
    """
    findings = _iter_findings(results)
    counts = _severity_counts(findings)
    total = sum(counts.values())

    if ci_failed is None:
        ci_failed = (counts["critical"] + counts["high"]) > 0

    return {
        "tool": "MIESC",
        "contract": contract,
        "status": "fail" if ci_failed else "pass",
        "total_findings": total,
        "severity_counts": counts,
        "threshold": min_severity,
        "top_findings": _top_findings(findings, top_n=top_n),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def build_slack_payload(
    results: Sequence[Dict[str, Any]],
    contract: str,
    *,
    min_severity: str = "low",
    ci_failed: Optional[bool] = None,
    top_n: int = DEFAULT_TOP_N,
) -> Dict[str, Any]:
    """Build a Slack Block Kit payload summarising the scan."""
    summary = build_summary(
        results, contract, min_severity=min_severity, ci_failed=ci_failed, top_n=top_n
    )
    counts = summary["severity_counts"]
    failed = summary["status"] == "fail"

    status_icon = ":x:" if failed else ":white_check_mark:"
    status_text = "FAIL" if failed else "PASS"

    counts_line = (
        f"C:{counts['critical']} H:{counts['high']} "
        f"M:{counts['medium']} L:{counts['low']} I:{counts['info']}"
    )

    blocks: List[Dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"MIESC scan: {contract}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{status_icon} *{status_text}* — "
                    f"*{summary['total_findings']}* finding(s)\n{counts_line}"
                ),
            },
        },
    ]

    top = summary["top_findings"]
    if top:
        lines = []
        for finding in top:
            emoji = _SLACK_EMOJI.get(str(finding["severity"]).lower(), ":white_circle:")
            location = f" (`{finding['file']}`)" if finding["file"] else ""
            lines.append(f"{emoji} *{finding['severity'].upper()}* {finding['title']}{location}")
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top findings:*\n" + "\n".join(lines),
                },
            }
        )

    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# Outbound POST (SSRF-guarded, error-swallowing)
# ---------------------------------------------------------------------------


def _post_json(url: str, payload: Dict[str, Any]) -> bool:
    """POST ``payload`` as JSON to ``url`` after SSRF validation.

    Returns True on a 2xx response, False on any validation or network error.
    Never raises — a broken sink must not abort a scan.
    """
    try:
        guard_outbound_url(url)
    except SSRFError as exc:
        logger.warning("Notifier: URL rejected by SSRF guard, not posting: %s", exc)
        return False

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "MIESC-notifier",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", None) or response.getcode()
            if 200 <= int(status) < 300:
                return True
            logger.warning("Notifier: sink returned HTTP %s", status)
            return False
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        logger.warning("Notifier: failed to reach sink: %s", exc)
        return False


def notify_webhook(
    url: str,
    results: Sequence[Dict[str, Any]],
    contract: str,
    *,
    min_severity: str = "low",
    ci_failed: Optional[bool] = None,
) -> bool:
    """POST a generic JSON summary to ``url``. Gated by ``min_severity``."""
    findings = _iter_findings(results)
    if not meets_threshold(findings, min_severity):
        logger.info("Notifier: no findings at/above %r severity; webhook skipped", min_severity)
        return False
    payload = build_summary(results, contract, min_severity=min_severity, ci_failed=ci_failed)
    return _post_json(url, payload)


def notify_slack(
    url: str,
    results: Sequence[Dict[str, Any]],
    contract: str,
    *,
    min_severity: str = "low",
    ci_failed: Optional[bool] = None,
) -> bool:
    """POST a Slack Block Kit summary to ``url``. Gated by ``min_severity``."""
    findings = _iter_findings(results)
    if not meets_threshold(findings, min_severity):
        logger.info("Notifier: no findings at/above %r severity; Slack skipped", min_severity)
        return False
    payload = build_slack_payload(results, contract, min_severity=min_severity, ci_failed=ci_failed)
    return _post_json(url, payload)


def dispatch_notifications(
    results: Sequence[Dict[str, Any]],
    contract: str,
    *,
    webhook_url: Optional[str] = None,
    slack_url: Optional[str] = None,
    min_severity: str = "low",
    ci_failed: Optional[bool] = None,
) -> Dict[str, bool]:
    """Fan a scan result out to any configured sinks.

    Returns a map of sink name -> delivered (True) / skipped-or-failed (False).
    Safe to call unconditionally; a missing URL is a no-op.
    """
    delivered: Dict[str, bool] = {}
    if webhook_url:
        delivered["webhook"] = notify_webhook(
            webhook_url, results, contract, min_severity=min_severity, ci_failed=ci_failed
        )
    if slack_url:
        delivered["slack"] = notify_slack(
            slack_url, results, contract, min_severity=min_severity, ci_failed=ci_failed
        )
    return delivered
