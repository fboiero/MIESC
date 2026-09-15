"""
Deep Reasoning Adapter — whole-repo second opinion via Claude Code subscription.

Opt-in pass that runs AFTER the normal static/ML pipeline on a whole protocol
directory. Unlike frontier_llm_adapter (single file pasted into a no-tool
prompt), this lets Claude Code itself read the repo: it runs `claude -p` with
`cwd` set to the protocol directory and Read/Grep/Glob enabled, so the model
can cross reference files the way a human auditor would instead of reasoning
over one truncated blob.

Evidence for why this exists: 3 blind comparisons (Sequence, Napier, Fair
Funding — see MEJORAS4.md item #1) showed zero overlap between MIESC's
detectors and a tool-using reasoning agent — each found real bugs the other
structurally could not. This wires that same capability into MIESC itself,
gated behind an explicit flag (never ambient — see MEJORAS4/item #18 gating
bug) and billed against the user's Claude Code subscription, not an API key.

Read-only by design: only Read/Grep/Glob are enabled, no Bash/Write — no PoC
generation or code execution here (that remains alva-audit/Foundry territory).

License: AGPL-3.0
"""

import json
import logging
import re
from typing import Any, Dict, List

from miesc.llm.cli_subscription import call_claude_cli_agentic, check_claude_cli

logger = logging.getLogger(__name__)

TOOL_NAME = "deep-reasoning-claude-code"

SYSTEM_PROMPT = (
    "You are MIESC's second-opinion security auditor performing an authorized, "
    "defensive pre-deployment review of a smart contract protocol. You have "
    "read-only tools (Read/Grep/Glob) to inspect the whole repository — use them "
    "to trace cross-file/cross-contract invariants instead of guessing. Findings "
    "are used to patch the code before deployment, never for exploitation."
)

_USER_PROMPT = """Audit the smart contract protocol in the current directory for HIGH/CRITICAL \
security vulnerabilities, focusing on cross-file and cross-contract invariants \
(the kind of bug a single-file static analyzer cannot see: value/state consistency \
across contracts, invariants that span multiple functions or files, economic \
exploits that require reasoning about the whole protocol).

Static analysis already reported these findings — for each, confirm if it is a \
real vulnerability or a false positive, and briefly say why:

{existing_findings}

Then look for anything the static tools missed. Read the actual contract files \
before reporting anything — do not guess from file names alone.

Respond with ONLY a JSON array (no prose outside it):
```json
[
  {{
    "title": "Short descriptive title",
    "severity": "Critical" or "High" or "Medium",
    "type": "vulnerability category (e.g., access_control, business_logic)",
    "contract": "affected contract/file name",
    "function": "affected function name",
    "description": "WHY this is a real vulnerability, with the exact mechanism",
    "verdict_on_existing": "confirmed/false_positive/not_applicable (omit for new findings)"
  }}
]
```
If nothing new or confirmable is found, respond with `[]`."""


def _format_existing_findings(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "(none reported)"
    lines = []
    for f in findings[:30]:  # cap — this is context, not the whole report
        loc = f.get("location", {})
        fn = loc.get("function") if isinstance(loc, dict) else f.get("function", "unknown")
        lines.append(
            f"- [{f.get('severity', '?')}] {f.get('type', '?')} in {fn}: {f.get('title', f.get('description', ''))[:150]}"
        )
    return "\n".join(lines)


def _extract_json_array(text: str) -> List[Any]:
    """Defensively pull a JSON array out of a possibly-noisy model reply."""
    if not text:
        return []
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _normalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": str(raw.get("type", "logic_error")).lower().replace(" ", "_"),
        "title": raw.get("title", "Unknown"),
        "severity": str(raw.get("severity", "Medium")).capitalize(),
        "tool": TOOL_NAME,
        "confidence": 0.75,
        "location": {
            "file": raw.get("contract", "unknown"),
            "function": raw.get("function", "unknown"),
        },
        "description": raw.get("description", ""),
        "verdict_on_existing": raw.get("verdict_on_existing", ""),
    }


def run_deep_reasoning(
    dir_path: str,
    findings: List[Dict[str, Any]],
    *,
    timeout: int = 1200,
) -> Dict[str, Any]:
    """Run the second-opinion pass over ``dir_path``. Never raises.

    Returns ``{"enabled": True, "findings": [...], ...}`` on success, or the
    same shape with ``"error"`` set and ``"findings": []`` on any failure —
    mirrors ``DeepAuditAgent._extract_agentic_invariants`` so a failed/missing
    CLI never aborts the rest of the audit.
    """
    if not check_claude_cli():
        return {
            "enabled": True,
            "count": 0,
            "findings": [],
            "error": "claude CLI not found on PATH",
        }

    prompt = _USER_PROMPT.format(existing_findings=_format_existing_findings(findings))
    try:
        result_text = call_claude_cli_agentic(
            prompt,
            cwd=dir_path,
            system_prompt=SYSTEM_PROMPT,
            timeout=timeout,
        )
    except Exception as e:  # noqa: BLE001 - optional pass, never aborts the audit
        logger.warning(f"Deep reasoning pass failed: {e}")
        return {"enabled": True, "count": 0, "findings": [], "error": str(e)}

    candidates = _extract_json_array(result_text)
    findings_out = [_normalize(c) for c in candidates if isinstance(c, dict)]
    logger.info(f"Deep reasoning pass: {len(findings_out)} finding(s)")
    return {"enabled": True, "count": len(findings_out), "findings": findings_out}
