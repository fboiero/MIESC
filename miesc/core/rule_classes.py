"""
Rule classes: lint / informational detector rules cannot outrank real findings.

The table lives in ``miesc/data/config/rule_classes.yaml`` (shipped with the
package). A rule listed there has a class, and a class has a severity ceiling:
``lint`` → Low, ``informational`` → Info. :func:`cap_severity` is the single
entry point; the intelligence engine, the ML orchestrator and the CLI tool
runner all call it so every report agrees.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml  # type: ignore[import-untyped]

RULE_CLASSES_PATH = Path(__file__).resolve().parent.parent / "data" / "config" / "rule_classes.yaml"

_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
_CANON = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# Keys, in priority order, under which adapters store the detector rule id.
_RULE_KEYS = ("rule", "check", "_aderyn_detector", "detector", "type")


@lru_cache(maxsize=4)
def load_rule_classes(path: Optional[str] = None) -> Dict[str, Any]:
    """Parse the table once per process. Returns ``{classes, rules}`` with
    tool and rule names lower-cased."""
    source = Path(path) if path else RULE_CLASSES_PATH
    with source.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    classes = {
        str(name).lower(): dict(spec or {}) for name, spec in (raw.get("classes") or {}).items()
    }
    rules: Dict[str, Dict[str, str]] = {}
    for tool, table in (raw.get("rules") or {}).items():
        rules[str(tool).lower()] = {
            str(rule).lower(): str(cls).lower() for rule, cls in (table or {}).items()
        }
    return {"classes": classes, "rules": rules}


def rule_ids(finding: Dict[str, Any]) -> Iterable[str]:
    """Every string a finding uses to name its detector rule (``rule``,
    ``check``, ``type`` …), most specific first."""
    seen = set()
    for key in _RULE_KEYS:
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            lowered = value.strip().lower()
            if lowered not in seen:
                seen.add(lowered)
                yield lowered


def rule_class(tool: str, rule: str) -> Optional[str]:
    """Class of ``rule`` as reported by ``tool`` (``"lint"``, ``"informational"``)
    or ``None`` when the rule is not in the table (treated as security)."""
    table = load_rule_classes()["rules"].get((tool or "").lower())
    if not table:
        return None
    return table.get((rule or "").lower())


def finding_rule_class(finding: Dict[str, Any]) -> Optional[str]:
    """:func:`rule_class` over every rule id the finding carries."""
    tool = str(finding.get("tool") or "")
    for rule in rule_ids(finding):
        cls = rule_class(tool, rule)
        if cls:
            return cls
    return None


def class_max_severity(cls: str) -> Optional[str]:
    spec = load_rule_classes()["classes"].get((cls or "").lower())
    if not spec:
        return None
    ceiling = str(spec.get("max_severity") or "").lower()
    return _CANON.get(ceiling)


def severity_rank(severity: Any) -> int:
    return _RANK.get(str(severity or "").lower(), 0)


def cap_severity(tool: str, rule: str, severity: Any) -> Any:
    """``severity`` lowered to the ceiling of the rule's class, or returned
    unchanged (same object) when the rule has no class or is already below it."""
    cls = rule_class(tool, rule)
    ceiling = class_max_severity(cls) if cls else None
    if ceiling and severity_rank(severity) > severity_rank(ceiling):
        return ceiling
    return severity


def cap_finding_severity(finding: Dict[str, Any]) -> bool:
    """Apply :func:`cap_severity` to one finding in place. Records the original
    value in ``severity_before_class_cap`` and the class in ``rule_class``.
    Returns True when the severity changed."""
    cls = finding_rule_class(finding)
    if not cls:
        return False
    finding.setdefault("rule_class", cls)
    ceiling = class_max_severity(cls)
    current = finding.get("severity")
    if ceiling and severity_rank(current) > severity_rank(ceiling):
        finding["severity_before_class_cap"] = current
        finding["severity"] = ceiling
        return True
    return False


def apply_rule_class_caps(findings: Iterable[Dict[str, Any]]) -> int:
    """Cap every finding in ``findings``; returns how many were lowered."""
    return sum(1 for f in findings if isinstance(f, dict) and cap_finding_severity(f))


__all__ = [
    "RULE_CLASSES_PATH",
    "apply_rule_class_caps",
    "cap_finding_severity",
    "cap_severity",
    "class_max_severity",
    "finding_rule_class",
    "load_rule_classes",
    "rule_class",
    "rule_ids",
    "severity_rank",
]
