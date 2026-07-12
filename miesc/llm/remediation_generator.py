"""
Remediation Code Generator for MIESC
=====================================

LLM-based generator for producing fixed code and remediation guidance
for detected vulnerabilities.

Features:
- Context-aware code fixes
- OpenZeppelin pattern suggestions
- Test case generation
- Diff-style output

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Institution: UNDEF - IUA
Date: January 2026
"""

import asyncio
import json
import logging
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from miesc.security.llm_output_validator import (
    extract_json_from_text,
    repair_common_json_errors,
)

_EXPORT_PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EXPORT_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_EXPORT_DIFF_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@(?: .*)?$")
_EXPORT_REFERENCE_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_EXPORT_REFERENCE_URL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://|^www\.", re.IGNORECASE)
_EXPORT_REFERENCE_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_EXPORT_MARKDOWN_LINK_RE = re.compile(r"^\[([^\]\x00-\x1f\x7f]+)\]\(([^()\s\x00-\x1f\x7f]+)\)$")
_EXPORT_TEST_NAME_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_OLLAMA_MODEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_SOLIDITY_IMPORT_RE = re.compile(
    r"""^import\s+(?:(?:"[^"\x00-\x1f\x7f]+"|'[^'\x00-\x1f\x7f]+')|(?:\{[^{}\x00-\x1f\x7f]+\}\s+from\s+(?:"[^"\x00-\x1f\x7f]+"|'[^'\x00-\x1f\x7f]+'))|(?:[A-Za-z_$][\w$]*\s+from\s+(?:"[^"\x00-\x1f\x7f]+"|'[^'\x00-\x1f\x7f]+')))\s*;$"""
)
MAX_LLM_RESPONSE_CHARS = 50_000
MAX_JSON_RESPONSE_CHARS = 100_000
MAX_JSON_RESPONSE_KEYS = 100
MAX_BATCH_FINDINGS = 500
MAX_CONCURRENT_REMEDIATIONS = 20
MAX_REMEDIATION_EXPORTS = 500
MAX_TIMEOUT_SECONDS = 600
MAX_SAFE_TEXT_CHARS = 100_000
MAX_PROMPT_FIELD_CHARS = 8_000
MAX_METADATA_LIST_ITEMS = 100
MAX_PATH_FIELD_CHARS = 240
MAX_REFERENCE_LABEL_CHARS = 200
MAX_REFERENCE_URL_CHARS = 2_000


def _is_unsafe_text_char(ch: str, *, allow_multiline: bool = False) -> bool:
    codepoint = ord(ch)
    if codepoint == 127:
        return True
    if allow_multiline and ch in "\n\r\t":
        return False
    if codepoint < 32:
        return True
    return codepoint in {0x2028, 0x2029}


def _safe_mapping_get(mapping: Any, key: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    try:
        return mapping.get(key, default)
    except (AttributeError, TypeError, RuntimeError, ValueError):
        return default


def _safe_text(value: Any, *, allow_multiline: bool = False) -> str:
    """Return stripped safe text, or an empty string for malformed values."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return ""
    if not isinstance(value, str):
        return ""
    if any(
        ord(ch) == 127 or ord(ch) in {0x2028, 0x2029} or (ord(ch) < 32 and ch not in "\n\r\t ")
        for ch in value
    ):
        return ""
    try:
        text = value.strip()
    except Exception:
        return ""
    if not text:
        return ""
    try:
        if len(text) > MAX_SAFE_TEXT_CHARS:
            return ""
    except Exception:
        return ""
    if allow_multiline:
        if any(_is_unsafe_text_char(ch, allow_multiline=True) for ch in text):
            return ""
    elif any(_is_unsafe_text_char(ch) for ch in text):
        return ""
    return text


def _safe_text_limited(
    value: Any,
    *,
    allow_multiline: bool = False,
    limit: int = MAX_PROMPT_FIELD_CHARS,
) -> str:
    """Return safe text truncated to a caller-specific boundary."""
    text = _safe_text(value, allow_multiline=allow_multiline)
    if not text:
        return ""
    if isinstance(limit, bool):
        limit = MAX_PROMPT_FIELD_CHARS
    try:
        normalized_limit = int(limit)
    except (TypeError, ValueError, OverflowError):
        normalized_limit = MAX_PROMPT_FIELD_CHARS
    if normalized_limit <= 0:
        normalized_limit = MAX_PROMPT_FIELD_CHARS
    return text[:normalized_limit]


def _bounded_list(value: Any, *, limit: int = MAX_METADATA_LIST_ITEMS) -> List[Any]:
    """Return a bounded list copy without trusting list subclass helpers."""
    if not isinstance(value, list):
        return []
    if isinstance(limit, bool):
        limit = MAX_METADATA_LIST_ITEMS
    try:
        normalized_limit = int(limit)
    except (TypeError, ValueError, OverflowError):
        normalized_limit = MAX_METADATA_LIST_ITEMS
    if normalized_limit <= 0:
        normalized_limit = MAX_METADATA_LIST_ITEMS
    copied = []
    try:
        iterator = iter(value)
    except (TypeError, RuntimeError, ValueError):
        return []
    try:
        for item in iterator:
            if len(copied) >= normalized_limit:
                break
            copied.append(item)
    except (TypeError, RuntimeError, ValueError):
        return copied
    return copied


def _safe_error_text(value: Any, default: str = "error", *, limit: int = 200) -> str:
    """Return single-line diagnostic text without trusting exception/string shapes."""
    text = _safe_text(value)
    return (text or default)[:limit]


def _export_string(value: Any, default: str) -> str:
    """Return a non-empty string for export payloads."""
    if isinstance(value, str):
        normalized = value.strip()
        if normalized and not any(_is_unsafe_text_char(ch) for ch in normalized):
            return normalized
    return default


def _export_code_or_patch_text(value: Any, default: str) -> str:
    """Return code/patch text only when diff hunk headers are well formed."""
    if not isinstance(value, str):
        return default

    normalized = value.strip()
    if not normalized:
        return default

    if any(_is_unsafe_text_char(ch, allow_multiline=True) for ch in normalized):
        return default

    for line in normalized.splitlines():
        stripped = line.strip()
        if stripped.startswith("@@") and not _EXPORT_DIFF_HUNK_RE.fullmatch(stripped):
            return default

    return normalized


def _export_optional_string(value: Any) -> Optional[str]:
    """Return a non-empty optional string for export payloads."""
    if isinstance(value, str):
        normalized = value.strip()
        if normalized and not any(_is_unsafe_text_char(ch) for ch in normalized):
            return normalized
    return None


def _export_patch_filename(value: Any) -> Optional[str]:
    """Return a safe patch filename without path traversal or separators."""
    normalized = _export_optional_string(value)
    if (
        normalized is None
        or len(normalized) > MAX_PATH_FIELD_CHARS
        or normalized in {".", ".."}
        or "/" in normalized
        or "\\" in normalized
        or _EXPORT_WINDOWS_DRIVE_RE.match(normalized)
        or _EXPORT_PATH_CONTROL_RE.search(normalized)
    ):
        return None
    return normalized


def _export_patch_file_path(value: Any) -> Optional[str]:
    """Return a safe relative patch file path for export payloads."""
    normalized = _export_optional_string(value)
    if (
        normalized is None
        or len(normalized) > MAX_PATH_FIELD_CHARS
        or normalized.startswith("/")
        or "\\" in normalized
        or _EXPORT_WINDOWS_DRIVE_RE.match(normalized)
        or _EXPORT_PATH_CONTROL_RE.search(normalized)
    ):
        return None

    parts = [part for part in normalized.split("/") if part]
    if not parts or any(part in {".", ".."} for part in parts):
        return None

    return "/".join(parts)


def _export_explanation(value: Any) -> str:
    """Return a safe explanation string for export payloads."""
    if not isinstance(value, str):
        return ""

    try:
        normalized = value.strip()
    except (AttributeError, TypeError, ValueError):
        return ""

    if not normalized or any(_is_unsafe_text_char(ch) for ch in normalized):
        return ""
    return normalized


def _export_string_list(value: Any) -> List[str]:
    """Return only non-empty string list items for export payloads."""
    strings = []
    for item in _bounded_list(value):
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text or any(_is_unsafe_text_char(ch) for ch in text):
            continue
        strings.append(text)
    return strings


def _export_reference_url(value: str) -> Optional[str]:
    """Return a safe HTTP(S) reference URL."""
    try:
        normalized = value.strip()
    except (AttributeError, TypeError, ValueError):
        return None

    if (
        not normalized
        or len(normalized) > MAX_REFERENCE_URL_CHARS
        or _EXPORT_REFERENCE_CONTROL_RE.search(normalized)
        or any(char.isspace() for char in normalized)
    ):
        return None

    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    if parsed.username or parsed.password or not parsed.hostname:
        return None

    return normalized


def _export_reference(value: Any) -> Optional[str]:
    """Return a safe exported remediation reference."""
    try:
        normalized = _export_optional_string(value)
    except (AttributeError, TypeError, ValueError):
        return None

    if normalized is None or _EXPORT_REFERENCE_CONTROL_RE.search(normalized):
        return None

    markdown_link = _EXPORT_MARKDOWN_LINK_RE.fullmatch(normalized)
    if markdown_link:
        try:
            label = markdown_link.group(1).strip()
        except (AttributeError, TypeError, ValueError):
            return None
        url = _export_reference_url(markdown_link.group(2))
        if label and len(label) <= MAX_REFERENCE_LABEL_CHARS and url is not None:
            return f"[{label}]({url})"
        return None

    if "](" in normalized or normalized.startswith("["):
        return None

    if _EXPORT_REFERENCE_URL_RE.match(normalized) or _EXPORT_REFERENCE_SCHEME_RE.match(normalized):
        return _export_reference_url(normalized)

    if "<" in normalized or ">" in normalized:
        return None

    return normalized


def _export_reference_list(value: Any) -> List[str]:
    """Return safe remediation references without malformed links or URLs."""
    exported = []
    seen = set()
    for item in _bounded_list(value):
        reference = _export_reference(item)
        if reference is None or reference in seen:
            continue
        seen.add(reference)
        exported.append(reference)
    return exported


def _export_unique_string_list(value: Any) -> List[str]:
    """Return unique non-empty string list items for export payloads."""
    exported = []
    seen = set()
    for item in _export_string_list(value):
        if item in seen:
            continue
        seen.add(item)
        exported.append(item)
    return exported


def _export_generated_test_name(value: Any) -> Optional[str]:
    """Return a safe generated test name for export payloads."""
    normalized = _export_optional_string(value)
    if (
        normalized is None
        or normalized in {".", ".."}
        or "/" in normalized
        or "\\" in normalized
        or _EXPORT_WINDOWS_DRIVE_RE.match(normalized)
        or _EXPORT_TEST_NAME_CONTROL_RE.search(normalized)
        or len(normalized) > 120
    ):
        return None
    return normalized


def _export_generated_test_names(value: Any) -> List[str]:
    """Return unique safe generated test names for export payloads."""
    if not isinstance(value, (list, tuple)):
        return []

    exported = []
    seen = set()
    if isinstance(value, list):
        items = _bounded_list(value)
    else:
        try:
            items = list(value[:MAX_METADATA_LIST_ITEMS])
        except (TypeError, RuntimeError, ValueError):
            return []
    for item in items:
        test_name = _export_generated_test_name(item)
        if test_name is None or test_name in seen:
            continue
        seen.add(test_name)
        exported.append(test_name)
    return exported


def _export_level(value: Any, allowed: set[str], default: str) -> str:
    """Return a bounded lowercase level for export payloads."""
    if isinstance(value, str):
        try:
            normalized = value.strip().lower()
        except (AttributeError, TypeError, ValueError):
            return default
        if normalized and not any(_is_unsafe_text_char(ch) for ch in normalized):
            if normalized in allowed:
                return normalized
    return default


def _export_non_negative_float(value: Any, default: float = 0.0) -> float:
    """Return a finite non-negative float for export payloads."""
    if isinstance(value, bool):
        return default
    if isinstance(value, str):
        if any(_is_unsafe_text_char(ch) for ch in value):
            return default
        text = value.strip()
        value = text

    try:
        normalized = float(value)
    except (TypeError, ValueError):
        return default

    return normalized if math.isfinite(normalized) and normalized >= 0 else default


def _export_confidence(value: Any, default: float = 0.0) -> float:
    """Return a finite confidence value bounded to the probability range."""
    normalized = _export_non_negative_float(value, default)
    return normalized if normalized <= 1.0 else default


def _export_non_negative_int(value: Any) -> int:
    """Return a non-negative integer for export payloads."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, str):
        if any(_is_unsafe_text_char(ch) for ch in value):
            return 0
        text = value.strip()
        value = text

    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return 0

    return normalized if normalized >= 0 else 0


def _export_positive_int_list(value: Any) -> List[int]:
    """Return unique positive integer list items for export payloads."""
    exported = []
    seen = set()
    for item in _bounded_list(value):
        if isinstance(item, bool):
            continue
        if isinstance(item, str):
            if any(_is_unsafe_text_char(ch) for ch in item):
                continue
            text = item.strip()
            item = text
        if isinstance(item, float) and not item.is_integer():
            continue

        try:
            normalized = int(item)
        except (TypeError, ValueError, OverflowError):
            continue

        if normalized <= 0 or normalized in seen:
            continue
        seen.add(normalized)
        exported.append(normalized)

    return exported


logger = logging.getLogger(__name__)

REMEDIATION_RUNTIME_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    TimeoutError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)


@dataclass
class Remediation:
    """A remediation suggestion for a vulnerability."""

    finding_id: str
    vulnerability_type: str
    severity: str
    vulnerable_code: str
    fixed_code: str
    explanation: str
    changes_summary: List[str]
    test_suggestions: List[str]
    references: List[str]
    confidence: float
    pattern_used: Optional[str] = None
    implementation_complexity: str = "medium"
    deployment_risk: str = "medium"
    gas_impact: str = "medium"
    affected_lines: Optional[List[int]] = None
    validation_notes: Optional[List[str]] = None
    patch_filename: Optional[str] = None
    patch_file_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Export remediation data without trusting malformed field values."""
        exported = {
            "finding_id": _export_string(self.finding_id, "unknown"),
            "vulnerability_type": _export_string(self.vulnerability_type, "unknown"),
            "severity": _export_level(
                self.severity,
                {"info", "informational", "low", "medium", "high", "critical"},
                "medium",
            ),
            "vulnerable_code": _export_code_or_patch_text(self.vulnerable_code, ""),
            "fixed_code": _export_code_or_patch_text(self.fixed_code, ""),
            "explanation": _export_explanation(self.explanation),
            "changes_summary": _export_string_list(self.changes_summary),
            "test_suggestions": _export_generated_test_names(self.test_suggestions),
            "references": _export_reference_list(self.references),
            "confidence": _export_confidence(self.confidence),
            "affected_lines": _export_positive_int_list(self.affected_lines),
            "pattern_used": _export_optional_string(self.pattern_used),
            "implementation_complexity": _export_level(
                self.implementation_complexity,
                {"low", "medium", "high"},
                "medium",
            ),
            "deployment_risk": _export_level(
                self.deployment_risk,
                {"low", "medium", "high", "critical"},
                "medium",
            ),
            "gas_impact": _export_level(
                self.gas_impact,
                {"none", "low", "medium", "high"},
                "medium",
            ),
            "validation_notes": _export_unique_string_list(self.validation_notes),
        }
        patch_filename = _export_patch_filename(self.patch_filename)
        patch_file_path = _export_patch_file_path(self.patch_file_path)
        if patch_filename is not None:
            exported["patch_filename"] = patch_filename
        if patch_file_path is not None:
            exported["patch_file_path"] = patch_file_path
        return exported


@dataclass
class RemediationResult:
    """Result from remediation generation."""

    remediations: List[Remediation]
    success_count: int
    failure_count: int
    execution_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Export generation results without trusting malformed field values."""
        remediations = _bounded_list(self.remediations, limit=MAX_REMEDIATION_EXPORTS)
        exported_remediations = []
        for remediation in remediations:
            if not isinstance(remediation, Remediation):
                continue
            try:
                exported = remediation.to_dict()
            except (TypeError, ValueError, AttributeError):
                continue
            if isinstance(exported, dict):
                exported_remediations.append(exported)

        return {
            "remediations": exported_remediations,
            "success_count": _export_non_negative_int(self.success_count),
            "failure_count": _export_non_negative_int(self.failure_count),
            "execution_time_ms": _export_non_negative_float(self.execution_time_ms),
        }


# Known remediation patterns by vulnerability type
REMEDIATION_PATTERNS: Dict[str, Dict[str, Any]] = {
    "reentrancy": {
        "pattern_name": "ReentrancyGuard + CEI",
        "imports": [
            "import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';"
        ],
        "inheritance": "ReentrancyGuard",
        "modifier": "nonReentrant",
        "description": "Use OpenZeppelin ReentrancyGuard and Checks-Effects-Interactions pattern",
    },
    "access-control": {
        "pattern_name": "Ownable or AccessControl",
        "imports": [
            "import {Ownable} from '@openzeppelin/contracts/access/Ownable.sol';",
            "// or for role-based:",
            "import {AccessControl} from '@openzeppelin/contracts/access/AccessControl.sol';",
        ],
        "inheritance": "Ownable",
        "modifier": "onlyOwner",
        "description": "Use OpenZeppelin Ownable for single-owner or AccessControl for roles",
    },
    "unchecked-call": {
        "pattern_name": "SafeERC20",
        "imports": [
            "import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';"
        ],
        "using": "using SafeERC20 for IERC20;",
        "methods": ["safeTransfer", "safeTransferFrom", "safeApprove"],
        "description": "Use SafeERC20 wrapper for all ERC20 operations",
    },
    "arithmetic": {
        "pattern_name": "Solidity 0.8+ or SafeMath",
        "description": "Upgrade to Solidity 0.8+ (built-in overflow checks) or use SafeMath for 0.7.x",
    },
    "flash-loan-attack": {
        "pattern_name": "TWAP Oracle",
        "description": "Use time-weighted average price (TWAP) instead of spot prices",
    },
    "front-running": {
        "pattern_name": "Commit-Reveal",
        "description": "Implement commit-reveal scheme to prevent front-running",
    },
}


# Remediation prompt template
REMEDIATION_PROMPT = """You are an expert Solidity security engineer. Generate a fix for this vulnerability.

## Vulnerability Details
- **Type**: {vuln_type}
- **Severity**: {severity}
- **Title**: {title}
- **Description**: {description}

## Vulnerable Code
```solidity
{vulnerable_code}
```

## Instructions
1. Generate the FIXED version of this code
2. Maintain the same business logic
3. Use OpenZeppelin contracts when applicable
4. Add necessary imports
5. Add comments explaining the fix
6. Suggest test cases to verify the fix

## Known Pattern
{pattern_info}

Respond in JSON format:
{{
    "fixed_code": "// Complete fixed Solidity code",
    "explanation": "Why this fix works",
    "changes": ["Change 1", "Change 2"],
    "imports_needed": ["import1", "import2"],
    "test_suggestions": ["Test case 1", "Test case 2"],
    "references": ["Link or reference 1"]
}}
"""


class RemediationGenerator:
    """
    Generates remediation code for vulnerabilities.

    Uses LLM to produce context-aware fixes with proper
    OpenZeppelin patterns and best practices.
    """

    def __init__(
        self,
        ollama_base_url: str = "http://localhost:11434",
        model: str = "deepseek-coder:6.7b",
        timeout: int = 120,
    ):
        """
        Initialize the remediation generator.

        Args:
            ollama_base_url: Ollama API URL
            model: Model to use for generation
            timeout: Request timeout
        """
        self.base_url = self._normalized_base_url(ollama_base_url)
        self.model = self._model_or_default(model)
        self.timeout = self._positive_int(timeout, 120, max_value=MAX_TIMEOUT_SECONDS)

        logger.info(f"RemediationGenerator initialized with model={model}")

    async def generate_remediation(
        self,
        finding: Dict[str, Any],
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Remediation:
        """
        Generate remediation for a single finding.

        Args:
            finding: The vulnerability finding
            code: Full contract code or relevant snippet
            context: Additional context (contract type, etc.)

        Returns:
            Remediation object with fixed code
        """
        finding = self._dict_or_empty(finding)
        vuln_type = self._parse_vuln_type(_safe_mapping_get(finding, "type", "unknown"))
        severity = self._string_or_default(_safe_mapping_get(finding, "severity"), "medium")
        title = self._string_or_default(
            _safe_mapping_get(finding, "title"),
            vuln_type if vuln_type != "unknown" else "Unknown",
        )
        description = self._string_or_default(_safe_mapping_get(finding, "description"), "")

        # Extract vulnerable code section
        vulnerable_code = self._extract_vulnerable_code(finding, code)

        # Get known pattern info
        pattern_info = self._get_pattern_info(vuln_type)

        # Build prompt
        prompt = REMEDIATION_PROMPT.format(
            vuln_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            vulnerable_code=vulnerable_code,
            pattern_info=pattern_info,
        )

        # Query LLM
        result = self._dict_or_empty(await self._query_llm(prompt))

        # Parse result without trusting malformed LLM field shapes.
        fixed_code = self._fixed_code_or_default(
            _safe_mapping_get(result, "fixed_code"), vulnerable_code
        )
        explanation = self._string_or_default(_safe_mapping_get(result, "explanation"), "")
        changes = self._string_list_or_empty(_safe_mapping_get(result, "changes"))
        imports = self._imports_to_prepend(fixed_code, _safe_mapping_get(result, "imports_needed"))
        tests = _export_generated_test_names(_safe_mapping_get(result, "test_suggestions"))
        references = self._unique_string_list_or_empty(_safe_mapping_get(result, "references"))
        implementation_complexity = self._normalized_level(
            _safe_mapping_get(
                result,
                "implementation_complexity",
                _safe_mapping_get(result, "complexity"),
            ),
            {"low", "medium", "high"},
            "medium",
        )
        deployment_risk = self._normalized_level(
            _safe_mapping_get(result, "deployment_risk", _safe_mapping_get(result, "risk_level")),
            {"low", "medium", "high", "critical"},
            "medium",
        )

        # Add imports to fixed code if not present
        if imports:
            imports_str = "\n".join(imports)
            if not fixed_code.startswith("//") or fixed_code.startswith("// SPDX-License-Identifier:"):
                fixed_code = f"{imports_str}\n\n{fixed_code}"

        return Remediation(
            finding_id=self._string_or_default(_safe_mapping_get(finding, "id"), "unknown"),
            vulnerability_type=vuln_type,
            severity=severity,
            vulnerable_code=vulnerable_code,
            fixed_code=fixed_code,
            explanation=explanation,
            changes_summary=changes,
            test_suggestions=tests,
            references=references,
            confidence=0.8,
            pattern_used=_safe_mapping_get(REMEDIATION_PATTERNS.get(vuln_type, {}), "pattern_name"),
            implementation_complexity=implementation_complexity,
            deployment_risk=deployment_risk,
        )

    async def generate_remediations(
        self,
        findings: List[Dict[str, Any]],
        code: str,
        parallel: bool = True,
        max_concurrent: int = 3,
    ) -> RemediationResult:
        """
        Generate remediations for multiple findings.

        Args:
            findings: List of vulnerability findings
            code: Full contract code
            parallel: Run in parallel (default: True)
            max_concurrent: Max concurrent requests

        Returns:
            RemediationResult with all remediations
        """
        import time

        start_time = time.time()

        findings, malformed_count = self._normalize_batch_findings(findings)
        remediations = []
        success_count = 0
        failure_count = malformed_count

        if parallel and len(findings) > 1:
            # Process in batches
            semaphore = asyncio.Semaphore(
                self._positive_int(
                    max_concurrent,
                    3,
                    max_value=MAX_CONCURRENT_REMEDIATIONS,
                )
            )

            async def process_with_semaphore(finding: Dict[str, Any]) -> Any:
                async with semaphore:
                    return await self.generate_remediation(finding, code)

            tasks = [process_with_semaphore(f) for f in findings]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, REMEDIATION_RUNTIME_ERRORS):
                    logger.warning(
                        "Remediation generation failed: %s",
                        _safe_error_text(result),
                    )
                    failure_count += 1
                elif isinstance(result, BaseException):
                    raise result
                else:
                    remediations.append(result)
                    success_count += 1
        else:
            # Process sequentially
            for finding in findings:
                try:
                    remediation = await self.generate_remediation(finding, code)
                    remediations.append(remediation)
                    success_count += 1
                except asyncio.CancelledError:
                    raise
                except REMEDIATION_RUNTIME_ERRORS as e:
                    logger.warning("Remediation generation failed: %s", _safe_error_text(e))
                    failure_count += 1

        execution_time = (time.time() - start_time) * 1000

        return RemediationResult(
            remediations=remediations,
            success_count=success_count,
            failure_count=failure_count,
            execution_time_ms=execution_time,
        )

    def generate_quick_fix(
        self,
        vuln_type: str,
        function_code: str,
    ) -> Tuple[str, str]:
        """
        Generate a quick fix using known patterns (no LLM).

        Args:
            vuln_type: Type of vulnerability
            function_code: The vulnerable function code

        Returns:
            Tuple of (fixed_code, explanation)
        """
        vuln_type = self._parse_vuln_type(vuln_type)
        if not isinstance(function_code, str):
            return "", "No function code available for quick fix"

        pattern = REMEDIATION_PATTERNS.get(vuln_type)

        if not pattern:
            return function_code, "No known pattern for this vulnerability type"

        fixed = function_code
        changes = []

        # Apply pattern-specific fixes
        if vuln_type == "reentrancy":
            # Add nonReentrant modifier
            updated = self._insert_function_modifier(fixed, "nonReentrant")
            if updated != fixed:
                fixed = updated
                changes.append("Added nonReentrant modifier")

        elif vuln_type == "access-control":
            # Add onlyOwner modifier
            updated = self._insert_function_modifier(
                fixed,
                "onlyOwner",
                existing_modifiers={"onlyOwner", "onlyRole"},
            )
            if updated != fixed:
                fixed = updated
                changes.append("Added onlyOwner modifier")

        elif vuln_type == "unchecked-call":
            # Replace transfer with safeTransfer
            updated = re.sub(r"(?<!safe)\.transfer\s*\(", ".safeTransfer(", fixed)
            updated = re.sub(r"(?<!safe)\.transferFrom\s*\(", ".safeTransferFrom(", updated)
            if updated != fixed:
                fixed = updated
                changes.append("Replaced transfer with safeTransfer")

        explanation = pattern.get("description", "")
        if changes:
            explanation += "\n\nChanges made:\n" + "\n".join(f"- {c}" for c in changes)

        return fixed, explanation

    def get_pattern_template(self, vuln_type: str) -> Dict[str, Any]:
        """
        Get the remediation pattern template for a vulnerability type.

        Args:
            vuln_type: Type of vulnerability

        Returns:
            Pattern template with imports, modifiers, etc.
        """
        pattern = REMEDIATION_PATTERNS.get(self._parse_vuln_type(vuln_type), {})
        copied = {}
        for key, value in pattern.items():
            copied[key] = list(value) if isinstance(value, list) else value
        return copied

    async def _query_llm(self, prompt: str) -> Dict[str, Any]:
        """Query the LLM and parse JSON response."""
        prompt_text = _safe_text(prompt, allow_multiline=True)
        payload = {
            "model": self._model_or_default(self.model),
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert Solidity security engineer. "
                        "Generate secure, production-ready code fixes. "
                        "Respond only with valid JSON."
                    ),
                },
                {"role": "user", "content": prompt_text},
            ],
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096,
            },
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._normalized_base_url(self.base_url)}/api/chat",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(
                        total=self._positive_int(
                            self.timeout,
                            120,
                            max_value=MAX_TIMEOUT_SECONDS,
                        )
                    ),
                ) as resp:
                    status = resp.status
                    if not isinstance(status, int) or isinstance(status, bool):
                        raise RuntimeError("LLM error: malformed status")
                    if status != 200:
                        try:
                            error_text = await resp.text()
                        except REMEDIATION_RUNTIME_ERRORS:
                            error_text = "error"
                        raise RuntimeError(f"LLM error: {_safe_error_text(error_text)}")

                    data = await resp.json()
                    if not isinstance(data, dict):
                        return {}

                    message = _safe_mapping_get(data, "message", {})
                    content = (
                        _safe_mapping_get(message, "content", "")
                        if isinstance(message, dict)
                        else ""
                    )
                    content = self._string_or_default(content, "")
                    content = content[:MAX_LLM_RESPONSE_CHARS]

                    return self._parse_json_response(content)

        except REMEDIATION_RUNTIME_ERRORS as e:
            logger.error("LLM query failed: %s", _safe_error_text(e))
            return {}

    def _parse_json_response(self, content: str) -> Dict[str, Any]:
        """Parse JSON from LLM response."""
        try:
            stripped = _safe_text(content, allow_multiline=True)
            if not stripped or len(stripped) > MAX_JSON_RESPONSE_CHARS:
                return {}
            json_str = (
                stripped if stripped.startswith(("[", "{")) else extract_json_from_text(content)
            )
            if json_str is None:
                json_str = stripped

            if json_str:
                if len(json_str) > MAX_JSON_RESPONSE_CHARS:
                    return {}
                parsed = json.loads(repair_common_json_errors(json_str))
                if isinstance(parsed, dict) and len(parsed) <= MAX_JSON_RESPONSE_KEYS:
                    return parsed
        except (json.JSONDecodeError, RecursionError, RuntimeError, TypeError, ValueError) as e:
            logger.debug(f"JSON parse error: {e}")

        return {}

    def _extract_vulnerable_code(
        self,
        finding: Dict[str, Any],
        full_code: str,
    ) -> str:
        """Extract the vulnerable code section from full contract."""
        full_code = _safe_text(full_code, allow_multiline=True)
        location_value = _safe_mapping_get(finding, "location", {})
        location = location_value if isinstance(location_value, dict) else {}

        # If snippet is provided, use it
        snippet = _safe_text(_safe_mapping_get(finding, "snippet"), allow_multiline=True)
        if snippet:
            return snippet

        # Try to extract by function name
        func_name = _safe_text(_safe_mapping_get(location, "function"))
        if func_name:
            function_code = self._extract_function_by_name(full_code, func_name)
            if function_code:
                return function_code

        # Try to extract by line number
        line = _safe_mapping_get(location, "line")
        if isinstance(line, int) and not isinstance(line, bool) and line > 0:
            lines = full_code.split("\n")
            start = max(0, line - 5)
            end = min(len(lines), line + 10)
            return "\n".join(lines[start:end])

        # Return a relevant section (first 50 lines or contract definition)
        lines = full_code.split("\n")
        return "\n".join(lines[: min(50, len(lines))])

    @staticmethod
    def _parse_vuln_type(value: Any) -> str:
        """Normalize vulnerability type fields without trusting malformed shapes."""
        value = _safe_text(value)
        if not value:
            return "unknown"

        normalized = value.lower()
        return normalized if normalized else "unknown"

    @staticmethod
    def _positive_int(
        value: Any, default: int, *, max_value: int = MAX_CONCURRENT_REMEDIATIONS
    ) -> int:
        """Return a positive int, defaulting malformed/bool/non-positive values."""
        if isinstance(value, bool):
            return default
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError):
            return default
        if normalized <= 0:
            return default
        return min(normalized, max_value)

    @staticmethod
    def _normalized_base_url(value: Any) -> str:
        """Return a usable base URL without trailing slash."""
        normalized = _safe_text(value)
        if not normalized or len(normalized) > MAX_REFERENCE_URL_CHARS:
            return "http://localhost:11434"
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return "http://localhost:11434"
        if parsed.username or parsed.password or not parsed.hostname:
            return "http://localhost:11434"
        if any(char.isspace() for char in parsed.netloc):
            return "http://localhost:11434"
        if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
            return "http://localhost:11434"
        return normalized.rstrip("/")

    @staticmethod
    def _string_or_default(value: Any, default: str) -> str:
        """Return string values from LLM results, falling back on malformed shapes."""
        value = _safe_text_limited(value)
        if not value:
            return default
        return value

    @staticmethod
    def _model_or_default(value: Any, default: str = "deepseek-coder:6.7b") -> str:
        """Return a bounded local model id without path or whitespace syntax."""
        value = _safe_text(value)
        if not value or len(value) > 128 or not _OLLAMA_MODEL_RE.fullmatch(value):
            return default
        return value

    @staticmethod
    def _fixed_code_or_default(value: Any, default: str) -> str:
        """Return non-empty fixed code from LLM results, falling back on malformed shapes."""
        normalized = _safe_text_limited(
            value,
            allow_multiline=True,
            limit=MAX_LLM_RESPONSE_CHARS,
        )
        return normalized or default

    @staticmethod
    def _string_list_or_empty(value: Any) -> List[str]:
        """Return only non-empty string list items from LLM results."""
        items = []
        for item in _bounded_list(value):
            text = _safe_text_limited(item)
            if not text:
                continue
            items.append(text)
        return items

    @classmethod
    def _unique_string_list_or_empty(cls, value: Any) -> List[str]:
        """Return unique non-empty string list items from LLM metadata."""
        items = []
        seen = set()
        for item in cls._string_list_or_empty(value):
            if item in seen:
                continue
            seen.add(item)
            items.append(item)
        return items

    @classmethod
    def _imports_to_prepend(cls, fixed_code: str, value: Any) -> List[str]:
        """Return unique imports that are not already present in fixed code."""
        fixed_code_text = _safe_text_limited(
            fixed_code,
            allow_multiline=True,
            limit=MAX_LLM_RESPONSE_CHARS,
        )
        existing_lines = {line.strip() for line in fixed_code_text.splitlines()}
        imports = []
        seen = set()
        for import_line in cls._string_list_or_empty(value):
            if not cls._is_import_statement(import_line):
                continue
            if import_line in seen or import_line in existing_lines:
                continue
            seen.add(import_line)
            imports.append(import_line)
        return imports

    @staticmethod
    def _dict_or_empty(value: Any) -> Dict[str, Any]:
        """Return mapping-shaped vulnerability findings only."""
        if not isinstance(value, dict):
            return {}
        try:
            value.get("__miesc_probe__")
        except (AttributeError, TypeError, RuntimeError, ValueError):
            return {}
        return value

    @staticmethod
    def _normalized_level(value: Any, allowed: set[str], default: str) -> str:
        """Return a bounded lowercase level from LLM result metadata."""
        value = _safe_text(value)
        if not value:
            return default

        normalized = value.lower()
        return normalized if normalized in allowed else default

    @classmethod
    def _is_import_statement(cls, value: Any) -> bool:
        """Return true for a single Solidity import statement."""
        line = _safe_text(value)
        return bool(line and _SOLIDITY_IMPORT_RE.fullmatch(line))

    @classmethod
    def _insert_function_modifier(
        cls,
        function_code: str,
        modifier: str,
        *,
        existing_modifiers: Optional[set[str]] = None,
    ) -> str:
        """Insert a modifier before returns/body while preserving Solidity modifier order."""
        if not isinstance(function_code, str):
            return function_code
        existing = existing_modifiers or {modifier}
        header_bounds = cls._function_header_bounds(function_code)
        if not header_bounds:
            return function_code
        start, end, header = header_bounds
        if any(re.search(rf"\b{re.escape(name)}(?:\s*\([^)]*\))?\b", header) for name in existing):
            return function_code

        insertion_point = header.find(" returns")
        if insertion_point == -1:
            insertion_point = len(header)
        updated_header = f"{header[:insertion_point].rstrip()} {modifier}{header[insertion_point:]}"
        return f"{function_code[:start]}{updated_header}{function_code[end:]}"

    @staticmethod
    def _function_header_bounds(function_code: str) -> Optional[Tuple[int, int, str]]:
        """Match a Solidity function header through the opening brace."""
        index = function_code.find("function")
        if index == -1:
            return None
        depth = 0
        for pos in range(index, len(function_code)):
            char = function_code[pos]
            if char == "(":
                depth += 1
            elif char == ")" and depth > 0:
                depth -= 1
            elif char == "{" and depth == 0:
                return index, pos, function_code[index:pos].rstrip()
        return None

    @classmethod
    def _extract_function_by_name(cls, full_code: str, func_name: str) -> str:
        """Extract a named Solidity function using balanced braces."""
        match = re.search(rf"\bfunction\s+{re.escape(func_name)}\b", full_code)
        if not match:
            return ""
        brace_index = cls._find_next_code_char(full_code, "{", match.end())
        if brace_index == -1:
            return ""
        end = cls._balanced_block_end(full_code, brace_index)
        if end == -1:
            return ""
        return full_code[match.start() : end]

    @staticmethod
    def _find_next_code_char(text: str, target: str, start: int) -> int:
        for index in range(start, len(text)):
            if text[index] == target:
                return index
        return -1

    @staticmethod
    def _balanced_block_end(text: str, start_brace: int) -> int:
        depth = 0
        quote: Optional[str] = None
        escaped = False
        line_comment = False
        block_comment = False
        index = start_brace
        while index < len(text):
            char = text[index]
            next_char = text[index + 1] if index + 1 < len(text) else ""

            if line_comment:
                if char in "\n\r":
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if char == "/" and next_char == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and next_char == "*":
                block_comment = True
                index += 2
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return -1

    @staticmethod
    def _normalize_batch_findings(value: Any) -> Tuple[List[Dict[str, Any]], int]:
        """Return valid batch findings and a count of malformed batch entries."""
        if not isinstance(value, list):
            return [], 1

        bounded = _bounded_list(value, limit=MAX_BATCH_FINDINGS)
        findings = [item for item in bounded if isinstance(item, dict)]
        try:
            total = len(value)
        except (TypeError, RuntimeError, ValueError):
            total = len(bounded)
        malformed = max(0, total - len(findings))
        return findings, malformed

    def _get_pattern_info(self, vuln_type: str) -> str:
        """Get pattern information for the vulnerability type."""
        pattern = REMEDIATION_PATTERNS.get(self._parse_vuln_type(vuln_type))

        if not pattern:
            return "No specific pattern known. Use security best practices."

        pattern_name = _safe_text_limited(pattern.get("pattern_name"), limit=120) or "Unknown"
        description = _safe_text_limited(pattern.get("description"), limit=MAX_PROMPT_FIELD_CHARS)
        info_parts = [
            f"**Pattern**: {pattern_name}",
            f"**Description**: {description}",
        ]

        if "imports" in pattern:
            imports = [
                item
                for item in _bounded_list(pattern.get("imports"), limit=2)
                if self._is_import_statement(item)
            ]
            if imports:
                info_parts.append(f"**Imports**: {', '.join(imports)}")

        if "modifier" in pattern:
            modifier = _safe_text_limited(pattern.get("modifier"), limit=120)
            if modifier:
                info_parts.append(f"**Modifier**: {modifier}")

        return "\n".join(info_parts)


# Convenience functions


async def generate_fix(
    finding: Dict[str, Any],
    code: str,
    model: str = "deepseek-coder:6.7b",
) -> Remediation:
    """
    Generate a fix for a single vulnerability.

    Args:
        finding: The vulnerability finding
        code: Contract code
        model: LLM model to use

    Returns:
        Remediation with fixed code
    """
    generator = RemediationGenerator(model=model)
    return await generator.generate_remediation(finding, code)


def get_quick_fix(vuln_type: str, code: str) -> Tuple[str, str]:
    """
    Get a quick fix without LLM (pattern-based).

    Args:
        vuln_type: Type of vulnerability
        code: Vulnerable code section

    Returns:
        Tuple of (fixed_code, explanation)
    """
    generator = RemediationGenerator()
    return generator.generate_quick_fix(vuln_type, code)


# Export
__all__ = [
    "RemediationGenerator",
    "Remediation",
    "RemediationResult",
    "REMEDIATION_PATTERNS",
    "generate_fix",
    "get_quick_fix",
]
