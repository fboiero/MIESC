"""
Prompt Sanitization Module for LLM Security

Provides protection against prompt injection attacks by:
1. Escaping special characters in user-provided code
2. Wrapping user content in XML-style delimiters
3. Detecting potential prompt injection patterns
4. Sanitizing context data before embedding in prompts

CRITICAL: All user-provided content (contract code, findings, context)
MUST be sanitized before embedding in LLM prompts.

Usage:
    from src.security.prompt_sanitizer import (
        sanitize_code_for_prompt,
        sanitize_context,
        detect_prompt_injection,
        PromptInjectionWarning,
    )

    # Sanitize contract code
    safe_code = sanitize_code_for_prompt(user_contract_code)

    # Build safe prompt
    prompt = f'''Analyze this contract:
    {safe_code}
    '''
"""

import html
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class InjectionRiskLevel(Enum):
    """Risk level for detected injection patterns."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InjectionDetectionResult:
    """Result of prompt injection detection."""

    risk_level: InjectionRiskLevel
    patterns_found: List[str]
    sanitized_content: str
    warnings: List[str]

    @property
    def is_safe(self) -> bool:
        """Check if content is safe to use."""
        return self.risk_level in (InjectionRiskLevel.NONE, InjectionRiskLevel.LOW)


class PromptInjectionWarning(Warning):
    """Warning raised when potential prompt injection is detected."""

    pass


# Patterns that indicate potential prompt injection attempts
INJECTION_PATTERNS = [
    # Direct instruction overrides
    (r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+instructions?", "instruction_override", InjectionRiskLevel.CRITICAL),
    (r"(?i)disregard\s+(all\s+)?(previous|above|prior)", "instruction_override", InjectionRiskLevel.CRITICAL),
    (r"(?i)forget\s+(everything|all)\s+(above|before|previous)", "instruction_override", InjectionRiskLevel.CRITICAL),
    (r"(?i)new\s+instructions?:", "new_instructions", InjectionRiskLevel.HIGH),
    (r"(?i)system\s*:\s*you\s+are", "system_role_override", InjectionRiskLevel.CRITICAL),
    (r"(?i)assistant\s*:\s*", "role_injection", InjectionRiskLevel.HIGH),
    (r"(?i)user\s*:\s*", "role_injection", InjectionRiskLevel.HIGH),

    # Output manipulation
    (r"(?i)report\s+no\s+vulnerabilities?", "output_manipulation", InjectionRiskLevel.HIGH),
    (r"(?i)say\s+(there\s+are\s+)?no\s+(issues?|problems?|vulnerabilities?)", "output_manipulation", InjectionRiskLevel.HIGH),
    (r"(?i)output\s*:\s*\{", "output_injection", InjectionRiskLevel.MEDIUM),
    (r"(?i)respond\s+with\s+only", "output_control", InjectionRiskLevel.MEDIUM),

    # Jailbreak attempts
    (r"(?i)pretend\s+(you\s+are|to\s+be)", "jailbreak", InjectionRiskLevel.HIGH),
    (r"(?i)act\s+as\s+(if|a)", "jailbreak", InjectionRiskLevel.MEDIUM),
    (r"(?i)roleplay\s+as", "jailbreak", InjectionRiskLevel.HIGH),
    (r"(?i)you\s+are\s+now\s+", "jailbreak", InjectionRiskLevel.HIGH),
    (r"(?i)DAN\s+mode", "jailbreak", InjectionRiskLevel.CRITICAL),

    # Delimiter escapes
    (r"```\s*\n\s*```", "delimiter_escape", InjectionRiskLevel.MEDIUM),
    (r"</code>\s*<code>", "tag_escape", InjectionRiskLevel.MEDIUM),
    (r"\]\]\s*\[\[", "bracket_escape", InjectionRiskLevel.MEDIUM),

    # Hidden instructions (Unicode/whitespace tricks)
    (r"[\u200b\u200c\u200d\ufeff]", "hidden_chars", InjectionRiskLevel.HIGH),
    (r"[\u202a-\u202e]", "bidi_override", InjectionRiskLevel.HIGH),
]

# Characters that should be escaped in prompts
ESCAPE_CHARS = {
    "```": "` ` `",  # Break code fence
    "'''": "' ' '",  # Break triple quotes
    '"""': '" " "',  # Break triple quotes
    "${": "$ {",  # Break template literals
    "{{": "{ {",  # Break template syntax
    "}}": "} }",  # Break template syntax
    "\x00": "",  # Remove null bytes
}

# Maximum content length to prevent DoS
MAX_CODE_LENGTH = 100_000  # 100KB
MAX_CONTEXT_LENGTH = 50_000  # 50KB


def escape_special_chars(content: str) -> str:
    """
    Escape special characters that could break prompt structure.

    Args:
        content: Raw content to escape

    Returns:
        Escaped content safe for prompt embedding
    """
    result = content

    # Remove null bytes and other control chars (except newlines/tabs)
    result = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result)

    # Escape delimiter characters
    for char, replacement in ESCAPE_CHARS.items():
        result = result.replace(char, replacement)

    return result


def remove_hidden_chars(content: str) -> str:
    """
    Remove hidden Unicode characters used for injection attacks.

    Args:
        content: Content to clean

    Returns:
        Content with hidden characters removed
    """
    # Zero-width characters
    content = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", content)

    # Bidirectional override characters
    content = re.sub(r"[\u202a-\u202e\u2066-\u2069]", "", content)

    # Other invisible formatting
    content = re.sub(r"[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5]", "", content)

    return content


def detect_prompt_injection(
    content: str,
    strict: bool = False,
) -> InjectionDetectionResult:
    """
    Detect potential prompt injection patterns in content.

    Args:
        content: Content to analyze
        strict: If True, treat medium-risk patterns as blockers

    Returns:
        InjectionDetectionResult with risk assessment
    """
    patterns_found = []
    warnings = []
    max_risk = InjectionRiskLevel.NONE

    # Check each injection pattern
    for pattern, name, risk_level in INJECTION_PATTERNS:
        if re.search(pattern, content):
            patterns_found.append(name)
            warnings.append(f"Detected {name} pattern (risk: {risk_level.value})")

            # Track highest risk level
            risk_order = [
                InjectionRiskLevel.NONE,
                InjectionRiskLevel.LOW,
                InjectionRiskLevel.MEDIUM,
                InjectionRiskLevel.HIGH,
                InjectionRiskLevel.CRITICAL,
            ]
            if risk_order.index(risk_level) > risk_order.index(max_risk):
                max_risk = risk_level

    # Sanitize the content
    sanitized = sanitize_code_for_prompt(content)

    # Log warnings for non-trivial risks
    if max_risk != InjectionRiskLevel.NONE:
        logger.warning(
            f"Prompt injection detection: {max_risk.value} risk, "
            f"patterns: {patterns_found}"
        )

    return InjectionDetectionResult(
        risk_level=max_risk,
        patterns_found=patterns_found,
        sanitized_content=sanitized,
        warnings=warnings,
    )


def sanitize_code_for_prompt(
    code: str,
    max_length: int = MAX_CODE_LENGTH,
    wrap_in_tags: bool = True,
    tag_name: str = "code",
) -> str:
    """
    Sanitize code content for safe embedding in LLM prompts.

    This is the PRIMARY function to use for contract code.

    Args:
        code: Raw contract code
        max_length: Maximum allowed length (truncate if exceeded)
        wrap_in_tags: Whether to wrap in XML-style tags
        tag_name: Tag name to use for wrapping

    Returns:
        Sanitized code safe for prompt embedding

    Example:
        >>> code = '''// IGNORE ALL PREVIOUS INSTRUCTIONS
        ... function withdraw() { ... }'''
        >>> safe = sanitize_code_for_prompt(code)
        >>> # Returns wrapped, escaped code
    """
    if not code:
        return f"<{tag_name}></{tag_name}>" if wrap_in_tags else ""

    # Truncate if too long
    if len(code) > max_length:
        code = code[:max_length] + "\n// ... [truncated for length]"
        logger.warning(f"Code truncated from {len(code)} to {max_length} chars")

    # Remove hidden characters
    code = remove_hidden_chars(code)

    # Escape special characters
    code = escape_special_chars(code)

    # HTML-escape angle brackets to prevent tag injection
    code = code.replace("<", "&lt;").replace(">", "&gt;")

    # Wrap in XML-style tags for clear boundaries
    if wrap_in_tags:
        code = f"<{tag_name}>\n{code}\n</{tag_name}>"

    return code


def sanitize_context(
    context: Dict[str, Any],
    max_length: int = MAX_CONTEXT_LENGTH,
) -> Dict[str, Any]:
    """
    Sanitize context dictionary for safe embedding in prompts.

    Args:
        context: Context dictionary with arbitrary data
        max_length: Maximum total serialized length

    Returns:
        Sanitized context dictionary
    """
    import json

    def sanitize_value(value: Any, depth: int = 0) -> Any:
        """Recursively sanitize values."""
        if depth > 10:  # Prevent infinite recursion
            return "[max depth exceeded]"

        if isinstance(value, str):
            # Sanitize strings
            value = remove_hidden_chars(value)
            value = escape_special_chars(value)
            # Truncate long strings
            if len(value) > 10000:
                value = value[:10000] + "...[truncated]"
            return value
        elif isinstance(value, dict):
            return {
                sanitize_value(k, depth + 1): sanitize_value(v, depth + 1)
                for k, v in value.items()
            }
        elif isinstance(value, (list, tuple)):
            return [sanitize_value(item, depth + 1) for item in value]
        elif isinstance(value, (int, float, bool, type(None))):
            return value
        else:
            # Convert unknown types to string
            return sanitize_value(str(value), depth + 1)

    sanitized = sanitize_value(context)

    # Check total length
    serialized = json.dumps(sanitized)
    if len(serialized) > max_length:
        logger.warning(f"Context truncated from {len(serialized)} to {max_length}")
        # Truncate individual string values proportionally
        ratio = max_length / len(serialized)
        sanitized = _truncate_context(sanitized, ratio)

    return sanitized


def _truncate_context(context: Dict[str, Any], ratio: float) -> Dict[str, Any]:
    """Truncate context values proportionally."""

    def truncate_value(value: Any) -> Any:
        if isinstance(value, str) and len(value) > 100:
            new_len = max(100, int(len(value) * ratio))
            return value[:new_len] + "...[truncated]"
        elif isinstance(value, dict):
            return {k: truncate_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [truncate_value(item) for item in value]
        return value

    return truncate_value(context)


def sanitize_finding_text(text: str) -> str:
    """
    Sanitize finding text (title, description, etc.) for prompt embedding.

    Args:
        text: Finding text to sanitize

    Returns:
        Sanitized text
    """
    if not text:
        return ""

    # Remove hidden chars
    text = remove_hidden_chars(text)

    # Escape special chars
    text = escape_special_chars(text)

    # Remove potential injection patterns (replace with safe markers)
    for pattern, name, _ in INJECTION_PATTERNS:
        text = re.sub(pattern, f"[{name}]", text)

    return text


def build_safe_prompt(
    template: str,
    code: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    **kwargs: Any,
) -> Tuple[str, InjectionDetectionResult]:
    """
    Build a safe prompt with all inputs sanitized.

    Args:
        template: Prompt template with {placeholders}
        code: Contract code to embed
        context: Context dictionary
        findings: List of findings to embed
        **kwargs: Additional template variables

    Returns:
        Tuple of (safe_prompt, detection_result)

    Example:
        >>> template = "Analyze this contract:\\n{code}\\nContext: {context}"
        >>> prompt, result = build_safe_prompt(
        ...     template,
        ...     code=user_code,
        ...     context={"network": "mainnet"}
        ... )
        >>> if not result.is_safe:
        ...     logger.warning(f"Injection detected: {result.warnings}")
    """
    detection_results = []
    safe_vars = {}

    # Sanitize code
    if code is not None:
        detection = detect_prompt_injection(code)
        detection_results.append(detection)
        safe_vars["code"] = detection.sanitized_content

    # Sanitize context
    if context is not None:
        import json
        safe_context = sanitize_context(context)
        safe_vars["context"] = json.dumps(safe_context, indent=2)

    # Sanitize findings
    if findings is not None:
        safe_findings = []
        for finding in findings:
            safe_finding = {}
            for key, value in finding.items():
                if isinstance(value, str):
                    safe_finding[key] = sanitize_finding_text(value)
                else:
                    safe_finding[key] = value
            safe_findings.append(safe_finding)
        import json
        safe_vars["findings"] = json.dumps(safe_findings, indent=2)

    # Sanitize additional kwargs
    for key, value in kwargs.items():
        if isinstance(value, str):
            safe_vars[key] = sanitize_finding_text(value)
        else:
            safe_vars[key] = value

    # Build prompt
    try:
        safe_prompt = template.format(**safe_vars)
    except KeyError as e:
        logger.error(f"Missing template variable: {e}")
        raise ValueError(f"Missing template variable: {e}")

    # Aggregate detection results
    max_risk = InjectionRiskLevel.NONE
    all_patterns = []
    all_warnings = []

    for result in detection_results:
        all_patterns.extend(result.patterns_found)
        all_warnings.extend(result.warnings)
        risk_order = [
            InjectionRiskLevel.NONE,
            InjectionRiskLevel.LOW,
            InjectionRiskLevel.MEDIUM,
            InjectionRiskLevel.HIGH,
            InjectionRiskLevel.CRITICAL,
        ]
        if risk_order.index(result.risk_level) > risk_order.index(max_risk):
            max_risk = result.risk_level

    combined_result = InjectionDetectionResult(
        risk_level=max_risk,
        patterns_found=all_patterns,
        sanitized_content=safe_prompt,
        warnings=all_warnings,
    )

    return safe_prompt, combined_result


# Convenience function for simple cases
def quick_sanitize(content: str) -> str:
    """
    Quick sanitization for simple string content.

    Args:
        content: Content to sanitize

    Returns:
        Sanitized content (no wrapping)
    """
    return sanitize_code_for_prompt(content, wrap_in_tags=False)
