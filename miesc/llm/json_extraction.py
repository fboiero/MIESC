"""One tolerant JSON extractor for every LLM-backed adapter.

Local and hosted models wrap their JSON in prose, code fences or ``<think>``
blocks, leave trailing commas, use single quotes, break strings with raw
newlines, or put unescaped double quotes inside Solidity snippets
(``call{value: balance}("")``). Before this module each adapter had its own
partial copy of the same heuristics; a response that one adapter could read,
another dropped silently as "0 findings".

:func:`extract_llm_json` never raises. It returns an
:class:`ExtractionResult` that says *what* was parsed, *which strategy*
succeeded and, on failure, *why*, so callers can mark the tool result as
``skipped (parse)`` and keep the raw text for diagnosis instead of reporting a
clean, empty scan.

Strategies, in order (the first that yields a usable value wins):

1. ``fenced``: the content of a ```` ```json ```` / ```` ``` ```` block.
2. ``anchored``: a balanced object starting at a known key
   (``{"findings": ...``), tracked with a string-aware brace scanner.
3. ``outermost``: first ``{`` to last ``}`` (or ``[`` ... ``]`` for arrays).
4. ``repaired``: the same slices after
   :func:`miesc.security.llm_output_validator.repair_common_json_errors`.
5. ``json_repair``: the ``json-repair`` library (optional dependency, in the
   ``llm`` extra), which handles unescaped quotes and truncated output.
6. ``ndjson``: one JSON object per line, for models that stream findings.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from miesc.security.llm_output_validator import repair_common_json_errors

try:  # optional dependency (miesc[llm])
    from json_repair import repair_json as _repair_json
except ImportError:  # pragma: no cover - exercised in minimal installs
    _repair_json = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Keys that identify the object an adapter is looking for; used to anchor the
# balanced scan when the model wrote prose before the JSON.
DEFAULT_ANCHOR_KEYS: Tuple[str, ...] = (
    "findings",
    "vulnerabilities",
    "issues",
    "reviewed_findings",
    "analysis",
    "properties",
    "invariants",
    "verdict",
    "result",
)

_FENCE = re.compile(r"```(?:json|JSON|javascript|js)?\s*\n?(.*?)```", re.DOTALL)
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_RAW_EXCERPT = 2000


@dataclass
class ExtractionResult:
    """Outcome of :func:`extract_llm_json`."""

    data: Any = None
    strategy: Optional[str] = None
    error: Optional[str] = None
    raw_excerpt: str = ""
    attempts: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.data is not None

    def as_dict(self) -> Dict[str, Any]:
        """Serialisable summary for tool-result metadata."""
        return {
            "parsed": self.ok,
            "strategy": self.strategy,
            "error": self.error,
            "raw_excerpt": self.raw_excerpt if not self.ok else "",
        }


def _maybe_dump(text: Optional[str], log_prefix: str) -> None:
    """Save the raw response when MIESC_LLM_DUMP_DIR is set (fixture capture)."""
    dump_dir = os.environ.get("MIESC_LLM_DUMP_DIR")
    if not dump_dir or text is None:
        return
    try:
        digest = hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:12]
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", log_prefix)[:40] or "llm"
        target = Path(dump_dir) / f"{safe}_{digest}.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text(text, encoding="utf-8")
    except OSError:  # pragma: no cover - never let diagnostics break a scan
        pass


def _clean(text: str) -> str:
    text = _THINK.sub("", text)
    text = _CONTROL.sub(" ", text)
    return text.strip()


def _loads(candidate: str) -> Any:
    """json.loads that tolerates raw newlines/tabs inside strings."""
    return json.loads(candidate, strict=False)


def _balanced_slice(text: str, start: int) -> Optional[str]:
    """Return the balanced ``{...}`` or ``[...]`` starting at ``start``.

    String-aware: braces inside quoted strings (code snippets) do not count,
    and backslash escapes are honoured. Returns None when unbalanced.
    """
    if start < 0 or start >= len(text):
        return None
    opener = text[start]
    closer = {"{": "}", "[": "]"}.get(opener)
    if closer is None:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _acceptable(value: Any, want: str, required_keys: Sequence[str]) -> bool:
    if want == "object":
        if not isinstance(value, dict):
            return False
        return not required_keys or any(k in value for k in required_keys)
    if want == "array":
        return isinstance(value, list) and all(isinstance(x, dict) for x in value) and bool(value)
    # auto
    if isinstance(value, dict):
        return not required_keys or any(k in value for k in required_keys)
    if isinstance(value, list):
        return bool(value) and all(isinstance(x, dict) for x in value)
    return False


def _candidates(text: str, want: str, anchor_keys: Sequence[str]) -> Iterable[Tuple[str, str]]:
    """Yield (strategy, candidate_json_text) pairs in priority order."""
    # 1. fenced blocks
    for block in _FENCE.findall(text):
        block = block.strip()
        if block:
            yield "fenced", block

    # 2. anchored object
    if want in ("object", "auto"):
        for key in anchor_keys:
            m = re.search(r"\{\s*[\"']" + re.escape(key) + r"[\"']\s*:", text)
            if m:
                sl = _balanced_slice(text, m.start())
                if sl:
                    yield "anchored", sl

    # 3. outermost object / array. The naive first..last span goes first: when
    # the model wrote several objects it keeps the whole payload, whereas the
    # balanced scan from the first brace could return an unrelated small dict
    # from the prose. The balanced slice follows for payloads with trailing text.
    if want in ("object", "auto"):
        first = text.find("{")
        if first != -1:
            last = text.rfind("}")
            if last > first:
                yield "outermost", text[first : last + 1]
            sl = _balanced_slice(text, first)
            if sl:
                yield "outermost", sl
    if want in ("array", "auto"):
        m = re.search(r"\[\s*\{", text)
        if m:
            sl = _balanced_slice(text, m.start())
            if sl:
                yield "outermost", sl
            last = text.rfind("]")
            if last > m.start():
                yield "outermost", text[m.start() : last + 1]


def extract_llm_json(
    text: Optional[str],
    *,
    want: str = "auto",
    required_keys: Sequence[str] = (),
    anchor_keys: Sequence[str] = DEFAULT_ANCHOR_KEYS,
    log_prefix: str = "LLM",
    warn: bool = True,
) -> ExtractionResult:
    """Extract the JSON payload from an LLM response without ever raising.

    Args:
        text: raw model output.
        want: ``"object"`` (a dict), ``"array"`` (a list of dicts) or ``"auto"``.
        required_keys: for objects, at least one of these keys must be present
            for a candidate to count (protects against grabbing an unrelated
            ``{...}`` from prose).
        anchor_keys: keys used to anchor the balanced scan.
        log_prefix: adapter name for log lines.
        warn: log a warning when nothing parses (callers that retry with looser
            requirements pass False on the first attempt).
    """
    result = ExtractionResult(raw_excerpt=(text or "")[:_RAW_EXCERPT])
    _maybe_dump(text, log_prefix)
    if not text or not text.strip():
        result.error = "empty response"
        return result

    cleaned = _clean(text)
    seen: set = set()

    def try_candidate(strategy: str, candidate: str, repair: bool = False) -> bool:
        key = (strategy, repair, candidate)
        if key in seen:
            return False
        seen.add(key)
        payload = repair_common_json_errors(candidate) if repair else candidate
        try:
            value = _loads(payload)
        except (json.JSONDecodeError, ValueError, RecursionError):
            result.attempts.append(f"{strategy}{'+repair' if repair else ''}")
            return False
        if _acceptable(value, want, required_keys):
            result.data = value
            result.strategy = f"{strategy}+repair" if repair else strategy
            return True
        result.attempts.append(f"{strategy}{'+repair' if repair else ''}:rejected")
        return False

    # Whole cleaned text as-is (the happy path).
    if try_candidate("direct", cleaned):
        return result

    candidates = list(_candidates(cleaned, want, anchor_keys))
    for strategy, candidate in candidates:
        if try_candidate(strategy, candidate):
            return result
    for strategy, candidate in candidates:
        if try_candidate(strategy, candidate, repair=True):
            return result
    if try_candidate("direct", cleaned, repair=True):
        return result

    # json-repair: handles unescaped quotes inside strings and truncation.
    if _repair_json is not None:
        slices: List[str] = [cleaned]
        slices.extend(c for _, c in candidates)
        for candidate in slices:
            try:
                value = _repair_json(candidate, return_objects=True)
            except Exception:  # pragma: no cover - library is defensive already
                continue
            if _acceptable(value, want, required_keys):
                result.data = value
                result.strategy = "json_repair"
                return result
        result.attempts.append("json_repair")

    # NDJSON / one object per line.
    if want in ("array", "auto"):
        objects: List[Dict[str, Any]] = []
        for line in cleaned.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = _loads(line)
                except (json.JSONDecodeError, ValueError):
                    try:
                        obj = _loads(repair_common_json_errors(line))
                    except (json.JSONDecodeError, ValueError):
                        continue
                if isinstance(obj, dict):
                    objects.append(obj)
        if objects:
            result.data = objects
            result.strategy = "ndjson"
            return result

    result.error = (
        f"no JSON {want if want != 'auto' else 'payload'} found after "
        f"{len(result.attempts)} attempt(s)"
    )
    if warn:
        logger.warning(
            "%s: could not parse response (%d chars): %s", log_prefix, len(text), result.error
        )
    logger.debug(
        "%s: unparseable response (first %d chars):\n%s",
        log_prefix,
        _RAW_EXCERPT,
        result.raw_excerpt,
    )
    return result


def extract_llm_object(
    text: Optional[str],
    *,
    required_keys: Sequence[str] = (),
    log_prefix: str = "LLM",
    warn: bool = True,
) -> Optional[Dict[str, Any]]:
    """Convenience: the dict payload or None (see :func:`extract_llm_json`)."""
    res = extract_llm_json(
        text, want="object", required_keys=required_keys, log_prefix=log_prefix, warn=warn
    )
    return res.data if isinstance(res.data, dict) else None


def extract_llm_array(text: Optional[str], *, log_prefix: str = "LLM") -> List[Dict[str, Any]]:
    """Convenience: the list-of-dicts payload or [] (see :func:`extract_llm_json`)."""
    res = extract_llm_json(text, want="array", log_prefix=log_prefix)
    if isinstance(res.data, list):
        return [x for x in res.data if isinstance(x, dict)]
    if isinstance(res.data, dict):
        # Some models wrap the array: {"findings": [...]}
        for key in DEFAULT_ANCHOR_KEYS:
            value = res.data.get(key)
            if isinstance(value, list) and all(isinstance(x, dict) for x in value):
                return value
    return []
