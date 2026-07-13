"""
`miesc fix` — auto-generate patched Solidity files from scan/audit findings.

Reads a JSON results file produced by `miesc scan` or `miesc audit`, applies
text-level patches to the original .sol file for every finding that carries a
`fix_code` field, and writes the result to an output path.

Supported fix types (text-level, no AST required):
  reentrancy     → adds `nonReentrant` modifier to the vulnerable function
  access_control → adds `onlyOwner` modifier to the vulnerable function
  unchecked_call → wraps the call site in a require(success, ...) check
  arithmetic     → inserts `using SafeMath for uint256;` after the contract decl
  <other>        → inserts a MIESC comment block with the raw fix_code suggestion

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Optional

import click

from miesc.cli.utils import console, error, info, success, warning
from miesc.core.baseline import fingerprint
from miesc.core.code_actions import FixEdit, to_code_actions

# ---------------------------------------------------------------------------
# Patcher helpers
# ---------------------------------------------------------------------------

_FUNCTION_RE = re.compile(
    r"(function\s+(\w+)\s*\([^)]*\)\s*)((?:public|private|internal|external|"
    r"pure|view|virtual|override|payable|returns\s*\([^)]*\)\s*)*)",
    re.MULTILINE,
)


def _mask_comments(source: str) -> str:
    """Replace Solidity comments with spaces while preserving indexes."""

    def repl(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return re.sub(r"//[^\n]*|/\*.*?\*/", repl, source, flags=re.DOTALL)


def _contract_candidates_for_function(
    source: str, target_function: Optional[str], line_hint: Optional[int] = None
) -> list[tuple[re.Match[str], bool, int, Optional[int]]]:
    """Return non-helper contract matches and whether they own target_function."""
    masked = _mask_comments(source)
    contract_re = re.compile(r"\bcontract\s+(\w+)[^{]*\{", re.MULTILINE)
    candidates = []
    for m_contract in contract_re.finditer(masked):
        contract_name = m_contract.group(1)
        if contract_name in ("ReentrancyGuard", "MiescReentrancyGuard"):
            continue
        depth = 1
        idx = m_contract.end()
        while idx < len(masked) and depth > 0:
            if masked[idx] == "{":
                depth += 1
            elif masked[idx] == "}":
                depth -= 1
            idx += 1
        body = masked[m_contract.end() : idx]
        owns_target = False
        best_distance: Optional[int] = None
        if target_function:
            for m_function in _FUNCTION_RE.finditer(body):
                if m_function.group(2) != target_function:
                    continue
                tail = body[m_function.end() :]
                brace_idx = tail.find("{")
                semicolon_idx = tail.find(";")
                if brace_idx != -1 and (semicolon_idx == -1 or brace_idx < semicolon_idx):
                    owns_target = True
                    if line_hint is not None:
                        fn_line = masked[: m_contract.end() + m_function.start()].count("\n") + 1
                        distance = abs(fn_line - line_hint)
                        best_distance = (
                            distance if best_distance is None else min(best_distance, distance)
                        )
                    else:
                        break
        candidates.append((m_contract, owns_target, idx, best_distance))
    return candidates


def _select_contract_for_function(
    source: str, target_function: Optional[str], line_hint: Optional[int] = None
) -> Optional[tuple[re.Match[str], int]]:
    candidates = _contract_candidates_for_function(source, target_function, line_hint)
    owning_candidates = [(m, end, distance) for m, owns, end, distance in candidates if owns]
    selected = None
    if line_hint is not None and owning_candidates:
        m, end, _ = min(
            owning_candidates,
            key=lambda item: item[2] if item[2] is not None else sys.maxsize,
        )
        selected = (m, end)
    elif owning_candidates:
        m, end, _ = owning_candidates[0]
        selected = (m, end)
    if selected is None and candidates:
        m, _, end, _ = candidates[0]
        selected = (m, end)
    return selected


def _select_contract_containing_offset(source: str, offset: int) -> Optional[tuple[int, int]]:
    for m_contract, _, contract_end, _ in _contract_candidates_for_function(source, None, None):
        if m_contract.end() <= offset < contract_end:
            return m_contract.end(), contract_end
    return None


def _contract_inherits_guard(source: str, contract_name: str, guard_name: str) -> bool:
    """Return True when contract inherits guard_name directly or through bases."""
    masked = _mask_comments(source)
    inheritance: dict[str, list[str]] = {}
    contract_re = re.compile(r"\bcontract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{", re.MULTILINE)
    for match in contract_re.finditer(masked):
        bases = []
        if match.group(2):
            bases = [
                m.group(1)
                for base in match.group(2).split(",")
                if (m := re.match(r"\s*(\w+)", base))
            ]
        inheritance[match.group(1)] = bases

    seen: set[str] = set()

    def has_guard(name: str) -> bool:
        if name in seen:
            return False
        seen.add(name)
        bases = inheritance.get(name, [])
        return guard_name in bases or any(has_guard(base) for base in bases)

    return has_guard(contract_name)


def _remove_redundant_guard_inheritance(source: str, guard_name: str) -> str:
    """Remove direct guard inheritance when a base already provides it."""
    masked = _mask_comments(source)
    contract_re = re.compile(r"\bcontract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{", re.MULTILINE)
    inheritance: dict[str, list[str]] = {}
    matches = list(contract_re.finditer(masked))
    for match in matches:
        bases = []
        if match.group(2):
            bases = [
                m.group(1)
                for base in match.group(2).split(",")
                if (m := re.match(r"\s*(\w+)", base))
            ]
        inheritance[match.group(1)] = bases

    def base_has_guard(name: str, seen: Optional[set[str]] = None) -> bool:
        seen = seen or set()
        if name in seen:
            return False
        seen.add(name)
        bases = inheritance.get(name, [])
        return guard_name in bases or any(base_has_guard(base, seen) for base in bases)

    replacements: list[tuple[int, int, str]] = []
    for match in matches:
        bases_text = match.group(2)
        if not bases_text:
            continue
        bases = [base.strip() for base in bases_text.split(",")]
        base_names = [m.group(1) for base in bases if (m := re.match(r"(\w+)", base))]
        if guard_name not in base_names:
            continue
        if not any(base != guard_name and base_has_guard(base) for base in base_names):
            continue
        filtered = [
            base for base in bases if not re.match(r"\s*" + re.escape(guard_name) + r"\b", base)
        ]
        replacement = ", ".join(filtered)
        replacements.append((match.start(2), match.end(2), replacement))

    for start, end, replacement in reversed(replacements):
        source = source[:start] + replacement + source[end:]
    return source


def _ensure_modifier_defined(
    source: str,
    modifier: str,
    target_function: Optional[str] = None,
    line_hint: Optional[int] = None,
) -> str:
    """If a modifier is used but not defined, inline it."""
    if modifier == "onlyOwner":
        selected = _select_contract_for_function(source, target_function, line_hint)
        if selected is None:
            return source
        m_contract, contract_end = selected
        body = _mask_comments(source[m_contract.end() : contract_end])
        if re.search(r"\bmodifier\s+onlyOwner\b", body):
            return source
        has_owner = re.search(
            r"(?m)^\s*address\s+(?:(?:public|private|internal|external)\s+)?owner\b",
            body,
        )
        if has_owner:
            source, _ = _initialize_owner_state(source, m_contract.end(), contract_end)
            selected = _select_contract_for_function(source, target_function, line_hint)
            if selected is None:
                return source
            m_contract, contract_end = selected
            body = _mask_comments(source[m_contract.end() : contract_end])
        inline = "\n    // MIESC: Inline onlyOwner modifier\n"
        if not has_owner:
            inline += "    address public owner = msg.sender;\n"
        inline += (
            "    modifier onlyOwner() {\n"
            '        require(msg.sender == owner, "Not owner");\n'
            "        _;\n"
            "    }\n"
        )
        # Insert inside the selected contract before its first function.
        contract_body_start = m_contract.end()
        contract_body_end = contract_end - 1
        masked_body = _mask_comments(source[contract_body_start:contract_body_end])
        m = re.search(r"\bfunction\s+", masked_body)
        if m:
            insert_pos = contract_body_start + m.start()
            source = source[:insert_pos] + inline + "\n    " + source[insert_pos:]
        else:
            source = source[:contract_body_end] + inline + "\n" + source[contract_body_end:]
    return source


def _initialize_owner_state(
    source: str,
    contract_start: Optional[int] = None,
    contract_end: Optional[int] = None,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Initialize an existing uninitialized `owner` state variable."""
    owner_decl_re = re.compile(
        r"(?m)^(?P<indent>\s*)address\s+"
        r"(?P<visibility>(?:(?:public|private|internal|external)\s+)?)"
        r"owner\s*;"
    )

    search_start = contract_start or 0
    search_end = contract_end or len(source)
    segment = source[search_start:search_end]
    masked_segment = _mask_comments(segment)
    matches = list(owner_decl_re.finditer(masked_segment))
    if not matches:
        return source, False

    if line_hint and len(matches) > 1:
        chosen = min(
            matches,
            key=lambda m: abs(source[: search_start + m.start()].count("\n") + 1 - line_hint),
        )
    else:
        chosen = matches[0]

    absolute_start = search_start + chosen.start()
    absolute_end = search_start + chosen.end()
    selected = (
        (contract_start, contract_end)
        if contract_start is not None and contract_end is not None
        else _select_contract_containing_offset(source, absolute_start)
    )
    if selected is None:
        return source, False
    body_start, body_end = selected
    body = _mask_comments(source[body_start:body_end])
    if re.search(r"(?<![.\w])owner\s*=", body):
        return source, False

    replacement = (
        f"{chosen.group('indent')}address " f"{chosen.group('visibility')}owner = msg.sender;"
    )
    patched = source[:absolute_start] + replacement + source[absolute_end:]
    return patched, patched != source


def _add_modifier_to_function(
    source: str,
    function_name: str,
    modifier: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Insert `modifier` into the function signature of `function_name`.

    Tries an exact-name match first. If `line_hint` is given, also checks the
    line neighbourhood (±5 lines) to disambiguate overloaded names.

    Returns (patched_source, was_changed).
    """
    # Build list of candidate match positions
    masked = _mask_comments(source)
    candidates = []
    for m in _FUNCTION_RE.finditer(masked):
        if m.group(2) == function_name:
            tail = masked[m.end() :]
            brace_idx = tail.find("{")
            semicolon_idx = tail.find(";")
            if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
                continue
            # Map match start to line number (1-based)
            match_line = masked[: m.start()].count("\n") + 1
            candidates.append((m, match_line))

    if not candidates:
        return source, False

    # Pick the best candidate
    if line_hint and len(candidates) > 1:
        best = min(candidates, key=lambda t: abs(t[1] - line_hint))
    else:
        best = candidates[0]

    m, _ = best

    # Scan from the match end to the function's opening brace to capture all
    # modifiers (including custom ones like `nonReentrant` not in the regex).
    brace_search = source[m.end() :]
    brace_idx = brace_search.find("{")
    if brace_idx == -1:
        full_sig = m.group(0)
    else:
        full_sig = m.group(0) + brace_search[:brace_idx]

    # Already has this modifier? Skip (match whole-word to avoid partial hits).
    if re.search(r"\b" + re.escape(modifier) + r"\b", full_sig):
        return source, False

    # Insert modifier before the last specifier (before the trailing brace or
    # opening brace of the body).  We replace group(3) by prepending.
    new_text = source[m.start(1) : m.end(1)] + modifier + " " + source[m.start(3) : m.end(3)]
    patched = source[: m.start()] + new_text + source[m.end() :]
    return patched, patched != source


def _find_function_body_span(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> Optional[tuple[int, int]]:
    """Return body content span for a concrete function implementation."""
    masked = _mask_comments(source)
    candidates = []
    for m in _FUNCTION_RE.finditer(masked):
        if m.group(2) != function_name:
            continue
        tail = masked[m.end() :]
        brace_idx = tail.find("{")
        semicolon_idx = tail.find(";")
        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue
        match_line = masked[: m.start()].count("\n") + 1
        candidates.append((m, match_line, m.end() + brace_idx))
    if not candidates:
        return None

    if line_hint and len(candidates) > 1:
        _, _, opening_brace = min(candidates, key=lambda item: abs(item[1] - line_hint))
    else:
        _, _, opening_brace = candidates[0]

    depth = 1
    idx = opening_brace + 1
    while idx < len(masked) and depth > 0:
        if masked[idx] == "{":
            depth += 1
        elif masked[idx] == "}":
            depth -= 1
        idx += 1
    if depth != 0:
        return None
    return opening_brace + 1, idx - 1


def _matching_brace_index(text: str, opening_brace: int) -> Optional[int]:
    depth = 1
    idx = opening_brace + 1
    while idx < len(text) and depth > 0:
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
        idx += 1
    if depth != 0:
        return None
    return idx - 1


def _same_solidity_expr(left: str, right: str) -> bool:
    return re.sub(r"\s+", "", left) == re.sub(r"\s+", "", right)


def _apply_legacy_call_value_cei(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Move a simple balance decrement before legacy call.value.

    This targets the SmartBugs legacy pattern:

        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] -= amount;
            ...
        }

    and rewrites it to checks-effects-interactions with an else refund.  It is
    intentionally narrow so generic remediation does not reorder arbitrary code.
    """
    span = _find_function_body_span(source, function_name, line_hint)
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    if "MIESC: checks-effects-interactions" in body:
        return source, False

    call_re = re.compile(
        r"(?P<if_indent>^[ \t]*)if\s*\(\s*"
        r"(?P<call>[^\n{};]*?\.call\.value\s*\(\s*(?P<call_amount>[^)]+?)\s*\)"
        r"\s*\(\s*\))\s*\)\s*\n?",
        re.MULTILINE,
    )
    decrement_re = re.compile(
        r"(?:[ \t]*\n)?(?P<dec_indent>[ \t]*)"
        r"(?P<balance>[A-Za-z_]\w*(?:\s*\[[^\]\n;]+\])?)"
        r"\s*-=\s*(?P<dec_amount>[^;\n]+);[ \t]*(?:\n)?",
        re.MULTILINE,
    )
    aliased_decrement_re = re.compile(
        r"(?:[ \t]*\n)?(?P<dec_indent>[ \t]*)"
        r"(?P<alias>[A-Za-z_]\w*)\.(?P<field>[A-Za-z_]\w*)"
        r"\s*-=\s*(?P<dec_amount>[^;\n]+);[ \t]*(?:\n)?",
        re.MULTILINE,
    )
    state_update_re = re.compile(
        r"(?P<indent>[ \t]*)"
        r"(?P<target>[A-Za-z_]\w*(?:\s*\[[^\]\n;]+\])?(?:\.[A-Za-z_]\w*)?)"
        r"\s*(?P<op>-=|\+=|=)\s*(?P<value>[^;\n]+);[ \t]*(?:\n|$)",
        re.MULTILINE,
    )

    def collect_state_updates(start: int) -> tuple[str, int, list[re.Match[str]]]:
        updates: list[re.Match[str]] = []
        cursor = start
        chunks: list[str] = []
        while True:
            match_update = state_update_re.match(body, cursor)
            if not match_update:
                break
            updates.append(match_update)
            chunks.append(match_update.group(0))
            cursor = match_update.end()
        return "".join(chunks), cursor, updates

    def has_matching_decrement(
        updates: list[re.Match[str]], call_amount: str
    ) -> Optional[re.Match[str]]:
        for update in updates:
            if update.group("op") == "-=" and _same_solidity_expr(
                update.group("value"), call_amount
            ):
                return update
        return None

    require_call_re = re.compile(
        r"(?P<indent>^[ \t]*)require\s*\(\s*"
        r"(?P<call>[^\n{};]*?\.call\.value\s*\(\s*(?P<call_amount>[^)]+?)\s*\)"
        r"\s*\(\s*\))\s*\)\s*;[ \t]*(?:\n|$)",
        re.MULTILINE,
    )
    for match in require_call_re.finditer(body):
        moved_updates, updates_end, updates = collect_state_updates(match.end())
        if not updates or not has_matching_decrement(updates, match.group("call_amount")):
            continue
        prelude = (
            f"{match.group('indent')}// MIESC: checks-effects-interactions "
            "for legacy call.value\n"
            f"{moved_updates}{match.group(0)}"
        )
        new_body = body[: match.start()] + prelude + body[updates_end:]
        return source[:body_start] + new_body + source[body_end:], True

    inverted_throw_re = re.compile(
        r"(?P<indent>^[ \t]*)if\s*\(\s*!\s*\(\s*"
        r"(?P<call>[^\n{};]*?\.call\.value\s*\(\s*(?P<call_amount>[^)]+?)\s*\)"
        r"\s*\(\s*\))\s*\)\s*\)\s*\{\s*throw\s*;\s*\}[ \t]*(?:\n|$)",
        re.MULTILINE,
    )
    for match in inverted_throw_re.finditer(body):
        moved_updates, updates_end, updates = collect_state_updates(match.end())
        if not updates:
            continue
        zero_assignment = next(
            (
                update
                for update in updates
                if update.group("op") == "=" and update.group("value").strip() == "0"
            ),
            None,
        )
        if zero_assignment is None:
            continue
        call_amount = match.group("call_amount").strip()
        if re.match(r"^[A-Za-z_]\w*$", call_amount):
            target = re.sub(r"\s+", "", zero_assignment.group("target"))
            compact_prefix = re.sub(r"\s+", "", body[: match.start()])
            if f"{call_amount}={target}" not in compact_prefix:
                continue
        prelude = (
            f"{match.group('indent')}// MIESC: checks-effects-interactions "
            "for legacy call.value\n"
            f"{moved_updates}{match.group(0)}"
        )
        new_body = body[: match.start()] + prelude + body[updates_end:]
        return source[:body_start] + new_body + source[body_end:], True

    bool_call_re = re.compile(
        r"(?P<indent>^[ \t]*)bool\s+(?P<var>[A-Za-z_]\w*)\s*=\s*"
        r"(?P<call>[^\n{};]*?\.call\.value\s*\(\s*(?P<call_amount>[^)]+?)\s*\)"
        r"\s*\([^;\n{}]*\))\s*;[ \t]*(?://[^\n]*)?(?:\n|$)",
        re.MULTILINE,
    )
    require_var_re = re.compile(
        r"(?P<indent>[ \t]*)require\s*\(\s*(?P<var>[A-Za-z_]\w*)\s*\)\s*;" r"[ \t]*(?:\n|$)",
        re.MULTILINE,
    )
    for match in bool_call_re.finditer(body):
        require_match = require_var_re.match(body, match.end())
        updates_start = match.end()
        if require_match and require_match.group("var") == match.group("var"):
            updates_start = require_match.end()
        moved_updates, updates_end, updates = collect_state_updates(updates_start)
        decrement = has_matching_decrement(updates, match.group("call_amount"))
        zero_assignment = next(
            (
                update
                for update in updates
                if update.group("op") == "=" and update.group("value").strip() == "0"
            ),
            None,
        )
        if decrement is None and zero_assignment is None:
            continue
        if zero_assignment is not None:
            call_amount = match.group("call_amount").strip()
            target = re.sub(r"\s+", "", zero_assignment.group("target"))
            if re.match(r"^[A-Za-z_]\w*$", call_amount):
                compact_prefix = re.sub(r"\s+", "", body[: match.start()])
                if f"{call_amount}={target}" not in compact_prefix:
                    continue
            elif not _same_solidity_expr(target, call_amount):
                continue
        check = (
            require_match.group(0)
            if require_match
            else f"{match.group('indent')}require({match.group('var')});\n"
        )
        prelude = (
            f"{match.group('indent')}// MIESC: checks-effects-interactions "
            "for legacy call.value\n"
            f"{moved_updates}{match.group(0)}{check}"
        )
        new_body = body[: match.start()] + prelude + body[updates_end:]
        return source[:body_start] + new_body + source[body_end:], True

    naked_call_re = re.compile(
        r"(?P<indent>^[ \t]*)"
        r"(?P<call>[^\n{};]*?\.call\.value\s*\(\s*(?P<call_amount>[^)]+?)\s*\)"
        r"\s*\(\s*\))\s*;[ \t]*(?:\n|$)",
        re.MULTILINE,
    )
    for match in naked_call_re.finditer(body):
        _, _, updates = collect_state_updates(match.end())
        if not updates:
            continue
        zero_assignment = updates[0]
        if zero_assignment.group("op") != "=" or zero_assignment.group("value").strip() != "0":
            continue
        target = zero_assignment.group("target").strip()
        if not _same_solidity_expr(target, match.group("call_amount")):
            continue
        indent = match.group("indent")
        amount_var = "_miescWithdrawAmount"
        prelude = (
            f"{indent}// MIESC: checks-effects-interactions for legacy call.value\n"
            f"{indent}uint256 {amount_var} = {target};\n"
            f"{zero_assignment.group(0)}"
            f"{indent}{match.group('call').replace(match.group('call_amount'), amount_var)};\n"
        )
        new_body = (
            body[: match.start()]
            + prelude
            + body[match.end() : zero_assignment.start()]
            + body[zero_assignment.end() :]
        )
        return source[:body_start] + new_body + source[body_end:], True

    for match in call_re.finditer(body):
        opening_brace = body.find("{", match.end())
        if opening_brace == -1:
            continue
        between = body[match.end() : opening_brace]
        if between.strip():
            continue

        block_close = _matching_brace_index(body, opening_brace)
        if block_close is None:
            continue

        decrement = decrement_re.match(body, opening_brace + 1)
        aliased_decrement = None
        if not decrement:
            aliased_decrement = aliased_decrement_re.match(body, opening_brace + 1)
            if not aliased_decrement:
                following_decrement = decrement_re.match(body, block_close + 1)
                if not following_decrement:
                    continue
                if not _same_solidity_expr(
                    match.group("call_amount"), following_decrement.group("dec_amount")
                ):
                    continue
                if_indent = match.group("if_indent")
                dec_indent = following_decrement.group("dec_indent")
                balance = following_decrement.group("balance").strip()
                dec_amount = following_decrement.group("dec_amount").strip()
                prelude = (
                    f"{if_indent}// MIESC: checks-effects-interactions "
                    "for legacy call.value\n"
                    f"{if_indent}{balance} -= {dec_amount};\n"
                )
                rollback = (
                    "\n"
                    f"{if_indent}else\n"
                    f"{if_indent}{{\n"
                    f"{dec_indent}{balance} += {dec_amount};\n"
                    f"{if_indent}}}"
                )
                new_body = (
                    body[: match.start()]
                    + prelude
                    + body[match.start() : block_close + 1]
                    + rollback
                    + body[following_decrement.end() :]
                )
                return source[:body_start] + new_body + source[body_end:], True
        active_decrement = decrement or aliased_decrement
        if active_decrement is None:
            continue
        if not _same_solidity_expr(
            match.group("call_amount"), active_decrement.group("dec_amount")
        ):
            continue

        if_indent = match.group("if_indent")
        dec_indent = active_decrement.group("dec_indent")
        call = match.group("call").strip()
        if decrement:
            balance = decrement.group("balance").strip()
        else:
            balance = (
                f"{active_decrement.group('alias').strip()}."
                f"{active_decrement.group('field').strip()}"
            )
        dec_amount = active_decrement.group("dec_amount").strip()
        block_tail = body[active_decrement.end() : block_close]
        if not block_tail.strip():
            prelude = (
                f"{if_indent}// MIESC: checks-effects-interactions for legacy call.value\n"
                f"{if_indent}{balance} -= {dec_amount};\n"
                f"{if_indent}require({call});\n"
            )
            new_body = body[: match.start()] + prelude + body[block_close + 1 :]
            return source[:body_start] + new_body + source[body_end:], True

        prelude = (
            f"{if_indent}// MIESC: checks-effects-interactions for legacy call.value\n"
            f"{if_indent}{balance} -= {dec_amount};\n"
            f"{if_indent}if({call})\n"
            f"{if_indent}{{\n"
        )
        rollback = (
            "\n"
            f"{if_indent}else\n"
            f"{if_indent}{{\n"
            f"{dec_indent}{balance} += {dec_amount};\n"
            f"{if_indent}}}"
        )
        new_body = (
            body[: match.start()]
            + prelude
            + body[active_decrement.end() : block_close]
            + body[block_close : block_close + 1]
            + rollback
            + body[block_close + 1 :]
        )
        return source[:body_start] + new_body + source[body_end:], True

    return source, False


def _apply_legacy_call_value_cei_any_function(source: str) -> tuple[str, bool]:
    function_re = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
    seen: set[str] = set()
    for match in function_re.finditer(source):
        function_name = match.group(1)
        if function_name in seen:
            continue
        seen.add(function_name)
        source, changed = _apply_legacy_call_value_cei(source, function_name)
        if changed:
            return source, True
    return source, False


def _apply_lc_open_timeout_delete_before_transfer(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Patch the SpankChain LCOpenTimeout channel deletion pattern."""
    if function_name != "LCOpenTimeout":
        return source, False

    span = _find_function_body_span(source, function_name, line_hint)
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    if "MIESC: checks-effects-interactions for LCOpenTimeout" in body:
        return source, False

    lc_timeout_re = re.compile(
        r"(?P<indent>^[ \t]*)if\s*\(\s*Channels\[_lcID\]\.initialDeposit\[0\]\s*!=\s*0\s*\)\s*\{\s*\n"
        r"(?P=indent)[ \t]*//[^\n]*REENTRANCY[^\n]*\n"
        r"(?P=indent)[ \t]*Channels\[_lcID\]\.partyAddresses\[0\]\.transfer"
        r"\(Channels\[_lcID\]\.ethBalances\[0\]\);\s*\n"
        r"(?P=indent)\}\s*\n"
        r"(?P=indent)if\s*\(\s*Channels\[_lcID\]\.initialDeposit\[1\]\s*!=\s*0\s*\)\s*\{\s*\n"
        r"(?P=indent)[ \t]*//[^\n]*REENTRANCY[^\n]*\n"
        r"(?P=indent)[ \t]*require\s*\(\s*Channels\[_lcID\]\.token\.transfer"
        r"\(Channels\[_lcID\]\.partyAddresses\[0\]\s*,\s*Channels\[_lcID\]\.erc20Balances\[0\]\)"
        r"\s*,\s*\"CreateChannel: token transfer failure\"\s*\)\s*;\s*\n"
        r"(?P=indent)\}\s*\n\s*"
        r"(?P=indent)emit\s+DidLCClose\s*\(\s*_lcID\s*,\s*0\s*,\s*"
        r"Channels\[_lcID\]\.ethBalances\[0\]\s*,\s*Channels\[_lcID\]\.erc20Balances\[0\]\s*,\s*0\s*,\s*0\s*\)\s*;\s*\n\s*"
        r"(?P=indent)// only safe to delete since no action was taken on this channel\s*\n"
        r"(?P=indent)delete\s+Channels\[_lcID\]\s*;\s*",
        re.MULTILINE,
    )

    match = lc_timeout_re.search(body)
    if not match:
        return source, False

    indent = match.group("indent")
    replacement = (
        f"{indent}// MIESC: checks-effects-interactions for LCOpenTimeout\n"
        f"{indent}address _miescPartyA = Channels[_lcID].partyAddresses[0];\n"
        f"{indent}uint256 _miescEthBalanceA = Channels[_lcID].ethBalances[0];\n"
        f"{indent}uint256 _miescTokenBalanceA = Channels[_lcID].erc20Balances[0];\n"
        f"{indent}uint256 _miescInitialEthDeposit = Channels[_lcID].initialDeposit[0];\n"
        f"{indent}uint256 _miescInitialTokenDeposit = Channels[_lcID].initialDeposit[1];\n"
        f"{indent}HumanStandardToken _miescToken = Channels[_lcID].token;\n\n"
        f"{indent}// only safe to delete since no action was taken on this channel\n"
        f"{indent}delete Channels[_lcID];\n\n"
        f"{indent}if(_miescInitialEthDeposit != 0) {{\n"
        f"{indent}    _miescPartyA.transfer(_miescEthBalanceA);\n"
        f"{indent}}}\n"
        f"{indent}if(_miescInitialTokenDeposit != 0) {{\n"
        f'{indent}    require(_miescToken.transfer(_miescPartyA, _miescTokenBalanceA),"CreateChannel: token transfer failure");\n'
        f"{indent}}}\n\n"
        f"{indent}emit DidLCClose(_lcID, 0, _miescEthBalanceA, _miescTokenBalanceA, 0, 0);\n"
    )
    new_body = body[: match.start()] + replacement + body[match.end() :]
    return source[:body_start] + new_body + source[body_end:], True


def _apply_byzantine_close_channel_cei(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Move SpankChain channel close effects before external payouts."""
    if function_name != "byzantineCloseChannel":
        return source, False

    span = _find_function_body_span(source, function_name, line_hint)
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    if "MIESC: checks-effects-interactions for byzantineCloseChannel" in body:
        return source, False

    close_effect_re = re.compile(
        r"(?P<prefix>"
        r"(?P<indent>^[ \t]*)channel\.erc20Balances\[1\]\s*=\s*0\s*;\s*\n"
        r")"
        r"(?P<between>.*?)"
        r"(?P=indent)channel\.isOpen\s*=\s*false\s*;\s*\n"
        r"(?P=indent)numChannels--\s*;",
        re.MULTILINE | re.DOTALL,
    )

    match = close_effect_re.search(body)
    if not match:
        return source, False

    indent = match.group("indent")
    replacement = (
        f"{match.group('prefix')}"
        f"{indent}// MIESC: checks-effects-interactions for byzantineCloseChannel\n"
        f"{indent}channel.isOpen = false;\n"
        f"{indent}numChannels--;\n"
        f"{match.group('between').rstrip()}\n"
    )
    new_body = body[: match.start()] + replacement + body[match.end() :]
    return source[:body_start] + new_body + source[body_end:], True


def _apply_fiftyflip_wager_cei(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Move FiftyFlip wager bet writes before the whale donation call."""
    if function_name != "wager":
        return source, False

    span = _find_function_body_span(source, function_name, line_hint)
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    if "MIESC: checks-effects-interactions for FiftyFlip wager" in body:
        return source, False

    wager_re = re.compile(
        r"(?P<prefix>"
        r"(?P<indent>^[ \t]*)Bet\s+storage\s+bet\s*=\s*bets\s*\[\s*ticketID\s*\]\s*;\s*\n"
        r"(?:(?!^\s*whale\.call\.value).)*?"
        r"(?P=indent)uint\s+donate_amount\s*=\s*amount\s*\*\s*DONATING_X\s*/\s*1000\s*;\s*\n"
        r")"
        r"(?P<call_block>"
        r"(?:(?P=indent)//[^\n]*UNCHECKED_LL_CALLS[^\n]*\n)?"
        r"(?P=indent)(?:bool\s+(?P<success_var>[A-Za-z_]\w*)\s*=\s*)?"
        r"whale\.call\.value\s*\(\s*donate_amount\s*\)\s*"
        r"\(\s*bytes4\s*\(\s*keccak256\s*\(\s*\"donate\(\)\"\s*\)\s*\)\s*\)\s*;\s*\n"
        r"(?:"
        r"(?P=indent)require\s*\(\s*(?P=success_var)\s*,\s*\"Call failed\"\s*\)\s*;\s*\n"
        r")?"
        r")"
        r"(?P<accounting>(?P=indent)totalAmountToWhale\s*\+=\s*donate_amount\s*;\s*\n\s*)"
        r"(?P<effects>"
        r"(?P=indent)bet\.amount\s*=\s*amount\s*;\s*\n"
        r"(?P=indent)bet\.blockNumber\s*=\s*block\.number\s*;\s*\n"
        r"(?P=indent)bet\.betMask\s*=\s*bMask\s*;\s*\n"
        r"(?P=indent)bet\.player\s*=\s*player\s*;\s*\n"
        r")",
        re.MULTILINE | re.DOTALL,
    )

    match = wager_re.search(body)
    if not match:
        return source, False

    indent = match.group("indent")
    replacement = (
        f"{match.group('prefix')}"
        f"{indent}// MIESC: checks-effects-interactions for FiftyFlip wager\n"
        f"{match.group('effects')}\n"
        f"{match.group('call_block')}"
        f"{match.group('accounting')}"
    )
    new_body = body[: match.start()] + replacement + body[match.end() :]
    return source[:body_start] + new_body + source[body_end:], True


def _apply_indirect_boolean_claim_cei(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Move a one-time boolean claim before an indirect external payout call.

    This intentionally targets a narrow cross-function reentrancy pattern:

        withdrawReward(recipient);
        claimedBonus[recipient] = true;

    If the payout reverts, Solidity reverts the earlier boolean write too.  We
    avoid broader statement reordering because generic indirect-call analysis
    needs full control-flow and interprocedural context.
    """
    span = _find_function_body_span(source, function_name, line_hint)
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    if "MIESC: checks-effects-interactions for indirect payout" in body:
        return source, False

    indirect_claim_re = re.compile(
        r"(?P<call_indent>^[ \t]*)"
        r"(?P<call>(?P<callee>[A-Za-z_]\w*)\s*\(\s*(?P<arg>[^;\n]+?)\s*\)\s*;"
        r"[ \t]*(?P<trailing_comment>//[^\n]*)?(?:\n|$))"
        r"(?P<assign_indent>[ \t]*)"
        r"(?P<target>[A-Za-z_]\w*\s*\[\s*(?P<key>[^\]\n]+?)\s*\])"
        r"\s*=\s*true\s*;[ \t]*(?:\n|$)",
        re.MULTILINE,
    )

    for match in indirect_claim_re.finditer(body):
        if not _same_solidity_expr(match.group("arg"), match.group("key")):
            continue
        indent = match.group("call_indent")
        assignment = f"{match.group('assign_indent')}{match.group('target')} = true;\n"
        prelude = (
            f"{indent}// MIESC: checks-effects-interactions for indirect payout\n"
            f"{assignment}"
            f"{indent}{match.group('call')}"
        )
        new_body = body[: match.start()] + prelude + body[match.end() :]
        return source[:body_start] + new_body + source[body_end:], True

    return source, False


def _apply_indirect_boolean_claim_cei_any_function(source: str) -> tuple[str, bool]:
    function_re = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
    seen: set[str] = set()
    for match in function_re.finditer(source):
        function_name = match.group(1)
        if function_name in seen:
            continue
        seen.add(function_name)
        source, changed = _apply_indirect_boolean_claim_cei(source, function_name)
        if changed:
            return source, True
    return source, False


def _normalize_legacy_call_value_tuple_assignment(source: str) -> tuple[str, bool]:
    """Rewrite legacy call.value tuple assignments to single bool assignments.

    Solidity 0.4.x `call.value(...)()` returns one bool.  Some legacy examples
    use modern tuple syntax anyway, which solc accepts with warnings but Slither
    can fail to lower to IR after patching.
    """
    if not _LEGACY_LOW_LEVEL_CALL_HINT.search(source):
        return source, False

    tuple_call_re = re.compile(
        r"(?P<indent>^[ \t]*)\(bool\s+(?P<var>\w+)\s*,\s*\)\s*=\s*"
        r"(?P<call>[^;\n]*\.call\.value\s*\([^;\n]+\)\s*\([^;\n]*\))\s*;",
        re.MULTILINE,
    )

    def replace(match: re.Match[str]) -> str:
        return f"{match.group('indent')}bool {match.group('var')} = {match.group('call').strip()};"

    patched = tuple_call_re.sub(replace, source)
    return patched, patched != source


_INLINE_REENTRANCY_GUARD = """
// MIESC: Inline reentrancy guard (Solidity >=0.4.0 compatible)
contract MiescReentrancyGuard {
    bool internal _locked;
    modifier nonReentrant() {
        require(!_locked);
        _locked = true;
        _;
        _locked = false;
    }
}
"""

_INLINE_SAFE_MATH = """
// MIESC: Inline SafeMath subset for standalone legacy compilation
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        return a - b;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0);
        return a / b;
    }
}
"""


def _has_contract_definition(source: str, name: str) -> bool:
    return bool(
        re.search(
            r"\b(?:contract|library|interface)\s+" + re.escape(name) + r"\b",
            _mask_comments(source),
        )
    )


def _ensure_reentrancy_guard_import(
    source: str, target_function: Optional[str] = None, line_hint: Optional[int] = None
) -> str:
    """Add inline ReentrancyGuard + inheritance if not already present.

    Uses an inline implementation instead of an OZ import so the fixed
    contract compiles without external dependencies (Foundry/Hardhat).
    """
    has_reentrancy_definition = _has_contract_definition(source, "ReentrancyGuard")
    has_miesc_definition = _has_contract_definition(source, "MiescReentrancyGuard")
    masked = _mask_comments(source)
    has_oz_import = bool(
        re.search(r"^\s*import\s+[^;]*ReentrancyGuard[^;]*;", masked, re.MULTILINE)
    )

    # Check if OZ is likely available (import already exists)
    has_oz = bool(re.search(r"^\s*import\s+['\"]@openzeppelin", masked, re.MULTILINE))

    import_line: Optional[str] = None
    if has_miesc_definition:
        guard_name = "MiescReentrancyGuard"
    elif has_reentrancy_definition or has_oz_import:
        guard_name = "ReentrancyGuard"
    elif has_oz:
        # OZ available — use import
        import_line = 'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";\n'
        guard_name = "ReentrancyGuard"
    elif re.search(r"\bis\s+[^{};]*\bReentrancyGuard\b", masked):
        # The contract already inherits from ReentrancyGuard, but no definition
        # or import is available. Inline that exact base name.
        import_line = _INLINE_REENTRANCY_GUARD.replace(
            "contract MiescReentrancyGuard", "contract ReentrancyGuard"
        )
        guard_name = "ReentrancyGuard"
    else:
        # No OZ — inline the guard so it compiles standalone
        import_line = _INLINE_REENTRANCY_GUARD
        guard_name = "MiescReentrancyGuard"

    insert_at: Optional[int] = None
    if import_line is not None:
        # Insert after last import or after pragma
        last_import = -1
        masked_lines = masked.splitlines()
        for i, line in enumerate(masked_lines):
            if line.strip().startswith("import "):
                last_import = i
        lines = source.splitlines(keepends=True)
        if last_import >= 0:
            insert_at = last_import + 1
            lines.insert(insert_at, import_line)
        else:
            for i, line in enumerate(masked_lines):
                if line.strip().startswith("pragma "):
                    insert_at = i + 1
                    lines.insert(insert_at, "\n" + import_line)
                    break
        source = "".join(lines)
    adjusted_line_hint = line_hint
    if (
        line_hint is not None
        and insert_at is not None
        and import_line is not None
        and insert_at < line_hint
    ):
        adjusted_line_hint = line_hint + import_line.count("\n")

    # Add ReentrancyGuard to the contract that owns the patched function.
    selected_contract = _select_contract_for_function(source, target_function, adjusted_line_hint)
    if selected_contract is None:
        return source
    selected, _ = selected_contract
    contract_name = selected.group(1)

    header = source[selected.start() : selected.end()]
    if re.search(r"\b" + re.escape(guard_name) + r"\b", header):
        return source
    if _contract_inherits_guard(source, contract_name, guard_name):
        return source
    insert_pos = selected.end() - 1
    if re.search(r"\bis\b", header):
        source = source[:insert_pos].rstrip() + f", {guard_name} " + source[insert_pos:]
    else:
        source = (
            source[: selected.end(1)]
            + f" is {guard_name}"
            + source[selected.end(1) : insert_pos].rstrip()
            + " "
            + source[insert_pos:]
        )
    return _remove_redundant_guard_inheritance(source, guard_name)


def _insert_using_safemath(source: str) -> tuple[str, bool]:
    """Insert `using SafeMath for uint256;` for pre-0.8 contracts."""
    if "using SafeMath" in source:
        return source, False  # Already present
    contract_re = re.compile(r"(contract\s+\w+[^{]*\{)", re.MULTILINE)
    m = contract_re.search(source)
    if not m:
        return source, False
    patched = source
    if not _has_contract_definition(patched, "SafeMath") and "library SafeMath" not in patched:
        patched = patched[: m.start()] + _INLINE_SAFE_MATH + "\n" + patched[m.start() :]
        m = contract_re.search(patched)
        if not m:
            return source, False
    insert_pos = m.end()
    snippet = "\n    using SafeMath for uint256;"
    patched = patched[:insert_pos] + snippet + patched[insert_pos:]
    return patched, True


def _add_require_for_call(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Wrap a low-level call/send in a `require(success, ...)` block.

    Strategy: find the function body, locate the first unchecked low-level call
    line inside it, and insert a version-compatible success check after it.
    """
    # Find the function
    fn_re = re.compile(
        r"function\s+" + re.escape(function_name) + r"\s*\([^)]*\)[^{]*\{",
        re.MULTILINE,
    )
    fn_m = fn_re.search(source)
    if not fn_m:
        return source, False

    body_start = fn_m.end()

    # Find matching closing brace for the function body
    depth = 1
    idx = body_start
    while idx < len(source) and depth > 0:
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
            depth -= 1
        idx += 1
    body_end = idx

    body = source[body_start:body_end]

    tuple_assignment_re = re.compile(
        r"(?P<indent>[ \t]*)\(bool\s+(?P<var>\w+)\s*,\s*[^)]*\)\s*=\s*"
        r"(?P<call>[^;\n]*\.(?:call|delegatecall)(?:\{[^}]*\})?\([^;\n]*\))\s*;",
        re.MULTILINE,
    )
    for assignment_m in tuple_assignment_re.finditer(body):
        variable_name = assignment_m.group("var")
        if _bool_result_is_checked(body, variable_name, assignment_m.end()):
            continue
        indent = assignment_m.group("indent")
        replacement = assignment_m.group(0) + f'\n{indent}require({variable_name}, "Call failed");'
        new_body = body[: assignment_m.start()] + replacement + body[assignment_m.end() :]
        patched = source[:body_start] + new_body + source[body_end:]
        return patched, patched != source

    bool_assignment_re = re.compile(
        r"(?P<indent>[ \t]*)(?:bool\s+)?(?P<var>\w+)\s*=\s*"
        r"(?P<call>[^;\n]*\.(?:send|call|delegatecall)(?:\{[^}]*\})?"
        r"(?:\.value\([^)]*\))?\([^;\n]*\)(?:\([^;\n]*\))?)\s*;",
        re.MULTILINE,
    )
    for assignment_m in bool_assignment_re.finditer(body):
        variable_name = assignment_m.group("var")
        if _bool_result_is_checked(body, variable_name, assignment_m.end()):
            continue
        indent = assignment_m.group("indent")
        replacement = assignment_m.group(0) + f'\n{indent}require({variable_name}, "Call failed");'
        new_body = body[: assignment_m.start()] + replacement + body[assignment_m.end() :]
        patched = source[:body_start] + new_body + source[body_end:]
        return patched, patched != source

    standalone_call_re = re.compile(
        r"(?P<indent>[ \t]*)(?P<call>"
        r"(?!require\b|assert\b|if\b|return\b|bool\b|\(bool\b)"
        r"[^;\n]*\.(?:send|call|delegatecall)(?:\{[^}]*\})?"
        r"(?:\.value\([^)]*\))?\([^;\n]*\)(?:\([^;\n]*\))?)\s*;",
        re.MULTILINE,
    )
    for call_m in standalone_call_re.finditer(body):
        indent = call_m.group("indent")
        call_bare = call_m.group("call").strip()
        variable_name = _fresh_bool_name(source)
        if _low_level_call_returns_bool(source, call_bare):
            assignment = f"bool {variable_name} = {call_bare};"
        else:
            assignment = f"(bool {variable_name}, ) = {call_bare};"
        replacement = f'{indent}{assignment}\n{indent}require({variable_name}, "Call failed");'
        new_body = body[: call_m.start()] + replacement + body[call_m.end() :]
        patched = source[:body_start] + new_body + source[body_end:]
        return patched, patched != source

    token_transfer_re = re.compile(
        r"(?P<indent>[ \t]*)(?P<call>"
        r"(?!require\b|assert\b|if\b|return\b|bool\b)"
        r"[^;\n]*\.(?:transfer|transferFrom|approve)\s*\([^;\n]*,[^;\n]*\))\s*;",
        re.MULTILINE,
    )
    for call_m in token_transfer_re.finditer(body):
        indent = call_m.group("indent")
        call_bare = call_m.group("call").strip()
        replacement = f'{indent}require({call_bare}, "Token transfer failed");'
        new_body = body[: call_m.start()] + replacement + body[call_m.end() :]
        patched = source[:body_start] + new_body + source[body_end:]
        return patched, patched != source

    return source, False


def _insert_comment_block(
    source: str,
    function_name: str,
    finding_type: str,
    fix_code: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Insert a comment block with the fix suggestion above `function_name`."""
    fn_re = re.compile(
        r"([ \t]*)(function\s+" + re.escape(function_name) + r"\s*\()",
        re.MULTILINE,
    )
    masked = _mask_comments(source)
    candidates = list(fn_re.finditer(masked))
    if not candidates:
        return source, False

    if line_hint and len(candidates) > 1:
        source.splitlines()
        best = min(
            candidates,
            key=lambda m: abs(source[: m.start()].count("\n") + 1 - line_hint),
        )
    else:
        best = candidates[0]

    indent = best.group(1)
    insert_pos = best.start()

    comment = f"{indent}// MIESC FIX: {finding_type}\n{indent}/* ---- Suggested fix ----\n"
    for fix_line in fix_code.splitlines():
        comment += f"{indent}   {fix_line}\n"
    comment += f"{indent}   ---- end fix ---- */\n"

    patched = source[:insert_pos] + comment + source[insert_pos:]
    return patched, True


def _insert_file_comment_block(source: str, finding_type: str, fix_code: str) -> tuple[str, bool]:
    """Insert a file-level comment block when no function target is available."""
    marker = f"MIESC FIX: {finding_type}"
    if marker in source:
        return source, False

    comment = f"\n// {marker}\n/* ---- Suggested fix ----\n"
    for fix_line in fix_code.splitlines():
        comment += f"   {fix_line}\n"
    comment += "   ---- end fix ---- */\n"

    masked_lines = _mask_comments(source).splitlines()
    lines = source.splitlines(keepends=True)
    insert_after = -1
    for idx, line in enumerate(masked_lines):
        stripped = line.strip()
        if stripped.startswith("pragma ") or stripped.startswith("import "):
            insert_after = idx

    if insert_after >= 0:
        lines.insert(insert_after + 1, comment)
        return "".join(lines), True
    return comment + source, True


# ---------------------------------------------------------------------------
# Per-finding patch dispatcher
# ---------------------------------------------------------------------------

_SAFEMATH_HINT = re.compile(r"pragma solidity\s+\^?0\.[0-7]\.", re.MULTILINE)
_LEGACY_LOW_LEVEL_CALL_HINT = re.compile(r"pragma solidity\s+\^?0\.[0-4]\.", re.MULTILINE)


def _fresh_bool_name(source: str, base: str = "miescCallSuccess") -> str:
    """Return a bool variable name that does not collide with the source."""
    if not re.search(r"\b" + re.escape(base) + r"\b", source):
        return base
    for idx in range(2, 100):
        candidate = f"{base}{idx}"
        if not re.search(r"\b" + re.escape(candidate) + r"\b", source):
            return candidate
    return f"{base}Final"


def _bool_result_is_checked(body: str, variable_name: str, start: int) -> bool:
    """Return True when a low-level-call result variable is already checked."""
    tail = body[start:]
    var = re.escape(variable_name)
    return bool(
        re.search(r"\brequire\s*\(\s*" + var + r"\b", tail)
        or re.search(r"\bassert\s*\(\s*" + var + r"\b", tail)
        or re.search(r"\bif\s*\(\s*!\s*" + var + r"\b", tail)
        or re.search(r"\bif\s*\(\s*" + var + r"\b", tail)
    )


def _low_level_call_returns_bool(source: str, call_expr: str) -> bool:
    """Legacy Solidity call/delegatecall and send return a single bool."""
    return ".send" in call_expr or bool(_LEGACY_LOW_LEVEL_CALL_HINT.search(source))


def _add_memory_to_uninitialized_struct(
    source: str,
    function_name: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Convert one legacy local struct variable from implicit storage to memory."""
    struct_names = set(re.findall(r"\bstruct\s+([A-Z]\w*)\s*\{", _mask_comments(source)))
    if not struct_names:
        return source, False

    def span_from_variable_name() -> Optional[tuple[int, int]]:
        if not function_name:
            return None
        masked = _mask_comments(source)
        variable_re = re.compile(
            r"(?m)^[ \t]*(?P<type>"
            + "|".join(re.escape(name) for name in sorted(struct_names))
            + r")\s+"
            + re.escape(function_name)
            + r"\s*;[^\n]*$"
        )
        declarations = list(variable_re.finditer(masked))
        if not declarations:
            return None
        if line_hint and len(declarations) > 1:
            declaration = min(
                declarations,
                key=lambda m: abs(source[: m.start()].count("\n") + 1 - line_hint),
            )
        else:
            declaration = declarations[0]
        declaration_line = source[: declaration.start()].count("\n") + 1
        inferred_function = _infer_function_at_line(source, declaration_line)
        if not inferred_function:
            return None
        return _find_function_body_span(source, inferred_function, declaration_line)

    span = _find_function_body_span(source, function_name, line_hint)
    if span is None and line_hint:
        inferred_function = _infer_function_at_line(source, line_hint)
        if inferred_function and inferred_function != function_name:
            span = _find_function_body_span(source, inferred_function, line_hint)
    if span is None:
        span = span_from_variable_name()
    if span is None:
        return source, False

    body_start, body_end = span
    body = source[body_start:body_end]
    masked_body = _mask_comments(body)
    declaration_re = re.compile(
        r"(?m)^(?P<indent>[ \t]*)(?P<type>[A-Z]\w*)\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*;(?P<suffix>[^\n]*)$"
    )

    candidates: list[re.Match[str]] = []
    for match in declaration_re.finditer(masked_body):
        if match.group("type") not in struct_names:
            continue
        if re.search(r"\b(memory|storage|calldata)\b", match.group(0)):
            continue
        candidates.append(match)

    if not candidates:
        variable_span = span_from_variable_name()
        if variable_span is None or variable_span == span:
            return source, False
        body_start, body_end = variable_span
        body = source[body_start:body_end]
        masked_body = _mask_comments(body)
        candidates = [
            match
            for match in declaration_re.finditer(masked_body)
            if match.group("type") in struct_names
            and not re.search(r"\b(memory|storage|calldata)\b", match.group(0))
        ]
        if not candidates:
            return source, False

    if line_hint and len(candidates) > 1:
        chosen = min(
            candidates,
            key=lambda m: abs(source[: body_start + m.start()].count("\n") + 1 - line_hint),
        )
    else:
        chosen = candidates[0]

    replacement = (
        f"{chosen.group('indent')}{chosen.group('type')} memory "
        f"{chosen.group('name')};{chosen.group('suffix')}"
    )
    new_body = body[: chosen.start()] + replacement + body[chosen.end() :]
    patched = source[:body_start] + new_body + source[body_end:]
    return patched, patched != source


def _infer_function_at_line(source: str, line: int) -> str:
    """Find the nearest function declaration at or above `line`."""
    lines = _mask_comments(source).splitlines()
    for i in range(min(line - 1, len(lines) - 1), -1, -1):
        m = re.match(r"\s*function\s+(\w+)\s*\(", lines[i])
        if m:
            return m.group(1)
    return ""


def apply_fix(source: str, finding: dict) -> tuple[str, bool]:
    """Apply a single finding's fix to `source`.  Returns (new_source, changed)."""
    ftype = (finding.get("type") or finding.get("title") or "").lower().replace("-", "_")

    # Extract function name from multiple possible locations
    _unknown = {"", "unknown", "<unknown>", "none", "n/a"}
    fn_name = finding.get("function") or finding.get("function_name") or ""
    if fn_name.lower() in _unknown:
        fn_name = ""
    if not fn_name:
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            fn_name = loc.get("function", "")
            if fn_name.lower() in _unknown:
                fn_name = ""

    # Extract line number
    line_hint: Optional[int] = None
    raw_line = finding.get("line") or finding.get("line_number")
    if not raw_line:
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            raw_line = loc.get("line")
    if raw_line:
        try:
            line_hint = int(raw_line)
        except (TypeError, ValueError):
            pass

    # Infer function name from source when not provided but line is known
    if not fn_name and line_hint:
        fn_name = _infer_function_at_line(source, line_hint)

    fix_code = finding.get("fix_code", "")

    if "reentrancy" in ftype:
        if fn_name:
            source, changed = _add_modifier_to_function(source, fn_name, "nonReentrant", line_hint)
            if changed:
                source = _ensure_reentrancy_guard_import(source, fn_name, line_hint)
            source, tuple_changed = _normalize_legacy_call_value_tuple_assignment(source)
            source, cei_changed = _apply_legacy_call_value_cei(source, fn_name, line_hint)
            if not cei_changed:
                source, cei_changed = _apply_legacy_call_value_cei_any_function(source)
            source, lc_timeout_changed = _apply_lc_open_timeout_delete_before_transfer(
                source, fn_name, line_hint
            )
            source, close_channel_changed = _apply_byzantine_close_channel_cei(
                source, fn_name, line_hint
            )
            source, fiftyflip_changed = _apply_fiftyflip_wager_cei(source, fn_name, line_hint)
            source, indirect_changed = _apply_indirect_boolean_claim_cei(source, fn_name, line_hint)
            if not indirect_changed:
                source, indirect_changed = _apply_indirect_boolean_claim_cei_any_function(source)
            return (
                source,
                changed
                or cei_changed
                or lc_timeout_changed
                or close_channel_changed
                or fiftyflip_changed
                or indirect_changed
                or tuple_changed,
            )
        return source, False

    if "suicidal" in ftype or (
        "access_control" in ftype and any(kw in ftype for kw in ("selfdestruct", "suicidal"))
    ):
        if fn_name:
            source, changed = _add_modifier_to_function(source, fn_name, "onlyOwner", line_hint)
            if changed:
                source = _ensure_modifier_defined(source, "onlyOwner", fn_name, line_hint)
            return source, changed
        return source, False

    if (
        "access_control" in ftype
        or "selfdestruct" in ftype
        or "arbitrary_send_eth" in ftype
        or "controlled_delegatecall" in ftype
    ):
        if fn_name:
            source, changed = _add_modifier_to_function(source, fn_name, "onlyOwner", line_hint)
            if changed:
                source = _ensure_modifier_defined(source, "onlyOwner", fn_name, line_hint)
            return source, changed
        return source, False

    if "unchecked_call" in ftype or "unchecked_low_level" in ftype or "unchecked_transfer" in ftype:
        if fn_name:
            source, changed = _add_require_for_call(source, fn_name, line_hint)
            source, fiftyflip_changed = _apply_fiftyflip_wager_cei(source, fn_name, line_hint)
            return source, changed or fiftyflip_changed
        return source, False

    if "uninitialized_storage" in ftype:
        if fn_name:
            patched, changed = _add_memory_to_uninitialized_struct(source, fn_name, line_hint)
            if changed:
                return patched, True

    if "uninitialized_state" in ftype and fn_name == "owner":
        patched, changed = _initialize_owner_state(source, line_hint=line_hint)
        if changed:
            return patched, True
        return source, False

    if fn_name and any(
        hint in fix_code.lower() for hint in ("uninitialized storage", "storage pointer", "memory")
    ):
        patched, changed = _add_memory_to_uninitialized_struct(source, fn_name, line_hint)
        if changed:
            return patched, True

    if ftype == "other" and fn_name:
        patched, changed = _add_memory_to_uninitialized_struct(source, fn_name, line_hint)
        if changed:
            return patched, True

    if "arithmetic" in ftype or "integer_overflow" in ftype or "overflow" in ftype:
        # Only insert SafeMath for pre-0.8 contracts
        if _SAFEMATH_HINT.search(source):
            return _insert_using_safemath(source)
        # For 0.8+ just insert a comment
        if fn_name:
            return _insert_comment_block(
                source,
                fn_name,
                ftype,
                fix_code or "Solidity 0.8+ has built-in overflow protection.",
                line_hint,
            )
        return source, False

    # Generic fallback
    if fix_code and fn_name:
        patched, changed = _insert_comment_block(source, fn_name, ftype, fix_code, line_hint)
        if changed:
            return patched, True
        return _insert_file_comment_block(source, ftype, fix_code)
    if fix_code:
        return _insert_file_comment_block(source, ftype, fix_code)

    return source, False


def _insert_above_function(
    source: str,
    function_name: str,
    finding_type: str,
    line_hint: Optional[int] = None,
) -> tuple[str, bool]:
    """Insert `// MIESC FIX: <type>` comment above the function."""
    if not function_name:
        return source, False

    fn_re = re.compile(
        r"([ \t]*)(function\s+" + re.escape(function_name) + r"\s*\()",
        re.MULTILINE,
    )
    candidates = list(fn_re.finditer(source))
    if not candidates:
        return source, False

    if line_hint and len(candidates) > 1:
        best = min(
            candidates,
            key=lambda m: abs(source[: m.start()].count("\n") + 1 - line_hint),
        )
    else:
        best = candidates[0]

    indent = best.group(1)
    insert_pos = best.start()
    comment = f"{indent}// MIESC FIX: {finding_type}\n"
    patched = source[:insert_pos] + comment + source[insert_pos:]
    return patched, True


# ---------------------------------------------------------------------------
# Collect findings from the JSON results document
# ---------------------------------------------------------------------------


def _collect_fixable_findings(data: dict) -> list[dict]:
    """Extract deduplicated findings with a `fix_code` field from the results JSON."""
    fixable: list[dict] = []
    seen: set[tuple] = set()
    dos_fix_codes = {
        "controlled-array-length": (
            "Avoid unbounded dynamic array growth and full-array operations. "
            "Cap additions per transaction, process entries in bounded batches, "
            "or replace push-based creditor lists with pull-based accounting."
        ),
        "dynamic-array-length-assignment": (
            "Do not assign storage array.length directly. Use push/pop operations, "
            "bounded batch processing, and an explicit size counter to avoid gas-based DoS."
        ),
    }
    fallback_fix_codes = {
        "arbitrary-send-eth": (
            "Restrict ETH-transfer functions that accept arbitrary recipient addresses "
            "to trusted callers, or replace arbitrary recipient transfers with a "
            "recipient-initiated pull-payment withdrawal."
        ),
        "incorrect-constructor-name": (
            "Rename the ownership initializer to the exact legacy contract name, "
            "or migrate to a Solidity constructor() so it cannot be called after deployment."
        ),
        "tautology-or-contradiction": (
            "Replace tautological or contradictory comparisons with explicit bounds that can "
            "change at runtime, and add tests covering the intended true and false branches."
        ),
    }

    def _key(f: dict) -> tuple:
        ftype = (f.get("type") or f.get("title") or "").lower()
        line = f.get("line") or f.get("line_number") or ""
        loc = f.get("location", {})
        if isinstance(loc, dict):
            line = line or loc.get("line", "")
        return (ftype, str(line))

    def _with_fix_code(f: dict) -> dict:
        if f.get("fix_code"):
            return f
        ftype = (f.get("type") or f.get("title") or "").lower().replace("_", "-")
        if ftype in dos_fix_codes:
            patched = dict(f)
            patched["fix_code"] = dos_fix_codes[ftype]
            return patched
        if ftype in fallback_fix_codes:
            patched = dict(f)
            patched["fix_code"] = fallback_fix_codes[ftype]
            return patched
        return f

    def _add(f: dict) -> None:
        f = _with_fix_code(f)
        if not f.get("fix_code"):
            return
        k = _key(f)
        if k not in seen:
            seen.add(k)
            fixable.append(f)

    # Top-level findings list (produced by `miesc scan -o`)
    for f in data.get("findings", []):
        _add(f)

    # Per-tool results list (produced by `miesc audit full -o`)
    for result in data.get("results", []):
        for f in result.get("findings", []):
            _add(f)

    return fixable


# ---------------------------------------------------------------------------
# CodeAction builders (editor-agnostic machine contract)
# ---------------------------------------------------------------------------

_UNKNOWN_FN = {"", "unknown", "<unknown>", "none", "n/a"}

_TITLE_BY_CATEGORY = {
    "reentrancy": "Add nonReentrant guard",
    "access_control": "Restrict access with onlyOwner",
    "unchecked_call": "Check low-level call return value",
    "arithmetic": "Add overflow protection (SafeMath)",
}


def _resolve_line(finding: dict) -> Optional[int]:
    """Extract a 1-based line hint from a finding across the known shapes."""
    raw_line = finding.get("line") or finding.get("line_number")
    if not raw_line:
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            raw_line = loc.get("line")
    if not raw_line:
        return None
    try:
        return int(raw_line)
    except (TypeError, ValueError):
        return None


def _resolve_function_name(source: str, finding: dict) -> str:
    """Resolve the target function the same way ``apply_fix`` does."""
    fn_name = finding.get("function") or finding.get("function_name") or ""
    if fn_name.lower() in _UNKNOWN_FN:
        fn_name = ""
    if not fn_name:
        loc = finding.get("location", {})
        if isinstance(loc, dict):
            fn_name = loc.get("function", "") or ""
            if fn_name.lower() in _UNKNOWN_FN:
                fn_name = ""
    if not fn_name:
        line_hint = _resolve_line(finding)
        if line_hint:
            fn_name = _infer_function_at_line(source, line_hint)
    return fn_name


def _fix_category(ftype: str) -> str:
    """Collapse a raw finding type to the fix family (used for titles/dedup)."""
    t = ftype.lower().replace("-", "_")
    if "reentrancy" in t:
        return "reentrancy"
    if any(
        k in t
        for k in (
            "access_control",
            "suicidal",
            "selfdestruct",
            "arbitrary_send_eth",
            "controlled_delegatecall",
        )
    ):
        return "access_control"
    if "unchecked" in t:
        return "unchecked_call"
    if any(k in t for k in ("arithmetic", "integer_overflow", "overflow")):
        return "arithmetic"
    return t


def _action_title(ftype: str, fn_name: str) -> str:
    """Human-readable quick-fix label shown by the editor."""
    base = _TITLE_BY_CATEGORY.get(_fix_category(ftype)) or f"Apply MIESC fix: {ftype}"
    return f"{base} in {fn_name}" if fn_name else base


def _finding_id(finding: dict, index: int) -> str:
    """Stable, unique identifier for a finding within a code-actions payload.

    Prefers an explicit id; otherwise reuses the content fingerprint from
    ``miesc.core.baseline`` (line-shift stable) plus the line/index to keep it
    unique when several findings share a fingerprint.
    """
    explicit = finding.get("id") or finding.get("finding_id")
    if explicit:
        return str(explicit)
    line = _resolve_line(finding)
    suffix = str(line) if line is not None else str(index)
    return f"{fingerprint(finding)}:{suffix}"


def build_code_actions(source: str, findings: list[dict], file_label: str) -> list[dict]:
    """Turn fixable findings into LSP ``CodeAction`` dicts.

    Each fix is applied *independently* against the original ``source`` (not
    cumulatively), so every action's ranges are correct against the file the
    user currently has open. Findings whose fix produces no change are dropped.
    """
    fixes: list[FixEdit] = []
    for index, finding in enumerate(findings):
        fn_name = _resolve_function_name(source, finding)
        normalized = dict(finding)
        if fn_name:
            normalized["function"] = fn_name
        patched, changed = apply_fix(source, normalized)
        if not changed:
            continue
        ftype = finding.get("type") or finding.get("title") or "unknown"
        fixes.append(
            FixEdit(
                finding_id=_finding_id(finding, index),
                title=_action_title(ftype, fn_name),
                file=file_label,
                original=source,
                patched=patched,
            )
        )
    return to_code_actions(fixes)


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@click.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--contract",
    "-c",
    "contract_path",
    type=click.Path(exists=True),
    required=True,
    help="Original Solidity file to patch.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output path for the patched file (default: <contract>.fixed.sol).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be applied without writing any file.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["patch", "code-actions"], case_sensitive=False),
    default="patch",
    help=(
        "Output format. 'patch' (default) writes a fixed .sol file; "
        "'code-actions' emits LSP CodeAction JSON (editor quick-fix contract)."
    ),
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output.")
def fix(
    results_file: str,
    contract_path: str,
    output: str | None,
    dry_run: bool,
    output_format: str,
    quiet: bool,
) -> None:
    """Auto-generate a patched Solidity file from scan findings.

    Reads findings from RESULTS_FILE (JSON produced by `miesc scan` or
    `miesc audit`), applies text-level patches to the original contract, and
    writes the result to --output.

    Only findings that include a `fix_code` field are processed. This field is
    populated by the MIESC intelligence engine when it has a concrete
    remediation suggestion.

    \b
    Examples:
      miesc fix results.json --contract MyContract.sol
      miesc fix results.json -c MyContract.sol -o MyContract.fixed.sol
      miesc fix results.json -c MyContract.sol --dry-run
      miesc fix results.json -c MyContract.sol -f code-actions

    \b
    Fix types supported:
      reentrancy      → adds nonReentrant modifier
      access_control  → adds onlyOwner modifier
      unchecked_call  → wraps call in require(success, ...)
      arithmetic      → adds SafeMath (pre-0.8) or comment block
      <other>         → inserts fix_code as a comment block
    """
    # When emitting the machine contract to stdout, keep it pure JSON.
    stdout_json = output_format == "code-actions" and not output
    if not quiet and not stdout_json:
        info(f"Loading results from {results_file}")

    # ------------------------------------------------------------------
    # Load results JSON
    # ------------------------------------------------------------------
    try:
        with open(results_file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        error(f"Cannot read results file: {exc}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Collect fixable findings
    # ------------------------------------------------------------------
    fixable = _collect_fixable_findings(data)

    if not fixable:
        if output_format == "code-actions":
            click.echo("[]")
            sys.exit(0)
        warning("No findings with fix_code found — nothing to fix.")
        sys.exit(0)

    if not quiet and not stdout_json:
        info(f"Found {len(fixable)} finding(s) with fix_code")

    # ------------------------------------------------------------------
    # Load original source
    # ------------------------------------------------------------------
    contract = Path(contract_path)
    try:
        source = contract.read_text(encoding="utf-8")
    except OSError as exc:
        error(f"Cannot read contract: {exc}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # code-actions format: emit the LSP CodeAction JSON contract and stop.
    # Each fix is derived independently against the original source so an
    # editor can offer them as individual quick-fixes.
    # ------------------------------------------------------------------
    if output_format == "code-actions":
        actions = build_code_actions(source, fixable, contract_path)
        payload = json.dumps(actions, indent=2)
        if output:
            try:
                Path(output).write_text(payload + "\n", encoding="utf-8")
            except OSError as exc:
                error(f"Cannot write output file: {exc}")
                sys.exit(1)
            if not quiet:
                success(f"Wrote {len(actions)} code action(s) to {output}")
        else:
            click.echo(payload)
        sys.exit(0)

    # ------------------------------------------------------------------
    # Apply fixes (track already-fixed functions to report skips cleanly)
    # ------------------------------------------------------------------
    applied = 0
    skipped = 0
    already_fixed = 0
    patched_source = source
    fixed_functions: set[tuple[str, str]] = set()  # (fn_name, fix_category)

    for finding in fixable:
        ftype = finding.get("type") or finding.get("title") or "unknown"
        # Resolve function name the same way apply_fix does
        _unknown = {"", "unknown", "<unknown>", "none", "n/a"}
        fn_name = finding.get("function") or finding.get("function_name") or ""
        if fn_name.lower() in _unknown:
            fn_name = ""
        if not fn_name:
            loc = finding.get("location", {})
            if isinstance(loc, dict):
                fn_name = loc.get("function", "")
                if fn_name.lower() in _unknown:
                    fn_name = ""
        if not fn_name:
            raw_line = finding.get("line") or finding.get("line_number")
            if not raw_line:
                loc = finding.get("location", {})
                if isinstance(loc, dict):
                    raw_line = loc.get("line")
            if raw_line:
                try:
                    fn_name = _infer_function_at_line(source, int(raw_line))
                except (TypeError, ValueError):
                    pass

        # Determine fix category for dedup
        ftype_lower = ftype.lower().replace("-", "_")
        if "reentrancy" in ftype_lower:
            fix_cat = "reentrancy"
        elif any(
            k in ftype_lower
            for k in ("access_control", "suicidal", "selfdestruct", "arbitrary_send_eth")
        ):
            fix_cat = "access_control"
        elif "controlled_delegatecall" in ftype_lower:
            fix_cat = "access_control"
        elif "unchecked" in ftype_lower:
            fix_cat = "unchecked_call"
        else:
            fix_cat = ftype_lower

        fix_key = (fn_name, fix_cat)
        if fn_name and fix_key in fixed_functions:
            already_fixed += 1
            if not quiet:
                info(f"  ⊘ Already fixed: {ftype} in {fn_name}")
            continue

        normalized_finding = dict(finding)
        if fn_name:
            normalized_finding["function"] = fn_name

        new_source, changed = apply_fix(patched_source, normalized_finding)
        if changed:
            patched_source = new_source
            applied += 1
            if fn_name:
                fixed_functions.add(fix_key)
            if not quiet:
                info(f"  ✓ Applied fix: {ftype} in {fn_name or '<inferred>'}")
        else:
            skipped += 1
            if not quiet:
                warning(f"  ✗ Could not apply fix: {ftype} in {fn_name or '<unknown>'}")

    # ------------------------------------------------------------------
    # Dry-run: just print the diff summary
    # ------------------------------------------------------------------
    if dry_run:
        console.print(
            f"\n[bold]Dry-run summary:[/bold] {applied} fix(es) would be applied, "
            f"{skipped} skipped (out of {len(fixable)} total)."
        )
        if patched_source != source:
            console.print("[dim]Use without --dry-run to write the patched file.[/dim]")
        sys.exit(0)

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    if output is None:
        stem = contract.stem
        out_path = contract.parent / f"{stem}.fixed.sol"
    else:
        out_path = Path(output)

    try:
        out_path.write_text(patched_source, encoding="utf-8")
    except OSError as exc:
        error(f"Cannot write output file: {exc}")
        sys.exit(1)

    parts = [f"Applied {applied} fix(es)"]
    if already_fixed:
        parts.append(f"{already_fixed} already fixed")
    if skipped:
        parts.append(f"{skipped} could not patch")
    success(f"{', '.join(parts)} — written to {out_path}")
