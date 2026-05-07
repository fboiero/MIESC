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

# ---------------------------------------------------------------------------
# Patcher helpers
# ---------------------------------------------------------------------------

_FUNCTION_RE = re.compile(
    r"(function\s+(\w+)\s*\([^)]*\)\s*)((?:public|private|internal|external|"
    r"pure|view|virtual|override|payable|returns\s*\([^)]*\)\s*)*)",
    re.MULTILINE,
)


def _ensure_modifier_defined(source: str, modifier: str) -> str:
    """If a modifier is used but not defined, inline it."""
    if modifier == "onlyOwner" and "modifier onlyOwner" not in source:
        has_owner = re.search(r"address\s+(?:public\s+)?owner\b", source)
        inline = "\n    // MIESC: Inline onlyOwner modifier\n"
        if not has_owner:
            inline += "    address public owner = msg.sender;\n"
        inline += (
            "    modifier onlyOwner() {\n"
            '        require(msg.sender == owner, "Not owner");\n'
            "        _;\n"
            "    }\n"
        )
        # Insert after the first state variable block (before first function)
        m = re.search(r"(function\s+)", source)
        if m:
            source = source[:m.start()] + inline + "\n    " + source[m.start():]
    return source


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
    source.splitlines(keepends=True)

    # Build list of candidate match positions
    candidates = []
    for m in _FUNCTION_RE.finditer(source):
        if m.group(2) == function_name:
            # Map match start to line number (1-based)
            match_line = source[: m.start()].count("\n") + 1
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
    old_text = m.group(0)
    new_text = m.group(1) + modifier + " " + m.group(3)
    patched = source.replace(old_text, new_text, 1)
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
    return bool(re.search(r"\b(?:contract|library|interface)\s+" + re.escape(name) + r"\b", source))


def _ensure_reentrancy_guard_import(source: str) -> str:
    """Add inline ReentrancyGuard + inheritance if not already present.

    Uses an inline implementation instead of an OZ import so the fixed
    contract compiles without external dependencies (Foundry/Hardhat).
    """
    has_reentrancy_definition = _has_contract_definition(source, "ReentrancyGuard")
    has_miesc_definition = _has_contract_definition(source, "MiescReentrancyGuard")
    has_oz_import = bool(re.search(r"import\s+[^;]*ReentrancyGuard[^;]*;", source))

    if has_reentrancy_definition or has_miesc_definition or has_oz_import:
        return source

    # Check if OZ is likely available (import already exists)
    has_oz = "@openzeppelin" in source

    if has_oz:
        # OZ available — use import
        import_line = 'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";\n'
        guard_name = "ReentrancyGuard"
    elif re.search(r"\bis\s+[^{};]*\bReentrancyGuard\b", source):
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

    # Insert after last import or after pragma
    last_import = -1
    for i, line in enumerate(source.splitlines()):
        if line.strip().startswith("import "):
            last_import = i
    lines = source.splitlines(keepends=True)
    if last_import >= 0:
        lines.insert(last_import + 1, import_line)
    else:
        for i, line in enumerate(lines):
            if line.strip().startswith("pragma "):
                lines.insert(i + 1, "\n" + import_line)
                break
    source = "".join(lines)

    # Add ReentrancyGuard to contract inheritance
    contract_re = re.compile(r"(contract\s+\w+)\s*(\{)", re.MULTILINE)
    # Find the TARGET contract (skip the inline guard itself)
    for m_contract in contract_re.finditer(source):
        contract_name = source[m_contract.start(1):m_contract.end(1)].split()[-1]
        if contract_name in ("ReentrancyGuard", "MiescReentrancyGuard"):
            continue  # Skip the guard definition itself
        m_is_check = re.search(
            r"(contract\s+" + re.escape(contract_name) + r"\s+is\s+)([^{]+)(\{)", source
        )
        if m_is_check:
            if guard_name not in m_is_check.group(2):
                source = source[: m_is_check.start(2)] + m_is_check.group(2).rstrip() + ", " + guard_name + " " + source[m_is_check.start(3):]
        else:
            source = source[: m_contract.end(1)] + " is " + guard_name + " " + source[m_contract.start(2):]
        break  # Only modify the first real contract
    return source


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
        patched = patched[:m.start()] + _INLINE_SAFE_MATH + "\n" + patched[m.start():]
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
    """Wrap a low-level `.call{...}(...)` in a `require(success, ...)` block.

    Strategy: find the function body, locate the first `.call{` or `.call(` line
    inside it, and insert `(bool success, ) = ` prefix + a require check after.
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

    # Look for `.call{...}` or `.call(` pattern (not already preceded by bool success)
    call_re = re.compile(r"([ \t]*)(\w+\.call(?:\{[^}]*\})?\([^;]*\);)", re.MULTILINE)
    call_m = call_re.search(body)
    if not call_m:
        return source, False

    indent = call_m.group(1)
    call_expr = call_m.group(2)
    # Strip trailing semicolon
    call_bare = call_expr.rstrip(";").strip()

    replacement = (
        f"{indent}(bool success, ) = {call_bare};\n"
        f'{indent}require(success, "Call failed");'
    )

    new_body = body[: call_m.start()] + replacement + body[call_m.end() :]
    patched = source[:body_start] + new_body + source[body_end:]
    return patched, patched != source


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
    candidates = list(fn_re.finditer(source))
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

    comment = (
        f"{indent}// MIESC FIX: {finding_type}\n"
        f"{indent}/* ---- Suggested fix ----\n"
    )
    for fix_line in fix_code.splitlines():
        comment += f"{indent}   {fix_line}\n"
    comment += f"{indent}   ---- end fix ---- */\n"

    patched = source[:insert_pos] + comment + source[insert_pos:]
    return patched, True


# ---------------------------------------------------------------------------
# Per-finding patch dispatcher
# ---------------------------------------------------------------------------

_SAFEMATH_HINT = re.compile(r"pragma solidity\s+\^?0\.[0-7]\.", re.MULTILINE)


def _infer_function_at_line(source: str, line: int) -> str:
    """Find the nearest function declaration at or above `line`."""
    lines = source.splitlines()
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
            source, changed = _add_modifier_to_function(
                source, fn_name, "nonReentrant", line_hint
            )
            if changed:
                source = _ensure_reentrancy_guard_import(source)
            return source, changed
        return source, False

    if "suicidal" in ftype or (
        "access_control" in ftype
        and any(kw in ftype for kw in ("selfdestruct", "suicidal"))
    ):
        if fn_name:
            source, changed = _add_modifier_to_function(
                source, fn_name, "onlyOwner", line_hint
            )
            if changed:
                source = _ensure_modifier_defined(source, "onlyOwner")
            return source, changed
        return source, False

    if "access_control" in ftype or "selfdestruct" in ftype:
        if fn_name:
            source, changed = _add_modifier_to_function(
                source, fn_name, "onlyOwner", line_hint
            )
            if changed:
                source = _ensure_modifier_defined(source, "onlyOwner")
            return source, changed
        return source, False

    if "unchecked_call" in ftype or "unchecked_low_level" in ftype:
        if fn_name:
            return _add_require_for_call(source, fn_name, line_hint)
        return source, False

    if "arithmetic" in ftype or "integer_overflow" in ftype or "overflow" in ftype:
        # Only insert SafeMath for pre-0.8 contracts
        if _SAFEMATH_HINT.search(source):
            return _insert_using_safemath(source)
        # For 0.8+ just insert a comment
        if fn_name:
            return _insert_comment_block(
                source, fn_name, ftype,
                fix_code or "Solidity 0.8+ has built-in overflow protection.",
                line_hint,
            )
        return source, False

    # Generic fallback
    if fix_code and fn_name:
        return _insert_comment_block(source, fn_name, ftype, fix_code, line_hint)

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

    def _key(f: dict) -> tuple:
        ftype = (f.get("type") or f.get("title") or "").lower()
        line = f.get("line") or f.get("line_number") or ""
        loc = f.get("location", {})
        if isinstance(loc, dict):
            line = line or loc.get("line", "")
        return (ftype, str(line))

    def _add(f: dict) -> None:
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
@click.option("--quiet", "-q", is_flag=True, help="Minimal output.")
def fix(results_file, contract_path, output, dry_run, quiet):
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

    \b
    Fix types supported:
      reentrancy      → adds nonReentrant modifier
      access_control  → adds onlyOwner modifier
      unchecked_call  → wraps call in require(success, ...)
      arithmetic      → adds SafeMath (pre-0.8) or comment block
      <other>         → inserts fix_code as a comment block
    """
    if not quiet:
        info(f"Loading results from {results_file}")

    # ------------------------------------------------------------------
    # Load results JSON
    # ------------------------------------------------------------------
    try:
        with open(results_file) as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        error(f"Cannot read results file: {exc}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Collect fixable findings
    # ------------------------------------------------------------------
    fixable = _collect_fixable_findings(data)

    if not fixable:
        warning("No findings with fix_code found — nothing to fix.")
        sys.exit(0)

    if not quiet:
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
        elif any(k in ftype_lower for k in ("access_control", "suicidal", "selfdestruct")):
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
        console.print(f"\n[bold]Dry-run summary:[/bold] {applied} fix(es) would be applied, "
                      f"{skipped} skipped (out of {len(fixable)} total).")
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
