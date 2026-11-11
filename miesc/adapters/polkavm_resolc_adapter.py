"""
PolkaVM / pallet-revive ``resolc`` compile-compatibility adapter (Rung 0).

Runs the Parity **revive compiler** (``resolc``) on a Solidity contract destined
for PolkaVM (RISC-V, via ``pallet-revive`` / Asset Hub) and surfaces the class
(A) *compile-time rejections* — opcodes that resolc refuses to lower to PolkaVM
(``EXTCODECOPY``, ``PC``, ``BLOBHASH`` ...). These are **authoritative**: the
compiler itself is the oracle, so a rejection is a confirmed deployability
blocker for the PolkaVM target, not a heuristic.

This is the *correlation pair* of :mod:`miesc.adapters.polkavm_diff_adapter`:

* ``polkavm_diff`` — built-in, source-level, flags class (B) *silent runtime
  differences* (code that compiles and is correct on the EVM but behaves
  differently on PolkaVM). It deliberately does NOT run a compiler.
* ``polkavm_resolc`` (this adapter) — shells out to ``resolc`` and reports class
  (A) rejections the compiler raises. It is the piece that lets MIESC surface
  the compiler's verdict instead of asking the user to run ``resolc`` by hand.

Honesty contract (the whole point of Rung 0):

* ``resolc`` exits 0 → the contract compiles for PolkaVM → **zero findings**.
  (This says nothing about class (B); that is ``polkavm_diff``'s job.)
* ``resolc`` exits non-zero AND stderr names an unsupported *instruction* → one
  finding per distinct opcode. ``resolc`` aborts at the FIRST unsupported
  opcode, so the finding is worded "at least" — more may remain.
* ``resolc`` exits non-zero with any OTHER error (a solc ``ParserError``, a
  rejected import, a missing ``solc``) → **honest error**, never a finding and
  never a false "clean".

Measured against resolc 1.5.0: ``EXTCODECOPY`` and ``BLOBHASH`` are rejected by
the LLVM-IR phase with "instruction is not supported" → findings. ``PC`` is
rejected earlier by ``solc`` itself ("disallowed in strict assembly") → an honest
error, not a finding. Detection keys on resolc's message, so any opcode it rejects
at the IR phase is caught without a code change.

Only single-file contracts are reliably supported: the ``npx`` ``resolcjs``
wrapper rejects relative ``import`` paths ("Invalid import path format"), so a
multi-file contract surfaces as an honest error, never a false "clean". When the
rejected opcode lives in an imported file, the source anchor finds nothing and the
finding reports ``line=0`` against the scanned file.

The ``L:C`` position in resolc's message is a **compiler-internal position**
(verified: not the Solidity source line), so it is kept only in metadata. The
finding is anchored by searching the opcode token in the comment-blanked source:
a unique hit gives that line, otherwise ``line=0``.

``is_available()`` is PATH-only and never downloads: a real ``resolc`` on PATH,
else ``npx @parity/resolc`` on demand (node + npx + solc present), matching
``miesc doctor``. The on-demand ``npx`` path may fetch the package on first
compile; that happens in ``analyze()``, never in the availability probe.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from miesc.adapters.polkavm_diff_adapter import (
    blank_comments_and_strings,
    enclosing_function,
)
from miesc.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

# Pinned resolc version for the on-demand npx path (matches doctor + the PoC).
RESOLC_NPX_SPEC = "@parity/resolc@1.5.0"

# resolc raises, e.g. (the trailing "in revive" seen on some opcodes is tolerated):
#   LLVM IR generator: 29:25 The `EXTCODECOPY` instruction is not supported
#   LLVM IR generator: 27:89 The `BLOBHASH` instruction is not supported in revive
# The L:C is a compiler-internal position (verified: NOT a Solidity source line).
_UNSUPPORTED_RE = re.compile(
    r"(?:(\d+):(\d+)\s+)?The\s+[`'\"]?([A-Za-z_]\w*)[`'\"]?\s+instruction\s+is\s+not\s+supported",
    re.IGNORECASE,
)

# Opcodes with no PolkaVM equivalent, for the recommendation text only. Detection
# is driven by resolc's message, so a newly-rejected opcode is caught without a
# code change. Note PC is rejected earlier by solc ("disallowed in strict
# assembly"), so it surfaces as an honest error here, not a finding.
_KNOWN_CLASS_A = ("EXTCODECOPY", "BLOBHASH", "BLOBBASEFEE", "PC (rejected by solc)")


class PolkaVMResolcAdapter(ToolAdapter):
    """Surfaces resolc class (A) compile-time rejections for the PolkaVM target."""

    NAME = "polkavm_resolc"
    VERSION = "0.1.0"

    CHECK = "polkavm-unsupported-opcode"

    # ------------------------------------------------------------------ metadata
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name=self.NAME,
            version=self.VERSION,
            category=ToolCategory.STATIC_ANALYSIS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC/blob/main/docs/MULTICHAIN.md",
            installation_cmd="needs node + solc, then `npx @parity/resolc@1.5.0` (on demand)",
            capabilities=[
                ToolCapability(
                    name="polkavm_resolc_compatibility",
                    description="Runs resolc and reports class (A) compile-time rejections "
                    "(unsupported opcodes) for the PolkaVM / pallet-revive target.",
                    supported_languages=["solidity"],
                    detection_types=[self.CHECK],
                )
            ],
            is_optional=True,
            requires_llm=False,
        )

    # -------------------------------------------------------------- availability
    def _resolc_base_cmd(self) -> Optional[List[str]]:
        """Return the argv prefix that runs resolc, or ``None`` if unavailable.

        PATH-only; never executes anything. Prefers a real ``resolc`` binary
        (no download), then the on-demand ``npx`` path (node + npx + solc).
        """
        if shutil.which("resolc"):
            return ["resolc"]
        if shutil.which("npx") and shutil.which("node") and shutil.which("solc"):
            return ["npx", "--yes", RESOLC_NPX_SPEC]
        return None

    def is_available(self) -> ToolStatus:
        return ToolStatus.AVAILABLE if self._resolc_base_cmd() else ToolStatus.NOT_INSTALLED

    def can_analyze(self, contract_path: str) -> bool:
        return contract_path.endswith(".sol")

    # ------------------------------------------------------------------- analyze
    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        start = time.time()
        path = Path(contract_path)
        if not path.is_file():
            return self.create_result(
                status="error",
                error=f"File not found: {contract_path}",
                execution_time=time.time() - start,
            )

        base_cmd = self._resolc_base_cmd()
        if base_cmd is None:
            return self.create_result(
                status="error",
                error="resolc not available (need `resolc` on PATH, or node + npx + solc)",
                execution_time=time.time() - start,
                metadata={"tool_status": ToolStatus.NOT_INSTALLED.value},
            )

        try:
            source = path.read_text(encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            return self.create_result(
                status="error",
                error=f"Could not read {contract_path}: {exc}",
                execution_time=time.time() - start,
            )

        timeout = int(kwargs.get("timeout", 180) or 180)
        abs_path = str(path.resolve())
        parent = str(path.resolve().parent)

        with tempfile.TemporaryDirectory(prefix="miesc-resolc-") as outdir:
            # --base-path lets resolc find same-dir sources; the npx resolcjs
            # wrapper still rejects relative `import` paths, so a multi-file
            # contract surfaces as an honest error below, never a false "clean".
            cmd = [*base_cmd, abs_path, "--bin", "-o", outdir, "--base-path", parent]
            try:
                rc, _stdout, stderr = self.run_subprocess(cmd, timeout=timeout, cwd=outdir)
            except subprocess.TimeoutExpired:
                return self.create_result(
                    status="error",
                    error=f"resolc timed out after {timeout}s",
                    execution_time=time.time() - start,
                    metadata={"timeout": timeout},
                )
            except FileNotFoundError:
                return self.create_result(
                    status="error",
                    error=f"resolc command not found: {' '.join(base_cmd)}",
                    execution_time=time.time() - start,
                )
            except Exception as exc:  # noqa: BLE001 — surface as honest error
                return self.create_result(
                    status="error",
                    error=f"resolc invocation failed: {exc}",
                    execution_time=time.time() - start,
                )
            artifact_produced = any(Path(outdir).iterdir())

        meta: Dict[str, Any] = {
            "target": "polkavm",
            "resolc_cmd": " ".join(base_cmd),
            "resolc_exit_code": rc,
            "artifact_produced": artifact_produced,
        }

        # exit 0 → compiles for PolkaVM → zero class (A) findings. An artifact may
        # legitimately be absent (an interface-only .sol compiles with no bytecode),
        # so the artifact is informational only and never gates "clean".
        if rc == 0:
            return self.create_result(
                status="success",
                findings=[],
                execution_time=time.time() - start,
                metadata=meta,
            )

        findings = self._parse_class_a(stderr, source, abs_path)
        stderr_tail = (stderr or "").strip()[-800:]
        meta["resolc_stderr_tail"] = stderr_tail
        if findings:
            return self.create_result(
                status="success",
                findings=findings,
                execution_time=time.time() - start,
                metadata=meta,
            )

        # Non-zero exit with no recognizable class (A) rejection: a solc parse
        # error, a missing import, a missing solc — a tooling/compile failure, NOT
        # a security finding and NOT a clean result.
        summary = next((ln.strip() for ln in (stderr or "").splitlines() if ln.strip()), "")
        return self.create_result(
            status="error",
            error=(
                f"resolc compilation failed (exit {rc}): {summary[:200]}"
                if summary
                else f"resolc compilation failed (exit {rc})"
            ),
            execution_time=time.time() - start,
            metadata=meta,
        )

    # --------------------------------------------------------------- parsing
    def _parse_class_a(self, stderr: str, source: str, file_path: str) -> List[Dict[str, Any]]:
        """Build class (A) findings from resolc stderr.

        resolc aborts at the first unsupported opcode, so in practice there is one
        match; findings are worded "at least". Each distinct opcode yields one
        finding, anchored by a unique source-token hit (else ``line=0``).
        """
        if not stderr:
            return []
        blank = blank_comments_and_strings(source)
        blank_lines = blank.splitlines()

        findings: List[Dict[str, Any]] = []
        seen: set[str] = set()
        counter = 0
        for m in _UNSUPPORTED_RE.finditer(stderr):
            raw_line, raw_col, opcode = m.group(1), m.group(2), m.group(3)
            opcode_u = opcode.upper()
            if opcode_u in seen:
                continue
            seen.add(opcode_u)
            counter += 1

            line = self._anchor_line(blank_lines, opcode)
            func = enclosing_function(blank_lines, line - 1) if line > 0 else ""
            compiler_pos = f"{raw_line}:{raw_col}" if raw_line and raw_col else ""

            anchor_note = (
                f" (source line {line})"
                if line > 0
                else " (source line could not be uniquely located; "
                "resolc's position is a compiler-internal offset, not a source line)"
            )
            finding = self.create_finding(
                finding_id=f"{self.CHECK}-{counter}",
                finding_type=self.CHECK,
                severity="high",
                message=f"`{opcode_u}` is not supported by resolc / PolkaVM "
                f"(pallet-revive): the contract cannot be compiled for the PolkaVM "
                f"target. resolc aborts at the first unsupported opcode, so at "
                f"least this one — and possibly more — must be removed{anchor_note}.",
                file_path=file_path,
                line=line,
                function=func,
                confidence=0.99,
                description=f"resolc (the Parity revive compiler) rejects `{opcode_u}` "
                f"when lowering this contract to PolkaVM/RISC-V. This is an "
                f"authoritative compile-time rejection, not a heuristic: the "
                f"contract will not deploy to pallet-revive as written.",
                recommendation=f"Remove or replace `{opcode_u}`; it has no PolkaVM "
                f"equivalent. See the revive compiler book, 'Differences to EVM'. "
                f"Other opcodes with no PolkaVM equivalent: {', '.join(_KNOWN_CLASS_A)}.",
                cwe_id=None,
            )
            finding["canonical_category"] = self.CHECK
            finding["tool"] = self.NAME
            finding["compiler_position"] = compiler_pos
            finding["compiler_position_note"] = "resolc compiler-internal offset, not a source line"
            findings.append(finding)
        return findings

    @staticmethod
    def _anchor_line(blank_lines: List[str], opcode: str) -> int:
        """1-based source line of the opcode token, or 0 if not unique.

        Opcodes appear in Yul assembly as lowercase builtins (``extcodecopy``),
        while resolc reports them uppercase. Match case-insensitively on a word
        boundary; a single hit anchors, zero or several give 0.
        """
        token_re = re.compile(r"\b" + re.escape(opcode) + r"\b", re.IGNORECASE)
        hits = [i for i, ln in enumerate(blank_lines) if token_re.search(ln)]
        return hits[0] + 1 if len(hits) == 1 else 0

    # ---------------------------------------------------------- normalize_findings
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Accept a ``(stderr, source, file_path)`` tuple and return findings.

        Lets callers/tests build findings from captured resolc output without a
        live compile.
        """
        if isinstance(raw_output, tuple) and len(raw_output) == 3:
            stderr, source, file_path = raw_output
            return self._parse_class_a(stderr, source, file_path)
        return []
