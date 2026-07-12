"""
Unified Formal-Verification Report
==================================

Aggregates the per-prover outputs produced by
:func:`miesc.formal.spec_runner.run_all_available` (Certora, Halmos,
SMTChecker) into a single, first-class artifact:

  * a deterministic JSON bundle (:meth:`UnifiedVerificationReport.to_json`)
  * a SARIF 2.1.0 mapping (:meth:`UnifiedVerificationReport.to_sarif`) that
    reuses :class:`miesc.core.exporters.SARIFExporter`, so every violated
    property / counterexample becomes a standard SARIF result with a source
    location and — when it can be tied to a MIESC finding — a related location
    linking the counterexample back to that finding.

Naming note
-----------
``spec_runner`` already exports a per-prover ``VerificationResult`` dataclass.
To avoid shadowing it we call the *aggregate* model
``UnifiedVerificationReport`` and the normalized per-prover entry
``ProverVerdict``.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from miesc.core.exporters import Finding, SARIFExporter

# ---------------------------------------------------------------------------
# Status normalization
# ---------------------------------------------------------------------------

#: Map the raw ``spec_runner`` statuses onto a stable, prover-agnostic vocabulary.
_STATUS_MAP: Dict[str, str] = {
    "passed": "verified",
    "failed": "violated",
    "error": "error",
    "timeout": "timeout",
    "no_tests": "no_tests",
}

#: Canonical verdict emitted when a prover was not installed / not run.
UNAVAILABLE = "unavailable"

#: Matches a source line reference inside a free-form counterexample string,
#: e.g. SMTChecker's ``"... Overflow at line 22 ..."``.
_LINE_RE = re.compile(r"line[:\s]+(\d+)", re.IGNORECASE)


def normalize_status(raw_status: str) -> str:
    """Translate a raw ``spec_runner`` status into the unified vocabulary."""
    return _STATUS_MAP.get(raw_status, "unknown")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Counterexample:
    """A single counterexample / violation witness attributed to a prover."""

    prover: str
    text: str
    property: Optional[str] = None
    source_line: Optional[int] = None
    #: id of the MIESC finding this counterexample was linked to (if any).
    linked_finding_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prover": self.prover,
            "property": self.property,
            "text": self.text,
            "source_line": self.source_line,
            "linked_finding_id": self.linked_finding_id,
        }

    @classmethod
    def from_text(cls, prover: str, text: str) -> "Counterexample":
        """Build a counterexample, best-effort parsing a source line from ``text``."""
        line: Optional[int] = None
        match = _LINE_RE.search(text)
        if match:
            try:
                parsed = int(match.group(1))
                line = parsed if parsed > 0 else None
            except ValueError:
                line = None
        return cls(prover=prover, text=text.strip(), source_line=line)


@dataclass
class ProverVerdict:
    """Normalized outcome for a single prover within the unified report."""

    prover: str  # "certora" | "halmos" | "smtchecker"
    status: str  # verified | violated | error | timeout | no_tests | unavailable
    properties_checked: int = 0
    properties_passed: int = 0
    properties_violated: int = 0
    counterexamples: List[Counterexample] = field(default_factory=list)
    spec_file: str = ""
    elapsed_seconds: float = 0.0
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prover": self.prover,
            "status": self.status,
            "properties_checked": self.properties_checked,
            "properties_passed": self.properties_passed,
            "properties_violated": self.properties_violated,
            "counterexamples": [c.to_dict() for c in self.counterexamples],
            "spec_file": self.spec_file,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "message": self.message,
        }

    @classmethod
    def from_runner_result(cls, result: Any) -> "ProverVerdict":
        """Build a :class:`ProverVerdict` from a ``spec_runner.VerificationResult``."""
        status = normalize_status(getattr(result, "status", "unknown"))
        prover = str(getattr(result, "tool", "unknown"))
        cexs = [
            Counterexample.from_text(prover, str(t))
            for t in getattr(result, "counterexamples", []) or []
        ]
        # SMTChecker only reports failures (rules_total == rules_failed); Certora /
        # Halmos report both. rules_passed defaults to 0 when the prover doesn't
        # surface per-rule pass counts, which is fine for aggregation.
        return cls(
            prover=prover,
            status=status,
            properties_checked=int(getattr(result, "rules_total", 0) or 0),
            properties_passed=int(getattr(result, "rules_passed", 0) or 0),
            properties_violated=int(getattr(result, "rules_failed", 0) or 0),
            counterexamples=cexs,
            spec_file=getattr(result, "spec_file", "") or "",
            elapsed_seconds=float(getattr(result, "elapsed_seconds", 0.0) or 0.0),
            message=(
                (getattr(result, "stderr", "") or "")[:500]
                if status in ("error", "timeout")
                else ""
            ),
        )


@dataclass
class UnifiedVerificationReport:
    """Aggregate of all prover verdicts for a single contract."""

    contract: str
    provers: List[ProverVerdict] = field(default_factory=list)
    #: Optional wall-clock stamp. Left ``None`` by default so ``to_json`` stays
    #: byte-for-byte deterministic; callers may set it explicitly for provenance.
    generated_at: Optional[str] = None

    # -- construction ------------------------------------------------------

    @classmethod
    def from_runner_results(
        cls,
        contract: str,
        results: Dict[str, Any],
        availability: Optional[Dict[str, bool]] = None,
        generated_at: Optional[str] = None,
    ) -> "UnifiedVerificationReport":
        """Aggregate a ``{prover: VerificationResult}`` mapping into one report.

        Args:
            contract: Path to the contract under verification.
            results: Mapping produced by ``run_all_available`` (or the verify
                command) — ``{prover_name: VerificationResult}``.
            availability: Optional ``{prover: bool}`` map; provers that are
                available-but-absent-from-``results`` or simply unavailable are
                recorded with status ``"unavailable"`` for completeness.
            generated_at: Optional ISO timestamp for provenance.
        """
        provers: List[ProverVerdict] = [
            ProverVerdict.from_runner_result(r) for r in results.values()
        ]
        if availability:
            for name in availability:
                if name in results:
                    continue
                provers.append(ProverVerdict(prover=name, status=UNAVAILABLE))
        # Stable ordering by prover name keeps JSON/SARIF deterministic.
        provers.sort(key=lambda p: p.prover)
        return cls(contract=contract, provers=provers, generated_at=generated_at)

    # -- verdict -----------------------------------------------------------

    @property
    def overall_verdict(self) -> str:
        """Aggregate verdict across all provers.

        Precedence: a single ``violated`` dominates (a property was falsified).
        Otherwise, with at least one runnable prover, ``verified`` requires every
        runnable prover to have verified; any mix with error/timeout/no_tests is
        ``inconclusive``. With no runnable provers the verdict is ``no_provers``.
        """
        runnable = [p.status for p in self.provers if p.status != UNAVAILABLE]
        if any(s == "violated" for s in runnable):
            return "violated"
        if not runnable:
            return "no_provers"
        if all(s == "verified" for s in runnable):
            return "verified"
        return "inconclusive"

    # -- finding linkage ---------------------------------------------------

    def link_findings(self, findings: List[Any]) -> int:
        """Link counterexamples to MIESC findings by source line + file.

        A counterexample is linked to a finding when it carries a resolved
        ``source_line`` that matches the finding's ``line_start`` and the file
        paths are compatible (equal or sharing a basename). The finding's id is
        stored on the counterexample and the finding is cached for SARIF reuse.

        Returns:
            The number of counterexamples that were linked.
        """
        normalized = [self._normalize_finding(f) for f in findings]
        self._findings_by_id = {n["id"]: n for n in normalized if n["id"]}
        linked = 0
        for prover in self.provers:
            for cex in prover.counterexamples:
                if cex.source_line is None:
                    continue
                for nf in normalized:
                    if nf["line_start"] == cex.source_line and self._files_match(
                        nf["file_path"], self.contract
                    ):
                        cex.linked_finding_id = nf["id"]
                        linked += 1
                        break
        return linked

    # -- serialization -----------------------------------------------------

    def summary(self) -> Dict[str, int]:
        """Aggregate counters across provers."""
        return {
            "provers_total": len(self.provers),
            "verified": sum(1 for p in self.provers if p.status == "verified"),
            "violated": sum(1 for p in self.provers if p.status == "violated"),
            "errored": sum(1 for p in self.provers if p.status in ("error", "timeout")),
            "unavailable": sum(1 for p in self.provers if p.status == UNAVAILABLE),
            "total_properties": sum(p.properties_checked for p in self.provers),
            "violated_properties": sum(p.properties_violated for p in self.provers),
            "counterexamples": sum(len(p.counterexamples) for p in self.provers),
            "linked_counterexamples": sum(
                1
                for p in self.provers
                for c in p.counterexamples
                if c.linked_finding_id is not None
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "contract": self.contract,
            "overall_verdict": self.overall_verdict,
            "summary": self.summary(),
            "provers": {p.prover: p.to_dict() for p in self.provers},
        }
        if self.generated_at is not None:
            payload["generated_at"] = self.generated_at
        return payload

    def to_json(self, output_path: Optional[str] = None) -> str:
        """Serialize to a stable, sorted JSON string (deterministic by default)."""
        text = json.dumps(self.to_dict(), indent=2, sort_keys=True)
        if output_path:
            from pathlib import Path

            Path(output_path).write_text(text, encoding="utf-8")
        return text

    def to_sarif(self, output_path: Optional[str] = None) -> str:
        """Map violated properties / counterexamples to SARIF 2.1.0.

        Reuses :class:`SARIFExporter` for driver/rules/result construction, then
        enriches each result with formal metadata and, where a counterexample is
        linked to a MIESC finding, a ``relatedLocations`` entry pointing at that
        finding's source location.
        """
        sarif_findings: List[Finding] = []
        metas: List[Dict[str, Any]] = []

        for prover in self.provers:
            if prover.status != "violated":
                continue
            if prover.counterexamples:
                for idx, cex in enumerate(prover.counterexamples):
                    finding, meta = self._cex_to_finding(prover, cex, idx)
                    sarif_findings.append(finding)
                    metas.append(meta)
            else:
                # Violation without a captured counterexample string (e.g. Certora
                # reporting only a VIOLATED count) — emit one summary result.
                finding = Finding(
                    id=f"formal-{prover.prover}-violation",
                    type=f"formal_{prover.prover}_violation",
                    severity="high",
                    title=f"{prover.prover} reported a violated property",
                    description=(
                        f"{prover.prover} reported {prover.properties_violated} "
                        f"violated property/properties on {self.contract}."
                    ),
                    file_path=self.contract,
                    line_start=1,
                    tool=prover.prover,
                    layer=4,
                )
                sarif_findings.append(finding)
                metas.append({"prover": prover.prover, "cex": None})

        exporter = SARIFExporter(tool_name="MIESC-Formal")
        sarif = json.loads(exporter.export(sarif_findings))

        # Enrich results in the same order they were constructed.
        results = sarif["runs"][0]["results"]
        for result, meta in zip(results, metas, strict=False):
            props = result.setdefault("properties", {})
            props["prover"] = meta["prover"]
            props["verificationLayer"] = "formal"
            cex = meta["cex"]
            if cex is not None:
                props["counterexample"] = cex.text
                if cex.linked_finding_id:
                    props["linkedFindingId"] = cex.linked_finding_id
                    related = self._related_location(cex.linked_finding_id)
                    if related is not None:
                        result.setdefault("relatedLocations", []).append(related)

        text = json.dumps(sarif, indent=2)
        if output_path:
            from pathlib import Path

            Path(output_path).write_text(text, encoding="utf-8")
        return text

    # -- internals ---------------------------------------------------------

    def _cex_to_finding(
        self, prover: ProverVerdict, cex: Counterexample, idx: int
    ) -> tuple[Finding, Dict[str, Any]]:
        """Convert a counterexample to a SARIF-bound :class:`Finding`.

        When the counterexample links to a MIESC finding, reuse that finding's
        type/severity/CWE/SWC and location so the SARIF rule aligns with the
        original detection; otherwise emit a generic formal-violation finding.
        """
        linked = getattr(self, "_findings_by_id", {}).get(cex.linked_finding_id or "")
        if linked:
            return (
                Finding(
                    id=f"formal-{prover.prover}-{linked['id']}-{idx}",
                    type=linked["type"] or f"formal_{prover.prover}_violation",
                    severity=linked["severity"] or "high",
                    title=f"Formal counterexample for {linked['type'] or 'finding'}",
                    description=f"Counterexample ({prover.prover}): {cex.text}",
                    file_path=linked["file_path"] or self.contract,
                    line_start=cex.source_line or linked["line_start"] or 1,
                    tool=prover.prover,
                    layer=4,
                    cwe=linked["cwe"],
                    swc=linked["swc"],
                ),
                {"prover": prover.prover, "cex": cex},
            )
        return (
            Finding(
                id=f"formal-{prover.prover}-cex-{idx}",
                type=f"formal_{prover.prover}_violation",
                severity="high",
                title=f"{prover.prover} counterexample",
                description=f"Counterexample ({prover.prover}): {cex.text}",
                file_path=self.contract,
                line_start=cex.source_line or 1,
                tool=prover.prover,
                layer=4,
            ),
            {"prover": prover.prover, "cex": cex},
        )

    def _related_location(self, finding_id: str) -> Optional[Dict[str, Any]]:
        nf = getattr(self, "_findings_by_id", {}).get(finding_id)
        if not nf:
            return None
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": nf["file_path"] or self.contract},
                "region": {"startLine": nf["line_start"] or 1},
            },
            "message": {
                "text": f"Linked MIESC finding {finding_id}"
                + (f": {nf['type']}" if nf["type"] else "")
            },
        }

    @staticmethod
    def _normalize_finding(finding: Any) -> Dict[str, Any]:
        """Normalize a Finding dataclass / dict into a flat lookup record."""

        def _get(obj: Any, key: str, default: Any = None) -> Any:
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        line = _get(finding, "line_start", None)
        if line in (None, ""):
            line = _get(finding, "line", None)
        try:
            line_int: Optional[int] = int(line) if line not in (None, "") else None
        except (TypeError, ValueError):
            line_int = None
        return {
            "id": str(_get(finding, "id", "") or ""),
            "type": _get(finding, "type", "") or "",
            "severity": _get(finding, "severity", "") or "",
            "file_path": _get(finding, "file_path", "") or _get(finding, "file", "") or "",
            "line_start": line_int,
            "cwe": _get(finding, "cwe", None),
            "swc": _get(finding, "swc", None),
        }

    @staticmethod
    def _files_match(a: str, b: str) -> bool:
        if not a or not b:
            return False
        if a == b:
            return True
        from pathlib import Path

        return Path(a).name == Path(b).name or a.endswith(b) or b.endswith(a)


__all__ = [
    "Counterexample",
    "ProverVerdict",
    "UnifiedVerificationReport",
    "normalize_status",
    "UNAVAILABLE",
]
