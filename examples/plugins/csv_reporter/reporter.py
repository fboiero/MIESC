"""
CSV Reporter Plugin
===================

Converts MIESC findings to a CSV file — alternative to the built-in
`miesc export ... -f csv` command, demonstrating the ReporterPlugin protocol.

The plugin writes one row per finding with a curated set of columns that
cover the most useful fields for spreadsheet analysis and triage.

Author: Example Plugin — MIESC v5.1.1
"""

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from miesc.plugins.protocol import (
        PLUGIN_API_VERSION,
        PluginContext,
        PluginMetadata,
        PluginType,
        ReporterPlugin,
    )
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    from miesc.plugins.protocol import (
        PLUGIN_API_VERSION,
        PluginContext,
        PluginMetadata,
        PluginType,
        ReporterPlugin,
    )


# Columns written to the CSV — order matters for readability in spreadsheets.
CSV_COLUMNS = [
    "id",
    "tool",
    "severity",
    "confidence",
    "type",
    "swc_id",
    "cwe_id",
    "file",
    "line",
    "column",
    "message",
    "description",
    "recommendation",
    "gas_saved",
    "pattern",
    "owasp_category",
    "code_snippet",
]


class CSVReporterPlugin(ReporterPlugin):
    """
    Generates a CSV report from MIESC findings.

    Each finding becomes one CSV row. Nested `location` fields are flattened
    (file, line, column, code_snippet). Missing fields are written as empty
    strings so the column structure is always consistent.

    The output file is UTF-8, comma-separated, with a header row.
    """

    # Plugin API version this plugin targets (see miesc.plugins.PLUGIN_API_VERSION).
    API_VERSION = PLUGIN_API_VERSION

    @property
    def name(self) -> str:
        return "csv-reporter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def format_name(self) -> str:
        return "csv"

    @property
    def file_extension(self) -> str:
        return "csv"

    @property
    def description(self) -> str:
        return "Exports MIESC findings as a CSV file for spreadsheet analysis."

    @property
    def author(self) -> str:
        return "Example Plugin — MIESC"

    def initialize(self, context: PluginContext) -> None:
        self._context = context
        self._config = context.config
        # Optional: override delimiter from config (default: comma)
        self._delimiter = context.config.get("delimiter", ",")
        self._include_header = context.config.get("include_header", True)

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            version=self.version,
            plugin_type=PluginType.REPORTER,
            description=self.description,
            author=self.author,
            license="MIT",
            tags=["csv", "export", "reporter", "example"],
            min_miesc_version="5.0.0",
            api_version=self.api_version,
            config_schema={
                "type": "object",
                "properties": {
                    "delimiter": {"type": "string", "default": ","},
                    "include_header": {"type": "boolean", "default": True},
                },
            },
        )

    # ------------------------------------------------------------------
    # Core generation logic
    # ------------------------------------------------------------------

    def generate(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        output_path: Union[str, Path],
    ) -> Path:
        """
        Write findings to a CSV file.

        Args:
            findings:    List of MIESC finding dicts.
            metadata:    Report metadata (title, date, contract, …).
                         Unused by this plugin but accepted for protocol compliance.
            output_path: Destination file path (will be created/overwritten).

        Returns:
            Path to the written CSV file.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=CSV_COLUMNS,
                delimiter=self._delimiter,
                extrasaction="ignore",
            )
            if self._include_header:
                writer.writeheader()

            for finding in findings:
                writer.writerow(self._flatten(finding))

        return output_path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _flatten(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Flatten a finding dict into a flat dict ready for csv.DictWriter."""
        location: Dict[str, Any] = finding.get("location", {})
        return {
            "id": str(finding.get("id", "")),
            "tool": str(finding.get("tool", "")),
            "severity": str(finding.get("severity", "")),
            "confidence": str(finding.get("confidence", "")),
            "type": str(finding.get("type", "")),
            "swc_id": str(finding.get("swc_id", "") or ""),
            "cwe_id": str(finding.get("cwe_id", "") or ""),
            "file": str(location.get("file", "")),
            "line": str(location.get("line", "")),
            "column": str(location.get("column", "")),
            "message": str(finding.get("message", "")),
            "description": str(finding.get("description", "")),
            "recommendation": str(finding.get("recommendation", "")),
            "gas_saved": str(finding.get("gas_saved", "")),
            "pattern": str(finding.get("pattern", "")),
            "owasp_category": str(finding.get("owasp_category", "") or ""),
            "code_snippet": str(location.get("code_snippet", "")),
        }

    # ------------------------------------------------------------------
    # Convenience: convert to CSV string without writing a file
    # ------------------------------------------------------------------

    def to_csv_string(
        self,
        findings: List[Dict[str, Any]],
        include_header: Optional[bool] = None,
    ) -> str:
        """
        Return findings as a CSV-formatted string (in-memory, no file I/O).

        Useful for testing and for embedding CSV data in API responses.
        """
        use_header = self._include_header if include_header is None else include_header
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=CSV_COLUMNS,
            delimiter=self._delimiter,
            extrasaction="ignore",
        )
        if use_header:
            writer.writeheader()
        for finding in findings:
            writer.writerow(self._flatten(finding))
        return buf.getvalue()
