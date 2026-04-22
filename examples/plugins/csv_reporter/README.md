# CSV Reporter Plugin

Example MIESC `ReporterPlugin` that converts findings to a CSV file,
demonstrating an alternative to the built-in `miesc export -f csv` command.

## Columns

```
id, tool, severity, confidence, type, swc_id, cwe_id,
file, line, column, message, description, recommendation,
gas_saved, pattern, owasp_category, code_snippet
```

Nested `location` fields are automatically flattened. Missing fields are
written as empty strings, so the column count is always consistent.

## Install

No package installation needed — load via the MIESC plugin loader:

```python
from pathlib import Path
from src.plugins.loader import PluginLoader
from src.plugins.protocol import PluginContext

loader = PluginLoader()
loaded = loader.load_plugin_file(
    Path("examples/plugins/csv_reporter/reporter.py")
)

context = PluginContext(
    miesc_version="5.1.1",
    config={"delimiter": ",", "include_header": True},
    data_dir=Path("/tmp"),
    cache_dir=Path("/tmp"),
)

plugin = loader.load_and_initialize(loaded[0], context)
```

## Usage

```python
# Write to a file
result = plugin.execute(
    findings=my_findings,
    metadata={"title": "Audit 2026-04"},
    output_path="/tmp/report.csv",
)
print(result.data)  # "/tmp/report.csv"

# Or get a CSV string without writing a file
csv_text = plugin.to_csv_string(my_findings)
print(csv_text)
```

## Config options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `delimiter` | str | `","` | CSV field delimiter (use `"\t"` for TSV) |
| `include_header` | bool | `true` | Write column header row |

## Entry point (pip-installable)

```toml
[project.entry-points."miesc.plugins"]
csv-reporter = "csv_reporter.reporter:CSVReporterPlugin"
```
