# Contributing to the MIESC Plugin Marketplace

## How to Submit a Plugin

### Prerequisites

1. Your plugin is published on [PyPI](https://pypi.org/) with a name starting with `miesc-`
2. Your plugin follows the MIESC plugin protocol (see [Plugin Development Guide](#plugin-development))
3. Your plugin has tests and documentation

### Step 1: Create Your Plugin

```bash
miesc plugins new my-detector --type detector --author "Your Name"
```

This scaffolds a complete plugin project with:
- `pyproject.toml` with MIESC entry points
- Plugin implementation template
- Test templates
- README

### Step 2: Develop and Test

```bash
cd miesc-my-detector
pip install -e ".[dev]"
pytest tests/ -v
```

### Step 3: Publish to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

### Step 4: Generate Submission

```bash
miesc plugins submit \
  --name "My Detector" \
  --package miesc-my-detector \
  --version 1.0.0 \
  --type detector \
  --description "Detects something important" \
  --author "Your Name"
```

### Step 5: Submit a Pull Request

1. Fork the [MIESC repository](https://github.com/fboiero/MIESC)
2. Add your plugin entry to `data/marketplace/marketplace-index.json`
3. Open a Pull Request

The CI will validate your submission automatically.

## Plugin Entry Format

Each plugin entry in `marketplace-index.json` must include:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable display name |
| `slug` | Yes | Unique identifier (lowercase, hyphens) |
| `pypi_package` | Yes | PyPI package name (must start with `miesc-`) |
| `version` | Yes | Semantic version (e.g., `1.0.0`) |
| `plugin_type` | Yes | One of: `detector`, `adapter`, `reporter`, `transformer` |
| `description` | Yes | Brief description (min 10 chars) |
| `author` | Yes | Author name |
| `author_email` | No | Contact email |
| `homepage` | No | Project homepage URL |
| `repository` | No | Source code repository URL |
| `license` | No | License identifier (e.g., `MIT`) |
| `tags` | No | List of searchable tags |
| `min_miesc_version` | No | Minimum compatible MIESC version (default: `4.0.0`) |
| `max_miesc_version` | No | Maximum compatible MIESC version |
| `verification_status` | Auto | Set by reviewers: `community` (default), `verified`, `experimental` |

## Verification Status

- **verified**: Reviewed and tested by the MIESC team
- **community**: Submitted by community, passed PR review
- **experimental**: Early stage, minimal review

New submissions default to `community` status.

## Plugin Development

### Plugin Types

| Type | Base Class | Purpose |
|------|-----------|---------|
| `detector` | `DetectorPlugin` | Custom vulnerability detectors |
| `adapter` | `AdapterPlugin` | External tool adapters |
| `reporter` | `ReporterPlugin` | Report format generators |
| `transformer` | `TransformerPlugin` | Code transformers/fixers |

### Entry Points

Register your plugin in `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
my-detector = "my_package:MyDetectorClass"
```

### Version Compatibility

Specify `min_miesc_version` to ensure your plugin works with the user's MIESC version. Use `max_miesc_version` only if you know your plugin breaks with newer versions.

## Review Criteria

PRs are reviewed for:

1. **PyPI package exists** and is installable
2. **Metadata accuracy** (description, version, author match PyPI)
3. **Slug uniqueness** in the marketplace index
4. **No malicious content** (manual review of plugin source)
5. **Basic functionality** (plugin loads and runs without errors)

## Questions?

Open an issue at https://github.com/fboiero/MIESC/issues
