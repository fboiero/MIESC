"""Plugin template scaffolding.

Provides functionality to create new MIESC detector plugin projects.
"""

from pathlib import Path

PYPROJECT_TEMPLATE = '''[project]
name = "miesc-{name}"
version = "0.1.0"
description = "{description}"
readme = "README.md"
requires-python = ">=3.10"
license = {{text = "MIT"}}
authors = [
    {{name = "{author}"}}
]
dependencies = [
    "miesc>=4.3.0",
]

[project.entry-points."miesc.detectors"]
{name} = "{package}.detectors:{class_name}"

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]
'''

DETECTOR_TEMPLATE = '''"""MIESC Detector Plugin: {description}

This module provides custom vulnerability detectors for MIESC.
"""

from miesc.detectors import BaseDetector, Finding, Severity, Category


class {class_name}(BaseDetector):
    """{description}"""

    name = "{name}"
    description = "{description}"
    version = "0.1.0"
    author = "{author}"
    category = Category.CUSTOM
    default_severity = Severity.MEDIUM

    def analyze(self, source_code: str, file_path: str | None = None) -> list[Finding]:
        """Analyze source code for vulnerabilities.

        Args:
            source_code: Solidity source code to analyze
            file_path: Optional path to the source file

        Returns:
            List of Finding objects for detected vulnerabilities
        """
        findings: list[Finding] = []

        # TODO: Implement your detection logic here
        # Example:
        # if "dangerous_pattern" in source_code:
        #     findings.append(Finding(
        #         detector=self.name,
        #         title="Dangerous Pattern Detected",
        #         description="Found a dangerous pattern in the code",
        #         severity=self.default_severity,
        #         category=self.category,
        #         file_path=file_path,
        #         line_number=1,
        #     ))

        return findings
'''

TEST_TEMPLATE = '''"""Tests for {name} detector."""

import pytest
from {package}.detectors import {class_name}


class Test{class_name}:
    """Test suite for {class_name}."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = {class_name}()

    def test_detector_metadata(self):
        """Test detector has correct metadata."""
        assert self.detector.name == "{name}"
        assert self.detector.version == "0.1.0"

    def test_analyze_empty_source(self):
        """Test analyzing empty source code."""
        findings = self.detector.analyze("")
        assert isinstance(findings, list)

    def test_analyze_safe_contract(self):
        """Test analyzing a safe contract."""
        safe_code = """
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;

        contract SafeContract {{
            uint256 public value;

            function setValue(uint256 _value) external {{
                value = _value;
            }}
        }}
        """
        findings = self.detector.analyze(safe_code)
        assert isinstance(findings, list)

    # TODO: Add tests for vulnerable patterns
    # def test_detect_vulnerability(self):
    #     \"\"\"Test detecting a vulnerability.\"\"\"
    #     vulnerable_code = "..."
    #     findings = self.detector.analyze(vulnerable_code)
    #     assert len(findings) > 0
'''

README_TEMPLATE = '''# miesc-{name}

{description}

## Installation

```bash
pip install miesc-{name}
```

## Usage

Once installed, the detector is automatically available in MIESC:

```bash
# List available detectors (should include {name})
miesc detectors list

# Run the detector
miesc detectors run contract.sol -d {name}

# Or run as part of a full audit
miesc audit quick contract.sol
```

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/miesc-{name}.git
cd miesc-{name}

# Install in development mode
pip install -e .

# Run tests
pytest
```

## License

MIT License
'''


def create_plugin_scaffold(
    name: str,
    output_dir: Path,
    description: str = "",
    author: str = "",
) -> Path:
    """Create a new plugin project scaffold.

    Args:
        name: Plugin name (without miesc- prefix)
        output_dir: Directory to create plugin in
        description: Plugin description
        author: Author name

    Returns:
        Path to created plugin directory
    """
    # Normalize name
    name = name.lower().replace("-", "_").replace(" ", "_")
    package = name.replace("-", "_")
    class_name = "".join(word.capitalize() for word in name.split("_")) + "Detector"

    if not description:
        description = f"MIESC detector plugin: {name}"

    if not author:
        author = "MIESC Plugin Author"

    # Create plugin directory
    plugin_dir = Path(output_dir) / f"miesc-{name}"
    plugin_dir.mkdir(parents=True, exist_ok=True)

    # Create package directory
    package_dir = plugin_dir / package
    package_dir.mkdir(exist_ok=True)

    # Create tests directory
    tests_dir = plugin_dir / "tests"
    tests_dir.mkdir(exist_ok=True)

    # Write pyproject.toml
    pyproject_content = PYPROJECT_TEMPLATE.format(
        name=name,
        package=package,
        class_name=class_name,
        description=description,
        author=author,
    )
    (plugin_dir / "pyproject.toml").write_text(pyproject_content)

    # Write package __init__.py
    (package_dir / "__init__.py").write_text(
        f'"""MIESC Plugin: {description}"""\n\n__version__ = "0.1.0"\n'
    )

    # Write detectors.py
    detector_content = DETECTOR_TEMPLATE.format(
        name=name,
        class_name=class_name,
        description=description,
        author=author,
    )
    (package_dir / "detectors.py").write_text(detector_content)

    # Write test file
    test_content = TEST_TEMPLATE.format(
        name=name,
        package=package,
        class_name=class_name,
    )
    (tests_dir / "__init__.py").write_text("")
    (tests_dir / f"test_{name}.py").write_text(test_content)

    # Write README
    readme_content = README_TEMPLATE.format(
        name=name,
        description=description,
    )
    (plugin_dir / "README.md").write_text(readme_content)

    return plugin_dir
