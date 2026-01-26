"""
Plugin Template Generator - Scaffold for New Plugins
=====================================================

Generates complete plugin project structures following the MIESC
plugin protocol. Supports all plugin types with proper templates.

Usage:
    generator = PluginTemplateGenerator()
    path = generator.create_plugin(
        name="my-detector",
        plugin_type=PluginType.DETECTOR,
        output_dir="./plugins",
        description="My custom detector",
        author="Developer Name",
    )

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
Version: 1.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .protocol import PluginType

logger = logging.getLogger(__name__)


@dataclass
class PluginTemplate:
    """Template for plugin generation."""
    name: str
    plugin_type: PluginType
    description: str = ""
    author: str = ""
    email: str = ""
    version: str = "0.1.0"
    license: str = "MIT"
    min_miesc_version: str = "4.5.0"
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


class PluginTemplateGenerator:
    """
    Generates plugin project scaffolds.

    Creates complete plugin projects with:
    - pyproject.toml
    - Plugin implementation file
    - Test files
    - README.md
    - Configuration files
    """

    def __init__(self):
        """Initialize the template generator."""
        pass

    def create_plugin(
        self,
        name: str,
        plugin_type: PluginType,
        output_dir: Path,
        description: str = "",
        author: str = "",
        email: str = "",
        version: str = "0.1.0",
        license_type: str = "MIT",
        tags: Optional[List[str]] = None,
    ) -> Path:
        """
        Create a complete plugin project.

        Args:
            name: Plugin name (will be normalized)
            plugin_type: Type of plugin to create
            output_dir: Directory to create plugin in
            description: Plugin description
            author: Author name
            email: Author email
            version: Initial version
            license_type: License type
            tags: Plugin tags

        Returns:
            Path to created plugin directory
        """
        # Normalize name
        normalized_name = self._normalize_name(name)
        package_name = f"miesc-{normalized_name}"
        module_name = normalized_name.replace("-", "_")

        # Create directory structure
        output_dir = Path(output_dir)
        plugin_dir = output_dir / package_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        src_dir = plugin_dir / module_name
        src_dir.mkdir(exist_ok=True)

        tests_dir = plugin_dir / "tests"
        tests_dir.mkdir(exist_ok=True)

        # Create template data
        template = PluginTemplate(
            name=normalized_name,
            plugin_type=plugin_type,
            description=description or f"MIESC {plugin_type.value} plugin",
            author=author,
            email=email,
            version=version,
            license=license_type,
            tags=tags or [plugin_type.value, "miesc"],
        )

        # Generate files
        self._create_pyproject_toml(plugin_dir, template, module_name)
        self._create_init_file(src_dir, template)
        self._create_plugin_file(src_dir, template)
        self._create_test_files(tests_dir, template, module_name)
        self._create_readme(plugin_dir, template)
        self._create_manifest(plugin_dir, template)

        logger.info(f"Created plugin scaffold: {plugin_dir}")
        return plugin_dir

    def _normalize_name(self, name: str) -> str:
        """Normalize plugin name to lowercase with hyphens."""
        # Remove miesc- prefix if present
        if name.lower().startswith("miesc-"):
            name = name[6:]

        # Convert to lowercase and replace underscores/spaces with hyphens
        name = name.lower()
        name = re.sub(r"[_\s]+", "-", name)
        name = re.sub(r"[^a-z0-9-]", "", name)
        name = re.sub(r"-+", "-", name)
        name = name.strip("-")

        return name

    def _create_pyproject_toml(
        self,
        plugin_dir: Path,
        template: PluginTemplate,
        module_name: str,
    ) -> None:
        """Create pyproject.toml file."""
        class_name = self._to_class_name(template.name)
        plugin_class = f"{class_name}{template.plugin_type.value.title()}"

        content = f'''[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "miesc-{template.name}"
version = "{template.version}"
description = "{template.description}"
readme = "README.md"
license = {{text = "{template.license}"}}
authors = [
    {{name = "{template.author}", email = "{template.email}"}}
]
requires-python = ">=3.9"
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance",
]
keywords = {template.tags}
dependencies = [
    "miesc>={template.min_miesc_version}",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
]

[project.urls]
Homepage = "https://github.com/yourusername/miesc-{template.name}"
Documentation = "https://github.com/yourusername/miesc-{template.name}#readme"
Issues = "https://github.com/yourusername/miesc-{template.name}/issues"

[project.entry-points."miesc.plugins"]
{template.name} = "{module_name}:{plugin_class}"

[tool.setuptools.packages.find]
where = ["."]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-v --tb=short"
'''
        (plugin_dir / "pyproject.toml").write_text(content)

    def _create_init_file(
        self,
        src_dir: Path,
        template: PluginTemplate,
    ) -> None:
        """Create __init__.py file."""
        class_name = self._to_class_name(template.name)
        plugin_class = f"{class_name}{template.plugin_type.value.title()}"

        content = f'''"""
{template.description}

MIESC Plugin: miesc-{template.name}
Type: {template.plugin_type.value}
Version: {template.version}
"""

from .plugin import {plugin_class}

__version__ = "{template.version}"
__all__ = ["{plugin_class}"]
'''
        (src_dir / "__init__.py").write_text(content)

    def _create_plugin_file(
        self,
        src_dir: Path,
        template: PluginTemplate,
    ) -> None:
        """Create the main plugin implementation file."""
        class_name = self._to_class_name(template.name)

        if template.plugin_type == PluginType.DETECTOR:
            content = self._get_detector_template(template, class_name)
        elif template.plugin_type == PluginType.ADAPTER:
            content = self._get_adapter_template(template, class_name)
        elif template.plugin_type == PluginType.REPORTER:
            content = self._get_reporter_template(template, class_name)
        elif template.plugin_type == PluginType.TRANSFORMER:
            content = self._get_transformer_template(template, class_name)
        else:
            content = self._get_generic_template(template, class_name)

        (src_dir / "plugin.py").write_text(content)

    def _get_detector_template(self, template: PluginTemplate, class_name: str) -> str:
        """Get detector plugin template."""
        return f'''"""
{class_name} Detector Plugin
{'=' * (len(class_name) + 16)}

{template.description}

Author: {template.author}
Version: {template.version}
"""

import logging
import re
from typing import Any, Dict, List, Optional

from src.plugins import DetectorPlugin, PluginContext, PluginMetadata

logger = logging.getLogger(__name__)


class {class_name}Detector(DetectorPlugin):
    """
    {template.description}

    This detector analyzes Solidity code for specific vulnerability patterns.
    """

    # Define detection patterns
    PATTERNS = [
        # Add your regex patterns here
        # (pattern, severity, message)
        (r"\\b(tx\\.origin)\\b", "medium", "Use of tx.origin for authorization"),
    ]

    @property
    def name(self) -> str:
        return "{template.name}"

    @property
    def version(self) -> str:
        return "{template.version}"

    @property
    def description(self) -> str:
        return "{template.description}"

    @property
    def author(self) -> str:
        return "{template.author}"

    def initialize(self, context: PluginContext) -> None:
        """
        Initialize the detector with context.

        Args:
            context: Plugin context with config and services
        """
        self._context = context
        self._config = context.config
        logger.debug(f"{{self.name}} initialized")

    def detect(
        self,
        code: str,
        filename: str = "",
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detect vulnerabilities in the provided code.

        Args:
            code: Solidity source code to analyze
            filename: Optional filename for context
            options: Detection options

        Returns:
            List of findings with type, severity, line, and message
        """
        findings = []
        lines = code.split("\\n")

        for pattern, severity, message in self.PATTERNS:
            regex = re.compile(pattern, re.IGNORECASE)

            for line_num, line in enumerate(lines, 1):
                if regex.search(line):
                    findings.append({{
                        "type": f"{{self.name}}-finding",
                        "severity": severity,
                        "line": line_num,
                        "column": 0,
                        "message": message,
                        "code_snippet": line.strip(),
                        "filename": filename,
                        "detector": self.name,
                    }})

        logger.debug(f"{{self.name}}: Found {{len(findings)}} issues in {{filename or 'code'}}")
        return findings

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name=self.name,
            version=self.version,
            plugin_type=self.plugin_type,
            description=self.description,
            author=self.author,
            tags={template.tags},
            min_miesc_version="{template.min_miesc_version}",
        )
'''

    def _get_adapter_template(self, template: PluginTemplate, class_name: str) -> str:
        """Get adapter plugin template."""
        return f'''"""
{class_name} Adapter Plugin
{'=' * (len(class_name) + 15)}

{template.description}

Author: {template.author}
Version: {template.version}
"""

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.plugins import AdapterPlugin, PluginContext, PluginMetadata

logger = logging.getLogger(__name__)


class {class_name}Adapter(AdapterPlugin):
    """
    Adapter for external security tool integration.

    This adapter wraps an external tool and normalizes its output
    to the MIESC finding format.
    """

    # Tool configuration
    TOOL_COMMAND = "mytool"  # Replace with actual tool command
    TOOL_ARGS = ["--json"]  # Default arguments

    @property
    def name(self) -> str:
        return "{template.name}"

    @property
    def version(self) -> str:
        return "{template.version}"

    @property
    def tool_name(self) -> str:
        return "{class_name.lower()}"

    @property
    def description(self) -> str:
        return "{template.description}"

    @property
    def author(self) -> str:
        return "{template.author}"

    def initialize(self, context: PluginContext) -> None:
        """Initialize the adapter."""
        self._context = context
        self._config = context.config
        logger.debug(f"{{self.name}} initialized")

    def is_available(self) -> bool:
        """Check if the external tool is available."""
        return shutil.which(self.TOOL_COMMAND) is not None

    def analyze(
        self,
        target: Union[str, Path],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run the external tool and return normalized findings.

        Args:
            target: File or directory to analyze
            options: Tool-specific options

        Returns:
            List of normalized findings
        """
        if not self.is_available():
            logger.warning(f"Tool {{self.TOOL_COMMAND}} not available")
            return []

        options = options or {{}}
        target = Path(target)

        # Build command
        cmd = [self.TOOL_COMMAND] + self.TOOL_ARGS + [str(target)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get("timeout", 300),
            )

            return self._parse_output(result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            logger.error(f"{{self.name}}: Tool timed out")
            return []
        except Exception as e:
            logger.error(f"{{self.name}}: Error running tool: {{e}}")
            return []

    def _parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse tool output to normalized findings.

        Override this method to implement actual parsing logic.
        """
        findings = []

        # TODO: Implement parsing logic for your tool's output
        # Example:
        # import json
        # data = json.loads(stdout)
        # for issue in data.get("issues", []):
        #     findings.append({{
        #         "type": issue["type"],
        #         "severity": self._map_severity(issue["severity"]),
        #         "line": issue.get("line", 0),
        #         "message": issue["message"],
        #         "detector": self.name,
        #     }})

        return findings

    def _map_severity(self, tool_severity: str) -> str:
        """Map tool severity to MIESC severity."""
        mapping = {{
            "error": "high",
            "warning": "medium",
            "info": "low",
        }}
        return mapping.get(tool_severity.lower(), "info")
'''

    def _get_reporter_template(self, template: PluginTemplate, class_name: str) -> str:
        """Get reporter plugin template."""
        return f'''"""
{class_name} Reporter Plugin
{'=' * (len(class_name) + 16)}

{template.description}

Author: {template.author}
Version: {template.version}
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from src.plugins import ReporterPlugin, PluginContext, PluginMetadata

logger = logging.getLogger(__name__)


class {class_name}Reporter(ReporterPlugin):
    """
    Custom report generator.

    Generates reports in a custom format from vulnerability findings.
    """

    @property
    def name(self) -> str:
        return "{template.name}"

    @property
    def version(self) -> str:
        return "{template.version}"

    @property
    def format_name(self) -> str:
        return "{template.name.replace('-', '_')}"

    @property
    def file_extension(self) -> str:
        return "txt"  # Change to your format extension

    @property
    def description(self) -> str:
        return "{template.description}"

    @property
    def author(self) -> str:
        return "{template.author}"

    def initialize(self, context: PluginContext) -> None:
        """Initialize the reporter."""
        self._context = context
        self._config = context.config
        logger.debug(f"{{self.name}} initialized")

    def generate(
        self,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        output_path: Union[str, Path],
    ) -> Path:
        """
        Generate a report from findings.

        Args:
            findings: List of vulnerability findings
            metadata: Report metadata (title, date, etc.)
            output_path: Output file path

        Returns:
            Path to generated report
        """
        output_path = Path(output_path)

        # Group findings by severity
        by_severity = {{"critical": [], "high": [], "medium": [], "low": [], "info": []}}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Generate report content
        content = self._generate_content(findings, by_severity, metadata)

        # Write report
        output_path.write_text(content)
        logger.info(f"Report generated: {{output_path}}")

        return output_path

    def _generate_content(
        self,
        findings: List[Dict[str, Any]],
        by_severity: Dict[str, List],
        metadata: Dict[str, Any],
    ) -> str:
        """Generate report content."""
        lines = [
            "=" * 60,
            f"SECURITY AUDIT REPORT",
            f"Generated by: {{self.name}} v{{self.version}}",
            "=" * 60,
            "",
            f"Title: {{metadata.get('title', 'Security Audit')}}",
            f"Date: {{metadata.get('date', 'N/A')}}",
            f"Total Findings: {{len(findings)}}",
            "",
            "-" * 60,
            "SUMMARY BY SEVERITY",
            "-" * 60,
        ]

        for severity, items in by_severity.items():
            if items:
                lines.append(f"  {{severity.upper()}}: {{len(items)}}")

        lines.extend(["", "-" * 60, "FINDINGS", "-" * 60, ""])

        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"[{{i}}] {{finding.get('type', 'Unknown')}}",
                f"    Severity: {{finding.get('severity', 'N/A')}}",
                f"    Line: {{finding.get('line', 'N/A')}}",
                f"    Message: {{finding.get('message', 'N/A')}}",
                "",
            ])

        return "\\n".join(lines)
'''

    def _get_transformer_template(self, template: PluginTemplate, class_name: str) -> str:
        """Get transformer plugin template."""
        return f'''"""
{class_name} Transformer Plugin
{'=' * (len(class_name) + 19)}

{template.description}

Author: {template.author}
Version: {template.version}
"""

import logging
import re
from typing import Any, Dict, Optional

from src.plugins import TransformerPlugin, PluginContext, PluginMetadata

logger = logging.getLogger(__name__)


class {class_name}Transformer(TransformerPlugin):
    """
    Code transformer for applying fixes.

    Transforms vulnerable code patterns to secure alternatives.
    """

    # Define transformation rules
    # (pattern, replacement, description)
    TRANSFORMATIONS = [
        (r"tx\\.origin", "msg.sender", "Replace tx.origin with msg.sender"),
    ]

    @property
    def name(self) -> str:
        return "{template.name}"

    @property
    def version(self) -> str:
        return "{template.version}"

    @property
    def description(self) -> str:
        return "{template.description}"

    @property
    def author(self) -> str:
        return "{template.author}"

    def initialize(self, context: PluginContext) -> None:
        """Initialize the transformer."""
        self._context = context
        self._config = context.config
        logger.debug(f"{{self.name}} initialized")

    def transform(
        self,
        code: str,
        finding: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Transform code to fix vulnerabilities.

        Args:
            code: Source code to transform
            finding: Optional finding to target
            options: Transformation options

        Returns:
            Transformed code
        """
        options = options or {{}}
        transformed = code

        if finding:
            # Apply targeted fix for specific finding
            transformed = self._apply_targeted_fix(transformed, finding)
        else:
            # Apply all transformation rules
            for pattern, replacement, desc in self.TRANSFORMATIONS:
                new_code = re.sub(pattern, replacement, transformed)
                if new_code != transformed:
                    logger.debug(f"Applied: {{desc}}")
                    transformed = new_code

        return transformed

    def _apply_targeted_fix(self, code: str, finding: Dict[str, Any]) -> str:
        """Apply a fix for a specific finding."""
        finding_type = finding.get("type", "")
        line_num = finding.get("line", 0)

        # Implement targeted fixes based on finding type
        # Example: fix specific line

        return code
'''

    def _get_generic_template(self, template: PluginTemplate, class_name: str) -> str:
        """Get generic plugin template."""
        return f'''"""
{class_name} Plugin
{'=' * (len(class_name) + 7)}

{template.description}

Author: {template.author}
Version: {template.version}
"""

import logging
from typing import Any, Dict, Optional

from src.plugins import MIESCPlugin, PluginContext, PluginType, PluginResult

logger = logging.getLogger(__name__)


class {class_name}Plugin(MIESCPlugin):
    """
    {template.description}
    """

    @property
    def name(self) -> str:
        return "{template.name}"

    @property
    def version(self) -> str:
        return "{template.version}"

    @property
    def plugin_type(self) -> PluginType:
        return PluginType.{template.plugin_type.name}

    @property
    def description(self) -> str:
        return "{template.description}"

    @property
    def author(self) -> str:
        return "{template.author}"

    def initialize(self, context: PluginContext) -> None:
        """Initialize the plugin."""
        self._context = context
        logger.debug(f"{{self.name}} initialized")

    def execute(self, *args: Any, **kwargs: Any) -> PluginResult:
        """Execute the plugin."""
        try:
            # Implement your plugin logic here
            result_data = {{"message": "Plugin executed successfully"}}

            return PluginResult(
                success=True,
                data=result_data,
            )
        except Exception as e:
            return PluginResult(
                success=False,
                error=str(e),
            )
'''

    def _create_test_files(
        self,
        tests_dir: Path,
        template: PluginTemplate,
        module_name: str,
    ) -> None:
        """Create test files."""
        class_name = self._to_class_name(template.name)
        plugin_class = f"{class_name}{template.plugin_type.value.title()}"

        # __init__.py
        (tests_dir / "__init__.py").write_text('"""Tests for the plugin."""\n')

        # Test file
        test_content = f'''"""
Tests for {plugin_class}
"""

import pytest
from pathlib import Path

from {module_name} import {plugin_class}
from src.plugins import PluginContext, PluginType


@pytest.fixture
def plugin_context():
    """Create test plugin context."""
    return PluginContext(
        miesc_version="4.5.0",
        config={{}},
        data_dir=Path("/tmp/miesc/data"),
        cache_dir=Path("/tmp/miesc/cache"),
    )


@pytest.fixture
def plugin(plugin_context):
    """Create and initialize plugin instance."""
    p = {plugin_class}()
    p.initialize(plugin_context)
    return p


class Test{plugin_class}:
    """Tests for {plugin_class}."""

    def test_plugin_name(self, plugin):
        """Should have correct name."""
        assert plugin.name == "{template.name}"

    def test_plugin_version(self, plugin):
        """Should have correct version."""
        assert plugin.version == "{template.version}"

    def test_plugin_type(self, plugin):
        """Should have correct type."""
        assert plugin.plugin_type == PluginType.{template.plugin_type.name}

    def test_plugin_initialize(self, plugin, plugin_context):
        """Should initialize with context."""
        assert plugin._context == plugin_context
'''

        # Add type-specific tests
        if template.plugin_type == PluginType.DETECTOR:
            test_content += '''
    def test_detect_vulnerability(self, plugin):
        """Should detect vulnerabilities."""
        code = """
        contract Test {
            function auth() public {
                require(tx.origin == owner);
            }
        }
        """
        findings = plugin.detect(code, "Test.sol")
        assert len(findings) >= 0  # Adjust based on your patterns

    def test_detect_safe_code(self, plugin):
        """Should return empty for safe code."""
        code = """
        contract Safe {
            function auth() public {
                require(msg.sender == owner);
            }
        }
        """
        findings = plugin.detect(code, "Safe.sol")
        # Adjust assertion based on expected behavior
'''
        elif template.plugin_type == PluginType.ADAPTER:
            test_content += '''
    def test_is_available(self, plugin):
        """Should check tool availability."""
        # Will be False unless tool is installed
        result = plugin.is_available()
        assert isinstance(result, bool)
'''
        elif template.plugin_type == PluginType.REPORTER:
            test_content += '''
    def test_generate_report(self, plugin, tmp_path):
        """Should generate a report."""
        findings = [
            {"type": "test", "severity": "high", "line": 1, "message": "Test finding"}
        ]
        output = tmp_path / "report.txt"

        result = plugin.generate(
            findings=findings,
            metadata={"title": "Test Report"},
            output_path=output,
        )

        assert result.exists()
        content = result.read_text()
        assert "Test Report" in content or "Test finding" in content
'''
        elif template.plugin_type == PluginType.TRANSFORMER:
            test_content += '''
    def test_transform_code(self, plugin):
        """Should transform vulnerable code."""
        code = "require(tx.origin == owner);"
        result = plugin.transform(code)
        # Adjust assertion based on your transformation rules
        assert "msg.sender" in result or result == code
'''

        (tests_dir / f"test_{module_name}.py").write_text(test_content)

    def _create_readme(self, plugin_dir: Path, template: PluginTemplate) -> None:
        """Create README.md file."""
        class_name = self._to_class_name(template.name)

        content = f'''# miesc-{template.name}

{template.description}

## Installation

```bash
pip install miesc-{template.name}
```

Or install from source:

```bash
git clone https://github.com/yourusername/miesc-{template.name}
cd miesc-{template.name}
pip install -e .
```

## Usage

The plugin is automatically discovered by MIESC after installation.

```bash
# List installed plugins
miesc plugins list

# Run audit with this plugin
miesc audit smart contract.sol
```

## Configuration

Add to your `miesc.yaml`:

```yaml
plugins:
  {template.name}:
    enabled: true
    # Add plugin-specific options here
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov={template.name.replace("-", "_")}
```

## Plugin Type

- **Type:** {template.plugin_type.value}
- **Version:** {template.version}
- **MIESC Version:** >={template.min_miesc_version}

## License

{template.license}

## Author

{template.author} {f"<{template.email}>" if template.email else ""}
'''
        (plugin_dir / "README.md").write_text(content)

    def _create_manifest(self, plugin_dir: Path, template: PluginTemplate) -> None:
        """Create MANIFEST.in file."""
        content = '''include README.md
include LICENSE
recursive-include tests *.py
'''
        (plugin_dir / "MANIFEST.in").write_text(content)

    def _to_class_name(self, name: str) -> str:
        """Convert plugin name to class name (PascalCase)."""
        parts = name.replace("-", " ").replace("_", " ").split()
        return "".join(part.capitalize() for part in parts)


# ============================================================================
# Export
# ============================================================================

__all__ = [
    "PluginTemplateGenerator",
    "PluginTemplate",
]
