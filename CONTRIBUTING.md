# Contributing to MIESC

Thank you for your interest in contributing to MIESC! This document provides guidelines and instructions for contributing.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)
- [Community](#community)

---

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to fboiero@frvm.utn.edu.ar.

---

## Getting Started

### Prerequisites

- Python 3.12 or higher
- Git
- Virtual environment (recommended)
- Solidity compiler (solc) for testing

### Quick Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/MIESC.git
cd MIESC

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements_dev.txt

# Run tests to verify setup
pytest tests/
```

---

## How to Contribute

### Types of Contributions

| Type | Description | Label |
|------|-------------|-------|
| Bug Fix | Fix a bug in existing code | `bug` |
| Feature | Add new functionality | `enhancement` |
| Documentation | Improve or add documentation | `documentation` |
| Testing | Add or improve tests | `testing` |
| Refactoring | Code improvements without changing behavior | `refactor` |
| Translation | Add language translations | `i18n` |

### Finding Issues

- Look for issues labeled [`good first issue`](https://github.com/fboiero/MIESC/labels/good%20first%20issue)
- Check [`help wanted`](https://github.com/fboiero/MIESC/labels/help%20wanted) for priority items
- Review the [project roadmap](./docs/ROADMAP.md)

### Proposing Changes

1. **Check existing issues** to avoid duplicates
2. **Open an issue** to discuss significant changes before coding
3. **Get feedback** from maintainers on your approach

---

## Development Setup

### Environment Configuration

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install all dependencies (including dev)
pip install -r requirements.txt
pip install -r requirements_dev.txt

# Install pre-commit hooks
pre-commit install

# Verify installation
python scripts/verify_installation.py
```

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| pytest | Testing | `pip install pytest pytest-cov` |
| black | Code formatting | `pip install black` |
| ruff | Linting | `pip install ruff` |
| mypy | Type checking | `pip install mypy` |
| pre-commit | Git hooks | `pip install pre-commit` |

### Project Structure

```
MIESC/
├── src/                    # Main source code
│   ├── adapters/          # Tool adapters
│   ├── core/              # Core framework
│   ├── ml/                # Machine learning components
│   └── mcp/               # MCP protocol implementation
├── tests/                  # Test suite
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── fixtures/          # Test data
├── docs/                   # Documentation
├── examples/               # Example scripts
└── contracts/              # Test contracts
```

---

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://peps.python.org/pep-0008/) with these additions:

| Rule | Setting |
|------|---------|
| Line length | 100 characters max |
| Formatter | Black |
| Import sorting | isort |
| Docstrings | Google style |

### Code Formatting

```bash
# Format code
black src/ tests/

# Sort imports
isort src/ tests/

# Lint code
ruff check src/ tests/

# Type check
mypy src/
```

### Example Code Style

```python
"""Module docstring describing purpose.

This module provides functionality for...
"""

from typing import Dict, List, Optional

from miesc.core import BaseAdapter


class MyAdapter(BaseAdapter):
    """Adapter for MyTool security scanner.

    This adapter wraps the MyTool CLI and normalizes
    its output to the MIESC finding format.

    Attributes:
        name: Tool identifier.
        category: Tool category (STATIC, DYNAMIC, etc.).
    """

    def __init__(self, config: Optional[Dict] = None) -> None:
        """Initialize the adapter.

        Args:
            config: Optional configuration dictionary.
        """
        super().__init__(config)
        self.name = "mytool"
        self.category = "STATIC"

    def analyze(self, contract_path: str, timeout: int = 300) -> Dict:
        """Analyze a smart contract.

        Args:
            contract_path: Path to the Solidity file.
            timeout: Maximum execution time in seconds.

        Returns:
            Dictionary containing analysis results with keys:
                - status: "success" or "error"
                - findings: List of vulnerability findings
                - metadata: Execution metadata

        Raises:
            FileNotFoundError: If contract file doesn't exist.
            TimeoutError: If analysis exceeds timeout.
        """
        # Implementation
        pass
```

---

## Testing

For comprehensive testing documentation, see [Testing Guide](./docs/guides/TESTING.md).

### Quick Reference

```bash
# Run all tests with coverage
make test

# Run tests without coverage (faster)
make test-quick

# Run only integration tests
pytest -m integration --no-cov

# Run specific test file
pytest tests/test_integration_pipeline.py -v --no-cov
```

### Writing Tests

```python
"""Tests for SlitherAdapter."""

import pytest
from src.adapters.slither_adapter import SlitherAdapter


class TestSlitherAdapter:
    """Test suite for SlitherAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter instance for tests."""
        return SlitherAdapter()

    @pytest.fixture
    def sample_contract(self, tmp_path):
        """Create a sample contract for testing."""
        contract = tmp_path / "test.sol"
        contract.write_text("""
            pragma solidity ^0.8.0;
            contract Test {
                function foo() public {}
            }
        """)
        return str(contract)

    def test_analyze_valid_contract(self, adapter, sample_contract):
        """Test analysis of a valid contract."""
        result = adapter.analyze(sample_contract)

        assert result["status"] == "success"
        assert "findings" in result
        assert isinstance(result["findings"], list)

    def test_analyze_invalid_path(self, adapter):
        """Test analysis with invalid file path."""
        with pytest.raises(FileNotFoundError):
            adapter.analyze("/nonexistent/path.sol")
```

### Test Coverage Requirements

- Minimum coverage: 80%
- New features must include tests
- Bug fixes must include regression tests

---

## Pull Request Process

### Before Submitting

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow coding standards
   - Add/update tests
   - Update documentation

3. **Run checks locally**
   ```bash
   # Format code
   black src/ tests/

   # Run linter
   ruff check src/ tests/

   # Run tests
   pytest tests/

   # Check types
   mypy src/
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "feat: add support for new tool X

   - Implement XAdapter class
   - Add unit tests for X integration
   - Update documentation

   Closes #123"
   ```

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance

### Submitting the PR

1. Push your branch
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create Pull Request on GitHub

3. Fill out the PR template:
   - Description of changes
   - Related issue(s)
   - Testing performed
   - Documentation updates

4. Request review from maintainers

### PR Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests pass and coverage maintained
- [ ] Documentation updated
- [ ] No security vulnerabilities introduced
- [ ] Commit messages follow convention
- [ ] PR description is complete

---

## Documentation

### Types of Documentation

| Type | Location | Format |
|------|----------|--------|
| Code docs | In source files | Docstrings |
| User guide | `docs/` | Markdown |
| API reference | `docs/api/` | Auto-generated |
| Examples | `examples/` | Python scripts |

### Building Documentation

```bash
# Install documentation dependencies
pip install mkdocs mkdocs-material

# Serve docs locally
mkdocs serve

# Build static site
mkdocs build
```

### Documentation Standards

- Use clear, concise language
- Include code examples
- Keep documentation up-to-date with code changes
- Add screenshots/diagrams where helpful

---

## Community

### Getting Help

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: Questions, ideas, community
- **Email**: fboiero@frvm.utn.edu.ar

### Recognition

Contributors are recognized in:
- [CONTRIBUTORS.md](./CONTRIBUTORS.md)
- Release notes
- Project documentation

### Becoming a Maintainer

Regular contributors may be invited to become maintainers. Criteria:
- Sustained quality contributions
- Understanding of project goals
- Positive community interactions
- Commitment to the project

---

## License

By contributing to MIESC, you agree that your contributions will be licensed under the [AGPL-3.0 License](./LICENSE).

---

## Questions?

Don't hesitate to ask questions! Open an issue or reach out via email.

Thank you for contributing to MIESC!
