# Custom Detector API

MIESC provides a powerful API for creating custom vulnerability detectors. Security researchers can write their own detection rules and integrate them seamlessly with MIESC.

## Quick Start

### 1. Create a Custom Detector

```python
from miesc.detectors import BaseDetector, Finding, Severity, Category

class MyCustomDetector(BaseDetector):
    name = "my-custom-detector"
    description = "Detects my custom vulnerability pattern"
    category = Category.CUSTOM
    default_severity = Severity.HIGH

    def analyze(self, source_code: str, file_path=None) -> list[Finding]:
        findings = []

        # Your detection logic here
        if "dangerous_pattern" in source_code:
            findings.append(self.create_finding(
                title="Dangerous Pattern Detected",
                description="Found a dangerous pattern in the code",
                line=1,
                recommendation="Remove or fix the dangerous pattern"
            ))

        return findings
```

### 2. Register Your Detector

Add to your `pyproject.toml`:

```toml
[project.entry-points."miesc.detectors"]
my-custom = "my_package.detectors:MyCustomDetector"
```

### 3. Run Your Detector

```bash
miesc detectors list                    # See registered detectors
miesc detectors run contract.sol        # Run all detectors
miesc detectors run contract.sol -d my-custom  # Run specific detector
```

## API Reference

### Severity Levels

```python
from miesc.detectors import Severity

Severity.CRITICAL  # System compromise, fund loss
Severity.HIGH      # Significant security risk
Severity.MEDIUM    # Moderate risk
Severity.LOW       # Minor issue
Severity.INFO      # Informational
```

### Categories

```python
from miesc.detectors import Category

Category.REENTRANCY          # Reentrancy vulnerabilities
Category.ACCESS_CONTROL      # Permission issues
Category.ARITHMETIC          # Integer overflow/underflow
Category.FLASH_LOAN          # Flash loan attacks
Category.ORACLE_MANIPULATION # Price oracle issues
Category.GOVERNANCE          # Governance attacks
Category.FRONT_RUNNING       # MEV/front-running
Category.DOS                 # Denial of service
Category.CUSTOM              # Custom category
```

### BaseDetector Class

The base class for all custom detectors:

```python
class BaseDetector(ABC):
    # Class attributes (override in subclass)
    name: str = "base-detector"
    description: str = "Base detector class"
    version: str = "1.0.0"
    author: str = ""
    category: Category = Category.CUSTOM
    default_severity: Severity = Severity.MEDIUM
    target_patterns: List[str] = []  # e.g., ["ERC20", "Governor"]

    @abstractmethod
    def analyze(self, source_code: str, file_path: Path = None) -> List[Finding]:
        """Main detection method - implement this."""
        pass

    def create_finding(self, title, description, severity=None, line=None,
                      code_snippet=None, recommendation="", **kwargs) -> Finding:
        """Helper to create findings with detector defaults."""
        pass

    def find_pattern(self, source_code, pattern, flags=re.IGNORECASE) -> List[tuple]:
        """Find pattern matches with line numbers."""
        pass

    def should_run(self, source_code: str) -> bool:
        """Check if detector should run on this code."""
        pass
```

### PatternDetector Class

Simplified detector for pattern-based detection:

```python
from miesc.detectors import PatternDetector, Severity

class UnsafeCallDetector(PatternDetector):
    name = "unsafe-call"
    description = "Detects unsafe external calls"

    # Pattern format: (regex, description, severity)
    PATTERNS = [
        (r'\.call\{value:', "Unchecked call with value", Severity.HIGH),
        (r'\.delegatecall\(', "Delegatecall detected", Severity.MEDIUM),
    ]
```

### Finding Dataclass

```python
@dataclass
class Finding:
    detector: str           # Detector name
    title: str              # Short title
    description: str        # Detailed description
    severity: Severity      # Severity level
    category: Category = Category.CUSTOM
    confidence: str = "high"  # high, medium, low
    location: Location = None
    code_snippet: str = None
    recommendation: str = ""
    references: List[str] = []
    cwe_id: str = None
    swc_id: str = None
    metadata: Dict = {}
```

## Example Detectors

### Flash Loan Detector

```python
class FlashLoanDetector(BaseDetector):
    name = "flash-loan"
    description = "Detects flash loan attack patterns"
    category = Category.FLASH_LOAN
    default_severity = Severity.HIGH
    target_patterns = ["swap", "pool", "oracle", "price"]

    ORACLE_PATTERNS = [
        (r'getPrice\s*\(\s*\)', "Direct price fetch without validation"),
        (r'balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)',
         "Contract balance used for pricing"),
    ]

    def analyze(self, source_code: str, file_path=None) -> List[Finding]:
        if not self.should_run(source_code):
            return []

        findings = []
        for pattern, desc in self.ORACLE_PATTERNS:
            for match, line, code in self.find_pattern(source_code, pattern):
                if not self._has_twap_protection(source_code, line):
                    findings.append(self.create_finding(
                        title="Flash Loan Oracle Manipulation",
                        description=f"{desc}. No TWAP protection found.",
                        severity=Severity.CRITICAL,
                        line=line,
                        code_snippet=code,
                        recommendation="Use time-weighted average price (TWAP)",
                        swc_id="SWC-136",
                    ))
        return findings

    def _has_twap_protection(self, source_code: str, line: int) -> bool:
        # Check surrounding context for TWAP indicators
        lines = source_code.split('\n')
        context = '\n'.join(lines[max(0, line-10):line+10])
        return any(ind in context.lower() for ind in
                   ['twap', 'timeweighted', 'average', 'cumulative'])
```

### Access Control Detector

```python
class AccessControlDetector(PatternDetector):
    name = "access-control"
    description = "Detects access control vulnerabilities"
    category = Category.ACCESS_CONTROL
    default_severity = Severity.HIGH

    PATTERNS = [
        (r'function\s+\w*[Ss]et(?:Owner|Admin)\w*\s*\([^)]*\)\s*(?:external|public)(?![^{]*onlyOwner)',
         "Admin function without access control", Severity.CRITICAL),
        (r'selfdestruct\s*\(\s*\w+\s*\)',
         "Selfdestruct - verify access control", Severity.CRITICAL),
        (r'require\s*\([^)]*tx\.origin',
         "tx.origin for auth - phishing vulnerable", Severity.HIGH),
    ]
```

## CLI Commands

```bash
# List all registered detectors
miesc detectors list
miesc detectors list --verbose

# Run detectors on a contract
miesc detectors run contract.sol
miesc detectors run contract.sol -d flash-loan -d access-control
miesc detectors run contract.sol --severity high
miesc detectors run contract.sol -o report.json

# Get detector information
miesc detectors info flash-loan
```

## Publishing Your Detectors

Create a Python package with your detectors:

```
my-miesc-detectors/
├── pyproject.toml
├── my_detectors/
│   ├── __init__.py
│   └── custom.py
```

`pyproject.toml`:

```toml
[project]
name = "my-miesc-detectors"
version = "1.0.0"
dependencies = ["miesc>=4.3.0"]

[project.entry-points."miesc.detectors"]
my-flash-loan = "my_detectors.custom:MyFlashLoanDetector"
my-governance = "my_detectors.custom:MyGovernanceDetector"
```

Users install with:

```bash
pip install my-miesc-detectors
miesc detectors list  # Shows your detectors
```

## Best Practices

1. **Be Specific**: Target specific contract types using `target_patterns`
2. **Reduce False Positives**: Check context before reporting findings
3. **Provide Recommendations**: Always include actionable fix suggestions
4. **Reference Standards**: Include CWE/SWC IDs when applicable
5. **Test Thoroughly**: Test on known vulnerable and safe contracts
6. **Version Your Detectors**: Use semantic versioning

## Integration with MIESC

Custom detectors integrate with the full MIESC pipeline:

- Results appear in audit reports
- Findings are correlated with other tools
- ML false positive filter applies
- Export to SARIF/JSON/Markdown supported

---

*Custom Detector API v4.3*
*MIESC - Multi-layer Intelligent Evaluation for Smart Contracts*
