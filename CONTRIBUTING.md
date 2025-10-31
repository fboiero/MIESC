# Contributing to MIESC

Thank you for your interest in contributing to MIESC (Multi-Agent Integrated Security Assessment Framework)! This document provides guidelines for both technical contributions and academic research collaboration.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Types of Contributions](#types-of-contributions)
- [Development Guidelines](#development-guidelines)
- [Research Contributions](#research-contributions)
- [Documentation Standards](#documentation-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Academic Collaboration](#academic-collaboration)
- [License and Attribution](#license-and-attribution)

---

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for researchers, developers, and security practitioners from all backgrounds. We value:

- **Scientific rigor** - Evidence-based discussions and peer-reviewed references
- **Constructive feedback** - Respectful critique focused on ideas, not individuals
- **Collaboration** - Sharing knowledge and building on each other's work
- **Reproducibility** - Transparent methods and open data

### Expected Behavior

✅ **DO**:
- Cite prior work appropriately (academic papers, tools, techniques)
- Provide evidence for claims (benchmarks, experiments, references)
- Document assumptions and limitations clearly
- Share reproducible examples
- Respect intellectual property and licenses

❌ **DON'T**:
- Submit unattributed work or plagiarism
- Make unsubstantiated security claims
- Share malicious code or exploits
- Violate responsible disclosure practices
- Engage in personal attacks or harassment

**Violations**: Report to fboiero@frvm.utn.edu.ar. Serious violations may result in ban from project participation.

---

## 🚀 Getting Started

### Prerequisites

1. **Technical Skills**:
   - Python 3.9+ (intermediate level)
   - Smart contract security fundamentals
   - Git/GitHub workflow
   - Understanding of at least one analysis technique (static/dynamic/formal)

2. **Research Background** (for academic contributions):
   - Familiarity with empirical software engineering methods
   - Understanding of security evaluation metrics (precision, recall, F1)
   - Experience with vulnerability taxonomies (SWC, CWE, OWASP)

### Development Setup

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/MIESC.git
cd MIESC

# Add upstream remote
git remote add upstream https://github.com/fboiero/MIESC.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements_dev.txt
pip install -r requirements_core.txt

# Install pre-commit hooks
pre-commit install

# Verify setup
python scripts/check_tools.py
pytest tests/
```

### Branching Strategy

- `main` - Stable releases (v2.2.0+)
- `develop` - Integration branch for next release
- `feature/description` - New features
- `fix/description` - Bug fixes
- `research/description` - Experimental research branches
- `docs/description` - Documentation improvements

**Example**:
```bash
git checkout -b feature/add-vyper-support
git checkout -b research/ensemble-ai-triage
git checkout -b docs/api-reference
```

---

## 🎯 Types of Contributions

### 1. Code Contributions

#### Adding New Security Tools

To integrate a new static/dynamic/formal analysis tool:

**Requirements**:
1. Tool must be **open-source** (GPL, MIT, Apache-2.0 compatible)
2. Must detect vulnerabilities not covered by existing tools
3. Must provide machine-readable output (JSON/XML preferred)
4. Should have published evaluation (paper, technical report)

**Process**:
```python
# Create new agent in src/agents/
class NewToolAgent(BaseAgent):
    """
    Agent for [Tool Name] - [Brief Description]

    Reference:
        Author et al. (Year). Tool Name: Description.
        Conference/Journal. DOI: xxx
    """

    def __init__(self):
        super().__init__(
            agent_name="NewToolAgent",
            capabilities=["vulnerability_detection"],
            agent_type="static"  # or dynamic, symbolic, formal
        )

    def analyze(self, contract_path: str, **kwargs):
        """
        Run [Tool Name] analysis on contract.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Additional configuration

        Returns:
            Dict with findings in standardized format
        """
        # Implementation
        pass
```

**Testing Requirements**:
- Unit tests in `tests/agents/test_newtool_agent.py`
- Integration test with MCP Context Bus
- Regression test ensuring no performance degradation
- Benchmark on SmartBugs Curated (143 contracts)

**Documentation**:
- Add tool description to `README.md` (Tool Integration section)
- Create usage guide in `docs/guides/NEWTOOL_SETUP.md`
- Update `docs/STATE_OF_THE_ART_COMPARISON.md` with benchmarks
- Cite original paper in `REFERENCES.md`

#### Improving Existing Agents

**Focus Areas**:
- **Performance optimization** (reduce execution time by >20%)
- **False positive reduction** (improve precision by >5%)
- **New vulnerability patterns** (extend detection coverage)
- **Better error handling** (graceful failures, informative messages)

**Guidelines**:
- Run full regression test suite (`pytest tests/`)
- Measure performance impact (`python scripts/benchmark.py`)
- Document changes in code comments and commit message
- Update relevant tests

### 2. AI/ML Contributions

#### Enhancing AIAgent

**Research Opportunities**:
- Fine-tune LLMs on smart contract vulnerability corpus
- Implement ensemble methods (combine GPT-4, Llama, CodeBERT)
- Develop few-shot prompting strategies
- Create adversarial test cases (prompt injection resistance)

**Requirements**:
1. **Ethical AI**:
   - Follow ISO/IEC 42001:2023 guidelines
   - Maintain human-in-the-loop for critical decisions
   - Document model provenance and training data
   - Test for bias and fairness

2. **Evaluation**:
   - Compare against baseline (current AIAgent)
   - Report precision, recall, F1-score
   - Measure computational cost (tokens, time, $)
   - Include ablation studies

3. **Reproducibility**:
   - Provide random seeds
   - Share prompt templates
   - Document hyperparameters
   - Include data splits (train/val/test)

**Example Contribution**:
```python
# research/experiments/ensemble_triage.py

"""
Ensemble-based AI Triage for False Positive Reduction

This experiment evaluates combining multiple LLMs:
- GPT-4 (commercial API)
- Llama 3.1 70B (local inference)
- CodeBERT (fine-tuned on SmartBugs)

Hypothesis: Ensemble voting reduces FP by 15% vs. single model.

Reference:
    Boiero, F. (2025). Multi-Model Triage for Smart Contract
    Analysis. In Proceedings of WETSEB'25.
"""

def run_ensemble_experiment():
    # Implementation with clear documentation
    pass
```

### 3. Research Contributions

#### Dataset Contributions

We welcome annotated vulnerability datasets to improve evaluation:

**Requirements**:
- **Size**: Minimum 50 contracts with ground truth labels
- **Diversity**: Multiple vulnerability types (SWC categories)
- **Quality**: Expert manual review (at least 1 auditor, documented)
- **Ethics**: No real-world exploits without responsible disclosure
- **License**: CC BY 4.0 or CC0 (public domain)

**Metadata Required**:
```json
{
  "dataset_name": "DeFi Reentrancy Corpus",
  "version": "1.0.0",
  "date": "2025-01-15",
  "contracts": 73,
  "vulnerabilities": [
    {"type": "SWC-107", "count": 42},
    {"type": "SWC-116", "count": 31}
  ],
  "annotators": [
    {"name": "Auditor 1", "experience": "5 years", "certifications": ["OSCP"]}
  ],
  "source": "Etherscan verified contracts",
  "license": "CC BY 4.0"
}
```

**Submission Process**:
1. Open issue with dataset description
2. Share via PR to `datasets/` directory
3. Include README with methodology
4. Provide baseline results (MIESC analysis)

#### Benchmark Studies

Comparative evaluations against other frameworks:

**Study Design**:
- **Hypothesis**: Clearly stated, falsifiable
- **Controls**: Same dataset, same metrics
- **Baseline**: State-of-the-art tools (Slither, Mythril, etc.)
- **Statistical Tests**: Appropriate tests (t-test, Wilcoxon, etc.)
- **Reproducibility**: Scripts + data in `research/studies/`

**Example**:
```
research/studies/miesc_vs_securify/
├── README.md                 # Study protocol
├── dataset.csv               # 500 contracts with labels
├── run_comparison.py         # Automated experiment
├── statistical_analysis.R    # Statistical tests
├── results/
│   ├── miesc_results.json
│   ├── securify_results.json
│   └── comparison_table.csv
└── paper_draft.pdf           # Optional pre-print
```

**Publication**: Studies accepted into `research/` may be published as technical reports and cited in MIESC documentation.

### 4. Compliance and Standards

#### Adding New Compliance Standards

To map MIESC findings to additional security standards:

**Requirements**:
1. Standard must be **publicly available** (ISO, NIST, OWASP, etc.)
2. Relevant to smart contract security or software assurance
3. Have clear, verifiable requirements

**Implementation**:
```python
# src/agents/policy_agent.py

def _check_new_standard_compliance(self, findings):
    """
    Check compliance with [Standard Name].

    Standard:
        [Full Standard Name] ([Standard ID])
        Published: [Date]
        URL: [Official Source]

    Requirements:
        - Requirement 1: Description
        - Requirement 2: Description
        ...

    Args:
        findings: List of vulnerability findings

    Returns:
        Dict with compliance status and evidence
    """
    compliance = {
        "standard": "Standard ID",
        "version": "1.0",
        "compliance_score": 0.0,
        "requirements": []
    }

    # Check each requirement
    # ...

    return compliance
```

**Documentation**:
- Create `standards/STANDARD_ID_mapping.md` with detailed mapping
- Update `COMPLIANCE.md` with standard description
- Add references to `REFERENCES.md`

### 5. Documentation Contributions

**Priority Areas**:
- User guides for specific use cases (DeFi audits, NFT contracts)
- Video tutorials (setup, usage, interpretation)
- Translation to other languages (Spanish, Chinese, French)
- API reference documentation
- Architecture diagrams and visualizations

**Style Guide**:
- Use clear, concise language (avoid jargon where possible)
- Provide runnable examples
- Include expected output
- Link to relevant sections
- Follow Markdown best practices

---

## 🛠️ Development Guidelines

### Code Style

**Python**:
- Follow **PEP 8** (enforced by `black` and `flake8`)
- Use type hints (`typing` module)
- Docstrings in **Google style**
- Maximum line length: 100 characters

**Example**:
```python
from typing import List, Dict, Any

def analyze_contract(
    contract_path: str,
    tools: List[str],
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Analyze smart contract with specified tools.

    Args:
        contract_path: Path to Solidity contract file.
        tools: List of tool names to run (e.g., ["slither", "mythril"]).
        timeout: Maximum execution time per tool in seconds (default: 300).

    Returns:
        Dictionary containing:
            - findings: List of detected vulnerabilities
            - summary: Aggregated statistics
            - metadata: Execution information

    Raises:
        FileNotFoundError: If contract_path does not exist.
        TimeoutError: If analysis exceeds timeout.

    Example:
        >>> results = analyze_contract("examples/reentrancy.sol", ["slither"])
        >>> len(results["findings"])
        12
    """
    # Implementation
    pass
```

**Formatting**:
```bash
# Auto-format with black
black src/ tests/

# Check with flake8
flake8 src/ tests/

# Type checking with mypy
mypy src/
```

### Performance

**Guidelines**:
- Profile slow code (`python -m cProfile`)
- Parallelize independent operations (multiprocessing)
- Cache expensive computations
- Minimize external tool calls

**Benchmarks**:
- Static analysis: <5 seconds per contract
- Dynamic fuzzing: <5 minutes per contract (configurable)
- Full pipeline: <10 minutes per contract (moderate complexity)

**Test Performance**:
```bash
# Benchmark tool execution time
python scripts/benchmark.py --tool slither --contracts 100

# Profile specific function
python -m cProfile -s cumtime scripts/demo_full_pipeline.py
```

### Security

**Critical**: MIESC analyzes potentially malicious contracts. Follow these rules:

1. **Sandboxing**:
   - Never execute contract code directly
   - Use containerization (Docker) when possible
   - Limit filesystem access

2. **Input Validation**:
   - Sanitize file paths (prevent directory traversal)
   - Validate Solidity syntax before analysis
   - Limit file sizes (max 1MB per contract)

3. **Dependency Management**:
   - Pin all dependencies in `requirements.txt`
   - Regularly update with `pip-audit`
   - Avoid running as root

4. **Disclosure**:
   - Report MIESC vulnerabilities privately to fboiero@frvm.utn.edu.ar
   - Do not publish 0-days against third-party tools without coordination

---

## 🧪 Testing Requirements

### Test Coverage

**Minimum Requirements**:
- **Unit tests**: 80%+ coverage for new code
- **Integration tests**: All agent interactions with Context Bus
- **Regression tests**: No performance degradation on benchmark suite

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src --cov-report=html tests/

# Run specific test file
pytest tests/agents/test_static_agent.py

# Run regression suite
python scripts/run_regression_tests.py --mode critical
```

### Writing Tests

**Structure**:
```python
# tests/agents/test_newtool_agent.py

import pytest
from src.agents.newtool_agent import NewToolAgent

class TestNewToolAgent:
    """Test suite for NewToolAgent."""

    @pytest.fixture
    def agent(self):
        """Create agent instance for testing."""
        return NewToolAgent()

    @pytest.fixture
    def sample_contract(self, tmp_path):
        """Create temporary contract file."""
        contract = tmp_path / "test.sol"
        contract.write_text("pragma solidity ^0.8.0; contract Test {}")
        return str(contract)

    def test_agent_initialization(self, agent):
        """Test agent initializes correctly."""
        assert agent.agent_name == "NewToolAgent"
        assert "vulnerability_detection" in agent.capabilities

    def test_analyze_success(self, agent, sample_contract):
        """Test successful analysis of valid contract."""
        result = agent.analyze(sample_contract)
        assert result["status"] == "success"
        assert "findings" in result

    def test_analyze_invalid_path(self, agent):
        """Test error handling for non-existent file."""
        with pytest.raises(FileNotFoundError):
            agent.analyze("/nonexistent/path.sol")

    @pytest.mark.slow
    def test_benchmark_performance(self, agent):
        """Test execution time on benchmark dataset."""
        # Performance test for 100 contracts
        pass
```

### Regression Testing

**Critical Tests** (must pass before merging):
1. All 30 critical tests in `scripts/run_regression_tests.py`
2. No crashes on SmartBugs Curated (143 contracts)
3. Performance: Full pipeline <15 min on reference machine

**Reference Machine**:
- CPU: 8-core 2.3GHz (M1/Ryzen 7 equivalent)
- RAM: 16GB
- SSD: 512GB

---

## 📤 Pull Request Process

### Before Submitting

✅ **Checklist**:
- [ ] Code follows style guide (black + flake8)
- [ ] All tests pass (`pytest tests/`)
- [ ] Documentation updated (README, docstrings, guides)
- [ ] No secrets or credentials in code
- [ ] Commit messages are descriptive
- [ ] Branch is up-to-date with `main`/`develop`
- [ ] Added entry to `CHANGELOG.md` (if applicable)

### PR Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Research contribution
- [ ] Performance improvement

## Motivation
Why is this change needed? Link to issue if applicable.

## Testing
How was this tested? Provide evidence (test output, benchmarks).

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No breaking changes (or documented)

## Related Issues
Closes #123
```

### Review Process

1. **Automated Checks**: GitHub Actions runs tests, linting, security scans
2. **Maintainer Review**: 1-2 maintainers review code and design
3. **Revisions**: Address feedback, update PR
4. **Approval**: Requires 1 approval from maintainer
5. **Merge**: Squash and merge to `develop` (or `main` for hotfixes)

**Timeline**:
- Small PRs (<100 lines): 1-3 days
- Medium PRs (100-500 lines): 3-7 days
- Large PRs (>500 lines): 1-2 weeks

**Tips**:
- Smaller PRs get reviewed faster
- Respond to feedback promptly
- Keep PR focused on single concern

---

## 🎓 Academic Collaboration

### Research Partnerships

We welcome collaboration with academic institutions on:
- Tool benchmarking studies
- Novel vulnerability detection techniques
- AI/ML applications in security analysis
- Compliance automation research
- Dataset curation and annotation

**To Propose Collaboration**:
1. Email research proposal to fboiero@frvm.utn.edu.ar
2. Include: objectives, methodology, timeline, expected outputs
3. We'll respond within 1 week

### Using MIESC in Your Research

**Encouraged**:
- Benchmark against MIESC in your tool papers
- Extend MIESC for new vulnerability types
- Use MIESC datasets in your experiments
- Cite MIESC in your publications

**Requirements**:
- Cite original MIESC paper/software (see [README.md](./README.md#citation))
- Share your findings (positive or negative results welcome!)
- Publish reproducible artifacts when possible

### Student Projects

**Bachelor/Master Theses**:
We've supervised multiple student projects using MIESC. Topics:
- Extending to other blockchain platforms (Solana, Cardano)
- Automated patch generation
- Gas optimization analysis
- Multi-contract DeFi protocol auditing

**Contact**: fboiero@frvm.utn.edu.ar with:
- Your interests and background
- Proposed topic (or ask for suggestions)
- Expected timeline

---

## 📜 License and Attribution

### Code Contributions

By submitting a PR, you agree:
1. Your contribution is licensed under **GPL-3.0**
2. You have rights to submit the code (original work or compatible license)
3. Your contribution may be used in academic publications citing MIESC

### Research Contributions

For datasets and research studies:
- Datasets: Must be CC BY 4.0 or CC0
- Research studies: Authors retain copyright, grant MIESC permission to link/cite

### Attribution

**Contributors**: All accepted PR authors are listed in `CONTRIBUTORS.md`

**Co-authorship**: Significant research contributions (>100 hours, novel methods) may qualify for co-authorship on academic papers. Discuss with maintainer.

---

## 📞 Contact

**Maintainer**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Institution**: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
**Affiliation**: Professor and Researcher at UTN-FRVM (Systems Engineering)

**Response Time**:
- Bug reports: 1-2 days
- Feature requests: 3-5 days
- Research proposals: 5-7 days

---

**Thank you for contributing to MIESC! Together, we're building a safer smart contract ecosystem.**
