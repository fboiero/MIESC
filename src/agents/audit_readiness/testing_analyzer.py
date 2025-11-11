"""
Testing Analyzer - Layer 7 (Audit Readiness)

Analyzes test coverage and quality per OpenZeppelin Audit Readiness Guide.

Requirements:
- Code coverage ≥ 90% (EXPLICIT OpenZeppelin requirement)
- Property-based tests (Echidna/Medusa)
- Integration tests

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL v3
"""
import logging
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class TestingAnalyzer:
    """
    Analyzes test coverage and quality

    Checks:
    - Line and branch coverage (≥90% per OpenZeppelin)
    - Property-based tests presence
    - Integration test coverage
    """

    def __init__(self):
        """Initialize TestingAnalyzer"""
        self.coverage_threshold = 90.0  # OpenZeppelin explicit requirement

    def analyze_test_coverage(self, project_root: str) -> Dict[str, Any]:
        """
        Execute pytest-cov to analyze test coverage

        OpenZeppelin requirement: ≥90% code coverage

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'line_coverage': float,
                'branch_coverage': float,
                'missing_lines': int,
                'total_lines': int,
                'passes_threshold': bool,  # ≥90%
                'coverage_file': str
            }
        """
        try:
            logger.info(f"Analyzing test coverage in {project_root}")

            # Run pytest with coverage
            result = subprocess.run(
                [
                    'python', '-m', 'pytest',
                    '--cov=miesc',  # Coverage for miesc package
                    '--cov-report=json',
                    '--cov-report=term-missing',
                    '-v'
                ],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            # Parse JSON coverage report
            coverage_file = Path(project_root) / 'coverage.json'

            if not coverage_file.exists():
                logger.warning("Coverage report not generated")
                return {
                    'error': 'Coverage report not found',
                    'passes_threshold': False,
                    'recommendation': 'Ensure pytest-cov is installed and tests exist'
                }

            with open(coverage_file) as f:
                cov_data = json.load(f)

            totals = cov_data.get('totals', {})
            line_coverage = totals.get('percent_covered', 0)
            branch_coverage = totals.get('percent_covered_branches', 0)
            missing_lines = totals.get('missing_lines', 0)
            total_lines = totals.get('num_statements', 0)

            passes = line_coverage >= self.coverage_threshold

            logger.info(f"Line coverage: {line_coverage:.2f}%")
            logger.info(f"Branch coverage: {branch_coverage:.2f}%")

            return {
                'line_coverage': round(line_coverage, 2),
                'branch_coverage': round(branch_coverage, 2),
                'missing_lines': missing_lines,
                'total_lines': total_lines,
                'passes_threshold': passes,
                'threshold': self.coverage_threshold,
                'coverage_file': str(coverage_file)
            }

        except subprocess.TimeoutExpired:
            logger.error("Test coverage analysis timed out")
            return {
                'error': 'Coverage analysis timeout',
                'passes_threshold': False
            }
        except FileNotFoundError:
            logger.error("pytest not found. Install with: pip install pytest pytest-cov")
            return {
                'error': 'pytest not installed',
                'passes_threshold': False,
                'recommendation': 'Install pytest and pytest-cov'
            }
        except Exception as e:
            logger.error(f"Error analyzing test coverage: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_property_tests(self, project_root: str) -> Dict[str, Any]:
        """
        Verify presence of property-based tests (Echidna/Medusa)

        Property-based tests are recommended by OpenZeppelin for
        complex invariant checking.

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'echidna_present': bool,
                'medusa_present': bool,
                'property_tests_found': int,
                'passes_threshold': bool,
                'tools_available': List[str]
            }
        """
        try:
            logger.info("Checking for property-based tests")

            project_path = Path(project_root)

            # Check for Echidna config/tests
            echidna_config = project_path / 'echidna.yaml'
            echidna_present = echidna_config.exists()

            # Check for Medusa config/tests
            medusa_config = project_path / 'medusa.json'
            medusa_present = medusa_config.exists()

            # Count property test files
            property_tests = []

            # Look for test files with property/invariant patterns
            test_dirs = [
                project_path / 'test',
                project_path / 'tests',
                project_path / 'contracts' / 'test'
            ]

            for test_dir in test_dirs:
                if test_dir.exists():
                    # Find Solidity test files
                    for test_file in test_dir.rglob('*.sol'):
                        content = test_file.read_text()
                        # Look for property test patterns
                        if any(pattern in content for pattern in [
                            'echidna_',
                            'invariant_',
                            'property_'
                        ]):
                            property_tests.append(str(test_file))

            tools_available = []
            if echidna_present:
                tools_available.append('echidna')
            if medusa_present:
                tools_available.append('medusa')

            # Passes if either tool is configured OR property tests exist
            passes = echidna_present or medusa_present or len(property_tests) > 0

            logger.info(f"Property tests found: {len(property_tests)}")
            logger.info(f"Tools configured: {', '.join(tools_available) if tools_available else 'none'}")

            return {
                'echidna_present': echidna_present,
                'medusa_present': medusa_present,
                'property_tests_found': len(property_tests),
                'property_test_files': property_tests[:10],  # Limit to 10
                'passes_threshold': passes,
                'tools_available': tools_available,
                'recommendation': 'Add property-based tests with Echidna or Medusa' if not passes else 'Property testing configured'
            }

        except Exception as e:
            logger.error(f"Error analyzing property tests: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_integration_tests(self, project_root: str) -> Dict[str, Any]:
        """
        Check for integration tests

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'integration_tests_found': int,
                'test_directories': List[str],
                'passes_threshold': bool
            }
        """
        try:
            logger.info("Checking for integration tests")

            project_path = Path(project_root)
            integration_tests = []

            # Look for integration test directories
            integration_dirs = [
                project_path / 'tests' / 'integration',
                project_path / 'test' / 'integration',
                project_path / 'tests' / 'e2e',
                project_path / 'test' / 'e2e'
            ]

            for test_dir in integration_dirs:
                if test_dir.exists():
                    # Count Python test files
                    py_tests = list(test_dir.rglob('test_*.py'))
                    integration_tests.extend(py_tests)

            passes = len(integration_tests) > 0

            logger.info(f"Integration tests found: {len(integration_tests)}")

            return {
                'integration_tests_found': len(integration_tests),
                'test_files': [str(t) for t in integration_tests[:10]],  # Limit to 10
                'passes_threshold': passes,
                'recommendation': 'Add integration tests' if not passes else 'Integration tests present'
            }

        except Exception as e:
            logger.error(f"Error analyzing integration tests: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_all(self, project_root: str) -> Dict[str, Any]:
        """
        Complete testing analysis

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'coverage': {...},
                'property_tests': {...},
                'integration_tests': {...},
                'overall_score': float (0-1),
                'passes_audit_readiness': bool
            }
        """
        coverage_result = self.analyze_test_coverage(project_root)
        property_result = self.analyze_property_tests(project_root)
        integration_result = self.analyze_integration_tests(project_root)

        # Overall score: 60% coverage + 20% property + 20% integration
        coverage_score = coverage_result.get('line_coverage', 0) / 100
        property_score = 1.0 if property_result.get('passes_threshold', False) else 0.0
        integration_score = 1.0 if integration_result.get('passes_threshold', False) else 0.0

        overall_score = (
            coverage_score * 0.6 +
            property_score * 0.2 +
            integration_score * 0.2
        )

        # Must pass coverage threshold (≥90%) for audit readiness
        passes = coverage_result.get('passes_threshold', False)

        logger.info(f"Testing overall score: {overall_score:.2f}")

        return {
            'coverage': coverage_result,
            'property_tests': property_result,
            'integration_tests': integration_result,
            'overall_score': round(overall_score, 2),
            'passes_audit_readiness': passes
        }
