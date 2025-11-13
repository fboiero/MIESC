"""
Documentation Analyzer - Layer 7 (Audit Readiness)

Analyzes documentation quality per OpenZeppelin Audit Readiness Guide.

Requirements:
- NatSpec coverage on all public/external functions
- Comprehensive README.md
- Architecture documentation
- Security considerations documented

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL v3
"""
import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class DocumentationAnalyzer:
    """
    Analyzes code documentation quality

    Checks:
    - NatSpec coverage (contracts, functions, events)
    - README.md presence and quality
    - Required documentation sections
    """

    def __init__(self):
        """Initialize DocumentationAnalyzer"""
        self.required_natspec_tags = {
            'contract': ['title', 'author', 'notice'],
            'function': ['notice', 'param', 'return'],
            'event': ['notice']
        }

        self.required_readme_sections = [
            'overview',
            'installation',
            'usage',
            'architecture',
            'security',
            'testing'
        ]

    def _validate_natspec_tags(self, natspec: Dict[str, Any], item_type: str,
                               item_name: str, params_count: int = 0,
                               has_return: bool = False) -> Dict[str, Any]:
        """
        Validate specific NatSpec tags for an item

        Args:
            natspec: NatSpec dictionary from Slither
            item_type: 'contract', 'function', or 'event'
            item_name: Name of the item for reporting
            params_count: Number of parameters (for functions)
            has_return: Whether function has return value

        Returns:
            {
                'is_complete': bool,
                'missing_tags': List[str],
                'quality_score': float (0-1)
            }
        """
        if not natspec:
            required_tags = self.required_natspec_tags.get(item_type, [])
            return {
                'is_complete': False,
                'missing_tags': required_tags,
                'quality_score': 0.0
            }

        missing_tags = []
        tags_found = 0
        total_required = 0

        if item_type == 'contract':
            # Contract should have @title, @author, @notice
            required = ['title', 'author', 'notice']
            total_required = len(required)

            for tag in required:
                if tag in natspec and natspec[tag]:
                    tags_found += 1
                else:
                    missing_tags.append(f"@{tag}")

        elif item_type == 'function':
            # Function should have @notice, @param (for each param), @return
            if 'notice' not in natspec or not natspec['notice']:
                missing_tags.append('@notice')
            else:
                tags_found += 1
            total_required += 1

            # Check @param tags
            if params_count > 0:
                params_doc = natspec.get('params', {})
                if len(params_doc) >= params_count:
                    tags_found += 1
                else:
                    missing_tags.append(f"@param (has {len(params_doc)}/{params_count})")
                total_required += 1

            # Check @return tag
            if has_return:
                if 'return' in natspec and natspec['return']:
                    tags_found += 1
                else:
                    missing_tags.append('@return')
                total_required += 1

        elif item_type == 'event':
            # Event should have @notice
            if 'notice' in natspec and natspec['notice']:
                tags_found += 1
            else:
                missing_tags.append('@notice')
            total_required = 1

        quality_score = tags_found / total_required if total_required > 0 else 0.0
        is_complete = len(missing_tags) == 0

        return {
            'is_complete': is_complete,
            'missing_tags': missing_tags,
            'quality_score': quality_score
        }

    def analyze_natspec_coverage(self, contract_path: str) -> Dict[str, Any]:
        """
        Calculate NatSpec documentation coverage

        OpenZeppelin requires comprehensive NatSpec on:
        - All contracts (@title, @author, @notice)
        - All public/external functions (@notice, @param, @return)
        - All events (@notice)

        Args:
            contract_path: Path to Solidity contract file

        Returns:
            {
                'total_items': int,
                'documented_items': int,
                'coverage_percentage': float,
                'passes_threshold': bool,  # ≥90% per OpenZeppelin
                'missing_items': List[str],
                'contracts_analyzed': int,
                'functions_analyzed': int
            }
        """
        try:
            from slither.slither import Slither

            logger.info(f"Analyzing NatSpec coverage for {contract_path}")
            slither = Slither(contract_path)

            total_items = 0
            documented_items = 0
            fully_documented_items = 0
            missing_items = []
            incomplete_items = []
            contracts_count = 0
            functions_count = 0
            quality_scores = []

            for contract in slither.contracts:
                # Skip interfaces and libraries for now
                if contract.is_interface or contract.is_library:
                    continue

                contracts_count += 1
                total_items += 1

                # Check contract-level NatSpec with detailed validation
                validation = self._validate_natspec_tags(
                    contract.natspec,
                    'contract',
                    contract.name
                )

                quality_scores.append(validation['quality_score'])

                if contract.natspec:
                    documented_items += 1
                    if validation['is_complete']:
                        fully_documented_items += 1
                    else:
                        incomplete_items.append(
                            f"Contract {contract.name}: missing {', '.join(validation['missing_tags'])}"
                        )
                else:
                    missing_items.append(f"Contract {contract.name}")

                # Check functions
                for function in contract.functions:
                    # Only check public and external functions
                    if function.visibility not in ['public', 'external']:
                        continue

                    # Skip constructors and special functions
                    if function.is_constructor or function.is_fallback or function.is_receive:
                        continue

                    functions_count += 1
                    total_items += 1

                    # Count parameters and check for return values
                    params_count = len(function.parameters)
                    has_return = len(function.returns) > 0

                    validation = self._validate_natspec_tags(
                        function.natspec,
                        'function',
                        f"{contract.name}.{function.name}",
                        params_count=params_count,
                        has_return=has_return
                    )

                    quality_scores.append(validation['quality_score'])

                    if function.natspec:
                        documented_items += 1
                        if validation['is_complete']:
                            fully_documented_items += 1
                        else:
                            incomplete_items.append(
                                f"Function {contract.name}.{function.name}: missing {', '.join(validation['missing_tags'])}"
                            )
                    else:
                        missing_items.append(f"Function {contract.name}.{function.name}")

                # Check events
                for event in contract.events:
                    total_items += 1

                    validation = self._validate_natspec_tags(
                        event.natspec,
                        'event',
                        f"{contract.name}.{event.name}"
                    )

                    quality_scores.append(validation['quality_score'])

                    if event.natspec:
                        documented_items += 1
                        if validation['is_complete']:
                            fully_documented_items += 1
                        else:
                            incomplete_items.append(
                                f"Event {contract.name}.{event.name}: missing {', '.join(validation['missing_tags'])}"
                            )
                    else:
                        missing_items.append(f"Event {contract.name}.{event.name}")

            coverage = (documented_items / total_items * 100) if total_items > 0 else 0
            quality_coverage = (fully_documented_items / total_items * 100) if total_items > 0 else 0
            avg_quality_score = sum(quality_scores) / len(quality_scores) if quality_scores else 0.0

            # Pass threshold: ≥90% basic coverage AND ≥80% quality coverage
            passes = coverage >= 90.0 and quality_coverage >= 80.0

            logger.info(f"NatSpec coverage: {coverage:.2f}% ({documented_items}/{total_items})")
            logger.info(f"Quality coverage: {quality_coverage:.2f}% ({fully_documented_items}/{total_items})")
            logger.info(f"Average quality score: {avg_quality_score:.2f}")

            return {
                'total_items': total_items,
                'documented_items': documented_items,
                'fully_documented_items': fully_documented_items,
                'coverage_percentage': round(coverage, 2),
                'quality_coverage_percentage': round(quality_coverage, 2),
                'average_quality_score': round(avg_quality_score, 2),
                'passes_threshold': passes,
                'missing_items': missing_items,
                'incomplete_items': incomplete_items,
                'contracts_analyzed': contracts_count,
                'functions_analyzed': functions_count
            }

        except ImportError:
            logger.error("Slither not available for NatSpec analysis")
            return {
                'error': 'Slither not installed',
                'passes_threshold': False
            }
        except Exception as e:
            logger.error(f"Error analyzing NatSpec: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_readme_quality(self, project_root: str) -> Dict[str, Any]:
        """
        Evaluate README.md quality

        OpenZeppelin requirements:
        - Overview of the project
        - Installation instructions
        - Usage examples
        - Architecture description
        - Security considerations
        - Testing instructions

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'exists': bool,
                'word_count': int,
                'sections_present': List[str],
                'sections_missing': List[str],
                'quality_score': float (0-1),
                'passes_threshold': bool,  # ≥0.8
                'recommendation': str
            }
        """
        try:
            readme_path = Path(project_root) / "README.md"

            if not readme_path.exists():
                logger.warning(f"README.md not found in {project_root}")
                return {
                    'exists': False,
                    'quality_score': 0.0,
                    'passes_threshold': False,
                    'recommendation': 'Create comprehensive README.md with project overview, installation, usage, architecture, security considerations, and testing instructions'
                }

            content = readme_path.read_text()
            word_count = len(content.split())

            # Check for required sections
            content_lower = content.lower()
            sections_found = []
            sections_missing = []

            for section in self.required_readme_sections:
                if section in content_lower:
                    sections_found.append(section)
                else:
                    sections_missing.append(section)

            # Calculate quality score
            quality_score = len(sections_found) / len(self.required_readme_sections)
            passes = quality_score >= 0.8

            # Generate recommendation
            recommendation = "README meets audit readiness standards"
            if sections_missing:
                recommendation = f"Add missing sections: {', '.join(sections_missing)}"

            logger.info(f"README quality: {quality_score:.2f} ({len(sections_found)}/{len(self.required_readme_sections)} sections)")

            return {
                'exists': True,
                'word_count': word_count,
                'sections_present': sections_found,
                'sections_missing': sections_missing,
                'quality_score': round(quality_score, 2),
                'passes_threshold': passes,
                'recommendation': recommendation
            }

        except Exception as e:
            logger.error(f"Error analyzing README: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_deployment_docs(self, project_root: str) -> Dict[str, Any]:
        """
        Check for deployment process documentation

        OpenZeppelin requirement: Deployment process should be documented

        Looks for:
        - DEPLOYMENT.md file
        - Deploy scripts (deploy/, scripts/deploy/)
        - Deployment instructions in README

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'deployment_doc_exists': bool,
                'deploy_scripts_exist': bool,
                'deployment_in_readme': bool,
                'score': float (0-1),
                'passes_threshold': bool
            }
        """
        try:
            project_path = Path(project_root)

            # Check for DEPLOYMENT.md or similar
            deployment_docs = [
                'DEPLOYMENT.md',
                'DEPLOY.md',
                'docs/DEPLOYMENT.md',
                'docs/deployment.md'
            ]

            deployment_doc_exists = any(
                (project_path / doc).exists()
                for doc in deployment_docs
            )

            # Check for deployment scripts
            deploy_dirs = [
                project_path / 'deploy',
                project_path / 'scripts' / 'deploy',
                project_path / 'deployment'
            ]

            deploy_scripts_exist = any(
                d.exists() and any(d.iterdir())
                for d in deploy_dirs if d.parent.exists()
            )

            # Check README for deployment section
            readme_path = project_path / 'README.md'
            deployment_in_readme = False

            if readme_path.exists():
                content = readme_path.read_text().lower()
                deployment_in_readme = 'deploy' in content

            # Calculate score
            checks = [deployment_doc_exists, deploy_scripts_exist, deployment_in_readme]
            score = sum(checks) / len(checks)
            passes = score >= 0.67  # At least 2 out of 3

            logger.info(f"Deployment documentation score: {score:.2f}")

            return {
                'deployment_doc_exists': deployment_doc_exists,
                'deploy_scripts_exist': deploy_scripts_exist,
                'deployment_in_readme': deployment_in_readme,
                'score': round(score, 2),
                'passes_threshold': passes
            }

        except Exception as e:
            logger.error(f"Error analyzing deployment docs: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_architecture_docs(self, project_root: str) -> Dict[str, Any]:
        """
        Check for architecture documentation and diagrams

        OpenZeppelin requirement: Architecture should be documented

        Looks for:
        - Architecture diagrams (.png, .svg, .mermaid)
        - Architecture documentation files
        - Architecture section in README

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'architecture_diagrams_found': int,
                'architecture_doc_exists': bool,
                'architecture_in_readme': bool,
                'score': float (0-1),
                'passes_threshold': bool
            }
        """
        try:
            project_path = Path(project_root)

            # Look for architecture diagrams
            diagram_patterns = ['*architecture*', '*arch*', '*diagram*']
            diagram_extensions = ['.png', '.svg', '.jpg', '.mermaid', '.puml']

            diagrams = []
            for pattern in diagram_patterns:
                for ext in diagram_extensions:
                    diagrams.extend(project_path.rglob(f"{pattern}{ext}"))

            architecture_diagrams_found = len(diagrams)

            # Check for architecture documentation
            arch_docs = [
                'ARCHITECTURE.md',
                'docs/ARCHITECTURE.md',
                'docs/architecture.md',
                'docs/design.md'
            ]

            architecture_doc_exists = any(
                (project_path / doc).exists()
                for doc in arch_docs
            )

            # Check README for architecture section
            readme_path = project_path / 'README.md'
            architecture_in_readme = False

            if readme_path.exists():
                content = readme_path.read_text().lower()
                architecture_in_readme = 'architecture' in content

            # Calculate score
            checks = [
                architecture_diagrams_found > 0,
                architecture_doc_exists,
                architecture_in_readme
            ]
            score = sum(checks) / len(checks)
            passes = score >= 0.67  # At least 2 out of 3

            logger.info(f"Architecture documentation score: {score:.2f}")

            return {
                'architecture_diagrams_found': architecture_diagrams_found,
                'architecture_doc_exists': architecture_doc_exists,
                'architecture_in_readme': architecture_in_readme,
                'score': round(score, 2),
                'passes_threshold': passes
            }

        except Exception as e:
            logger.error(f"Error analyzing architecture docs: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_api_docs(self, project_root: str) -> Dict[str, Any]:
        """
        Check for API documentation

        Looks for:
        - API documentation directory (docs/api/)
        - Interface documentation
        - Function documentation

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'api_docs_exist': bool,
                'interface_count': int,
                'score': float (0-1),
                'passes_threshold': bool
            }
        """
        try:
            project_path = Path(project_root)

            # Check for API docs directory
            api_doc_paths = [
                project_path / 'docs' / 'api',
                project_path / 'docs' / 'API',
                project_path / 'api-docs'
            ]

            api_docs_exist = any(
                d.exists() and any(d.rglob('*.md'))
                for d in api_doc_paths
            )

            # Count Solidity interfaces (these should be documented)
            interface_files = list(project_path.rglob('I*.sol'))
            interface_count = len(interface_files)

            # Calculate score
            score = 1.0 if api_docs_exist else (0.5 if interface_count > 0 else 0.0)
            passes = score >= 0.5

            logger.info(f"API documentation score: {score:.2f}")

            return {
                'api_docs_exist': api_docs_exist,
                'interface_count': interface_count,
                'score': round(score, 2),
                'passes_threshold': passes
            }

        except Exception as e:
            logger.error(f"Error analyzing API docs: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_audit_history(self, project_root: str) -> Dict[str, Any]:
        """
        Check for audit history documentation

        Looks for:
        - Audit reports (audits/, security-audits/)
        - SECURITY.md with audit history
        - Known issues documentation

        Args:
            project_root: Path to project root directory

        Returns:
            {
                'audit_reports_found': int,
                'security_doc_exists': bool,
                'known_issues_documented': bool,
                'score': float (0-1),
                'passes_threshold': bool
            }
        """
        try:
            project_path = Path(project_root)

            # Look for audit reports
            audit_dirs = [
                project_path / 'audits',
                project_path / 'audit-reports',
                project_path / 'security-audits',
                project_path / 'docs' / 'audits'
            ]

            audit_reports = []
            for audit_dir in audit_dirs:
                if audit_dir.exists():
                    audit_reports.extend(audit_dir.rglob('*.pdf'))
                    audit_reports.extend(audit_dir.rglob('*.md'))

            audit_reports_found = len(audit_reports)

            # Check for SECURITY.md
            security_doc_exists = (project_path / 'SECURITY.md').exists()

            # Check for known issues documentation
            known_issues_files = [
                'KNOWN_ISSUES.md',
                'docs/KNOWN_ISSUES.md',
                'ISSUES.md'
            ]

            known_issues_documented = any(
                (project_path / f).exists()
                for f in known_issues_files
            )

            # Calculate score
            checks = [
                audit_reports_found > 0,
                security_doc_exists,
                known_issues_documented
            ]
            score = sum(checks) / len(checks)
            passes = score >= 0.33  # At least 1 out of 3 (optional for new projects)

            logger.info(f"Audit history score: {score:.2f}")

            return {
                'audit_reports_found': audit_reports_found,
                'security_doc_exists': security_doc_exists,
                'known_issues_documented': known_issues_documented,
                'score': round(score, 2),
                'passes_threshold': passes
            }

        except Exception as e:
            logger.error(f"Error analyzing audit history: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_all(self, contract_path: str, project_root: str = None) -> Dict[str, Any]:
        """
        Complete documentation analysis

        Now includes:
        - NatSpec coverage
        - README quality
        - Deployment documentation
        - Architecture documentation
        - API documentation
        - Audit history

        Args:
            contract_path: Path to Solidity contract file
            project_root: Path to project root (defaults to contract directory)

        Returns:
            {
                'natspec': {...},
                'readme': {...},
                'deployment': {...},
                'architecture': {...},
                'api': {...},
                'audit_history': {...},
                'overall_score': float (0-1),
                'passes_audit_readiness': bool
            }
        """
        if project_root is None:
            project_root = str(Path(contract_path).parent)

        natspec_result = self.analyze_natspec_coverage(contract_path)
        readme_result = self.analyze_readme_quality(project_root)
        deployment_result = self.analyze_deployment_docs(project_root)
        architecture_result = self.analyze_architecture_docs(project_root)
        api_result = self.analyze_api_docs(project_root)
        audit_result = self.analyze_audit_history(project_root)

        # Overall score with weighted components
        # NatSpec: 30%, README: 25%, Deployment: 15%, Architecture: 15%, API: 10%, Audit: 5%
        natspec_score = natspec_result.get('coverage_percentage', 0) / 100
        readme_score = readme_result.get('quality_score', 0)
        deployment_score = deployment_result.get('score', 0)
        architecture_score = architecture_result.get('score', 0)
        api_score = api_result.get('score', 0)
        audit_score = audit_result.get('score', 0)

        overall_score = (
            natspec_score * 0.30 +
            readme_score * 0.25 +
            deployment_score * 0.15 +
            architecture_score * 0.15 +
            api_score * 0.10 +
            audit_score * 0.05
        )

        # Must pass NatSpec and README at minimum
        passes = (
            natspec_result.get('passes_threshold', False) and
            readme_result.get('passes_threshold', False)
        )

        logger.info(f"Documentation overall score: {overall_score:.2f}")

        return {
            'natspec': natspec_result,
            'readme': readme_result,
            'deployment': deployment_result,
            'architecture': architecture_result,
            'api': api_result,
            'audit_history': audit_result,
            'overall_score': round(overall_score, 2),
            'passes_audit_readiness': passes
        }
