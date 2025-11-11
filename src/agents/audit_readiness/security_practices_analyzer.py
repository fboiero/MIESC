"""
Security Practices Analyzer - Layer 7 (Audit Readiness)

Detects security best practices implementation.

Patterns:
- Access control (Ownable, AccessControl)
- Upgradeability (UUPS, Transparent Proxy)
- Emergency controls (Pausable)
- Reentrancy protection (ReentrancyGuard)
- Safe arithmetic (SafeMath, Solidity 0.8+)
- No hardcoded addresses

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL v3
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class SecurityPracticesAnalyzer:
    """
    Analyzes security practices implementation

    Checks for OpenZeppelin recommended patterns:
    - Access control modifiers
    - Upgrade mechanisms
    - Emergency pause capability
    - Reentrancy guards
    - Safe arithmetic operations
    - No hardcoded sensitive values
    """

    def __init__(self):
        """Initialize SecurityPracticesAnalyzer"""
        self.security_patterns = {
            'access_control': [
                'Ownable', 'Ownable2Step',
                'AccessControl', 'AccessControlEnumerable',
                'AccessControlDefaultAdminRules',
                'Roles'  # Custom roles pattern
            ],
            'upgradeable': [
                'UUPSUpgradeable',
                'TransparentUpgradeableProxy',
                'Initializable',
                'Initializable',
                'ERC1967Proxy',
                'BeaconProxy'
            ],
            'pausable': [
                'Pausable',
                'PausableUpgradeable'
            ],
            'reentrancy_guard': [
                'ReentrancyGuard',
                'ReentrancyGuardUpgradeable',
                'nonReentrant'
            ],
            'safe_math': [
                'SafeMath',
                'Math',  # OZ Math library
                'SignedMath'
            ],
            'pull_over_push': [
                'PullPayment'  # OZ pull payment pattern
            ],
            'timelock': [
                'TimelockController',
                'Timelock'
            ],
            'multisig': [
                'Multisig',
                'MultiSigWallet',
                'Gnosis'
            ]
        }

        # Event patterns for critical operations
        self.critical_event_patterns = [
            'Transfer',
            'Approval',
            'OwnershipTransferred',
            'RoleGranted',
            'RoleRevoked',
            'Paused',
            'Unpaused',
            'Upgraded'
        ]

    def analyze_security_practices(self, contract_path: str) -> Dict[str, Any]:
        """
        Verify implementation of security best practices

        OpenZeppelin recommendations:
        - Use access control for privileged functions
        - Implement upgrade mechanisms safely
        - Add emergency pause for critical systems
        - Protect against reentrancy
        - Use safe arithmetic (Solidity 0.8+ or SafeMath)
        - Avoid hardcoded addresses
        - Use pull over push for payments
        - Add timelock for critical operations
        - Use multisig for governance

        Args:
            contract_path: Path to Solidity contract file

        Returns:
            {
                'access_control': bool,
                'upgradeable': bool,
                'pausable': bool,
                'reentrancy_guard': bool,
                'safe_arithmetic': bool,
                'no_hardcoded_addresses': bool,
                'pull_over_push': bool,
                'timelock': bool,
                'multisig': bool,
                'critical_events': bool,
                'security_score': float (0-1),
                'passes_threshold': bool,
                'recommendations': List[str]
            }
        """
        try:
            from slither.slither import Slither

            logger.info(f"Analyzing security practices for {contract_path}")
            slither = Slither(contract_path)

            practices = {
                'access_control': False,
                'upgradeable': False,
                'pausable': False,
                'reentrancy_guard': False,
                'safe_arithmetic': False,
                'no_hardcoded_addresses': True,  # Assume true unless found
                'pull_over_push': False,
                'timelock': False,
                'multisig': False,
                'critical_events': False
            }

            recommendations = []
            contracts_analyzed = 0
            events_found = []

            for contract in slither.contracts:
                # Skip interfaces and libraries
                if contract.is_interface or contract.is_library:
                    continue

                contracts_analyzed += 1

                # Get inherited contracts
                inherited = [c.name for c in contract.inheritance]

                # 1. Access control
                if any(ac in inherited for ac in self.security_patterns['access_control']):
                    practices['access_control'] = True
                else:
                    # Check for custom access control modifiers
                    for modifier in contract.modifiers:
                        if 'only' in modifier.name.lower() or 'authorized' in modifier.name.lower():
                            practices['access_control'] = True
                            break

                # 2. Upgradeability
                if any(up in inherited for up in self.security_patterns['upgradeable']):
                    practices['upgradeable'] = True

                # 3. Pausable
                if any(p in inherited for p in self.security_patterns['pausable']):
                    practices['pausable'] = True

                # 4. Reentrancy guard
                if any(rg in inherited for rg in self.security_patterns['reentrancy_guard']):
                    practices['reentrancy_guard'] = True
                else:
                    # Check for nonReentrant modifier usage
                    for function in contract.functions:
                        if any(mod.name == 'nonReentrant' for mod in function.modifiers):
                            practices['reentrancy_guard'] = True
                            break

                # 5. Safe arithmetic
                # Check Solidity version
                solc_version = contract.compilation_unit.solc_version
                if solc_version.startswith('0.8') or solc_version.startswith('0.9'):
                    practices['safe_arithmetic'] = True
                elif any(sm in inherited for sm in self.security_patterns['safe_math']):
                    practices['safe_arithmetic'] = True

                # 6. Hardcoded addresses check
                for function in contract.functions:
                    source = function.source_mapping.get('content', '')
                    if source:
                        # Look for Ethereum addresses (0x followed by 40 hex chars)
                        import re
                        addresses = re.findall(r'0x[a-fA-F0-9]{40}', source)
                        if addresses:
                            # Filter out common constants
                            for addr in addresses:
                                if addr.lower() not in ['0x0000000000000000000000000000000000000000']:
                                    practices['no_hardcoded_addresses'] = False
                                    break

                # 7. Pull over push pattern
                if any(pop in inherited for pop in self.security_patterns['pull_over_push']):
                    practices['pull_over_push'] = True
                else:
                    # Check for withdraw pattern (pull)
                    for function in contract.functions:
                        if 'withdraw' in function.name.lower() or 'claim' in function.name.lower():
                            practices['pull_over_push'] = True
                            break

                # 8. Timelock
                if any(tl in inherited for tl in self.security_patterns['timelock']):
                    practices['timelock'] = True

                # 9. Multisig
                if any(ms in inherited for ms in self.security_patterns['multisig']):
                    practices['multisig'] = True

                # 10. Critical events emission
                contract_events = [e.name for e in contract.events]
                for event_pattern in self.critical_event_patterns:
                    if event_pattern in contract_events:
                        events_found.append(event_pattern)

                # Consider critical events implemented if at least 2 are found
                if len(events_found) >= 2:
                    practices['critical_events'] = True

            # Generate recommendations
            if not practices['access_control']:
                recommendations.append("Add access control (Ownable or AccessControl)")

            if not practices['reentrancy_guard']:
                recommendations.append("Add reentrancy protection (ReentrancyGuard)")

            if not practices['safe_arithmetic']:
                recommendations.append("Use Solidity 0.8+ or SafeMath for arithmetic")

            if not practices['pausable'] and contracts_analyzed > 0:
                recommendations.append("Consider adding Pausable for emergency stops")

            if not practices['no_hardcoded_addresses']:
                recommendations.append("Remove hardcoded addresses, use constructor parameters")

            if not practices['pull_over_push']:
                recommendations.append("Consider pull over push pattern for payments (PullPayment)")

            if not practices['timelock']:
                recommendations.append("Consider adding TimelockController for critical operations")

            if not practices['multisig']:
                recommendations.append("Consider multisig wallet for privileged operations")

            if not practices['critical_events']:
                recommendations.append("Emit events for critical state changes (Transfer, Approval, etc.)")

            # Calculate security score
            # Core practices (required): 6, Advanced practices (optional): 4
            core_practices = ['access_control', 'reentrancy_guard', 'safe_arithmetic',
                            'no_hardcoded_addresses', 'pausable', 'critical_events']
            advanced_practices = ['upgradeable', 'pull_over_push', 'timelock', 'multisig']

            core_implemented = sum(1 for p in core_practices if practices[p])
            advanced_implemented = sum(1 for p in advanced_practices if practices[p])

            # Core: 70%, Advanced: 30%
            core_score = core_implemented / len(core_practices)
            advanced_score = advanced_implemented / len(advanced_practices)
            security_score = core_score * 0.7 + advanced_score * 0.3

            # Pass threshold: ≥0.7 (all core or most core + some advanced)
            passes = security_score >= 0.7

            total_implemented = sum(1 for v in practices.values() if v)

            logger.info(f"Security practices: {total_implemented}/{len(practices)}")
            logger.info(f"Core: {core_implemented}/{len(core_practices)}, Advanced: {advanced_implemented}/{len(advanced_practices)}")
            logger.info(f"Security score: {security_score:.2f}")

            return {
                **practices,
                'security_score': round(security_score, 2),
                'passes_threshold': passes,
                'threshold': 0.7,
                'implemented_count': total_implemented,
                'total_count': len(practices),
                'core_implemented': core_implemented,
                'core_total': len(core_practices),
                'advanced_implemented': advanced_implemented,
                'advanced_total': len(advanced_practices),
                'events_found': events_found,
                'recommendations': recommendations,
                'contracts_analyzed': contracts_analyzed
            }

        except ImportError:
            logger.error("Slither not available for security practices analysis")
            return {
                'error': 'Slither not installed',
                'passes_threshold': False,
                'recommendation': 'Install Slither for security analysis'
            }
        except Exception as e:
            logger.error(f"Error analyzing security practices: {e}")
            return {
                'error': str(e),
                'passes_threshold': False
            }

    def analyze_scsvs_compliance(self, contract_path: str) -> Dict[str, Any]:
        """
        Check OWASP SCSVS G12 (Audit Readiness) compliance

        SCSVS G12 requirements:
        - G12.1: Code is documented
        - G12.2: Upgradeability considered
        - G12.3: Access controls implemented
        - G12.4: Emergency controls exist

        Args:
            contract_path: Path to Solidity contract file

        Returns:
            {
                'g12_1_documentation': bool,
                'g12_2_upgradeability': bool,
                'g12_3_access_control': bool,
                'g12_4_emergency_controls': bool,
                'scsvs_score': float (0-1),
                'passes_scsvs': bool
            }
        """
        try:
            from slither.slither import Slither

            logger.info("Checking SCSVS G12 compliance")
            slither = Slither(contract_path)

            scsvs_checks = {
                'g12_1_documentation': False,
                'g12_2_upgradeability': False,
                'g12_3_access_control': False,
                'g12_4_emergency_controls': False
            }

            for contract in slither.contracts:
                if contract.is_interface or contract.is_library:
                    continue

                # G12.1: Documentation (NatSpec)
                if contract.natspec:
                    scsvs_checks['g12_1_documentation'] = True

                inherited = [c.name for c in contract.inheritance]

                # G12.2: Upgradeability
                if any(up in inherited for up in self.security_patterns['upgradeable']):
                    scsvs_checks['g12_2_upgradeability'] = True

                # G12.3: Access control
                if any(ac in inherited for ac in self.security_patterns['access_control']):
                    scsvs_checks['g12_3_access_control'] = True

                # G12.4: Emergency controls
                if any(p in inherited for p in self.security_patterns['pausable']):
                    scsvs_checks['g12_4_emergency_controls'] = True

            # Calculate SCSVS score
            scsvs_score = sum(scsvs_checks.values()) / len(scsvs_checks)
            passes = scsvs_score >= 0.75  # 3 out of 4 checks

            logger.info(f"SCSVS G12 score: {scsvs_score:.2f}")

            return {
                **scsvs_checks,
                'scsvs_score': round(scsvs_score, 2),
                'passes_scsvs': passes
            }

        except Exception as e:
            logger.error(f"Error checking SCSVS compliance: {e}")
            return {
                'error': str(e),
                'passes_scsvs': False
            }

    def analyze_all(self, contract_path: str) -> Dict[str, Any]:
        """
        Complete security practices analysis

        Args:
            contract_path: Path to Solidity contract file

        Returns:
            {
                'practices': {...},
                'scsvs': {...},
                'overall_score': float (0-1),
                'passes_audit_readiness': bool
            }
        """
        practices_result = self.analyze_security_practices(contract_path)
        scsvs_result = self.analyze_scsvs_compliance(contract_path)

        # Overall score: 70% practices + 30% SCSVS
        practices_score = practices_result.get('security_score', 0)
        scsvs_score = scsvs_result.get('scsvs_score', 0)

        overall_score = practices_score * 0.7 + scsvs_score * 0.3

        passes = practices_result.get('passes_threshold', False)

        logger.info(f"Security practices overall score: {overall_score:.2f}")

        return {
            'practices': practices_result,
            'scsvs': scsvs_result,
            'overall_score': round(overall_score, 2),
            'passes_audit_readiness': passes
        }
