"""
MIESC Integration Tests - Multichain Analysis
End-to-end tests for chain detection, adapter selection, analysis, and reporting.
"""

import pytest

from src.core.chain_abstraction import (
    ChainType,
    ContractLanguage,
    ChainRegistry,
    AbstractChainAnalyzer,
    AbstractContract,
    VulnerabilityMapping,
    VULNERABILITY_MAPPINGS,
    get_vulnerability_mapping,
    normalize_vulnerability_type,
    SecurityProperty,
    Location,
)


# ============================================================================
# TestMultichainPipeline - Chain detection -> analysis -> report
# ============================================================================


@pytest.mark.integration
class TestMultichainPipeline:
    """End-to-end multichain analysis tests."""

    def test_solidity_contract_detects_evm_chain(self):
        """A .sol file should detect EVM chain type."""
        # Create a fresh registry to avoid singleton interference
        registry = ChainRegistry.__new__(ChainRegistry)
        registry._analyzers = {}

        # Register a mock EVM analyzer
        class MockEVMAnalyzer(AbstractChainAnalyzer):
            @property
            def name(self):
                return "MockEVM"

            @property
            def version(self):
                return "1.0.0"

            @property
            def supported_extensions(self):
                return [".sol"]

            def parse(self, source_path):
                return AbstractContract(
                    name="Test",
                    chain_type=ChainType.ETHEREUM,
                    language=ContractLanguage.SOLIDITY,
                    source_path=str(source_path),
                )

            def detect_vulnerabilities(self, contract, properties=None):
                return []

        analyzer = MockEVMAnalyzer(ChainType.ETHEREUM, ContractLanguage.SOLIDITY)
        registry.register(analyzer)

        # Should find analyzer for .sol files
        found = registry.get_for_file("contract.sol")
        assert found is not None
        assert found.chain_type == ChainType.ETHEREUM
        assert found.language == ContractLanguage.SOLIDITY

    def test_cardano_aiken_analysis(self):
        """Aiken contract should map to Cardano adapter and produce findings."""
        class MockCardanoAnalyzer(AbstractChainAnalyzer):
            @property
            def name(self):
                return "MockCardano"

            @property
            def version(self):
                return "1.0.0"

            @property
            def supported_extensions(self):
                return [".ak"]

            def parse(self, source_path):
                return AbstractContract(
                    name="CardanoValidator",
                    chain_type=ChainType.CARDANO,
                    language=ContractLanguage.AIKEN,
                    source_path=str(source_path),
                )

            def detect_vulnerabilities(self, contract, properties=None):
                return [
                    self.normalize_finding(
                        vuln_type="missing-datum-check",
                        severity="High",
                        message="Missing datum validation in validator",
                        location=Location(file="validator.ak", line=10),
                    )
                ]

        analyzer = MockCardanoAnalyzer(ChainType.CARDANO, ContractLanguage.AIKEN)
        result = analyzer.analyze("validator.ak")

        assert result['status'] == 'success'
        assert result['chain_type'] == 'cardano'
        assert result['language'] == 'aiken'
        assert len(result['findings']) >= 1
        # missing-datum-check maps to access_control in VULNERABILITY_MAPPINGS
        assert result['findings'][0]['type'] == 'access_control'

    def test_solana_anchor_analysis(self):
        """Anchor program should map to Solana adapter and produce findings."""
        class MockSolanaAnalyzer(AbstractChainAnalyzer):
            @property
            def name(self):
                return "MockSolana"

            @property
            def version(self):
                return "1.0.0"

            @property
            def supported_extensions(self):
                return [".rs"]

            def parse(self, source_path):
                return AbstractContract(
                    name="AnchorProgram",
                    chain_type=ChainType.SOLANA,
                    language=ContractLanguage.RUST,
                    source_path=str(source_path),
                )

            def detect_vulnerabilities(self, contract, properties=None):
                return [
                    self.normalize_finding(
                        vuln_type="missing-signer-check",
                        severity="Critical",
                        message="Missing signer check in instruction handler",
                        location=Location(file="program.rs", line=25),
                    )
                ]

        analyzer = MockSolanaAnalyzer(ChainType.SOLANA, ContractLanguage.RUST)
        result = analyzer.analyze("program.rs")

        assert result['status'] == 'success'
        assert result['chain_type'] == 'solana'
        assert result['language'] == 'rust'
        assert len(result['findings']) >= 1

        finding = result['findings'][0]
        assert finding['type'] == 'access_control'
        assert finding['severity'] == 'Critical'

    def test_chain_registry_returns_correct_analyzer(self):
        """Registry should map chain type to correct analyzer."""
        registry = ChainRegistry.__new__(ChainRegistry)
        registry._analyzers = {}

        class MockAnalyzer(AbstractChainAnalyzer):
            @property
            def name(self):
                return f"Mock{self.chain_type.value}"

            @property
            def version(self):
                return "1.0.0"

            @property
            def supported_extensions(self):
                ext_map = {
                    ChainType.ETHEREUM: [".sol"],
                    ChainType.SOLANA: [".rs"],
                    ChainType.CARDANO: [".ak"],
                }
                return ext_map.get(self.chain_type, [])

            def parse(self, source_path):
                return AbstractContract(
                    name="Test",
                    chain_type=self.chain_type,
                    language=self.language,
                    source_path=str(source_path),
                )

            def detect_vulnerabilities(self, contract, properties=None):
                return []

        # Register multiple analyzers
        eth = MockAnalyzer(ChainType.ETHEREUM, ContractLanguage.SOLIDITY)
        sol = MockAnalyzer(ChainType.SOLANA, ContractLanguage.RUST)
        ada = MockAnalyzer(ChainType.CARDANO, ContractLanguage.AIKEN)

        registry.register(eth)
        registry.register(sol)
        registry.register(ada)

        assert registry.get(ChainType.ETHEREUM) is eth
        assert registry.get(ChainType.SOLANA) is sol
        assert registry.get(ChainType.CARDANO) is ada

        # List should contain all registered
        chains = registry.list_chains()
        assert ChainType.ETHEREUM in chains
        assert ChainType.SOLANA in chains
        assert ChainType.CARDANO in chains

    def test_multichain_findings_normalized(self):
        """Findings from different chains should share a common format."""
        class MockAnalyzer(AbstractChainAnalyzer):
            @property
            def name(self):
                return "Mock"

            @property
            def version(self):
                return "1.0.0"

            @property
            def supported_extensions(self):
                return [".sol"]

            def parse(self, source_path):
                return AbstractContract(
                    name="Test",
                    chain_type=self.chain_type,
                    language=self.language,
                    source_path=str(source_path),
                )

            def detect_vulnerabilities(self, contract, properties=None):
                return []

        # EVM finding
        evm_analyzer = MockAnalyzer(ChainType.ETHEREUM, ContractLanguage.SOLIDITY)
        evm_finding = evm_analyzer.normalize_finding(
            vuln_type="reentrancy-eth",
            severity="Critical",
            message="Reentrancy detected",
            location=Location(file="contract.sol", line=10),
        )

        # Solana finding
        sol_analyzer = MockAnalyzer(ChainType.SOLANA, ContractLanguage.RUST)
        sol_finding = sol_analyzer.normalize_finding(
            vuln_type="missing-signer-check",
            severity="High",
            message="Missing signer check",
            location=Location(file="program.rs", line=25),
        )

        # Both should share the same schema keys
        common_keys = {'id', 'type', 'severity', 'location', 'message', 'chain_type', 'language'}
        assert common_keys.issubset(evm_finding.keys())
        assert common_keys.issubset(sol_finding.keys())

        # Location should have consistent sub-keys
        assert 'file' in evm_finding['location']
        assert 'line' in evm_finding['location']
        assert 'file' in sol_finding['location']
        assert 'line' in sol_finding['location']

    def test_vulnerability_mapping_cross_chain(self):
        """Same vulnerability type should map correctly across chains."""
        # Test access_control mapping
        ac_mapping = get_vulnerability_mapping('access_control')
        assert ac_mapping is not None
        assert ac_mapping.canonical_name == 'access_control'
        assert len(ac_mapping.solidity_names) > 0
        assert len(ac_mapping.solana_names) > 0
        assert len(ac_mapping.cardano_names) > 0

        # Test reentrancy mapping
        re_mapping = get_vulnerability_mapping('reentrancy')
        assert re_mapping is not None
        assert re_mapping.canonical_name == 'reentrancy'
        assert 'reentrancy-eth' in re_mapping.solidity_names
        assert 'cpi-reentrancy' in re_mapping.solana_names
        assert 'double-satisfaction' in re_mapping.cardano_names

        # Test normalization across chains
        evm_normalized = normalize_vulnerability_type(
            'reentrancy-eth', ChainType.ETHEREUM
        )
        solana_normalized = normalize_vulnerability_type(
            'cpi-reentrancy', ChainType.SOLANA
        )
        assert evm_normalized == solana_normalized == 'reentrancy'

        # Arithmetic mapping
        arith_mapping = get_vulnerability_mapping('arithmetic')
        assert arith_mapping is not None
        assert arith_mapping.security_property == SecurityProperty.ARITHMETIC


# ============================================================================
# TestChainTypeHelpers
# ============================================================================


@pytest.mark.integration
class TestChainTypeHelpers:
    """Tests for ChainType helper methods."""

    def test_evm_chains_list(self):
        """EVM chains list should include standard EVM chains."""
        evm = ChainType.evm_chains()
        assert ChainType.ETHEREUM in evm
        assert ChainType.POLYGON in evm
        assert ChainType.ARBITRUM in evm
        assert ChainType.SOLANA not in evm

    def test_move_chains_list(self):
        """Move chains should include Sui and Aptos."""
        move = ChainType.move_chains()
        assert ChainType.SUI in move
        assert ChainType.APTOS in move
        assert ChainType.ETHEREUM not in move

    def test_all_vulnerability_mappings_have_required_fields(self):
        """All vulnerability mappings should have canonical name and security property."""
        for key, mapping in VULNERABILITY_MAPPINGS.items():
            assert mapping.canonical_name == key
            assert isinstance(mapping.description, str)
            assert len(mapping.description) > 0
            assert mapping.severity_default in [
                'Critical', 'High', 'Medium', 'Low', 'Informational'
            ]
            assert isinstance(mapping.security_property, SecurityProperty)

    def test_abstract_contract_to_dict(self):
        """AbstractContract.to_dict should produce complete dictionary."""
        contract = AbstractContract(
            name="TestContract",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="test.sol",
            source_code="pragma solidity ^0.8.0; contract Test {}",
        )

        d = contract.to_dict()
        assert d['name'] == 'TestContract'
        assert d['chain_type'] == 'ethereum'
        assert d['language'] == 'solidity'
        assert 'content_hash' in d
        assert 'functions' in d
        assert 'variables' in d


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
