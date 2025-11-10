"""
Comprehensive Test Suite for All MIESC Adapters
================================================

Tests all 5 tool adapters siguiendo Tool Adapter Protocol.

Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: 2025-01-09
"""

import pytest
import tempfile
import os
from pathlib import Path

from src.core.tool_protocol import (
    ToolStatus, ToolCategory, get_tool_registry
)
from src.adapters import (
    GasAnalyzerAdapter,
    MEVDetectorAdapter,
    VertigoAdapter,
    OyenteAdapter,
    ThreatModelAdapter,
    register_all_adapters
)


# Sample Solidity contract for testing
SAMPLE_CONTRACT = """
pragma solidity ^0.8.0;

contract TestContract {
    uint public counter = 0;  // Zero init
    address owner;

    function increment() public {  // Could be external
        for (uint i = 0; i++; i < 10) {  // Postfix increment
            counter++;
        }
    }

    function unsafeTransfer(address to) public {
        // No access control
        payable(to).transfer(address(this).balance);
    }
}
"""


class TestToolAdapterProtocol:
    """Test que todos los adapters implementan el protocolo correctamente"""

    def test_all_adapters_have_metadata(self):
        """Verify all adapters provide metadata"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            VertigoAdapter(),
            OyenteAdapter(),
            ThreatModelAdapter()
        ]

        for adapter in adapters:
            metadata = adapter.get_metadata()
            assert metadata.name is not None
            assert metadata.version is not None
            assert metadata.category is not None
            assert metadata.is_optional is True  # DPGA requirement

    def test_all_adapters_check_availability(self):
        """Verify all adapters can check availability"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            VertigoAdapter(),
            OyenteAdapter(),
            ThreatModelAdapter()
        ]

        for adapter in adapters:
            status = adapter.is_available()
            assert isinstance(status, ToolStatus)

    def test_all_adapters_can_analyze(self):
        """Verify all adapters have analyze() method"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            ThreatModelAdapter()
        ]

        # Create temp contract file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            contract_path = f.name

        try:
            for adapter in adapters:
                result = adapter.analyze(contract_path)
                assert 'tool' in result
                assert 'status' in result
                assert 'findings' in result
                assert isinstance(result['findings'], list)
        finally:
            os.unlink(contract_path)

    def test_all_adapters_normalize_findings(self):
        """Verify all adapters can normalize findings"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            ThreatModelAdapter()
        ]

        for adapter in adapters:
            # Test with empty data
            normalized = adapter.normalize_findings({})
            assert isinstance(normalized, list)


class TestGasAnalyzerAdapter:
    """Tests específicos para GasAnalyzer"""

    def test_gas_analyzer_is_built_in(self):
        """GasAnalyzer debe estar siempre disponible (built-in)"""
        adapter = GasAnalyzerAdapter()
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_gas_analyzer_detects_patterns(self):
        """Test que detecta patrones de gas"""
        adapter = GasAnalyzerAdapter()

        contract = """
        pragma solidity ^0.8.0;
        contract Test {
            uint public x = 0;  // Zero init
            function test() public {  // Could be external
                for (uint i = 0; i++; i < 10) {}  // Postfix increment
            }
        }
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            assert result['status'] == 'success'
            assert len(result['findings']) > 0
            assert 'total_gas_savings' in result['metadata']
        finally:
            os.unlink(contract_path)

    def test_gas_analyzer_calculates_savings(self):
        """Test que calcula gas savings"""
        adapter = GasAnalyzerAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            total_savings = result['metadata']['total_gas_savings']
            assert isinstance(total_savings, (int, float))
            assert total_savings >= 0
        finally:
            os.unlink(contract_path)


class TestMEVDetectorAdapter:
    """Tests específicos para MEVDetector"""

    def test_mev_detector_is_built_in(self):
        """MEVDetector debe estar siempre disponible"""
        adapter = MEVDetectorAdapter()
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_mev_detector_detects_vulnerabilities(self):
        """Test que detecta vulnerabilidades MEV"""
        adapter = MEVDetectorAdapter()

        contract = """
        pragma solidity ^0.8.0;
        contract DEX {
            function swap(uint amountIn) public {
                // No slippage protection - sandwich attack vector
                uint amountOut = getPrice() * amountIn;
                transfer(msg.sender, amountOut);
            }

            function getPrice() public view returns (uint) {
                return block.timestamp;  // Timestamp dependence
            }

            function transfer(address to, uint amount) internal {}
        }
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            assert result['status'] == 'success'
            assert len(result['findings']) > 0
            assert 'mev_risk_score' in result['metadata']
        finally:
            os.unlink(contract_path)

    def test_mev_risk_score_calculation(self):
        """Test que calcula MEV risk score correctamente"""
        adapter = MEVDetectorAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            risk_score = result['metadata']['mev_risk_score']
            assert isinstance(risk_score, (int, float))
            assert 0 <= risk_score <= 100
        finally:
            os.unlink(contract_path)


class TestThreatModelAdapter:
    """Tests específicos para ThreatModel"""

    def test_threat_model_is_built_in(self):
        """ThreatModel debe estar siempre disponible"""
        adapter = ThreatModelAdapter()
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_threat_model_detects_stride_threats(self):
        """Test que detecta amenazas STRIDE"""
        adapter = ThreatModelAdapter()

        contract = """
        pragma solidity ^0.8.0;
        contract Vulnerable {
            uint public balance;

            function withdraw(uint amount) external {  // No auth - Spoofing
                // No events - Repudiation
                payable(msg.sender).transfer(amount);
            }

            function upgrade(address newImpl) public {  // No auth - Privilege escalation
                // Upgrade without protection
            }
        }
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(contract)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            assert result['status'] == 'success'
            assert len(result['findings']) > 0
            assert 'stride_breakdown' in result['metadata']
            assert 'audit_readiness_score' in result['metadata']
        finally:
            os.unlink(contract_path)

    def test_dread_scoring(self):
        """Test que DREAD scores son válidos"""
        adapter = ThreatModelAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(SAMPLE_CONTRACT)
            contract_path = f.name

        try:
            result = adapter.analyze(contract_path)
            for finding in result['findings']:
                if 'dread_score' in finding:
                    assert 0 <= finding['dread_score'] <= 10
                    assert 'dread_breakdown' in finding
        finally:
            os.unlink(contract_path)


class TestExternalAdapters:
    """Tests para adapters externos (Vertigo, Oyente)"""

    def test_vertigo_adapter_metadata(self):
        """Vertigo adapter tiene metadata correcta"""
        adapter = VertigoAdapter()
        metadata = adapter.get_metadata()
        assert metadata.name == "vertigo"
        assert metadata.category == ToolCategory.DYNAMIC_TESTING
        assert metadata.is_optional is True

    def test_vertigo_availability_check(self):
        """Vertigo check availability funciona"""
        adapter = VertigoAdapter()
        status = adapter.is_available()
        # Puede ser NOT_INSTALLED si vertigo no está instalado
        assert status in [ToolStatus.AVAILABLE, ToolStatus.NOT_INSTALLED]

    def test_oyente_adapter_metadata(self):
        """Oyente adapter tiene metadata correcta"""
        adapter = OyenteAdapter()
        metadata = adapter.get_metadata()
        assert metadata.name == "oyente"
        assert metadata.category == ToolCategory.SYMBOLIC_EXECUTION
        assert metadata.is_optional is True

    def test_oyente_availability_check(self):
        """Oyente check availability funciona"""
        adapter = OyenteAdapter()
        status = adapter.is_available()
        # Puede ser NOT_INSTALLED si Docker/Oyente no está disponible
        assert status in [ToolStatus.AVAILABLE, ToolStatus.NOT_INSTALLED]


class TestAdapterRegistry:
    """Tests para el registro de adapters"""

    def test_register_all_adapters(self):
        """Test que register_all_adapters funciona"""
        report = register_all_adapters()
        assert report['total_adapters'] == 5
        assert report['registered'] == 5
        assert report['failed'] == 0

    def test_all_adapters_are_optional(self):
        """DPGA compliance: todos los adapters deben ser opcionales"""
        report = register_all_adapters()
        for adapter_info in report['adapters']:
            assert adapter_info['optional'] is True

    def test_registry_get_tool(self):
        """Test que se pueden obtener tools del registry"""
        register_all_adapters()
        registry = get_tool_registry()

        gas_adapter = registry.get_tool("gas_analyzer")
        assert gas_adapter is not None
        assert isinstance(gas_adapter, GasAnalyzerAdapter)

    def test_registry_get_available_tools(self):
        """Test que get_available_tools retorna solo disponibles"""
        register_all_adapters()
        registry = get_tool_registry()

        available = registry.get_available_tools()
        assert len(available) >= 3  # Al menos los 3 built-in

        # Verificar que todos están realmente disponibles
        for tool in available:
            assert tool.is_available() == ToolStatus.AVAILABLE

    def test_registry_status_report(self):
        """Test que status report tiene formato correcto"""
        register_all_adapters()
        registry = get_tool_registry()

        report = registry.get_tool_status_report()
        assert 'total_tools' in report
        assert 'available' in report
        assert 'tools' in report
        assert isinstance(report['tools'], list)


class TestDPGACompliance:
    """Tests específicos para verificar cumplimiento DPGA"""

    def test_no_mandatory_tools(self):
        """DPGA: No debe haber herramientas obligatorias"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            VertigoAdapter(),
            OyenteAdapter(),
            ThreatModelAdapter()
        ]

        for adapter in adapters:
            metadata = adapter.get_metadata()
            assert metadata.is_optional is True, f"{metadata.name} is not optional!"

    def test_graceful_degradation(self):
        """DPGA: Sistema debe funcionar incluso si tools externas no están disponibles"""
        # Esto se verifica automáticamente: si Vertigo u Oyente no están instalados,
        # sus status será NOT_INSTALLED pero el sistema no falla
        adapters = [VertigoAdapter(), OyenteAdapter()]

        for adapter in adapters:
            status = adapter.is_available()
            # Puede ser AVAILABLE o NOT_INSTALLED, ambos son válidos
            assert status in [ToolStatus.AVAILABLE, ToolStatus.NOT_INSTALLED]
            # El adapter no debe lanzar exception

    def test_all_adapters_have_open_source_compatible_license(self):
        """DPGA: Verificar que todas las licencias son open source compatibles"""
        adapters = [
            GasAnalyzerAdapter(),
            MEVDetectorAdapter(),
            VertigoAdapter(),
            OyenteAdapter(),
            ThreatModelAdapter()
        ]

        open_source_licenses = ["MIT", "GPL-3.0", "AGPL-3.0", "Apache-2.0", "BSD"]

        for adapter in adapters:
            metadata = adapter.get_metadata()
            # Verificar que la licencia está en la lista de open source
            assert any(lic in metadata.license for lic in open_source_licenses), \
                f"{metadata.name} has non-open-source license: {metadata.license}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
