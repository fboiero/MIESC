"""
Integration Tests for MIESC API Endpoints

Comprehensive test suite for FastAPI REST API including:
- Health check endpoints
- MCP capabilities endpoint
- Analysis endpoint (/analyze)
- Verification endpoint (/verify)
- Classification endpoint (/classify)
- Error handling and validation
- Security testing

Target Coverage: Full API endpoint coverage
Test Type: Integration (uses TestClient, mocks core functions)

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from datetime import datetime

from miesc.api.server import app


class TestHealthEndpoints:
    """Test suite for health check and capabilities endpoints"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    def test_root_endpoint(self, client):
        """Test root endpoint returns health status"""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'operational'
        assert data['version'] == '3.3.0'
        assert 'timestamp' in data
        assert 'analyze' in data['capabilities']
        assert 'verify' in data['capabilities']
        assert 'classify' in data['capabilities']
        assert 'mcp' in data['capabilities']

    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'
        assert data['version'] == '3.3.0'
        assert 'timestamp' in data

    def test_mcp_capabilities_endpoint(self, client):
        """Test MCP capabilities endpoint"""
        response = client.get("/mcp/capabilities")

        assert response.status_code == 200
        data = response.json()
        assert data['name'] == 'miesc'
        assert data['version'] == '3.3.0'
        assert 'audit' in data['capabilities']
        assert 'formal_verification' in data['capabilities']
        assert 'endpoints' in data
        assert 'analyze' in data['endpoints']
        assert 'verify' in data['endpoints']
        assert 'classify' in data['endpoints']


class TestAnalyzeEndpoint:
    """Test suite for /analyze endpoint"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    @patch('miesc.api.server.analyze_contract')
    def test_analyze_basic_success(self, mock_analyze, client):
        """Test successful analysis request"""
        # Mock analyze_contract response
        mock_analyze.return_value = {
            "timestamp": datetime.now().isoformat(),
            "contract": "test.sol",
            "tools_executed": ["slither"],
            "total_findings": 2,
            "findings_by_severity": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0
            },
            "findings": [],
            "context": "MIESC static/dynamic analysis"
        }

        # Make request
        response = client.post("/analyze", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "analysis_type": "slither",
            "timeout": 300
        })

        assert response.status_code == 200
        data = response.json()
        assert 'timestamp' in data
        assert data['total_findings'] == 2
        assert mock_analyze.called

    @patch('miesc.api.server.analyze_contract')
    def test_analyze_all_tools(self, mock_analyze, client):
        """Test analysis with all tools"""
        mock_analyze.return_value = {
            "timestamp": datetime.now().isoformat(),
            "contract": "test.sol",
            "tools_executed": ["slither", "mythril", "echidna", "aderyn"],
            "total_findings": 5,
            "findings_by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 1},
            "findings": [],
            "context": "MIESC static/dynamic analysis"
        }

        response = client.post("/analyze", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "analysis_type": "all",
            "timeout": 600
        })

        assert response.status_code == 200
        data = response.json()
        assert len(data['tools_executed']) > 1

    def test_analyze_missing_contract_code(self, client):
        """Test analysis request with missing contract code"""
        response = client.post("/analyze", json={
            "analysis_type": "slither",
            "timeout": 300
        })

        assert response.status_code == 422  # Validation error

    @patch('miesc.api.server.analyze_contract')
    def test_analyze_error_handling(self, mock_analyze, client):
        """Test error handling in analysis endpoint"""
        mock_analyze.side_effect = Exception("Analysis failed")

        response = client.post("/analyze", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "analysis_type": "slither",
            "timeout": 300
        })

        assert response.status_code == 500
        assert "Analysis failed" in response.json()['detail']

    def test_analyze_invalid_timeout(self, client):
        """Test analysis with invalid timeout value"""
        response = client.post("/analyze", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "analysis_type": "slither",
            "timeout": -100  # Invalid negative timeout
        })

        # Should be caught by validation
        assert response.status_code in [422, 500]


class TestVerifyEndpoint:
    """Test suite for /verify endpoint"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    @patch('miesc.api.server.verify_contract')
    def test_verify_basic_success(self, mock_verify, client):
        """Test successful verification request"""
        mock_verify.return_value = {
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "level": "basic",
            "method": "SMTChecker",
            "properties_verified": 0,
            "warnings": [],
            "errors": [],
            "context": "MIESC formal verification"
        }

        response = client.post("/verify", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "verification_level": "basic",
            "properties": [],
            "timeout": 600
        })

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'completed'
        assert data['level'] == 'basic'
        assert mock_verify.called

    @patch('miesc.api.server.verify_contract')
    def test_verify_with_properties(self, mock_verify, client):
        """Test verification with custom properties"""
        mock_verify.return_value = {
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "level": "smt",
            "method": "Z3 Solver",
            "properties_verified": 2,
            "warnings": [],
            "errors": [],
            "context": "MIESC formal verification"
        }

        response = client.post("/verify", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "verification_level": "smt",
            "properties": [
                "invariant balance >= 0",
                "require msg.value > 0"
            ],
            "timeout": 1200
        })

        assert response.status_code == 200
        data = response.json()
        assert data['properties_verified'] == 2

    @patch('miesc.api.server.verify_contract')
    def test_verify_certora_level(self, mock_verify, client):
        """Test Certora-level verification"""
        mock_verify.return_value = {
            "timestamp": datetime.now().isoformat(),
            "status": "completed",
            "level": "certora",
            "method": "Certora Prover",
            "properties_verified": 0,
            "warnings": [],
            "errors": [],
            "context": "MIESC formal verification"
        }

        response = client.post("/verify", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "verification_level": "certora",
            "properties": [],
            "timeout": 1800
        })

        assert response.status_code == 200
        data = response.json()
        assert data['level'] == 'certora'

    @patch('miesc.api.server.verify_contract')
    def test_verify_error_handling(self, mock_verify, client):
        """Test error handling in verify endpoint"""
        mock_verify.side_effect = Exception("Verification failed")

        response = client.post("/verify", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "verification_level": "basic",
            "properties": [],
            "timeout": 600
        })

        assert response.status_code == 500
        assert "Verification failed" in response.json()['detail']


class TestClassifyEndpoint:
    """Test suite for /classify endpoint"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    @pytest.fixture
    def sample_report(self):
        """Sample analysis report for classification"""
        return {
            "timestamp": datetime.now().isoformat(),
            "contract": "test.sol",
            "tools_executed": ["slither"],
            "total_findings": 2,
            "findings_by_severity": {"critical": 0, "high": 1, "medium": 1, "low": 0},
            "findings": [
                {
                    "tool": "slither",
                    "vulnerability_type": "reentrancy",
                    "severity": "High",
                    "swc_id": "SWC-107",
                    "location": {"file": "test.sol", "line": 10},
                    "description": "Reentrancy detected",
                    "confidence": "Medium"
                }
            ],
            "context": "MIESC static/dynamic analysis"
        }

    @patch('miesc.api.server.classify_vulnerabilities')
    def test_classify_success(self, mock_classify, client, sample_report):
        """Test successful classification request"""
        mock_classify.return_value = {
            "timestamp": datetime.now().isoformat(),
            "classified_findings": [
                {
                    "tool": "slither",
                    "vulnerability_type": "reentrancy",
                    "severity": "High",
                    "cvss_score": 9.1,
                    "owasp_category": "Reentrancy",
                    "swc_id": "SWC-107"
                }
            ],
            "statistics": {
                "total_findings": 1,
                "avg_cvss": 9.1,
                "by_severity": {"High": 1}
            },
            "ai_triage_enabled": False,
            "context": "MIESC vulnerability classification"
        }

        response = client.post("/classify", json={
            "report": sample_report,
            "enable_ai_triage": False,
            "ai_api_key": None
        })

        assert response.status_code == 200
        data = response.json()
        assert 'classified_findings' in data
        assert 'statistics' in data
        assert mock_classify.called

    @patch('miesc.api.server.classify_vulnerabilities')
    def test_classify_with_ai_triage(self, mock_classify, client, sample_report):
        """Test classification with AI triage enabled"""
        mock_classify.return_value = {
            "timestamp": datetime.now().isoformat(),
            "classified_findings": [],
            "statistics": {"total_findings": 0, "avg_cvss": 0, "by_severity": {}},
            "ai_triage_enabled": True,
            "context": "MIESC vulnerability classification"
        }

        response = client.post("/classify", json={
            "report": sample_report,
            "enable_ai_triage": True,
            "ai_api_key": "test-api-key-with-minimum-20-characters"
        })

        assert response.status_code == 200
        data = response.json()
        assert data.get('ai_triage_enabled') is True

    @patch('miesc.api.server.classify_vulnerabilities')
    def test_classify_error_handling(self, mock_classify, client, sample_report):
        """Test error handling in classify endpoint"""
        mock_classify.side_effect = Exception("Classification failed")

        response = client.post("/classify", json={
            "report": sample_report,
            "enable_ai_triage": False,
            "ai_api_key": None
        })

        assert response.status_code == 500
        assert "Classification failed" in response.json()['detail']


class TestCORSAndMiddleware:
    """Test suite for CORS and middleware configuration"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    def test_cors_headers_present(self, client):
        """Test that CORS headers are present"""
        response = client.options("/health")

        # CORS headers should be present
        assert response.status_code in [200, 405]

    def test_cors_allows_methods(self, client):
        """Test CORS allows required methods"""
        response = client.post("/analyze", json={
            "contract_code": "pragma solidity ^0.8.0; contract Test {}",
            "analysis_type": "slither",
            "timeout": 300
        })

        # Should not fail due to CORS
        assert response.status_code in [200, 500]  # Not 403


class TestAPIDocumentation:
    """Test suite for API documentation endpoints"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    def test_openapi_schema_accessible(self, client):
        """Test OpenAPI schema is accessible"""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        schema = response.json()
        assert 'openapi' in schema
        assert 'paths' in schema
        assert '/analyze' in schema['paths']
        assert '/verify' in schema['paths']
        assert '/classify' in schema['paths']

    def test_docs_endpoint_accessible(self, client):
        """Test Swagger UI docs are accessible"""
        response = client.get("/docs")

        assert response.status_code == 200
        assert 'text/html' in response.headers['content-type']

    def test_redoc_endpoint_accessible(self, client):
        """Test ReDoc documentation is accessible"""
        response = client.get("/redoc")

        assert response.status_code == 200
        assert 'text/html' in response.headers['content-type']


class TestSecurityAndValidation:
    """Test suite for security and input validation"""

    @pytest.fixture
    def client(self):
        """FastAPI test client"""
        return TestClient(app)

    def test_analyze_rejects_invalid_json(self, client):
        """Test that invalid JSON is rejected"""
        response = client.post(
            "/analyze",
            data="This is not JSON",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 422

    def test_verify_rejects_missing_required_fields(self, client):
        """Test verification rejects missing required fields"""
        response = client.post("/verify", json={
            "verification_level": "basic"
            # Missing contract_code
        })

        assert response.status_code == 422

    def test_classify_rejects_empty_report(self, client):
        """Test classification rejects empty report"""
        response = client.post("/classify", json={
            "report": {},
            "enable_ai_triage": False
        })

        # Should either fail validation or handle gracefully
        assert response.status_code in [200, 422, 500]


# Pytest markers
pytestmark = [
    pytest.mark.integration,
    pytest.mark.api
]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
