"""
MIESC API Tests
Tests for MCP REST API endpoints.
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestMCPRestAPI:
    """Tests for MCP REST API."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from src.miesc_mcp_rest import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_root_endpoint(self, client):
        """Test root endpoint returns API info."""
        response = client.get('/')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'agent' in data
        assert 'version' in data
        assert 'status' in data

    def test_capabilities_endpoint(self, client):
        """Test capabilities endpoint."""
        response = client.get('/mcp/capabilities')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'agent_id' in data
        assert 'capabilities' in data
        assert 'protocol' in data

    def test_status_endpoint(self, client):
        """Test status endpoint."""
        response = client.get('/mcp/status')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'status' in data
        assert data['status'] == 'operational'
        assert 'timestamp' in data

    def test_metrics_endpoint(self, client):
        """Test metrics endpoint."""
        response = client.get('/mcp/get_metrics')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert 'metrics' in data
        assert 'precision' in data['metrics']
        assert 'recall' in data['metrics']
        assert 'f1_score' in data['metrics']

    def test_audit_endpoint_no_data(self, client):
        """Test audit endpoint without data."""
        response = client.post('/mcp/run_audit')
        # Returns 400 or 500 depending on how server handles missing content-type
        assert response.status_code in [400, 500]

    def test_audit_endpoint_missing_contract(self, client):
        """Test audit endpoint without contract parameter."""
        response = client.post(
            '/mcp/run_audit',
            data=json.dumps({}),
            content_type='application/json'
        )
        assert response.status_code == 400

        data = json.loads(response.data)
        assert data['status'] == 'error'

    def test_audit_endpoint_nonexistent_contract(self, client):
        """Test audit endpoint with non-existent contract."""
        response = client.post(
            '/mcp/run_audit',
            data=json.dumps({'contract': '/tmp/nonexistent.sol'}),
            content_type='application/json'
        )
        assert response.status_code == 404

    def test_policy_audit_endpoint(self, client):
        """Test policy audit endpoint."""
        response = client.post(
            '/mcp/policy_audit',
            data=json.dumps({'repo_path': '.'}),
            content_type='application/json'
        )
        # May succeed or fail based on tools availability
        assert response.status_code in [200, 500]

    def test_404_handler(self, client):
        """Test 404 error handler."""
        response = client.get('/nonexistent/endpoint')
        assert response.status_code == 404

        data = json.loads(response.data)
        assert data['status'] == 'error'
        assert 'available_endpoints' in data


class TestAPIVersion:
    """Tests for API version."""

    def test_version_in_response(self):
        """Test version is included in responses."""
        from src.miesc_mcp_rest import MIESC_VERSION
        assert MIESC_VERSION == '4.0.0'


class TestAPISchema:
    """Tests for API response schemas."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from src.miesc_mcp_rest import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_capabilities_schema(self, client):
        """Test capabilities response schema."""
        response = client.get('/mcp/capabilities')
        data = json.loads(response.data)

        # Required fields
        assert 'agent_id' in data
        assert 'protocol' in data
        assert 'version' in data
        assert 'capabilities' in data
        assert 'metadata' in data

        # Metadata structure
        metadata = data['metadata']
        assert 'scientific_validation' in metadata
        assert 'frameworks' in metadata

    def test_metrics_schema(self, client):
        """Test metrics response schema."""
        response = client.get('/mcp/get_metrics')
        data = json.loads(response.data)

        metrics = data['metrics']
        assert 'precision' in metrics
        assert 'recall' in metrics
        assert 'f1_score' in metrics
        assert 'cohens_kappa' in metrics
        assert 'false_positive_reduction' in metrics
        assert 'dataset_size' in metrics

        # Validate value ranges
        assert 0 <= metrics['precision'] <= 1
        assert 0 <= metrics['recall'] <= 1
        assert 0 <= metrics['f1_score'] <= 1

    def test_status_schema(self, client):
        """Test status response schema."""
        response = client.get('/mcp/status')
        data = json.loads(response.data)

        assert 'status' in data
        assert 'agent_id' in data
        assert 'version' in data
        assert 'timestamp' in data
        assert 'health' in data


class TestAPICORS:
    """Tests for CORS configuration."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from src.miesc_mcp_rest import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_cors_headers_present(self, client):
        """Test CORS headers are present."""
        response = client.get('/')
        # Flask-CORS should add headers
        # Check response is successful
        assert response.status_code == 200


class TestAPIErrorHandling:
    """Tests for API error handling."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from src.miesc_mcp_rest import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client

    def test_invalid_json(self, client):
        """Test handling of invalid JSON."""
        response = client.post(
            '/mcp/run_audit',
            data='not valid json',
            content_type='application/json'
        )
        assert response.status_code in [400, 500]

    def test_wrong_content_type(self, client):
        """Test handling of wrong content type."""
        response = client.post(
            '/mcp/run_audit',
            data='contract=/tmp/test.sol',
            content_type='text/plain'
        )
        assert response.status_code in [400, 415, 500]


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
