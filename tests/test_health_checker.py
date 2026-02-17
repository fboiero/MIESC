"""
Tests for Health Checker module.

Tests the health check and observability system.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.core.health_checker import (
    HealthChecker,
    HealthStatus,
    SystemHealth,
    ToolHealth,
)


class TestHealthStatus:
    """Test HealthStatus enum."""

    def test_all_statuses_exist(self):
        """Test all statuses exist."""
        assert HealthStatus.HEALTHY.value == "healthy"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.UNHEALTHY.value == "unhealthy"
        assert HealthStatus.UNKNOWN.value == "unknown"


class TestToolHealth:
    """Test ToolHealth dataclass."""

    def test_create_tool_health(self):
        """Test creating tool health."""
        health = ToolHealth(
            name="slither",
            status=HealthStatus.HEALTHY,
            available=True,
            version="0.10.0",
            response_time_ms=150.5,
        )
        assert health.name == "slither"
        assert health.status == HealthStatus.HEALTHY
        assert health.available is True
        assert health.version == "0.10.0"

    def test_default_values(self):
        """Test default values."""
        health = ToolHealth(
            name="test",
            status=HealthStatus.UNKNOWN,
            available=False,
        )
        assert health.version is None
        assert health.response_time_ms == 0.0
        assert health.last_check is None
        assert health.error_message is None
        assert health.details == {}

    def test_to_dict(self):
        """Test dictionary conversion."""
        now = datetime.now()
        health = ToolHealth(
            name="mythril",
            status=HealthStatus.HEALTHY,
            available=True,
            version="0.24.0",
            response_time_ms=200.555,
            last_check=now,
            details={"layer": "symbolic_execution"},
        )
        d = health.to_dict()
        assert d["name"] == "mythril"
        assert d["status"] == "healthy"
        assert d["available"] is True
        assert d["response_time_ms"] == 200.56
        assert d["version"] == "0.24.0"

    def test_to_dict_no_last_check(self):
        """Test dict with no last check."""
        health = ToolHealth(
            name="test",
            status=HealthStatus.UNKNOWN,
            available=False,
        )
        d = health.to_dict()
        assert d["last_check"] is None


class TestSystemHealth:
    """Test SystemHealth dataclass."""

    @pytest.fixture
    def tool_healths(self):
        """Create sample tool healths."""
        return [
            ToolHealth(name="slither", status=HealthStatus.HEALTHY, available=True),
            ToolHealth(name="mythril", status=HealthStatus.UNHEALTHY, available=False),
        ]

    def test_create_system_health(self, tool_healths):
        """Test creating system health."""
        health = SystemHealth(
            status=HealthStatus.DEGRADED,
            total_tools=2,
            healthy_tools=1,
            degraded_tools=0,
            unhealthy_tools=1,
            tools=tool_healths,
            check_duration_ms=500.0,
            timestamp=datetime.now(),
        )
        assert health.status == HealthStatus.DEGRADED
        assert health.total_tools == 2
        assert health.healthy_tools == 1

    def test_to_dict(self, tool_healths):
        """Test dictionary conversion."""
        now = datetime.now()
        health = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=2,
            healthy_tools=2,
            degraded_tools=0,
            unhealthy_tools=0,
            tools=tool_healths,
            check_duration_ms=123.456,
            timestamp=now,
        )
        d = health.to_dict()
        assert d["status"] == "healthy"
        assert "summary" in d
        assert d["summary"]["total"] == 2
        assert d["summary"]["healthy"] == 2
        assert d["check_duration_ms"] == 123.46
        assert "tools" in d


class TestHealthChecker:
    """Test HealthChecker class."""

    @pytest.fixture
    def checker(self):
        """Create checker instance."""
        return HealthChecker(max_workers=2)

    def test_init(self, checker):
        """Test initialization."""
        assert checker.max_workers == 2
        assert checker._cache == {}
        assert checker._cache_ttl == 60

    def test_adapter_map_exists(self, checker):
        """Test adapter map is defined."""
        assert "slither" in checker.ADAPTER_MAP
        assert "mythril" in checker.ADAPTER_MAP
        assert "echidna" in checker.ADAPTER_MAP

    def test_adapter_map_format(self, checker):
        """Test adapter map format."""
        for name, (module, cls) in checker.ADAPTER_MAP.items():
            assert module.startswith("src.adapters.")
            assert cls.endswith("Adapter")


class TestHealthCheckerLoadAdapter:
    """Test adapter loading."""

    @pytest.fixture
    def checker(self):
        """Create checker."""
        return HealthChecker()

    def test_load_adapter_unknown(self, checker):
        """Test loading unknown adapter."""
        result = checker._load_adapter("unknown_tool")
        assert result is None

    @patch("importlib.import_module")
    def test_load_adapter_success(self, mock_import, checker):
        """Test successful adapter loading."""
        mock_module = MagicMock()
        mock_adapter = MagicMock()
        mock_module.SlitherAdapter = mock_adapter
        mock_import.return_value = mock_module

        result = checker._load_adapter("slither")

        mock_adapter.assert_called_once()

    @patch("importlib.import_module")
    def test_load_adapter_import_error(self, mock_import, checker):
        """Test adapter import error."""
        mock_import.side_effect = ImportError("Module not found")
        result = checker._load_adapter("slither")
        assert result is None


class TestHealthCheckerCheckTool:
    """Test tool checking."""

    @pytest.fixture
    def checker(self):
        """Create checker."""
        return HealthChecker()

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_not_found(self, mock_load, checker):
        """Test checking non-existent tool."""
        mock_load.return_value = None
        health = checker.check_tool("unknown")

        assert health.status == HealthStatus.UNKNOWN
        assert health.available is False
        assert "not found" in health.error_message.lower()

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_available(self, mock_load, checker):
        """Test checking available tool."""
        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = True
        mock_adapter.get_metadata.return_value = MagicMock(
            version="1.0.0", layer="static", category="analysis"
        )
        mock_load.return_value = mock_adapter

        health = checker.check_tool("slither")

        assert health.status == HealthStatus.HEALTHY
        assert health.available is True
        assert health.version == "1.0.0"

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_unavailable(self, mock_load, checker):
        """Test checking unavailable tool."""
        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = False
        mock_load.return_value = mock_adapter

        health = checker.check_tool("mythril")

        assert health.status == HealthStatus.UNHEALTHY
        assert health.available is False

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_exception(self, mock_load, checker):
        """Test checking tool with exception."""
        mock_load.side_effect = Exception("Test error")

        health = checker.check_tool("slither")

        assert health.status == HealthStatus.UNHEALTHY
        assert "Test error" in health.error_message

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_uses_cache(self, mock_load, checker):
        """Test tool check uses cache."""
        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = True
        mock_load.return_value = mock_adapter

        # First check
        health1 = checker.check_tool("slither")
        # Second check (should use cache)
        health2 = checker.check_tool("slither")

        # Adapter should only be loaded once
        assert mock_load.call_count == 1

    @patch.object(HealthChecker, "_load_adapter")
    def test_check_tool_bypass_cache(self, mock_load, checker):
        """Test bypassing cache."""
        mock_adapter = MagicMock()
        mock_adapter.is_available.return_value = True
        mock_load.return_value = mock_adapter

        # First check
        checker.check_tool("slither")
        # Second check with cache disabled
        checker.check_tool("slither", use_cache=False)

        # Adapter should be loaded twice
        assert mock_load.call_count == 2


class TestHealthCheckerCheckAll:
    """Test checking all tools."""

    @pytest.fixture
    def checker(self):
        """Create checker."""
        return HealthChecker(max_workers=2)

    @patch.object(HealthChecker, "check_tool")
    def test_check_all_specific_tools(self, mock_check, checker):
        """Test checking specific tools."""
        mock_check.return_value = ToolHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            available=True,
        )

        health = checker.check_all(tools=["slither", "mythril"])

        assert health.total_tools == 2

    @patch.object(HealthChecker, "check_tool")
    def test_check_all_default_tools(self, mock_check, checker):
        """Test checking all default tools."""
        mock_check.return_value = ToolHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            available=True,
        )

        health = checker.check_all()

        # Should check all tools in ADAPTER_MAP
        assert health.total_tools == len(checker.ADAPTER_MAP)

    @patch.object(HealthChecker, "check_tool")
    def test_check_all_overall_status_healthy(self, mock_check, checker):
        """Test overall status when all healthy."""
        mock_check.return_value = ToolHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            available=True,
        )

        health = checker.check_all(tools=["slither"])

        assert health.status == HealthStatus.HEALTHY

    @patch.object(HealthChecker, "check_tool")
    def test_check_all_overall_status_degraded(self, mock_check, checker):
        """Test overall status when degraded (more healthy than unhealthy)."""
        results = [
            ToolHealth(name="slither", status=HealthStatus.HEALTHY, available=True),
            ToolHealth(name="mythril", status=HealthStatus.HEALTHY, available=True),
            ToolHealth(name="aderyn", status=HealthStatus.UNHEALTHY, available=False),
        ]
        mock_check.side_effect = results

        health = checker.check_all(tools=["slither", "mythril", "aderyn"])

        # healthy (2) > unhealthy (1) means DEGRADED
        assert health.status == HealthStatus.DEGRADED

    @patch.object(HealthChecker, "check_tool")
    def test_check_all_overall_status_unhealthy(self, mock_check, checker):
        """Test overall status when mostly unhealthy."""
        results = [
            ToolHealth(name="slither", status=HealthStatus.UNHEALTHY, available=False),
            ToolHealth(name="mythril", status=HealthStatus.UNHEALTHY, available=False),
        ]
        mock_check.side_effect = results

        health = checker.check_all(tools=["slither", "mythril"])

        assert health.status == HealthStatus.UNHEALTHY


class TestHealthCheckerHelpers:
    """Test helper methods."""

    @pytest.fixture
    def checker(self):
        """Create checker."""
        return HealthChecker()

    @patch.object(HealthChecker, "check_all")
    def test_get_available_tools(self, mock_check, checker):
        """Test getting available tools."""
        mock_check.return_value = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=2,
            healthy_tools=1,
            degraded_tools=0,
            unhealthy_tools=1,
            tools=[
                ToolHealth(name="slither", status=HealthStatus.HEALTHY, available=True),
                ToolHealth(name="mythril", status=HealthStatus.UNHEALTHY, available=False),
            ],
            check_duration_ms=100.0,
            timestamp=datetime.now(),
        )

        available = checker.get_available_tools()

        assert "slither" in available
        assert "mythril" not in available

    @patch.object(HealthChecker, "check_all")
    def test_get_tools_by_layer(self, mock_check, checker):
        """Test grouping tools by layer."""
        mock_check.return_value = SystemHealth(
            status=HealthStatus.HEALTHY,
            total_tools=2,
            healthy_tools=2,
            degraded_tools=0,
            unhealthy_tools=0,
            tools=[
                ToolHealth(
                    name="slither",
                    status=HealthStatus.HEALTHY,
                    available=True,
                    details={"layer": "static"},
                ),
                ToolHealth(
                    name="mythril",
                    status=HealthStatus.HEALTHY,
                    available=True,
                    details={"layer": "symbolic"},
                ),
            ],
            check_duration_ms=100.0,
            timestamp=datetime.now(),
        )

        layers = checker.get_tools_by_layer()

        assert "static" in layers
        assert "slither" in layers["static"]

    def test_clear_cache(self, checker):
        """Test clearing cache."""
        checker._cache["test"] = ToolHealth(
            name="test",
            status=HealthStatus.HEALTHY,
            available=True,
        )

        checker.clear_cache()

        assert checker._cache == {}
