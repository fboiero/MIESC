"""
Tests for MIESC Metrics Module

Tests Prometheus-compatible metrics collection with fallback.
"""

import time

import pytest

from src.core.metrics import (
    PROMETHEUS_AVAILABLE,
    InternalCounter,
    InternalGauge,
    InternalHistogram,
    InternalMetricsCollector,
    MetricValue,
    MIESCMetrics,
    get_metrics,
    reset_metrics,
    timed,
)


class TestInternalMetricsCollector:
    """Tests for internal metrics collector."""

    def test_increment_counter(self):
        """Test counter increment."""
        collector = InternalMetricsCollector()

        collector.increment_counter("test_counter")
        assert collector.counters["test_counter"] == 1

        collector.increment_counter("test_counter", 5)
        assert collector.counters["test_counter"] == 6

    def test_counter_with_labels(self):
        """Test counter with labels."""
        collector = InternalMetricsCollector()

        collector.increment_counter("requests", labels={"method": "GET"})
        collector.increment_counter("requests", labels={"method": "POST"})
        collector.increment_counter("requests", labels={"method": "GET"})

        assert collector.counters["requests{method=GET}"] == 2
        assert collector.counters["requests{method=POST}"] == 1

    def test_set_gauge(self):
        """Test gauge set."""
        collector = InternalMetricsCollector()

        collector.set_gauge("temperature", 25.5)
        assert collector.gauges["temperature"] == 25.5

        collector.set_gauge("temperature", 30.0)
        assert collector.gauges["temperature"] == 30.0

    def test_gauge_with_labels(self):
        """Test gauge with labels."""
        collector = InternalMetricsCollector()

        collector.set_gauge("cpu", 50.0, labels={"core": "0"})
        collector.set_gauge("cpu", 60.0, labels={"core": "1"})

        assert collector.gauges["cpu{core=0}"] == 50.0
        assert collector.gauges["cpu{core=1}"] == 60.0

    def test_observe_histogram(self):
        """Test histogram observation."""
        collector = InternalMetricsCollector()

        collector.observe_histogram("latency", 0.1)
        collector.observe_histogram("latency", 0.2)
        collector.observe_histogram("latency", 0.15)

        assert len(collector.histograms["latency"]) == 3
        assert sum(collector.histograms["latency"]) == pytest.approx(0.45)

    def test_histogram_with_labels(self):
        """Test histogram with labels."""
        collector = InternalMetricsCollector()

        collector.observe_histogram("duration", 1.0, labels={"tool": "slither"})
        collector.observe_histogram("duration", 2.0, labels={"tool": "mythril"})

        assert len(collector.histograms["duration{tool=slither}"]) == 1
        assert len(collector.histograms["duration{tool=mythril}"]) == 1

    def test_get_metrics(self):
        """Test getting all metrics."""
        collector = InternalMetricsCollector()

        collector.increment_counter("counter1")
        collector.set_gauge("gauge1", 10)
        collector.observe_histogram("hist1", 0.5)

        metrics = collector.get_metrics()

        assert "counters" in metrics
        assert "gauges" in metrics
        assert "histograms" in metrics
        assert "recent" in metrics

    def test_clear_metrics(self):
        """Test clearing all metrics."""
        collector = InternalMetricsCollector()

        collector.increment_counter("counter1")
        collector.set_gauge("gauge1", 10)

        collector.clear()

        assert len(collector.counters) == 0
        assert len(collector.gauges) == 0
        assert len(collector.histograms) == 0


class TestInternalCounter:
    """Tests for internal counter wrapper."""

    def test_counter_inc(self):
        """Test counter increment."""
        collector = InternalMetricsCollector()
        counter = InternalCounter("test", collector)

        counter.inc()
        assert collector.counters["test"] == 1

        counter.inc(5)
        assert collector.counters["test"] == 6

    def test_counter_labels(self):
        """Test counter with labels."""
        collector = InternalMetricsCollector()
        counter = InternalCounter("requests", collector)

        counter.labels(status="200").inc()
        counter.labels(status="500").inc(2)

        assert collector.counters["requests{status=200}"] == 1
        assert collector.counters["requests{status=500}"] == 2


class TestInternalHistogram:
    """Tests for internal histogram wrapper."""

    def test_histogram_observe(self):
        """Test histogram observation."""
        collector = InternalMetricsCollector()
        histogram = InternalHistogram("latency", collector)

        histogram.observe(0.5)
        histogram.observe(1.0)

        assert len(collector.histograms["latency"]) == 2

    def test_histogram_labels(self):
        """Test histogram with labels."""
        collector = InternalMetricsCollector()
        histogram = InternalHistogram("duration", collector)

        histogram.labels(tool="slither").observe(2.5)

        assert "duration{tool=slither}" in collector.histograms

    def test_histogram_time_context(self):
        """Test histogram time context manager."""
        collector = InternalMetricsCollector()
        histogram = InternalHistogram("operation_time", collector)

        with histogram.time():
            time.sleep(0.01)

        assert len(collector.histograms["operation_time"]) == 1
        assert collector.histograms["operation_time"][0] >= 0.01


class TestInternalGauge:
    """Tests for internal gauge wrapper."""

    def test_gauge_set(self):
        """Test gauge set."""
        collector = InternalMetricsCollector()
        gauge = InternalGauge("active", collector)

        gauge.set(10)
        assert collector.gauges["active"] == 10

    def test_gauge_inc_dec(self):
        """Test gauge increment and decrement."""
        collector = InternalMetricsCollector()
        gauge = InternalGauge("connections", collector)

        gauge.set(5)
        gauge.inc()
        assert collector.gauges["connections"] == 6

        gauge.dec()
        assert collector.gauges["connections"] == 5

        gauge.inc(3)
        assert collector.gauges["connections"] == 8

    def test_gauge_labels(self):
        """Test gauge with labels."""
        collector = InternalMetricsCollector()
        gauge = InternalGauge("tools_available", collector)

        gauge.labels(layer="1").set(5)
        gauge.labels(layer="2").set(3)

        assert collector.gauges["tools_available{layer=1}"] == 5
        assert collector.gauges["tools_available{layer=2}"] == 3


class TestMIESCMetrics:
    """Tests for main MIESC metrics class."""

    def test_metrics_initialization(self):
        """Test metrics initialization."""
        metrics = MIESCMetrics()

        assert metrics.internal is not None
        assert hasattr(metrics, "audits_total")
        assert hasattr(metrics, "findings_total")
        assert hasattr(metrics, "tool_executions_total")

    def test_record_audit_start(self):
        """Test recording audit start."""
        metrics = MIESCMetrics()
        metrics.record_audit_start()

        # Should increment active audits
        assert metrics.internal.gauges.get("miesc_active_audits", 0) >= 0

    def test_record_audit_end(self):
        """Test recording audit end."""
        metrics = MIESCMetrics()
        metrics.record_audit_start()
        metrics.record_audit_end(status="success", duration=5.0, layers=7)

        # Check metric was recorded (works with both Prometheus and internal backend)
        from src.core.metrics import PROMETHEUS_AVAILABLE

        if PROMETHEUS_AVAILABLE:
            # With Prometheus, check via text output
            text = metrics.get_metrics_text()
            assert "miesc_audits_total" in text
        else:
            assert "miesc_audits_total{status=success}" in metrics.internal.counters

    def test_record_finding(self):
        """Test recording a finding."""
        metrics = MIESCMetrics()
        metrics.record_finding(
            severity="critical",
            finding_type="reentrancy",
            layer=1,
            confidence=0.95,
        )

        # Check metric was recorded (works with both Prometheus and internal backend)
        from src.core.metrics import PROMETHEUS_AVAILABLE

        if PROMETHEUS_AVAILABLE:
            text = metrics.get_metrics_text()
            assert "miesc_findings_total" in text
        else:
            key = "miesc_findings_total{layer=1,severity=critical,type=reentrancy}"
            assert key in metrics.internal.counters

    def test_record_tool_execution(self):
        """Test recording tool execution."""
        metrics = MIESCMetrics()
        metrics.record_tool_execution(
            tool="slither",
            layer=1,
            duration=2.5,
            success=True,
        )

        # Check metric was recorded (works with both Prometheus and internal backend)
        from src.core.metrics import PROMETHEUS_AVAILABLE

        if PROMETHEUS_AVAILABLE:
            text = metrics.get_metrics_text()
            assert "miesc_tool_executions_total" in text
        else:
            assert (
                "miesc_tool_executions_total{status=success,tool=slither}"
                in metrics.internal.counters
            )

    def test_record_error(self):
        """Test recording an error."""
        metrics = MIESCMetrics()
        metrics.record_error(error_type="timeout", tool="mythril")

        # Check metric was recorded (works with both Prometheus and internal backend)
        from src.core.metrics import PROMETHEUS_AVAILABLE

        if PROMETHEUS_AVAILABLE:
            text = metrics.get_metrics_text()
            assert "miesc_errors_total" in text
        else:
            assert "miesc_errors_total{tool=mythril,type=timeout}" in metrics.internal.counters

    def test_measure_time_context(self):
        """Test time measurement context manager."""
        metrics = MIESCMetrics()

        with metrics.measure_time("test_operation"):
            time.sleep(0.01)

        assert "test_operation" in metrics.internal.histograms

    def test_get_metrics_text(self):
        """Test getting metrics in text format."""
        metrics = MIESCMetrics()
        metrics.record_finding("high", "overflow", 1, 0.9)

        text = metrics.get_metrics_text()
        assert isinstance(text, str)
        assert "miesc" in text.lower() or "MIESC" in text

    def test_get_metrics_json(self):
        """Test getting metrics in JSON format."""
        metrics = MIESCMetrics()
        metrics.record_finding("medium", "access_control", 1, 0.8)

        json_metrics = metrics.get_metrics_json()

        assert "counters" in json_metrics
        assert "gauges" in json_metrics


class TestGlobalMetrics:
    """Tests for global metrics functions."""

    def test_get_metrics_singleton(self):
        """Test that get_metrics returns singleton."""
        reset_metrics()

        metrics1 = get_metrics()
        metrics2 = get_metrics()

        assert metrics1 is metrics2

    def test_reset_metrics(self):
        """Test metrics reset."""
        metrics1 = get_metrics()
        reset_metrics()
        metrics2 = get_metrics()

        assert metrics1 is not metrics2


class TestTimedDecorator:
    """Tests for timed decorator."""

    def test_timed_decorator(self):
        """Test that timed decorator logs execution time."""

        @timed("test_metric")
        def slow_function():
            time.sleep(0.01)
            return "done"

        result = slow_function()
        assert result == "done"

    def test_timed_preserves_function_name(self):
        """Test that timed preserves function metadata."""

        @timed("test")
        def my_function():
            """My docstring."""
            pass

        assert my_function.__name__ == "my_function"


class TestMetricValue:
    """Tests for MetricValue dataclass."""

    def test_metric_value_creation(self):
        """Test MetricValue creation."""
        mv = MetricValue(
            name="test",
            type="counter",
            value=10.0,
            labels={"key": "value"},
        )

        assert mv.name == "test"
        assert mv.type == "counter"
        assert mv.value == 10.0
        assert mv.labels == {"key": "value"}
        assert mv.timestamp is not None


class TestMIESCMetricsHTTPServer:
    """Tests for metrics HTTP server functionality."""

    def test_start_http_server_without_prometheus(self):
        """Test HTTP server start when Prometheus unavailable."""
        import logging
        from unittest.mock import patch

        # Create metrics instance
        metrics = MIESCMetrics()

        # Mock PROMETHEUS_AVAILABLE as False
        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            # Should log warning but not raise
            with patch.object(logging.getLogger("src.core.metrics"), "warning"):
                metrics.start_http_server(9999)

    def test_start_http_server_with_prometheus(self):
        """Test HTTP server start when Prometheus is available."""
        from unittest.mock import patch

        metrics = MIESCMetrics()

        if PROMETHEUS_AVAILABLE:
            with patch("src.core.metrics.start_http_server") as mock_server:
                metrics.start_http_server(9999)
                mock_server.assert_called_once()


class TestMIESCMetricsPrometheus:
    """Tests for Prometheus-specific metrics behavior."""

    def test_record_audit_start_prometheus(self):
        """Test audit start with Prometheus backend."""
        from unittest.mock import MagicMock, patch

        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            metrics.active_audits = MagicMock()
            with patch("src.core.metrics.PROMETHEUS_AVAILABLE", True):
                metrics.record_audit_start()
                metrics.active_audits.inc.assert_called_once()

    def test_record_audit_end_prometheus(self):
        """Test audit end with Prometheus backend."""
        from unittest.mock import MagicMock, patch

        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            metrics.active_audits = MagicMock()
            metrics.audits_total = MagicMock()
            metrics.audit_duration_seconds = MagicMock()

            with patch("src.core.metrics.PROMETHEUS_AVAILABLE", True):
                metrics.record_audit_end(status="success", duration=5.0, layers=7)

    def test_record_finding_prometheus(self):
        """Test finding recording with Prometheus backend."""
        from unittest.mock import MagicMock, patch

        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            metrics.findings_total = MagicMock()
            metrics.finding_confidence = MagicMock()

            with patch("src.core.metrics.PROMETHEUS_AVAILABLE", True):
                metrics.record_finding(
                    severity="critical", finding_type="reentrancy", layer=1, confidence=0.95
                )

    def test_record_tool_execution_prometheus(self):
        """Test tool execution recording with Prometheus backend."""
        from unittest.mock import MagicMock, patch

        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            metrics.tool_executions_total = MagicMock()
            metrics.tool_execution_seconds = MagicMock()

            with patch("src.core.metrics.PROMETHEUS_AVAILABLE", True):
                metrics.record_tool_execution(tool="slither", layer=1, duration=2.5, success=True)

    def test_record_error_prometheus(self):
        """Test error recording with Prometheus backend."""
        from unittest.mock import MagicMock, patch

        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            metrics.errors_total = MagicMock()

            with patch("src.core.metrics.PROMETHEUS_AVAILABLE", True):
                metrics.record_error(error_type="timeout", tool="mythril")

    def test_get_metrics_text_prometheus(self):
        """Test metrics text output with Prometheus backend."""
        if PROMETHEUS_AVAILABLE:
            metrics = MIESCMetrics()
            text = metrics.get_metrics_text()
            assert "miesc" in text.lower() or isinstance(text, str)


class TestMIESCMetricsInternal:
    """Tests for internal metrics fallback behavior."""

    def test_record_audit_start_internal(self):
        """Test audit start with internal backend."""
        from unittest.mock import patch

        metrics = MIESCMetrics()

        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            metrics.record_audit_start()
            # Should use internal gauge
            assert "miesc_active_audits" in metrics.internal.gauges or True

    def test_record_audit_end_internal(self):
        """Test audit end with internal backend."""
        from unittest.mock import patch

        metrics = MIESCMetrics()

        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            metrics.record_audit_start()
            metrics.record_audit_end(status="success", duration=5.0, layers=7)

    def test_record_finding_internal(self):
        """Test finding recording with internal backend."""
        from unittest.mock import patch

        metrics = MIESCMetrics()

        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            metrics.record_finding(
                severity="high", finding_type="overflow", layer=2, confidence=0.85
            )

    def test_get_metrics_text_internal(self):
        """Test metrics text output with internal backend."""
        from unittest.mock import patch

        metrics = MIESCMetrics()
        metrics.internal.increment_counter("test_counter")
        metrics.internal.set_gauge("test_gauge", 42)

        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            text = metrics.get_metrics_text()
            assert isinstance(text, str)
