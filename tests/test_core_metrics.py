"""
Tests for Core Metrics module.

Tests the observability metrics system for monitoring MIESC performance.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from src.core.metrics import (
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


class TestMetricValue:
    """Test MetricValue dataclass."""

    def test_create_metric_value(self):
        """Test creating metric value."""
        metric = MetricValue(
            name="test_counter",
            type="counter",
            value=42.0,
            labels={"tool": "slither"},
        )
        assert metric.name == "test_counter"
        assert metric.type == "counter"
        assert metric.value == 42.0
        assert metric.labels["tool"] == "slither"

    def test_default_labels(self):
        """Test default empty labels."""
        metric = MetricValue(name="test", type="gauge", value=1.0)
        assert metric.labels == {}

    def test_has_timestamp(self):
        """Test metric has timestamp."""
        metric = MetricValue(name="test", type="counter", value=1.0)
        assert metric.timestamp is not None


class TestInternalMetricsCollector:
    """Test InternalMetricsCollector class."""

    @pytest.fixture
    def collector(self):
        """Create collector instance."""
        return InternalMetricsCollector()

    def test_init(self, collector):
        """Test initialization."""
        assert collector.metrics == []
        assert collector.counters == {}
        assert collector.gauges == {}
        assert collector.histograms == {}

    def test_increment_counter(self, collector):
        """Test incrementing counter."""
        collector.increment_counter("test_counter")
        assert collector.counters["test_counter"] == 1.0

    def test_increment_counter_multiple(self, collector):
        """Test incrementing counter multiple times."""
        collector.increment_counter("test_counter")
        collector.increment_counter("test_counter")
        collector.increment_counter("test_counter", value=5.0)
        assert collector.counters["test_counter"] == 7.0

    def test_increment_counter_with_labels(self, collector):
        """Test counter with labels."""
        collector.increment_counter("test_counter", labels={"status": "success"})
        key = "test_counter{status=success}"
        assert collector.counters[key] == 1.0

    def test_set_gauge(self, collector):
        """Test setting gauge."""
        collector.set_gauge("test_gauge", 42.0)
        assert collector.gauges["test_gauge"] == 42.0

    def test_set_gauge_overwrite(self, collector):
        """Test overwriting gauge value."""
        collector.set_gauge("test_gauge", 10.0)
        collector.set_gauge("test_gauge", 20.0)
        assert collector.gauges["test_gauge"] == 20.0

    def test_observe_histogram(self, collector):
        """Test histogram observation."""
        collector.observe_histogram("test_histogram", 1.5)
        assert collector.histograms["test_histogram"] == [1.5]

    def test_observe_histogram_multiple(self, collector):
        """Test multiple histogram observations."""
        collector.observe_histogram("test_histogram", 1.0)
        collector.observe_histogram("test_histogram", 2.0)
        collector.observe_histogram("test_histogram", 3.0)
        assert collector.histograms["test_histogram"] == [1.0, 2.0, 3.0]

    def test_make_key_no_labels(self, collector):
        """Test key generation without labels."""
        key = collector._make_key("metric_name")
        assert key == "metric_name"

    def test_make_key_with_labels(self, collector):
        """Test key generation with labels."""
        key = collector._make_key("metric_name", {"a": "1", "b": "2"})
        assert key == "metric_name{a=1,b=2}"

    def test_get_metrics(self, collector):
        """Test getting all metrics."""
        collector.increment_counter("counter")
        collector.set_gauge("gauge", 5.0)
        collector.observe_histogram("hist", 1.0)

        metrics = collector.get_metrics()
        assert "counters" in metrics
        assert "gauges" in metrics
        assert "histograms" in metrics
        assert "recent" in metrics

    def test_clear(self, collector):
        """Test clearing metrics."""
        collector.increment_counter("counter")
        collector.set_gauge("gauge", 5.0)
        collector.clear()

        assert collector.counters == {}
        assert collector.gauges == {}
        assert collector.histograms == {}
        assert collector.metrics == []


class TestInternalCounter:
    """Test InternalCounter class."""

    @pytest.fixture
    def collector(self):
        """Create collector."""
        return InternalMetricsCollector()

    def test_inc(self, collector):
        """Test incrementing counter."""
        counter = InternalCounter("test", collector)
        counter.inc()
        assert collector.counters["test"] == 1.0

    def test_inc_value(self, collector):
        """Test incrementing with value."""
        counter = InternalCounter("test", collector)
        counter.inc(5.0)
        assert collector.counters["test"] == 5.0

    def test_labels(self, collector):
        """Test counter with labels."""
        counter = InternalCounter("test", collector)
        counter.labels(status="ok").inc()
        assert "test{status=ok}" in collector.counters


class TestInternalHistogram:
    """Test InternalHistogram class."""

    @pytest.fixture
    def collector(self):
        """Create collector."""
        return InternalMetricsCollector()

    def test_observe(self, collector):
        """Test observing value."""
        hist = InternalHistogram("test", collector)
        hist.observe(1.5)
        assert collector.histograms["test"] == [1.5]

    def test_labels(self, collector):
        """Test histogram with labels."""
        hist = InternalHistogram("test", collector)
        hist.labels(layer="1").observe(2.0)
        assert "test{layer=1}" in collector.histograms

    def test_time_context_manager(self, collector):
        """Test time context manager."""
        hist = InternalHistogram("test", collector)
        with hist.time():
            time.sleep(0.01)
        assert len(collector.histograms["test"]) == 1
        assert collector.histograms["test"][0] >= 0.01


class TestInternalGauge:
    """Test InternalGauge class."""

    @pytest.fixture
    def collector(self):
        """Create collector."""
        return InternalMetricsCollector()

    def test_set(self, collector):
        """Test setting gauge."""
        gauge = InternalGauge("test", collector)
        gauge.set(42.0)
        assert collector.gauges["test"] == 42.0

    def test_inc(self, collector):
        """Test incrementing gauge."""
        gauge = InternalGauge("test", collector)
        gauge.set(10.0)
        gauge.inc()
        assert collector.gauges["test"] == 11.0

    def test_dec(self, collector):
        """Test decrementing gauge."""
        gauge = InternalGauge("test", collector)
        gauge.set(10.0)
        gauge.dec()
        assert collector.gauges["test"] == 9.0

    def test_labels(self, collector):
        """Test gauge with labels."""
        gauge = InternalGauge("test", collector)
        gauge.labels(layer="2").set(5.0)
        assert "test{layer=2}" in collector.gauges


class TestMIESCMetrics:
    """Test MIESCMetrics class."""

    @pytest.fixture
    def metrics(self):
        """Create metrics without Prometheus."""
        with patch("src.core.metrics.PROMETHEUS_AVAILABLE", False):
            return MIESCMetrics()

    def test_init_internal(self, metrics):
        """Test initialization without Prometheus."""
        assert metrics.internal is not None
        assert metrics.registry is None

    def test_record_audit_start(self, metrics):
        """Test recording audit start."""
        metrics.record_audit_start()
        assert metrics.internal.gauges.get("miesc_active_audits", 0) == 1

    def test_record_audit_end(self, metrics):
        """Test recording audit end."""
        metrics.record_audit_start()
        metrics.record_audit_end(status="success", duration=10.5, layers=5)
        # Active audits should be 0
        assert metrics.internal.gauges.get("miesc_active_audits", 0) == 0
        # Should have counter
        assert any("miesc_audits_total" in k for k in metrics.internal.counters)

    def test_record_finding(self, metrics):
        """Test recording finding."""
        metrics.record_finding(
            severity="high",
            finding_type="reentrancy",
            layer=2,
            confidence=0.85,
        )
        assert any("miesc_findings_total" in k for k in metrics.internal.counters)
        assert any("miesc_finding_confidence" in k for k in metrics.internal.histograms)

    def test_record_tool_execution(self, metrics):
        """Test recording tool execution."""
        metrics.record_tool_execution(
            tool="slither",
            layer=1,
            duration=2.5,
            success=True,
        )
        assert any("miesc_tool_executions_total" in k for k in metrics.internal.counters)
        assert any("miesc_tool_execution_seconds" in k for k in metrics.internal.histograms)

    def test_record_error(self, metrics):
        """Test recording error."""
        metrics.record_error(error_type="timeout", tool="mythril")
        assert any("miesc_errors_total" in k for k in metrics.internal.counters)

    def test_measure_time(self, metrics):
        """Test time measurement context manager."""
        with metrics.measure_time("test_metric", {"operation": "test"}):
            time.sleep(0.01)
        assert any("test_metric" in k for k in metrics.internal.histograms)

    def test_get_metrics_text(self, metrics):
        """Test getting metrics text."""
        metrics.record_finding("high", "reentrancy", 1, 0.9)
        text = metrics.get_metrics_text()
        assert "MIESC" in text

    def test_get_metrics_json(self, metrics):
        """Test getting metrics as JSON."""
        metrics.record_finding("high", "reentrancy", 1, 0.9)
        data = metrics.get_metrics_json()
        assert "counters" in data
        assert "gauges" in data


class TestTimedDecorator:
    """Test timed decorator."""

    def test_timed_decorator(self):
        """Test timed decorator."""

        @timed("test_function")
        def slow_function():
            time.sleep(0.01)
            return "result"

        result = slow_function()
        assert result == "result"

    def test_timed_preserves_return(self):
        """Test decorator preserves return value."""

        @timed("test_metric")
        def func():
            return {"key": "value"}

        result = func()
        assert result == {"key": "value"}


class TestGetAndResetMetrics:
    """Test global metrics functions."""

    def test_get_metrics(self):
        """Test getting global metrics."""
        reset_metrics()
        metrics = get_metrics()
        assert isinstance(metrics, MIESCMetrics)

    def test_get_metrics_singleton(self):
        """Test metrics is singleton."""
        reset_metrics()
        m1 = get_metrics()
        m2 = get_metrics()
        assert m1 is m2

    def test_reset_metrics(self):
        """Test resetting global metrics."""
        m1 = get_metrics()
        reset_metrics()
        m2 = get_metrics()
        assert m1 is not m2
