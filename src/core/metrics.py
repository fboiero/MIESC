"""
MIESC Metrics System

Provides observability metrics for monitoring audit performance,
tool execution, and system health using Prometheus format.

Author: Fernando Boiero
License: GPL-3.0
"""

import time
import logging
from typing import Any, Callable, Dict, List, Optional
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timezone
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Try to import prometheus_client, provide fallback if not available
try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Summary,
        Info,
        CollectorRegistry,
        generate_latest,
        CONTENT_TYPE_LATEST,
        start_http_server
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed. Metrics will be collected internally only.")


@dataclass
class MetricValue:
    """Internal metric value storage."""
    name: str
    type: str  # counter, histogram, gauge, summary
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class InternalMetricsCollector:
    """
    Internal metrics collector for when Prometheus is not available.
    Stores metrics in memory for later retrieval.
    """

    def __init__(self):
        self.metrics: List[MetricValue] = []
        self.counters: Dict[str, float] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = {}

    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        key = self._make_key(name, labels)
        self.counters[key] = self.counters.get(key, 0) + value
        self.metrics.append(MetricValue(name, "counter", self.counters[key], labels or {}))

    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric."""
        key = self._make_key(name, labels)
        self.gauges[key] = value
        self.metrics.append(MetricValue(name, "gauge", value, labels or {}))

    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Add observation to histogram."""
        key = self._make_key(name, labels)
        if key not in self.histograms:
            self.histograms[key] = []
        self.histograms[key].append(value)
        self.metrics.append(MetricValue(name, "histogram", value, labels or {}))

    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Create a unique key from name and labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        return {
            "counters": self.counters,
            "gauges": self.gauges,
            "histograms": {k: {"count": len(v), "sum": sum(v), "values": v[-100:]}
                         for k, v in self.histograms.items()},
            "recent": self.metrics[-100:]
        }

    def clear(self):
        """Clear all metrics."""
        self.metrics.clear()
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()


class MIESCMetrics:
    """
    MIESC Metrics collection system.

    Provides both Prometheus metrics (if available) and internal
    metrics collection for monitoring audit performance.

    Usage:
        metrics = MIESCMetrics()

        # Count findings
        metrics.findings_total.labels(severity="high").inc()

        # Track audit duration
        with metrics.audit_duration.labels(layers="7").time():
            run_audit()

        # Track tool execution
        metrics.tool_execution_seconds.labels(tool="slither").observe(2.5)
    """

    def __init__(self, registry: Optional['CollectorRegistry'] = None):
        self.internal = InternalMetricsCollector()

        if PROMETHEUS_AVAILABLE:
            self.registry = registry or CollectorRegistry()
            self._init_prometheus_metrics()
        else:
            self.registry = None
            self._init_internal_metrics()

    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics."""
        # Counters
        self.audits_total = Counter(
            'miesc_audits_total',
            'Total number of audits performed',
            ['status'],
            registry=self.registry
        )

        self.findings_total = Counter(
            'miesc_findings_total',
            'Total number of findings detected',
            ['severity', 'type', 'layer'],
            registry=self.registry
        )

        self.tool_executions_total = Counter(
            'miesc_tool_executions_total',
            'Total tool executions',
            ['tool', 'status'],
            registry=self.registry
        )

        self.errors_total = Counter(
            'miesc_errors_total',
            'Total errors encountered',
            ['type', 'tool'],
            registry=self.registry
        )

        # Histograms
        self.audit_duration_seconds = Histogram(
            'miesc_audit_duration_seconds',
            'Audit duration in seconds',
            ['layers'],
            buckets=[1, 5, 10, 30, 60, 120, 300, 600],
            registry=self.registry
        )

        self.tool_execution_seconds = Histogram(
            'miesc_tool_execution_seconds',
            'Tool execution duration in seconds',
            ['tool', 'layer'],
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60],
            registry=self.registry
        )

        self.finding_confidence = Histogram(
            'miesc_finding_confidence',
            'Finding confidence scores',
            ['severity'],
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            registry=self.registry
        )

        # Gauges
        self.active_audits = Gauge(
            'miesc_active_audits',
            'Number of currently running audits',
            registry=self.registry
        )

        self.tools_available = Gauge(
            'miesc_tools_available',
            'Number of available tools',
            ['layer'],
            registry=self.registry
        )

        self.cache_size = Gauge(
            'miesc_cache_size_bytes',
            'Size of result cache in bytes',
            registry=self.registry
        )

        # Info
        self.info = Info(
            'miesc',
            'MIESC version and configuration info',
            registry=self.registry
        )
        self.info.info({
            'version': '4.1.0',
            'layers': '7',
            'python_version': '3.11'
        })

    def _init_internal_metrics(self):
        """Initialize internal-only metrics when Prometheus is unavailable."""
        # Create wrapper objects that use internal collector
        self.audits_total = InternalCounter('miesc_audits_total', self.internal)
        self.findings_total = InternalCounter('miesc_findings_total', self.internal)
        self.tool_executions_total = InternalCounter('miesc_tool_executions_total', self.internal)
        self.errors_total = InternalCounter('miesc_errors_total', self.internal)

        self.audit_duration_seconds = InternalHistogram('miesc_audit_duration_seconds', self.internal)
        self.tool_execution_seconds = InternalHistogram('miesc_tool_execution_seconds', self.internal)
        self.finding_confidence = InternalHistogram('miesc_finding_confidence', self.internal)

        self.active_audits = InternalGauge('miesc_active_audits', self.internal)
        self.tools_available = InternalGauge('miesc_tools_available', self.internal)
        self.cache_size = InternalGauge('miesc_cache_size_bytes', self.internal)

    def record_audit_start(self):
        """Record the start of an audit."""
        if PROMETHEUS_AVAILABLE:
            self.active_audits.inc()
        else:
            self.internal.set_gauge('miesc_active_audits',
                                   self.internal.gauges.get('miesc_active_audits', 0) + 1)

    def record_audit_end(self, status: str, duration: float, layers: int):
        """Record the completion of an audit."""
        if PROMETHEUS_AVAILABLE:
            self.active_audits.dec()
            self.audits_total.labels(status=status).inc()
            self.audit_duration_seconds.labels(layers=str(layers)).observe(duration)
        else:
            self.internal.set_gauge('miesc_active_audits',
                                   max(0, self.internal.gauges.get('miesc_active_audits', 0) - 1))
            self.internal.increment_counter('miesc_audits_total', labels={'status': status})
            self.internal.observe_histogram('miesc_audit_duration_seconds', duration,
                                           labels={'layers': str(layers)})

    def record_finding(self, severity: str, finding_type: str, layer: int, confidence: float):
        """Record a security finding."""
        if PROMETHEUS_AVAILABLE:
            self.findings_total.labels(
                severity=severity,
                type=finding_type,
                layer=str(layer)
            ).inc()
            self.finding_confidence.labels(severity=severity).observe(confidence)
        else:
            self.internal.increment_counter('miesc_findings_total',
                                           labels={'severity': severity, 'type': finding_type, 'layer': str(layer)})
            self.internal.observe_histogram('miesc_finding_confidence', confidence,
                                           labels={'severity': severity})

    def record_tool_execution(self, tool: str, layer: int, duration: float, success: bool):
        """Record a tool execution."""
        status = "success" if success else "failure"
        if PROMETHEUS_AVAILABLE:
            self.tool_executions_total.labels(tool=tool, status=status).inc()
            self.tool_execution_seconds.labels(tool=tool, layer=str(layer)).observe(duration)
        else:
            self.internal.increment_counter('miesc_tool_executions_total',
                                           labels={'tool': tool, 'status': status})
            self.internal.observe_histogram('miesc_tool_execution_seconds', duration,
                                           labels={'tool': tool, 'layer': str(layer)})

    def record_error(self, error_type: str, tool: str = "unknown"):
        """Record an error."""
        if PROMETHEUS_AVAILABLE:
            self.errors_total.labels(type=error_type, tool=tool).inc()
        else:
            self.internal.increment_counter('miesc_errors_total',
                                           labels={'type': error_type, 'tool': tool})

    @contextmanager
    def measure_time(self, metric_name: str, labels: Dict[str, str] = None):
        """Context manager to measure execution time."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.internal.observe_histogram(metric_name, duration, labels)

    def get_metrics_text(self) -> str:
        """Get metrics in Prometheus text format."""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(self.registry).decode('utf-8')
        else:
            # Generate simple text format for internal metrics
            lines = ["# MIESC Internal Metrics\n"]
            for key, value in self.internal.counters.items():
                lines.append(f"{key} {value}")
            for key, value in self.internal.gauges.items():
                lines.append(f"{key} {value}")
            return "\n".join(lines)

    def get_metrics_json(self) -> Dict[str, Any]:
        """Get metrics as JSON-serializable dictionary."""
        return self.internal.get_metrics()

    def start_http_server(self, port: int = 9090):
        """Start HTTP server to expose metrics."""
        if PROMETHEUS_AVAILABLE:
            start_http_server(port, registry=self.registry)
            logger.info(f"Prometheus metrics server started on port {port}")
        else:
            logger.warning("Cannot start HTTP server: prometheus_client not installed")


class InternalCounter:
    """Internal counter wrapper for when Prometheus is unavailable."""

    def __init__(self, name: str, collector: InternalMetricsCollector):
        self.name = name
        self.collector = collector

    def labels(self, **kwargs) -> 'InternalCounter':
        """Return labeled counter."""
        self._labels = kwargs
        return self

    def inc(self, value: float = 1.0):
        """Increment counter."""
        labels = getattr(self, '_labels', {})
        self.collector.increment_counter(self.name, value, labels)


class InternalHistogram:
    """Internal histogram wrapper for when Prometheus is unavailable."""

    def __init__(self, name: str, collector: InternalMetricsCollector):
        self.name = name
        self.collector = collector

    def labels(self, **kwargs) -> 'InternalHistogram':
        """Return labeled histogram."""
        self._labels = kwargs
        return self

    def observe(self, value: float):
        """Record observation."""
        labels = getattr(self, '_labels', {})
        self.collector.observe_histogram(self.name, value, labels)

    @contextmanager
    def time(self):
        """Context manager to measure time."""
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(time.perf_counter() - start)


class InternalGauge:
    """Internal gauge wrapper for when Prometheus is unavailable."""

    def __init__(self, name: str, collector: InternalMetricsCollector):
        self.name = name
        self.collector = collector
        self._labels = {}

    def labels(self, **kwargs) -> 'InternalGauge':
        """Return labeled gauge."""
        self._labels = kwargs
        return self

    def set(self, value: float):
        """Set gauge value."""
        self.collector.set_gauge(self.name, value, self._labels)

    def inc(self, value: float = 1.0):
        """Increment gauge."""
        key = self.collector._make_key(self.name, self._labels)
        current = self.collector.gauges.get(key, 0)
        self.set(current + value)

    def dec(self, value: float = 1.0):
        """Decrement gauge."""
        key = self.collector._make_key(self.name, self._labels)
        current = self.collector.gauges.get(key, 0)
        self.set(current - value)


def timed(metric: str):
    """Decorator to measure function execution time."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration = time.perf_counter() - start
                logger.debug(f"{metric}: {func.__name__} took {duration:.3f}s")
        return wrapper
    return decorator


# Global metrics instance
_metrics: Optional[MIESCMetrics] = None


def get_metrics() -> MIESCMetrics:
    """Get the global metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = MIESCMetrics()
    return _metrics


def reset_metrics():
    """Reset the global metrics instance."""
    global _metrics
    _metrics = None
