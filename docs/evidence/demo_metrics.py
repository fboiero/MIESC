#!/usr/bin/env python3
"""
MIESC v4.2.0 - Demo: Metrics Module
====================================
Demonstrates the observability metrics system:
- Prometheus-compatible metrics
- Internal fallback collector
- Audit, tool, and finding tracking
- Time measurement utilities

Author: Fernando Boiero
License: GPL-3.0
"""

import sys
import time
sys.path.insert(0, '/Users/fboiero/Documents/GitHub/MIESC')

from src.core.metrics import (
    MIESCMetrics,
    InternalMetricsCollector,
    MetricValue,
    get_metrics,
    reset_metrics,
    timed,
    PROMETHEUS_AVAILABLE,
)


def print_separator(title: str):
    """Print a visual separator."""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def demo_internal_collector():
    """Demo the internal metrics collector."""
    print_separator("Internal Metrics Collector")

    collector = InternalMetricsCollector()

    # Counter operations
    print("Counter Operations:")
    collector.increment_counter("test_counter", 1, {"env": "demo"})
    collector.increment_counter("test_counter", 5, {"env": "demo"})
    print(f"  test_counter{{env=demo}} = {collector.counters.get('test_counter{env=demo}', 0)}")

    # Gauge operations
    print("\nGauge Operations:")
    collector.set_gauge("active_connections", 42, {"service": "api"})
    print(f"  active_connections{{service=api}} = {collector.gauges.get('active_connections{service=api}', 0)}")

    # Histogram observations
    print("\nHistogram Operations:")
    for duration in [0.1, 0.5, 1.2, 0.8, 2.5]:
        collector.observe_histogram("request_duration", duration, {"endpoint": "/audit"})

    hist_key = "request_duration{endpoint=/audit}"
    hist_data = collector.histograms.get(hist_key, [])
    print(f"  request_duration observations: {len(hist_data)}")
    print(f"  Values: {hist_data}")
    print(f"  Sum: {sum(hist_data):.2f}s")
    print(f"  Avg: {sum(hist_data)/len(hist_data):.2f}s")

    # Get all metrics
    print("\nAll Metrics Summary:")
    metrics = collector.get_metrics()
    print(f"  Counters: {len(metrics['counters'])}")
    print(f"  Gauges: {len(metrics['gauges'])}")
    print(f"  Histograms: {len(metrics['histograms'])}")


def demo_miesc_metrics():
    """Demo the main MIESC metrics system."""
    print_separator("MIESC Metrics System")

    print(f"Prometheus Available: {PROMETHEUS_AVAILABLE}")

    # Reset and get fresh instance
    reset_metrics()
    metrics = get_metrics()

    print("\nSimulating Audit Workflow:")

    # 1. Start audit
    print("\n  [1] Starting audit...")
    metrics.record_audit_start()

    # 2. Simulate tool executions
    tools_data = [
        ("slither", 1, 2.5, True, 3),
        ("aderyn", 1, 1.8, True, 2),
        ("mythril", 3, 45.2, True, 5),
        ("smtchecker", 5, 120.5, True, 1),
        ("echidna", 4, 30.0, False, 0),  # Simulated failure
    ]

    print("\n  [2] Running tools...")
    for tool, layer, duration, success, findings in tools_data:
        metrics.record_tool_execution(tool, layer, duration, success)
        status = "OK" if success else "FAIL"
        print(f"      {tool:12} Layer {layer} - {duration:6.1f}s [{status}]")

    # 3. Record findings
    findings_data = [
        ("critical", "reentrancy", 1, 0.95),
        ("high", "overflow", 3, 0.88),
        ("high", "unchecked_call", 1, 0.82),
        ("medium", "gas_optimization", 1, 0.75),
        ("low", "naming_convention", 1, 0.60),
    ]

    print("\n  [3] Recording findings...")
    for severity, ftype, layer, confidence in findings_data:
        metrics.record_finding(severity, ftype, layer, confidence)
        print(f"      {severity:10} - {ftype:20} (confidence: {confidence:.0%})")

    # 4. Record an error
    print("\n  [4] Recording error...")
    metrics.record_error("timeout", "echidna")
    print("      Recorded: timeout error in echidna")

    # 5. End audit
    print("\n  [5] Completing audit...")
    total_duration = sum(t[2] for t in tools_data)
    metrics.record_audit_end("success", total_duration, 7)
    print(f"      Total duration: {total_duration:.1f}s")

    # 6. Show collected metrics
    print("\n  [6] Metrics Summary:")
    internal_metrics = metrics.internal.get_metrics()

    print("\n      Counters:")
    for key, value in internal_metrics['counters'].items():
        print(f"        {key} = {value}")

    print("\n      Gauges:")
    for key, value in internal_metrics['gauges'].items():
        print(f"        {key} = {value}")

    print("\n      Histograms:")
    for key, data in internal_metrics['histograms'].items():
        print(f"        {key}:")
        print(f"          count={data['count']}, sum={data['sum']:.2f}")


def demo_time_measurement():
    """Demo time measurement utilities."""
    print_separator("Time Measurement Utilities")

    reset_metrics()
    metrics = get_metrics()

    # Using context manager
    print("Context Manager (measure_time):")
    with metrics.measure_time("demo_operation", {"type": "context_manager"}):
        time.sleep(0.1)  # Simulate work
    print("  Measured demo_operation with context manager")

    # Using decorator
    print("\nDecorator (@timed):")

    @timed("decorated_function")
    def sample_operation():
        time.sleep(0.05)
        return "done"

    result = sample_operation()
    print(f"  Function returned: {result}")

    # Show timing results
    print("\nTiming Results:")
    hist = metrics.internal.histograms
    for key, values in hist.items():
        if values:
            print(f"  {key}: {values[-1]*1000:.1f}ms")


def demo_metric_value():
    """Demo MetricValue dataclass."""
    print_separator("MetricValue Dataclass")

    metric = MetricValue(
        name="miesc_findings_total",
        type="counter",
        value=42.0,
        labels={"severity": "critical", "layer": "1"}
    )

    print(f"Name: {metric.name}")
    print(f"Type: {metric.type}")
    print(f"Value: {metric.value}")
    print(f"Labels: {metric.labels}")
    print(f"Timestamp: {metric.timestamp.isoformat()}")


def demo_prometheus_format():
    """Demo Prometheus text format output."""
    print_separator("Prometheus Text Format")

    reset_metrics()
    metrics = get_metrics()

    # Record some data
    metrics.record_finding("critical", "reentrancy", 1, 0.95)
    metrics.record_finding("high", "overflow", 3, 0.88)
    metrics.record_tool_execution("slither", 1, 2.5, True)

    # Get text format
    text_output = metrics.get_metrics_text()
    print(text_output)


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("       MIESC v4.2.0 'Fortress' - Metrics Demo")
    print("       Observability & Monitoring System")
    print("=" * 60)

    demo_internal_collector()
    demo_miesc_metrics()
    demo_time_measurement()
    demo_metric_value()
    demo_prometheus_format()

    print("\n" + "=" * 60)
    print("  Metrics Demo Complete!")
    print("=" * 60 + "\n")
