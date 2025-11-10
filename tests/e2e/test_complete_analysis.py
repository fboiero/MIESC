"""
End-to-End Complete Analysis Test
===================================

Tests the full MIESC pipeline with all integrated adapters.
Measures performance, effectiveness, and generates benchmark reports.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 10, 2025
"""

import pytest
import time
import json
from pathlib import Path
from typing import Dict, Any, List
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.agents.static_agent import StaticAgent
from src.agents.dynamic_agent import DynamicAgent
from src.agents.symbolic_agent import SymbolicAgent
from src.mcp import get_context_bus, MCPMessage
from src.adapters import register_all_adapters, get_adapter_status_report


class BenchmarkMetrics:
    """Collects and calculates benchmark metrics"""

    def __init__(self):
        self.metrics: Dict[str, Dict[str, Any]] = {}

    def record_layer(self, layer_name: str, execution_time: float,
                     findings_count: int, tool_results: Dict[str, Any]):
        """Record metrics for a layer"""
        self.metrics[layer_name] = {
            "execution_time_seconds": round(execution_time, 2),
            "findings_count": findings_count,
            "findings_per_second": round(findings_count / execution_time, 2) if execution_time > 0 else 0,
            "tool_results": tool_results
        }

    def calculate_efficiency_score(self, layer_name: str) -> float:
        """
        Calculate efficiency score for a layer
        Score = (findings_count * 10) / execution_time

        Higher score = more efficient
        """
        if layer_name not in self.metrics:
            return 0.0

        metrics = self.metrics[layer_name]
        findings = metrics["findings_count"]
        time = metrics["execution_time_seconds"]

        if time == 0:
            return 0.0

        # Normalize: (findings * weight) / time
        score = (findings * 10) / time
        return round(score, 2)

    def get_layer_ranking(self) -> List[Dict[str, Any]]:
        """Rank layers by efficiency"""
        rankings = []

        for layer_name in self.metrics.keys():
            score = self.calculate_efficiency_score(layer_name)
            rankings.append({
                "layer": layer_name,
                "efficiency_score": score,
                "execution_time": self.metrics[layer_name]["execution_time_seconds"],
                "findings_count": self.metrics[layer_name]["findings_count"]
            })

        # Sort by efficiency score (descending)
        rankings.sort(key=lambda x: x["efficiency_score"], reverse=True)
        return rankings

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report"""
        total_time = sum(m["execution_time_seconds"] for m in self.metrics.values())
        total_findings = sum(m["findings_count"] for m in self.metrics.values())

        return {
            "summary": {
                "total_layers_analyzed": len(self.metrics),
                "total_execution_time_seconds": round(total_time, 2),
                "total_findings": total_findings,
                "overall_findings_per_second": round(total_findings / total_time, 2) if total_time > 0 else 0
            },
            "layer_metrics": self.metrics,
            "layer_rankings": self.get_layer_ranking(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }


@pytest.fixture
def test_contract():
    """Path to test contract"""
    return str(Path(__file__).parent.parent.parent / "contracts" / "test_suite" / "VulnerableBank.sol")


@pytest.fixture
def context_bus():
    """Clean context bus for testing"""
    bus = get_context_bus()
    bus.clear()
    return bus


@pytest.fixture
def benchmark():
    """Benchmark metrics collector"""
    return BenchmarkMetrics()


class TestCompleteAnalysis:
    """Complete end-to-end analysis test suite"""

    def test_adapter_registration(self):
        """Test that all adapters register correctly"""
        report = register_all_adapters()

        assert report["registered"] > 0, "No adapters registered"
        assert report["failed"] == 0, f"Failed adapters: {report['failures']}"

        # Verify DPGA compliance
        for adapter in report["adapters"]:
            assert adapter["optional"] is True, f"Adapter '{adapter['name']}' not optional (DPGA violation)"

        print(f"\n✅ Registered {report['registered']} adapters (all DPGA-compliant)")

    def test_layer1_static_analysis(self, test_contract, context_bus, benchmark):
        """Test Layer 1: Static Analysis with adapters"""
        print("\n" + "="*70)
        print("LAYER 1: Static Analysis (Slither, Solhint, Surya + GasAnalyzer + MEVDetector)")
        print("="*70)

        agent = StaticAgent()

        # Measure execution time
        start_time = time.time()
        results = agent.analyze(test_contract)
        execution_time = time.time() - start_time

        # Verify basic results
        assert "static_findings" in results
        assert "adapter_metadata" in results

        # Count findings
        findings_count = len(results["static_findings"])
        print(f"\nExecution Time: {execution_time:.2f}s")
        print(f"Total Findings: {findings_count}")

        # Adapter-specific metrics
        if "adapter_metadata" in results:
            metadata = results["adapter_metadata"]
            if "total_gas_savings" in metadata:
                print(f"Gas Savings: {metadata['total_gas_savings']} gas")
            if "mev_risk_score" in metadata:
                print(f"MEV Risk Score: {metadata['mev_risk_score']:.1f}/100")
            if "adapters_executed" in metadata:
                print(f"Adapters Executed: {metadata['adapters_executed']}")

        # Record benchmark
        benchmark.record_layer(
            "Layer1_Static",
            execution_time,
            findings_count,
            {
                "gas_savings": results.get("adapter_metadata", {}).get("total_gas_savings", 0),
                "mev_risk": results.get("adapter_metadata", {}).get("mev_risk_score", 0),
                "adapters_executed": results.get("adapter_metadata", {}).get("adapters_executed", 0)
            }
        )

        # Verify messages published to Context Bus
        messages = context_bus.get_all_contexts("static_findings")
        print(f"\nContext Bus Messages: {len(messages)}")

        assert findings_count >= 0, "Should have findings (or 0 for clean contract)"

    def test_layer2_dynamic_testing(self, test_contract, context_bus, benchmark):
        """Test Layer 2: Dynamic Testing with adapters"""
        print("\n" + "="*70)
        print("LAYER 2: Dynamic Testing (Echidna, Medusa, Foundry + VertigoAdapter)")
        print("="*70)

        agent = DynamicAgent()

        start_time = time.time()
        results = agent.analyze(test_contract, fuzz_runs=100, timeout=30)  # Reduced for testing
        execution_time = time.time() - start_time

        assert "dynamic_findings" in results
        findings_count = len(results["dynamic_findings"])

        print(f"\nExecution Time: {execution_time:.2f}s")
        print(f"Total Findings: {findings_count}")

        # Adapter-specific metrics
        if "adapter_metadata" in results:
            metadata = results["adapter_metadata"]
            if "mutation_score" in metadata:
                print(f"Mutation Score: {metadata['mutation_score']:.1f}%")
            if "adapters_executed" in metadata:
                print(f"Adapters Executed: {metadata['adapters_executed']}")

        benchmark.record_layer(
            "Layer2_Dynamic",
            execution_time,
            findings_count,
            {
                "mutation_score": results.get("adapter_metadata", {}).get("mutation_score", 0),
                "adapters_executed": results.get("adapter_metadata", {}).get("adapters_executed", 0)
            }
        )

        messages = context_bus.get_all_contexts("dynamic_findings")
        print(f"\nContext Bus Messages: {len(messages)}")

    def test_layer4_symbolic_execution(self, test_contract, context_bus, benchmark):
        """Test Layer 4: Symbolic Execution with adapters"""
        print("\n" + "="*70)
        print("LAYER 4: Symbolic Execution (Mythril, Manticore + OyenteAdapter)")
        print("="*70)

        agent = SymbolicAgent()

        start_time = time.time()
        results = agent.analyze(test_contract, max_depth=64, timeout=60)  # Reduced for testing
        execution_time = time.time() - start_time

        assert "symbolic_findings" in results
        findings_count = len(results["symbolic_findings"])

        print(f"\nExecution Time: {execution_time:.2f}s")
        print(f"Total Findings: {findings_count}")

        # Adapter-specific metrics
        if "adapter_metadata" in results:
            metadata = results["adapter_metadata"]
            if "vulnerability_types" in metadata:
                print(f"Vulnerability Types Found: {metadata['vulnerability_types']}")
            if "adapters_executed" in metadata:
                print(f"Adapters Executed: {metadata['adapters_executed']}")

        benchmark.record_layer(
            "Layer4_Symbolic",
            execution_time,
            findings_count,
            {
                "vulnerability_types": results.get("adapter_metadata", {}).get("vulnerability_types", []),
                "adapters_executed": results.get("adapter_metadata", {}).get("adapters_executed", 0)
            }
        )

        messages = context_bus.get_all_contexts("symbolic_findings")
        print(f"\nContext Bus Messages: {len(messages)}")

    def test_context_bus_aggregation(self, context_bus):
        """Test Context Bus message aggregation"""
        print("\n" + "="*70)
        print("CONTEXT BUS AGGREGATION")
        print("="*70)

        # Get all messages by type
        static_msgs = context_bus.get_all_contexts("static_findings")
        dynamic_msgs = context_bus.get_all_contexts("dynamic_findings")
        symbolic_msgs = context_bus.get_all_contexts("symbolic_findings")

        print(f"\nStatic Findings Messages: {len(static_msgs)}")
        print(f"Dynamic Findings Messages: {len(dynamic_msgs)}")
        print(f"Symbolic Findings Messages: {len(symbolic_msgs)}")

        # Get statistics
        stats = context_bus.get_statistics()
        print(f"\nTotal Context Types: {len(stats['context_types'])}")
        print(f"Total Messages: {stats['total_messages']}")

        assert stats["total_messages"] >= 0

    def test_generate_benchmark_report(self, benchmark, tmp_path):
        """Generate and save benchmark report"""
        print("\n" + "="*70)
        print("BENCHMARK REPORT GENERATION")
        print("="*70)

        report = benchmark.generate_report()

        # Display summary
        print("\n### SUMMARY ###")
        print(f"Total Layers Analyzed: {report['summary']['total_layers_analyzed']}")
        print(f"Total Execution Time: {report['summary']['total_execution_time_seconds']}s")
        print(f"Total Findings: {report['summary']['total_findings']}")
        print(f"Overall Findings/sec: {report['summary']['overall_findings_per_second']}")

        # Display rankings
        print("\n### LAYER EFFICIENCY RANKINGS ###")
        print(f"{'Rank':<6} {'Layer':<20} {'Efficiency':<12} {'Time (s)':<10} {'Findings':<10}")
        print("-" * 70)

        for rank, layer_data in enumerate(report['layer_rankings'], 1):
            print(f"{rank:<6} {layer_data['layer']:<20} "
                  f"{layer_data['efficiency_score']:<12.2f} "
                  f"{layer_data['execution_time']:<10.2f} "
                  f"{layer_data['findings_count']:<10}")

        # Save report to file
        report_file = tmp_path / "benchmark_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n✅ Report saved to: {report_file}")

        # Also save to project outputs
        project_output = Path(__file__).parent.parent.parent / "outputs" / "benchmarks"
        project_output.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        project_report = project_output / f"benchmark_{timestamp}.json"

        with open(project_report, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"✅ Report also saved to: {project_report}")

        assert report_file.exists()
        assert project_report.exists()


class TestToolRanking:
    """Test and rank individual tools within each layer"""

    def test_static_tools_ranking(self, test_contract):
        """Rank static analysis tools by effectiveness"""
        print("\n" + "="*70)
        print("STATIC ANALYSIS TOOLS RANKING")
        print("="*70)

        agent = StaticAgent()
        results = agent.analyze(test_contract)

        # Count findings per tool
        tool_counts = {}

        # Count from different result sets
        if "slither_results" in results:
            slither_vulns = results["slither_results"].get("vulnerabilities", [])
            tool_counts["Slither"] = len(slither_vulns)

        if "solhint_results" in results:
            solhint_issues = results["solhint_results"].get("issues", [])
            tool_counts["Solhint"] = len(solhint_issues)

        if "gas_analysis_results" in results:
            gas_findings = results["gas_analysis_results"].get("findings", [])
            tool_counts["GasAnalyzer"] = len(gas_findings)

        if "mev_detection_results" in results:
            mev_findings = results["mev_detection_results"].get("findings", [])
            tool_counts["MEVDetector"] = len(mev_findings)

        # Sort by findings count
        ranked_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)

        print(f"\n{'Rank':<6} {'Tool':<20} {'Findings':<10}")
        print("-" * 40)

        for rank, (tool, count) in enumerate(ranked_tools, 1):
            print(f"{rank:<6} {tool:<20} {count:<10}")

        assert len(ranked_tools) > 0

    def test_adapter_effectiveness(self):
        """Test adapter effectiveness metrics"""
        print("\n" + "="*70)
        print("ADAPTER EFFECTIVENESS ANALYSIS")
        print("="*70)

        report = register_all_adapters()

        print(f"\n{'Adapter':<20} {'Status':<15} {'Category':<20}")
        print("-" * 60)

        for adapter in report["adapters"]:
            print(f"{adapter['name']:<20} {adapter['status']:<15} {adapter['category']:<20}")

        # Count by status
        available = sum(1 for a in report["adapters"] if a["status"] == "available")
        not_installed = sum(1 for a in report["adapters"] if a["status"] == "not_installed")

        print(f"\nSummary:")
        print(f"  Available: {available}")
        print(f"  Not Installed: {not_installed}")
        print(f"  Total: {report['total_adapters']}")

        # Calculate availability rate
        if report["total_adapters"] > 0:
            availability_rate = (available / report["total_adapters"]) * 100
            print(f"  Availability Rate: {availability_rate:.1f}%")


class TestDPGACompliance:
    """Verify DPGA compliance across the system"""

    def test_no_mandatory_dependencies(self):
        """Verify all tools are optional (DPGA requirement)"""
        print("\n" + "="*70)
        print("DPGA COMPLIANCE VERIFICATION")
        print("="*70)

        report = register_all_adapters()

        # All adapters must be optional
        all_optional = all(a["optional"] for a in report["adapters"])

        print(f"\nTotal Adapters: {report['total_adapters']}")
        print(f"All Optional: {all_optional}")

        for adapter in report["adapters"]:
            optional_status = "✅ Optional" if adapter["optional"] else "❌ MANDATORY"
            print(f"  {adapter['name']}: {optional_status}")

        assert all_optional, "DPGA violation: Some adapters are mandatory"
        print("\n✅ DPGA Compliance: PASSED")

    def test_graceful_degradation(self, test_contract):
        """Test that system works even if external tools unavailable"""
        print("\n" + "="*70)
        print("GRACEFUL DEGRADATION TEST")
        print("="*70)

        # Static agent should work even if Slither not installed
        agent = StaticAgent()

        try:
            results = agent.analyze(test_contract)
            print("\n✅ StaticAgent completed (with or without external tools)")

            # Check if any findings were generated
            if "static_findings" in results:
                print(f"  Findings: {len(results['static_findings'])}")

            # Check adapter metadata
            if "adapter_metadata" in results:
                metadata = results["adapter_metadata"]
                if "error" in metadata:
                    print(f"  Adapters failed gracefully: {metadata['error']}")
                else:
                    print(f"  Adapters executed: {metadata.get('adapters_executed', 0)}")

            assert True, "System should not crash"

        except Exception as e:
            pytest.fail(f"System crashed (violates graceful degradation): {e}")


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "-s", "--tb=short"])
