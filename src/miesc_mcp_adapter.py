"""
MIESC MCP Adapter - Model Context Protocol Integration

Exposes MIESC capabilities as an MCP-compatible agent for:
- Inter-agent communication
- Collaborative cyberdefense
- Distributed security assessment
- Real-time threat intelligence sharing

MCP Protocol: https://modelcontextprotocol.io/specification
Scientific Context: Multi-agent systems for cyberdefense (Wooldridge & Jennings, 1995)

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import json
import logging
import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from src.miesc_core import MIESCCore
from src.miesc_ai_layer import AICorrelator
from src.miesc_policy_mapper import PolicyMapper
from src.mcp.context_bus import MCPMessage, get_context_bus

logger = logging.getLogger(__name__)


@dataclass
class MCPCapability:
    """MCP Agent Capability Definition"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    category: str  # "analysis", "correlation", "compliance", "reporting"


class MIESCMCPAdapter:
    """
    MCP Adapter for MIESC - Model Context Protocol Integration

    Capabilities exposed:
    1. run_audit: Execute complete multi-tool audit
    2. correlate_findings: AI-powered finding correlation
    3. map_compliance: Map findings to standards
    4. calculate_metrics: Compute precision/recall/F1/kappa
    5. generate_report: Create structured reports
    6. get_agent_status: Query agent status
    7. subscribe_to_findings: Real-time finding subscription
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize MCP Adapter

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.agent_id = "miesc-agent-v3.0.0"
        self.protocol_version = "mcp/1.0"

        # Initialize MIESC components
        self.core = MIESCCore(config)
        self.correlator = AICorrelator(
            api_key=config.get('openai_api_key'),
            model=config.get('llm_model', 'gpt-4o')
        )
        self.policy_mapper = PolicyMapper()

        # MCP Context Bus
        self.context_bus = get_context_bus()

        # Capability registry
        self.capabilities = self._register_capabilities()

        # Active subscriptions
        self.subscriptions: Dict[str, List[Callable]] = {}

        logger.info(f"MIESC MCP Adapter initialized: {self.agent_id}")

    def _register_capabilities(self) -> Dict[str, MCPCapability]:
        """Register all MCP capabilities"""
        return {
            "run_audit": MCPCapability(
                name="run_audit",
                description="Execute comprehensive multi-tool security audit",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contract_path": {"type": "string"},
                        "tools": {"type": "array", "items": {"type": "string"}},
                        "enable_ai_triage": {"type": "boolean"}
                    },
                    "required": ["contract_path"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array"},
                        "metrics": {"type": "object"},
                        "compliance": {"type": "object"}
                    }
                },
                category="analysis"
            ),

            "correlate_findings": MCPCapability(
                name="correlate_findings",
                description="Apply AI correlation to reduce false positives",
                input_schema={
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array"},
                        "contract_source": {"type": "string"}
                    },
                    "required": ["findings"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "correlated_findings": {"type": "array"},
                        "reduction_rate": {"type": "number"}
                    }
                },
                category="correlation"
            ),

            "map_compliance": MCPCapability(
                name="map_compliance",
                description="Map findings to international security standards",
                input_schema={
                    "type": "object",
                    "properties": {
                        "findings": {"type": "array"}
                    },
                    "required": ["findings"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "compliance_matrix": {"type": "object"},
                        "compliance_score": {"type": "number"},
                        "gaps": {"type": "array"}
                    }
                },
                category="compliance"
            ),

            "calculate_metrics": MCPCapability(
                name="calculate_metrics",
                description="Calculate scientific validation metrics",
                input_schema={
                    "type": "object",
                    "properties": {
                        "predictions": {"type": "array"},
                        "ground_truth": {"type": "array"}
                    },
                    "required": ["predictions", "ground_truth"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "precision": {"type": "number"},
                        "recall": {"type": "number"},
                        "f1_score": {"type": "number"},
                        "cohens_kappa": {"type": "number"}
                    }
                },
                category="metrics"
            ),

            "generate_report": MCPCapability(
                name="generate_report",
                description="Generate structured audit report",
                input_schema={
                    "type": "object",
                    "properties": {
                        "audit_results": {"type": "object"},
                        "format": {"type": "string", "enum": ["json", "html", "pdf"]}
                    },
                    "required": ["audit_results"]
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "report_path": {"type": "string"},
                        "report_data": {"type": "object"}
                    }
                },
                category="reporting"
            ),

            "get_status": MCPCapability(
                name="get_status",
                description="Get MIESC agent status and capabilities",
                input_schema={
                    "type": "object",
                    "properties": {}
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "agent_id": {"type": "string"},
                        "status": {"type": "string"},
                        "capabilities": {"type": "array"}
                    }
                },
                category="management"
            )
        }

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle MCP request (JSON-RPC style)

        Args:
            request: MCP request dictionary

        Returns:
            MCP response dictionary
        """
        method = request.get("method")
        params = request.get("params", {})
        request_id = request.get("id")

        logger.info(f"MCP Request: {method} (ID: {request_id})")

        try:
            # Route to appropriate handler
            if method == "run_audit":
                result = await self._handle_run_audit(params)
            elif method == "correlate_findings":
                result = await self._handle_correlate_findings(params)
            elif method == "map_compliance":
                result = await self._handle_map_compliance(params)
            elif method == "calculate_metrics":
                result = await self._handle_calculate_metrics(params)
            elif method == "generate_report":
                result = await self._handle_generate_report(params)
            elif method == "get_status":
                result = await self._handle_get_status(params)
            else:
                raise ValueError(f"Unknown method: {method}")

            # Success response
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result
            }

        except Exception as e:
            logger.error(f"MCP Request failed: {e}")
            # Error response
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32000,
                    "message": str(e),
                    "data": {"agent_id": self.agent_id}
                }
            }

        return response

    async def _handle_run_audit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute complete audit workflow"""
        contract_path = params["contract_path"]
        tools = params.get("tools", ["slither", "mythril", "aderyn"])
        enable_ai = params.get("enable_ai_triage", True)

        # Phase 1: Multi-tool scanning
        scan_results = self.core.scan_contract(contract_path, tools=tools)

        # Publish to Context Bus
        self.context_bus.publish(MCPMessage(
            agent=self.agent_id,
            context_type="miesc_scan_results",
            contract=contract_path,
            data=scan_results
        ))

        # Phase 2: AI correlation (if enabled)
        correlated_findings = []
        if enable_ai:
            raw_findings = scan_results['raw_findings']
            correlated = self.correlator.correlate_findings(raw_findings)
            correlated_findings = [asdict(c) for c in correlated]

            # Publish correlated findings
            self.context_bus.publish(MCPMessage(
                agent=self.agent_id,
                context_type="miesc_correlated_findings",
                contract=contract_path,
                data={"findings": correlated_findings}
            ))

        # Phase 3: Compliance mapping
        findings_to_map = correlated_findings if correlated_findings else scan_results['raw_findings']
        compliance_matrix = self.policy_mapper.generate_compliance_matrix(findings_to_map)

        # Publish compliance data
        self.context_bus.publish(MCPMessage(
            agent=self.agent_id,
            context_type="miesc_compliance",
            contract=contract_path,
            data=compliance_matrix
        ))

        # Return complete results
        return {
            "contract": contract_path,
            "scan_results": scan_results,
            "correlated_findings": correlated_findings,
            "compliance_matrix": compliance_matrix,
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    async def _handle_correlate_findings(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle correlation request"""
        findings = params["findings"]
        contract_source = params.get("contract_source")

        original_count = len(findings)
        correlated = self.correlator.correlate_findings(findings, contract_source)
        correlated_count = len(correlated)

        reduction_rate = (original_count - correlated_count) / original_count if original_count > 0 else 0

        return {
            "correlated_findings": [asdict(c) for c in correlated],
            "original_count": original_count,
            "correlated_count": correlated_count,
            "reduction_rate": round(reduction_rate, 4)
        }

    async def _handle_map_compliance(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle compliance mapping request"""
        findings = params["findings"]

        compliance_matrix = self.policy_mapper.generate_compliance_matrix(findings)

        return compliance_matrix

    async def _handle_calculate_metrics(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle metrics calculation request"""
        from src.miesc_ai_layer import MetricsCalculator

        predictions = params["predictions"]
        ground_truth = params["ground_truth"]

        metrics = MetricsCalculator.calculate_metrics(predictions, ground_truth)

        return metrics

    async def _handle_generate_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle report generation request"""
        audit_results = params["audit_results"]
        format = params.get("format", "json")

        # Generate report
        report_path = f"analysis/results/miesc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.{format}"

        if format == "json":
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, 'w') as f:
                json.dump(audit_results, f, indent=2)

        return {
            "report_path": report_path,
            "format": format,
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }

    async def _handle_get_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle status request"""
        return {
            "agent_id": self.agent_id,
            "protocol_version": self.protocol_version,
            "status": "active",
            "capabilities": [
                {
                    "name": cap.name,
                    "description": cap.description,
                    "category": cap.category
                }
                for cap in self.capabilities.values()
            ],
            "components": {
                "core": "active",
                "ai_correlator": "active" if self.correlator else "disabled",
                "policy_mapper": "active",
                "context_bus": "connected"
            },
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def publish_finding(self, finding: Dict[str, Any], contract: str) -> None:
        """
        Publish a finding to the MCP Context Bus

        Args:
            finding: Finding dictionary
            contract: Contract path
        """
        self.context_bus.publish(MCPMessage(
            agent=self.agent_id,
            context_type="miesc_finding",
            contract=contract,
            data=finding
        ))

    def subscribe_to_context(
        self,
        context_type: str,
        callback: Callable[[MCPMessage], None]
    ) -> None:
        """
        Subscribe to MCP context updates

        Args:
            context_type: Type of context to subscribe to
            callback: Callback function
        """
        self.context_bus.subscribe(context_type, callback)
        logger.info(f"Subscribed to {context_type}")

    def get_manifest(self) -> Dict[str, Any]:
        """
        Get MCP agent manifest

        Returns:
            Agent manifest for discovery and interoperability
        """
        return {
            "agent_id": self.agent_id,
            "agent_name": "MIESC - Multi-layer Intelligent Evaluation for Smart Contracts",
            "version": "3.0.0",
            "protocol": self.protocol_version,
            "description": (
                "Automated security assessment framework for smart contracts. "
                "Provides multi-tool scanning, AI-powered correlation, and compliance mapping."
            ),
            "author": "Fernando Boiero - UNDEF",
            "license": "GPL-3.0",
            "capabilities": [
                {
                    "name": cap.name,
                    "description": cap.description,
                    "category": cap.category,
                    "input_schema": cap.input_schema,
                    "output_schema": cap.output_schema
                }
                for cap in self.capabilities.values()
            ],
            "context_types": [
                "miesc_scan_results",
                "miesc_correlated_findings",
                "miesc_compliance",
                "miesc_finding"
            ],
            "subscriptions": [
                "contract_deployed",
                "security_incident",
                "compliance_request"
            ],
            "endpoints": {
                "jsonrpc": "/mcp/jsonrpc",
                "websocket": "/mcp/ws",
                "rest": "/api/v1"
            },
            "metadata": {
                "scientific_foundation": "Defense-in-depth, Multi-agent systems",
                "compliance_standards": [
                    "ISO/IEC 27001:2022",
                    "NIST CSF",
                    "OWASP SC Top 10",
                    "CWE",
                    "SWC",
                    "MITRE ATT&CK"
                ],
                "thesis": "Master's in Cyberdefense - UNDEF",
                "contact": "fboiero@frvm.utn.edu.ar"
            }
        }

    def export_manifest(self, output_path: str) -> None:
        """Export agent manifest to JSON file"""
        manifest = self.get_manifest()

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"Manifest exported to {output_path}")


# Example usage
if __name__ == "__main__":
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize adapter
    adapter = MIESCMCPAdapter()

    # Export manifest
    adapter.export_manifest("mcp/manifest.json")

    # Example request
    async def test_request():
        request = {
            "jsonrpc": "2.0",
            "id": "test-001",
            "method": "get_status",
            "params": {}
        }

        response = await adapter.handle_request(request)
        print(json.dumps(response, indent=2))

    asyncio.run(test_request())
