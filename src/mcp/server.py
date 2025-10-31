#!/usr/bin/env python3
"""
MCP Server for MIESC Framework

Exposes MIESC agents as Model Context Protocol server
Allows Claude Desktop to use agents as tools via MCP

Usage:
    python mcp_server.py --host localhost --port 3000

Configuration for Claude Desktop (~/.config/claude/claude_desktop_config.json):
{
  "mcpServers": {
    "miesc": {
      "command": "python",
      "args": ["/path/to/xaudit/mcp_server.py", "--stdio"],
      "env": {}
    }
  }
}
"""
import sys
import json
import logging
import argparse
from typing import Dict, Any, List
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.mcp.context_bus import get_context_bus
from src.agents.static_agent import StaticAgent
from src.agents.dynamic_agent import DynamicAgent
from src.agents.symbolic_agent import SymbolicAgent
from src.agents.formal_agent import FormalAgent
from src.agents.ai_agent import AIAgent
from src.agents.policy_agent import PolicyAgent
from src.agents.coordinator_agent import CoordinatorAgent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MCPServer:
    """
    MCP Server exposing MIESC agents as tools

    Implements Model Context Protocol for Claude Desktop integration
    """

    def __init__(self):
        self.context_bus = get_context_bus()
        self.agents = self._initialize_agents()
        logger.info("MCP Server initialized with %d agents", len(self.agents))

    def _initialize_agents(self) -> Dict[str, Any]:
        """
        Initialize all MIESC agents

        Returns:
            Dictionary of agent instances
        """
        return {
            "static": StaticAgent(),
            "dynamic": DynamicAgent(),
            "symbolic": SymbolicAgent(),
            "formal": FormalAgent(),
            "ai": AIAgent(),
            "policy": PolicyAgent(),
            "coordinator": CoordinatorAgent()
        }

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """
        Get MCP tools schema for Claude Desktop

        Returns:
            List of tool definitions in MCP format
        """
        return [
            {
                "name": "audit_contract",
                "description": (
                    "Perform comprehensive security audit on Solidity smart contract. "
                    "Uses multi-agent architecture with static analysis, dynamic testing, "
                    "symbolic execution, formal verification, and AI triage. "
                    "Compliant with ISO/IEC 27001, NIST SSDF, OWASP SC Top 10."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {
                            "type": "string",
                            "description": "Path to Solidity contract file"
                        },
                        "priority": {
                            "type": "string",
                            "enum": ["fast", "balanced", "comprehensive"],
                            "description": "Audit priority level",
                            "default": "balanced"
                        },
                        "layers": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": ["static", "dynamic", "symbolic", "formal", "ai", "policy"]
                            },
                            "description": "Layers to execute (default: all)"
                        }
                    },
                    "required": ["contract_path"]
                }
            },
            {
                "name": "static_analysis",
                "description": (
                    "Run static analysis tools (Slither, Solhint, Surya) on contract. "
                    "Fast initial security check for common vulnerabilities."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {
                            "type": "string",
                            "description": "Path to Solidity contract file"
                        },
                        "solc_version": {
                            "type": "string",
                            "description": "Solidity compiler version",
                            "default": "0.8.0"
                        }
                    },
                    "required": ["contract_path"]
                }
            },
            {
                "name": "ai_triage",
                "description": (
                    "AI-powered triage of vulnerability findings. "
                    "Identifies false positives, performs root cause analysis, "
                    "generates remediation recommendations."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {
                            "type": "string",
                            "description": "Path to Solidity contract file"
                        }
                    },
                    "required": ["contract_path"]
                }
            },
            {
                "name": "compliance_check",
                "description": (
                    "Check compliance with ISO/IEC 27001, NIST SSDF, OWASP SC Top 10. "
                    "Generates compliance report and recommendations."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "contract_path": {
                            "type": "string",
                            "description": "Path to Solidity contract file"
                        }
                    },
                    "required": ["contract_path"]
                }
            },
            {
                "name": "get_audit_status",
                "description": (
                    "Get current status of ongoing audit, including completed phases, "
                    "findings count, and real-time progress."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            },
            {
                "name": "export_audit_trail",
                "description": (
                    "Export complete audit trail for compliance (ISO 27001 A.8.15). "
                    "Includes all MCP messages and agent interactions."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "output_path": {
                            "type": "string",
                            "description": "Path to save audit trail JSON"
                        }
                    },
                    "required": ["output_path"]
                }
            }
        ]

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle MCP tool call from Claude Desktop

        Args:
            tool_name: Name of tool being called
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        try:
            if tool_name == "audit_contract":
                return self._audit_contract(arguments)

            elif tool_name == "static_analysis":
                return self._static_analysis(arguments)

            elif tool_name == "ai_triage":
                return self._ai_triage(arguments)

            elif tool_name == "compliance_check":
                return self._compliance_check(arguments)

            elif tool_name == "get_audit_status":
                return self._get_audit_status()

            elif tool_name == "export_audit_trail":
                return self._export_audit_trail(arguments)

            else:
                return {"error": f"Unknown tool: {tool_name}"}

        except Exception as e:
            logger.error(f"Tool call error: {e}", exc_info=True)
            return {"error": str(e)}

    def _audit_contract(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute comprehensive audit via CoordinatorAgent"""
        contract_path = args["contract_path"]
        priority = args.get("priority", "balanced")
        layers = args.get("layers", ["static", "dynamic", "ai", "policy"])

        coordinator = self.agents["coordinator"]
        results = coordinator.run(
            contract_path,
            priority=priority,
            audit_scope=layers
        )

        return {
            "success": True,
            "contract": contract_path,
            "audit_summary": results.get("audit_summary", {}),
            "audit_plan": results.get("audit_plan", {}),
            "message": "Audit completed successfully"
        }

    def _static_analysis(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute static analysis via StaticAgent"""
        contract_path = args["contract_path"]
        solc_version = args.get("solc_version", "0.8.0")

        static_agent = self.agents["static"]
        results = static_agent.run(contract_path, solc_version=solc_version)

        return {
            "success": True,
            "findings": results.get("static_findings", []),
            "total_findings": len(results.get("static_findings", [])),
            "message": f"Static analysis complete: {len(results.get('static_findings', []))} findings"
        }

    def _ai_triage(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute AI triage via AIAgent"""
        contract_path = args["contract_path"]

        ai_agent = self.agents["ai"]
        results = ai_agent.run(contract_path)

        return {
            "success": True,
            "triaged_findings": results.get("ai_triage", []),
            "false_positives": results.get("false_positives", []),
            "root_cause_analyses": results.get("root_cause_analysis", []),
            "message": "AI triage complete"
        }

    def _compliance_check(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance check via PolicyAgent"""
        contract_path = args["contract_path"]

        policy_agent = self.agents["policy"]
        results = policy_agent.run(contract_path)

        return {
            "success": True,
            "compliance_report": results.get("compliance_report", {}),
            "iso27001_status": results.get("iso27001_status", {}),
            "nist_ssdf_status": results.get("nist_ssdf_status", {}),
            "owasp_coverage": results.get("owasp_coverage", {}),
            "message": "Compliance check complete"
        }

    def _get_audit_status(self) -> Dict[str, Any]:
        """Get current audit status from CoordinatorAgent"""
        coordinator = self.agents["coordinator"]
        status = coordinator.get_audit_status()

        bus_stats = self.context_bus.get_stats()

        return {
            "success": True,
            "audit_status": status,
            "context_bus_stats": bus_stats,
            "active_agents": list(self.agents.keys())
        }

    def _export_audit_trail(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Export audit trail to file"""
        output_path = args["output_path"]

        self.context_bus.export_audit_trail(output_path)

        return {
            "success": True,
            "output_path": output_path,
            "message": f"Audit trail exported to {output_path}"
        }

    def run_stdio(self):
        """
        Run server in stdio mode for Claude Desktop

        Implements MCP protocol over stdin/stdout
        """
        logger.info("MCP Server running in stdio mode")

        while True:
            try:
                # Read JSON-RPC message from stdin
                line = sys.stdin.readline()
                if not line:
                    break

                message = json.loads(line)

                # Handle initialize request
                if message.get("method") == "initialize":
                    response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "protocolVersion": "1.0",
                            "serverInfo": {
                                "name": "miesc",
                                "version": "2.0"
                            },
                            "capabilities": {
                                "tools": self.get_tools_schema()
                            }
                        }
                    }
                    print(json.dumps(response), flush=True)

                # Handle tool call
                elif message.get("method") == "tools/call":
                    params = message.get("params", {})
                    tool_name = params.get("name")
                    arguments = params.get("arguments", {})

                    result = self.handle_tool_call(tool_name, arguments)

                    response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(result, indent=2)
                                }
                            ]
                        }
                    }
                    print(json.dumps(response), flush=True)

            except Exception as e:
                logger.error(f"Server error: {e}", exc_info=True)
                error_response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id") if 'message' in locals() else None,
                    "error": {
                        "code": -32603,
                        "message": str(e)
                    }
                }
                print(json.dumps(error_response), flush=True)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="MIESC MCP Server")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run in stdio mode for Claude Desktop"
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host to bind to (HTTP mode)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="Port to bind to (HTTP mode)"
    )

    args = parser.parse_args()

    server = MCPServer()

    if args.stdio:
        server.run_stdio()
    else:
        logger.info(f"MCP Server would run on {args.host}:{args.port}")
        logger.info("HTTP mode not yet implemented, use --stdio for Claude Desktop")
        logger.info("Configure Claude Desktop with:")
        print(json.dumps({
            "mcpServers": {
                "miesc": {
                    "command": "python",
                    "args": [str(Path(__file__).absolute()), "--stdio"],
                    "env": {}
                }
            }
        }, indent=2))


if __name__ == "__main__":
    main()
