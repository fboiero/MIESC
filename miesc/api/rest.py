"""
MIESC REST API - Django REST Framework Implementation

Provides REST endpoints for smart contract security analysis:
- POST /api/v1/analyze/ - Run security audits
- GET /api/v1/tools/ - List available tools
- GET /api/v1/layers/ - Layer information
- GET /api/v1/reports/ - Manage audit reports
- GET /api/v1/health/ - System health checks

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
License: AGPL-3.0
"""

import importlib
import logging
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Add src to path for imports
ROOT_DIR = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))
sys.path.insert(0, str(ROOT_DIR))

logger = logging.getLogger(__name__)

# Try to import Django components
try:
    import django
    from django.conf import settings as django_settings
    from django.core.wsgi import get_wsgi_application as django_get_wsgi_application
    from django.http import HttpRequest, HttpResponse, JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    from django.views.decorators.http import require_http_methods

    DJANGO_AVAILABLE = True
except ImportError:
    DJANGO_AVAILABLE = False
    logger.warning("Django not installed. REST API unavailable.")

# Try to import DRF components
try:
    from rest_framework import status
    from rest_framework.decorators import api_view, permission_classes
    from rest_framework.permissions import AllowAny
    from rest_framework.request import Request
    from rest_framework.response import Response

    DRF_AVAILABLE = True
except ImportError:
    DRF_AVAILABLE = False
    logger.warning("Django REST Framework not installed.")


# ============================================================================
# Configuration
# ============================================================================

VERSION = "4.3.2"

# Layer definitions (same as CLI)
LAYERS = {
    1: {
        "name": "Static Analysis",
        "description": "Pattern-based code analysis",
        "tools": ["slither", "aderyn", "solhint", "wake"],
    },
    2: {
        "name": "Dynamic Testing",
        "description": "Fuzzing and property testing",
        "tools": ["echidna", "medusa", "foundry", "dogefuzz", "vertigo"],
    },
    3: {
        "name": "Symbolic Execution",
        "description": "Path exploration and constraint solving",
        "tools": ["mythril", "manticore", "halmos", "oyente"],
    },
    4: {
        "name": "Formal Verification",
        "description": "Mathematical proofs of correctness",
        "tools": ["certora", "smtchecker", "propertygpt"],
    },
    5: {
        "name": "AI Analysis",
        "description": "LLM-powered vulnerability detection",
        "tools": ["smartllm", "gptscan", "llmsmartaudit"],
    },
    6: {
        "name": "ML Detection",
        "description": "Machine learning classifiers",
        "tools": ["dagnn", "smartbugs_ml", "smartbugs_detector", "smartguard"],
    },
    7: {
        "name": "Specialized Analysis",
        "description": "Domain-specific security checks",
        "tools": [
            "threat_model",
            "gas_analyzer",
            "mev_detector",
            "contract_clone_detector",
            "defi",
            "advanced_detector",
        ],
    },
    8: {
        "name": "Cross-Chain & ZK Security",
        "description": "Bridge security and zero-knowledge circuit analysis",
        "tools": ["crosschain", "zk_circuit"],
    },
    9: {
        "name": "Advanced AI Ensemble",
        "description": "Multi-LLM ensemble with consensus-based detection",
        "tools": ["llmbugscanner"],
    },
}

# Adapter class mapping
ADAPTER_MAP = {
    "slither": "SlitherAdapter",
    "aderyn": "AderynAdapter",
    "solhint": "SolhintAdapter",
    "wake": "WakeAdapter",
    "echidna": "EchidnaAdapter",
    "medusa": "MedusaAdapter",
    "foundry": "FoundryAdapter",
    "dogefuzz": "DogeFuzzAdapter",
    "vertigo": "VertigoAdapter",
    "mythril": "MythrilAdapter",
    "manticore": "ManticoreAdapter",
    "halmos": "HalmosAdapter",
    "oyente": "OyenteAdapter",
    "certora": "CertoraAdapter",
    "smtchecker": "SMTCheckerAdapter",
    "propertygpt": "PropertyGPTAdapter",
    "smartllm": "SmartLLMAdapter",
    "gptscan": "GPTScanAdapter",
    "llmsmartaudit": "LLMSmartAuditAdapter",
    "dagnn": "DAGNNAdapter",
    "smartbugs_ml": "SmartBugsMLAdapter",
    "smartbugs_detector": "SmartBugsDetectorAdapter",
    "smartguard": "SmartGuardAdapter",
    "threat_model": "ThreatModelAdapter",
    "gas_analyzer": "GasAnalyzerAdapter",
    "mev_detector": "MEVDetectorAdapter",
    "contract_clone_detector": "ContractCloneDetectorAdapter",
    "defi": "DeFiAdapter",
    "advanced_detector": "AdvancedDetectorAdapter",
    # Layer 8: Cross-Chain & ZK Security
    "crosschain": "CrossChainAdapter",
    "zk_circuit": "ZKCircuitAdapter",
    # Layer 9: Advanced AI Ensemble
    "llmbugscanner": "LLMBugScannerAdapter",
}

# Quick scan tools
QUICK_TOOLS = ["slither", "aderyn", "solhint", "mythril"]


# ============================================================================
# Django Settings Configuration
# ============================================================================


def configure_django():
    """Configure Django settings if not already configured."""
    if not django_settings.configured:
        django_settings.configure(
            DEBUG=os.environ.get("MIESC_DEBUG", "false").lower() == "true",
            SECRET_KEY=os.environ.get(
                "MIESC_SECRET_KEY", "miesc-development-key-change-in-production"
            ),
            ROOT_URLCONF="miesc.api.rest",
            ALLOWED_HOSTS=["*"],
            INSTALLED_APPS=[
                "django.contrib.contenttypes",
                "django.contrib.auth",
                "rest_framework",
                "corsheaders",
            ],
            MIDDLEWARE=[
                "corsheaders.middleware.CorsMiddleware",
                "django.middleware.common.CommonMiddleware",
            ],
            CORS_ALLOW_ALL_ORIGINS=True,
            CORS_ALLOW_CREDENTIALS=True,
            REST_FRAMEWORK={
                "DEFAULT_PERMISSION_CLASSES": [
                    "rest_framework.permissions.AllowAny",
                ],
                "DEFAULT_RENDERER_CLASSES": [
                    "rest_framework.renderers.JSONRenderer",
                ],
                "DEFAULT_PARSER_CLASSES": [
                    "rest_framework.parsers.JSONParser",
                    "rest_framework.parsers.FormParser",
                    "rest_framework.parsers.MultiPartParser",
                ],
                "EXCEPTION_HANDLER": "miesc.api.rest.custom_exception_handler",
            },
            DATABASES={},
            USE_TZ=True,
        )
        django.setup()


# ============================================================================
# Adapter Loader
# ============================================================================


class AdapterLoader:
    """Dynamic loader for tool adapters."""

    _adapters: Dict[str, Any] = {}
    _loaded = False

    @classmethod
    def load_all(cls) -> Dict[str, Any]:
        """Load all available adapters from src/adapters/."""
        if cls._loaded:
            return cls._adapters

        for tool_name, class_name in ADAPTER_MAP.items():
            try:
                module_name = f"src.adapters.{tool_name}_adapter"
                module = importlib.import_module(module_name)
                adapter_class = getattr(module, class_name, None)

                if adapter_class:
                    cls._adapters[tool_name] = adapter_class()
                    logger.debug(f"Loaded adapter: {tool_name}")

            except ImportError as e:
                logger.debug(f"Could not import {tool_name}: {e}")
            except Exception as e:
                logger.debug(f"Error loading {tool_name}: {e}")

        cls._loaded = True
        return cls._adapters

    @classmethod
    def get_adapter(cls, tool_name: str):
        """Get a specific adapter by name."""
        if not cls._loaded:
            cls.load_all()
        return cls._adapters.get(tool_name)

    @classmethod
    def get_available_tools(cls) -> List[str]:
        """Get list of tools with available adapters."""
        if not cls._loaded:
            cls.load_all()
        return list(cls._adapters.keys())

    @classmethod
    def check_tool_status(cls, tool_name: str) -> Dict[str, Any]:
        """Check if a tool is installed and available."""
        adapter = cls.get_adapter(tool_name)
        if not adapter:
            return {"status": "no_adapter", "available": False}

        try:
            from src.core.tool_protocol import ToolStatus

            tool_status = adapter.is_available()
            return {
                "status": tool_status.value if hasattr(tool_status, "value") else str(tool_status),
                "available": tool_status == ToolStatus.AVAILABLE,
            }
        except Exception as e:
            return {"status": "error", "available": False, "error": str(e)}


# ============================================================================
# Analysis Functions
# ============================================================================


def run_tool(tool: str, contract_path: str, timeout: int = 300, **kwargs) -> Dict[str, Any]:
    """
    Run a single security tool using its adapter.

    Args:
        tool: Tool name (e.g., 'slither', 'mythril')
        contract_path: Path to Solidity contract
        timeout: Timeout in seconds
        **kwargs: Additional tool-specific parameters

    Returns:
        Normalized results dictionary
    """
    start_time = datetime.now(timezone.utc)

    adapter = AdapterLoader.get_adapter(tool)

    if not adapter:
        return {
            "tool": tool,
            "contract": contract_path,
            "status": "no_adapter",
            "findings": [],
            "execution_time": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": f"No adapter found for {tool}",
        }

    try:
        from src.core.tool_protocol import ToolStatus

        tool_status = adapter.is_available()

        if tool_status != ToolStatus.AVAILABLE:
            return {
                "tool": tool,
                "contract": contract_path,
                "status": "not_available",
                "findings": [],
                "execution_time": (datetime.now(timezone.utc) - start_time).total_seconds(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": f"Tool {tool} not available: {tool_status.value}",
            }

        result = adapter.analyze(contract_path, timeout=timeout, **kwargs)

        return {
            "tool": tool,
            "contract": contract_path,
            "status": result.get("status", "success"),
            "findings": result.get("findings", []),
            "execution_time": result.get(
                "execution_time", (datetime.now(timezone.utc) - start_time).total_seconds()
            ),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": result.get("metadata", {}),
            "error": result.get("error"),
        }

    except Exception as e:
        logger.error(f"Error running {tool}: {e}", exc_info=True)
        return {
            "tool": tool,
            "contract": contract_path,
            "status": "error",
            "findings": [],
            "execution_time": (datetime.now(timezone.utc) - start_time).total_seconds(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }


def run_layer(layer: int, contract_path: str, timeout: int = 300) -> List[Dict[str, Any]]:
    """Run all tools in a specific layer."""
    if layer not in LAYERS:
        return []

    results = []
    layer_info = LAYERS[layer]

    for tool in layer_info["tools"]:
        result = run_tool(tool, contract_path, timeout)
        results.append(result)

    return results


def run_full_audit(
    contract_path: str, layers: List[int] = None, timeout: int = 600
) -> Dict[str, Any]:
    """Run a complete multi-layer audit."""
    if layers is None:
        layers = list(LAYERS.keys())

    audit_id = str(uuid.uuid4())
    start_time = datetime.now(timezone.utc)
    all_results = []

    for layer in layers:
        if layer in LAYERS:
            layer_results = run_layer(layer, contract_path, timeout)
            all_results.extend(layer_results)

    summary = summarize_findings(all_results)
    execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()

    return {
        "audit_id": audit_id,
        "contract": contract_path,
        "layers": layers,
        "results": all_results,
        "summary": summary,
        "execution_time": execution_time,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
    }


def summarize_findings(results: List[Dict[str, Any]]) -> Dict[str, int]:
    """Summarize findings by severity."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for result in results:
        for finding in result.get("findings", []):
            sev = str(finding.get("severity", "INFO")).upper()
            if sev in ["CRITICAL", "CRIT"]:
                summary["CRITICAL"] += 1
            elif sev in ["HIGH", "HI"]:
                summary["HIGH"] += 1
            elif sev in ["MEDIUM", "MED"]:
                summary["MEDIUM"] += 1
            elif sev in ["LOW", "LO"]:
                summary["LOW"] += 1
            else:
                summary["INFO"] += 1

    return summary


def to_sarif(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convert results to SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MIESC",
                        "version": VERSION,
                        "informationUri": "https://github.com/fboiero/MIESC",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }

    rule_ids = set()

    for result in results:
        tool_name = result.get("tool", "unknown")

        for finding in result.get("findings", []):
            rule_id = finding.get("type", finding.get("id", finding.get("title", "unknown")))

            if rule_id not in rule_ids:
                sarif["runs"][0]["tool"]["driver"]["rules"].append(
                    {
                        "id": rule_id,
                        "name": finding.get("title", rule_id),
                        "shortDescription": {"text": finding.get("message", rule_id)},
                        "fullDescription": {"text": finding.get("description", "")},
                        "properties": {"tool": tool_name},
                    }
                )
                rule_ids.add(rule_id)

            severity = str(finding.get("severity", "INFO")).upper()
            level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
                severity, "note"
            )

            location = finding.get("location", {})
            if isinstance(location, dict):
                file_path = location.get("file", result.get("contract", "unknown"))
                line = location.get("line", 1)
            else:
                file_path = result.get("contract", "unknown")
                line = 1

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": finding.get("description", finding.get("message", ""))},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path},
                                "region": {"startLine": max(1, int(line))},
                            }
                        }
                    ],
                    "properties": {"tool": tool_name, "confidence": finding.get("confidence", 0.5)},
                }
            )

    return sarif


# ============================================================================
# Custom Exception Handler
# ============================================================================


def custom_exception_handler(exc, context):
    """Custom exception handler for DRF."""
    if DRF_AVAILABLE:
        from rest_framework.views import exception_handler

        response = exception_handler(exc, context)

        if response is not None:
            response.data["status_code"] = response.status_code
            return response

    return Response({"error": str(exc), "status_code": 500}, status=500)


# ============================================================================
# API Views (Django REST Framework)
# ============================================================================

if DRF_AVAILABLE:

    @api_view(["GET"])
    @permission_classes([AllowAny])
    def api_root(request: Request) -> Response:
        """API root endpoint with available endpoints."""
        return Response(
            {
                "service": "MIESC REST API",
                "version": VERSION,
                "description": "Multi-layer Intelligent Evaluation for Smart Contracts",
                "endpoints": {
                    "analyze": {
                        "quick": "/api/v1/analyze/quick/",
                        "full": "/api/v1/analyze/full/",
                        "layer": "/api/v1/analyze/layer/{layer_num}/",
                        "tool": "/api/v1/analyze/tool/{tool_name}/",
                    },
                    "tools": {"list": "/api/v1/tools/", "info": "/api/v1/tools/{tool_name}/"},
                    "layers": "/api/v1/layers/",
                    "health": "/api/v1/health/",
                    "reports": "/api/v1/reports/",
                },
                "documentation": "https://fboiero.github.io/MIESC/api/",
                "repository": "https://github.com/fboiero/MIESC",
            }
        )

    @api_view(["POST"])
    @permission_classes([AllowAny])
    def analyze_quick(request: Request) -> Response:
        """
        Run a quick 4-tool scan (slither, aderyn, solhint, mythril).

        Request Body:
            - contract_code: str - Solidity source code
            - contract_path: str - Path to contract file (alternative)
            - timeout: int - Timeout per tool in seconds (default: 300)
            - format: str - Output format: json, sarif (default: json)
        """
        contract_code = request.data.get("contract_code")
        contract_path = request.data.get("contract_path")
        timeout = request.data.get("timeout", 300)
        output_format = request.data.get("format", "json")

        if not contract_code and not contract_path:
            return Response(
                {"error": "Either contract_code or contract_path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # If code is provided, save to temp file
        if contract_code:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
                f.write(contract_code)
                contract_path = f.name

        try:
            all_results = []
            for tool in QUICK_TOOLS:
                result = run_tool(tool, contract_path, timeout)
                all_results.append(result)

            summary = summarize_findings(all_results)

            response_data = {
                "audit_type": "quick",
                "tools": QUICK_TOOLS,
                "results": all_results,
                "summary": summary,
                "total_findings": sum(summary.values()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": VERSION,
            }

            if output_format == "sarif":
                response_data = to_sarif(all_results)

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Quick analysis error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            # Cleanup temp file if created
            if contract_code and contract_path and os.path.exists(contract_path):
                os.unlink(contract_path)

    @api_view(["POST"])
    @permission_classes([AllowAny])
    def analyze_full(request: Request) -> Response:
        """
        Run a complete 7-layer audit with all 29 tools.

        Request Body:
            - contract_code: str - Solidity source code
            - contract_path: str - Path to contract file (alternative)
            - layers: list[int] - Specific layers to run (default: 1-7)
            - timeout: int - Timeout per tool in seconds (default: 600)
            - format: str - Output format: json, sarif (default: json)
        """
        contract_code = request.data.get("contract_code")
        contract_path = request.data.get("contract_path")
        layers = request.data.get("layers", list(LAYERS.keys()))
        timeout = request.data.get("timeout", 600)
        output_format = request.data.get("format", "json")

        if not contract_code and not contract_path:
            return Response(
                {"error": "Either contract_code or contract_path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate layers
        valid_layers = [l for l in layers if l in LAYERS]
        if not valid_layers:
            return Response(
                {"error": "Invalid layers. Valid layers: 1-7"}, status=status.HTTP_400_BAD_REQUEST
            )

        # If code is provided, save to temp file
        if contract_code:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
                f.write(contract_code)
                contract_path = f.name

        try:
            result = run_full_audit(contract_path, valid_layers, timeout)

            if output_format == "sarif":
                result = to_sarif(result.get("results", []))

            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Full audit error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            if contract_code and contract_path and os.path.exists(contract_path):
                os.unlink(contract_path)

    @api_view(["POST"])
    @permission_classes([AllowAny])
    def analyze_layer(request: Request, layer_num: int) -> Response:
        """
        Run all tools in a specific layer (1-7).
        """
        if layer_num not in LAYERS:
            return Response(
                {"error": f"Invalid layer: {layer_num}. Valid layers: 1-7"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        contract_code = request.data.get("contract_code")
        contract_path = request.data.get("contract_path")
        timeout = request.data.get("timeout", 300)

        if not contract_code and not contract_path:
            return Response(
                {"error": "Either contract_code or contract_path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if contract_code:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
                f.write(contract_code)
                contract_path = f.name

        try:
            layer_info = LAYERS[layer_num]
            results = run_layer(layer_num, contract_path, timeout)
            summary = summarize_findings(results)

            return Response(
                {
                    "layer": layer_num,
                    "layer_name": layer_info["name"],
                    "layer_description": layer_info["description"],
                    "tools": layer_info["tools"],
                    "results": results,
                    "summary": summary,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Layer analysis error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            if contract_code and contract_path and os.path.exists(contract_path):
                os.unlink(contract_path)

    @api_view(["POST"])
    @permission_classes([AllowAny])
    def analyze_tool(request: Request, tool_name: str) -> Response:
        """
        Run a single security tool.
        """
        if tool_name not in ADAPTER_MAP:
            return Response(
                {
                    "error": f"Unknown tool: {tool_name}",
                    "available_tools": list(ADAPTER_MAP.keys()),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        contract_code = request.data.get("contract_code")
        contract_path = request.data.get("contract_path")
        timeout = request.data.get("timeout", 300)

        if not contract_code and not contract_path:
            return Response(
                {"error": "Either contract_code or contract_path is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if contract_code:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
                f.write(contract_code)
                contract_path = f.name

        try:
            result = run_tool(tool_name, contract_path, timeout)
            return Response(result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Tool analysis error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        finally:
            if contract_code and contract_path and os.path.exists(contract_path):
                os.unlink(contract_path)

    @api_view(["GET"])
    @permission_classes([AllowAny])
    def tools_list(request: Request) -> Response:
        """
        List all 29 security tools with their status.
        """
        AdapterLoader.load_all()

        tools_by_layer = {}
        all_tools = []

        for layer_num, layer_info in LAYERS.items():
            layer_tools = []
            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)
                tool_data = {
                    "name": tool,
                    "layer": layer_num,
                    "layer_name": layer_info["name"],
                    "status": status_info.get("status", "unknown"),
                    "available": status_info.get("available", False),
                }
                layer_tools.append(tool_data)
                all_tools.append(tool_data)

            tools_by_layer[layer_num] = {
                "name": layer_info["name"],
                "description": layer_info["description"],
                "tools": layer_tools,
            }

        available_count = sum(1 for t in all_tools if t["available"])

        return Response(
            {
                "total_tools": len(all_tools),
                "available_tools": available_count,
                "layers": tools_by_layer,
                "tools": all_tools,
            },
            status=status.HTTP_200_OK,
        )

    @api_view(["GET"])
    @permission_classes([AllowAny])
    def tools_info(request: Request, tool_name: str) -> Response:
        """
        Get detailed information about a specific tool.
        """
        if tool_name not in ADAPTER_MAP:
            return Response(
                {"error": f"Unknown tool: {tool_name}"}, status=status.HTTP_404_NOT_FOUND
            )

        adapter = AdapterLoader.get_adapter(tool_name)

        if not adapter:
            return Response(
                {
                    "name": tool_name,
                    "status": "no_adapter",
                    "available": False,
                    "error": f"Adapter for {tool_name} not loaded",
                },
                status=status.HTTP_200_OK,
            )

        try:
            metadata = adapter.get_metadata()
            tool_status = adapter.is_available()

            # Find which layer this tool belongs to
            tool_layer = None
            for layer_num, layer_info in LAYERS.items():
                if tool_name in layer_info["tools"]:
                    tool_layer = {"number": layer_num, **layer_info}
                    break

            return Response(
                {
                    "name": metadata.name,
                    "version": metadata.version,
                    "category": (
                        metadata.category.value
                        if hasattr(metadata.category, "value")
                        else str(metadata.category)
                    ),
                    "author": metadata.author,
                    "license": metadata.license,
                    "homepage": metadata.homepage,
                    "repository": metadata.repository,
                    "documentation": metadata.documentation,
                    "installation_cmd": metadata.installation_cmd,
                    "status": (
                        tool_status.value if hasattr(tool_status, "value") else str(tool_status)
                    ),
                    "available": (
                        tool_status.value == "available" if hasattr(tool_status, "value") else False
                    ),
                    "layer": tool_layer,
                    "capabilities": (
                        [
                            {
                                "name": cap.name,
                                "description": cap.description,
                                "detection_types": cap.detection_types[:10],
                            }
                            for cap in metadata.capabilities
                        ]
                        if hasattr(metadata, "capabilities")
                        else []
                    ),
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"Error getting tool info: {e}", exc_info=True)
            return Response(
                {"name": tool_name, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @api_view(["GET"])
    @permission_classes([AllowAny])
    def layers_list(request: Request) -> Response:
        """
        Get information about all 7 defense layers.
        """
        AdapterLoader.load_all()

        layers_data = []
        for layer_num, layer_info in LAYERS.items():
            # Check tool availability for this layer
            tools_status = []
            available_count = 0
            for tool in layer_info["tools"]:
                status_info = AdapterLoader.check_tool_status(tool)
                is_available = status_info.get("available", False)
                if is_available:
                    available_count += 1
                tools_status.append(
                    {
                        "name": tool,
                        "available": is_available,
                        "status": status_info.get("status", "unknown"),
                    }
                )

            layers_data.append(
                {
                    "number": layer_num,
                    "name": layer_info["name"],
                    "description": layer_info["description"],
                    "total_tools": len(layer_info["tools"]),
                    "available_tools": available_count,
                    "tools": tools_status,
                }
            )

        return Response(
            {"total_layers": len(LAYERS), "layers": layers_data}, status=status.HTTP_200_OK
        )

    @api_view(["GET"])
    @permission_classes([AllowAny])
    def health_check(request: Request) -> Response:
        """
        System health check endpoint.
        """
        AdapterLoader.load_all()
        available_tools = AdapterLoader.get_available_tools()

        # Check basic dependencies
        dependencies = {}
        import subprocess

        for dep, cmd in [
            ("python", "python3 --version"),
            ("solc", "solc --version"),
            ("node", "node --version"),
        ]:
            try:
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
                dependencies[dep] = {
                    "available": result.returncode == 0,
                    "version": (
                        result.stdout.strip().split("\n")[0][:50]
                        if result.returncode == 0
                        else None
                    ),
                }
            except Exception:
                dependencies[dep] = {"available": False, "version": None}

        # Count tools by status
        all_tools = []
        for layer_info in LAYERS.values():
            all_tools.extend(layer_info["tools"])

        available_count = 0
        for tool in all_tools:
            status_info = AdapterLoader.check_tool_status(tool)
            if status_info.get("available"):
                available_count += 1

        overall_status = (
            "healthy"
            if available_count >= 5
            else "degraded" if available_count > 0 else "unhealthy"
        )

        return Response(
            {
                "status": overall_status,
                "version": VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "total": len(all_tools),
                    "available": available_count,
                    "percentage": (
                        round(available_count / len(all_tools) * 100, 1) if all_tools else 0
                    ),
                },
                "dependencies": dependencies,
                "endpoints": {
                    "rest_api": True,
                    "websocket": False,  # WebSocket handled separately
                    "mcp": True,
                },
            },
            status=status.HTTP_200_OK,
        )

    @api_view(["GET", "POST"])
    @permission_classes([AllowAny])
    def reports_list(request: Request) -> Response:
        """
        List or create audit reports.

        Note: In this version, reports are not persisted to database.
        This endpoint returns sample data or processes inline reports.
        """
        if request.method == "GET":
            return Response(
                {
                    "message": "Reports endpoint",
                    "note": "Reports are returned inline with analysis results. Persistence coming in v4.3.",
                    "documentation": "https://fboiero.github.io/MIESC/api/reports/",
                },
                status=status.HTTP_200_OK,
            )

        elif request.method == "POST":
            # Accept a report for processing/validation
            report_data = request.data
            if not report_data:
                return Response(
                    {"error": "Report data required"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Validate and return enhanced report
            return Response(
                {
                    "status": "accepted",
                    "report_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": report_data,
                },
                status=status.HTTP_201_CREATED,
            )


# ============================================================================
# URL Configuration
# ============================================================================

if DJANGO_AVAILABLE:
    from django.urls import path

    urlpatterns = []

    if DRF_AVAILABLE:
        urlpatterns = [
            # Root
            path("", api_root, name="api-root"),
            path("api/", api_root, name="api-root-alt"),
            path("api/v1/", api_root, name="api-v1-root"),
            # Analysis endpoints
            path("api/v1/analyze/quick/", analyze_quick, name="analyze-quick"),
            path("api/v1/analyze/full/", analyze_full, name="analyze-full"),
            path("api/v1/analyze/layer/<int:layer_num>/", analyze_layer, name="analyze-layer"),
            path("api/v1/analyze/tool/<str:tool_name>/", analyze_tool, name="analyze-tool"),
            # Tools endpoints
            path("api/v1/tools/", tools_list, name="tools-list"),
            path("api/v1/tools/<str:tool_name>/", tools_info, name="tools-info"),
            # Layers endpoints
            path("api/v1/layers/", layers_list, name="layers-list"),
            # Health endpoint
            path("api/v1/health/", health_check, name="health-check"),
            path("health/", health_check, name="health-check-alt"),
            # Reports endpoints
            path("api/v1/reports/", reports_list, name="reports-list"),
        ]


# ============================================================================
# Application Factory
# ============================================================================


def create_app():
    """Create and configure the Django application."""
    if not DJANGO_AVAILABLE:
        raise ImportError(
            "Django is not installed. Run: pip install django djangorestframework django-cors-headers"
        )

    configure_django()

    # Pre-load adapters
    AdapterLoader.load_all()

    return True


def get_wsgi_application():
    """Get the WSGI application."""
    create_app()
    return django_get_wsgi_application()


# Create the app instance
app = None
if DJANGO_AVAILABLE:
    try:
        create_app()
        app = get_wsgi_application()
    except Exception as e:
        logger.error(f"Error creating Django app: {e}")


# ============================================================================
# Server Runner
# ============================================================================


def run_server(host: str = "0.0.0.0", port: int = 5001, debug: bool = False):
    """Run the Django development server."""
    if not DJANGO_AVAILABLE:
        print(
            "Django is not installed. Run: pip install django djangorestframework django-cors-headers"
        )
        return

    import sys

    from django.core.management import execute_from_command_line

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "miesc.api.rest")
    create_app()

    sys.argv = ["manage.py", "runserver", f"{host}:{port}"]
    if not debug:
        sys.argv.append("--noreload")

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MIESC REST API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address")
    parser.add_argument("--port", type=int, default=5001, help="Port number")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    print(f"Starting MIESC REST API on http://{args.host}:{args.port}")
    print(f"API Documentation: http://{args.host}:{args.port}/api/v1/")
    print(f"Health Check: http://{args.host}:{args.port}/health/")

    run_server(args.host, args.port, args.debug)
