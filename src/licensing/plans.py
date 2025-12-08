"""
Definición de planes de licencia para MIESC SaaS.
"""

from enum import Enum
from typing import Dict, List, Any


class PlanType(str, Enum):
    """Tipos de planes disponibles."""
    FREE = "FREE"
    STARTER = "STARTER"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"


# Herramientas disponibles por capa
TOOLS_LAYER_1 = ["slither", "solhint", "aderyn"]  # Static Analysis
TOOLS_LAYER_2 = ["echidna", "medusa", "foundry"]  # Dynamic Testing
TOOLS_LAYER_3 = ["mythril", "manticore", "halmos"]  # Symbolic Execution
TOOLS_LAYER_4 = ["certora", "smtchecker", "wake"]  # Formal Verification
TOOLS_LAYER_5 = ["smartllm", "gptscan"]  # AI Analysis
TOOLS_LAYER_6 = ["dagnn", "policyagent"]  # ML Detection
TOOLS_LAYER_7 = ["layer7agent"]  # Audit Readiness

ALL_TOOLS = (
    TOOLS_LAYER_1 + TOOLS_LAYER_2 + TOOLS_LAYER_3 +
    TOOLS_LAYER_4 + TOOLS_LAYER_5 + TOOLS_LAYER_6 + TOOLS_LAYER_7
)


# Configuración de planes
PLANS: Dict[PlanType, Dict[str, Any]] = {
    PlanType.FREE: {
        "name": "Free",
        "description": "Plan gratuito con funcionalidades básicas",
        "max_audits_month": 5,
        "max_contract_size_kb": 50,
        "allowed_tools": ["slither", "solhint"],
        "ai_enabled": False,
        "formal_verification": False,
        "export_formats": ["json"],
        "priority_support": False,
        "api_access": False,
    },
    PlanType.STARTER: {
        "name": "Starter",
        "description": "Plan inicial para desarrolladores individuales",
        "max_audits_month": 50,
        "max_contract_size_kb": 200,
        "allowed_tools": ["slither", "solhint", "aderyn", "mythril", "echidna"],
        "ai_enabled": False,
        "formal_verification": False,
        "export_formats": ["json", "markdown"],
        "priority_support": False,
        "api_access": True,
    },
    PlanType.PRO: {
        "name": "Pro",
        "description": "Plan profesional con todas las herramientas",
        "max_audits_month": 500,
        "max_contract_size_kb": 1024,  # 1MB
        "allowed_tools": ALL_TOOLS,
        "ai_enabled": True,
        "formal_verification": True,
        "export_formats": ["json", "markdown", "html", "pdf"],
        "priority_support": True,
        "api_access": True,
    },
    PlanType.ENTERPRISE: {
        "name": "Enterprise",
        "description": "Plan empresarial sin límites",
        "max_audits_month": -1,  # Ilimitado
        "max_contract_size_kb": -1,  # Sin límite
        "allowed_tools": ALL_TOOLS,
        "ai_enabled": True,
        "formal_verification": True,
        "export_formats": ["json", "markdown", "html", "pdf"],
        "priority_support": True,
        "api_access": True,
        "dedicated_support": True,
        "custom_integrations": True,
    },
}


def get_plan_config(plan_type: PlanType) -> Dict[str, Any]:
    """Obtiene la configuración de un plan."""
    return PLANS.get(plan_type, PLANS[PlanType.FREE])


def get_allowed_tools(plan_type: PlanType) -> List[str]:
    """Obtiene las herramientas permitidas para un plan."""
    config = get_plan_config(plan_type)
    return config.get("allowed_tools", [])


def is_tool_allowed(plan_type: PlanType, tool_name: str) -> bool:
    """Verifica si una herramienta está permitida en un plan."""
    allowed = get_allowed_tools(plan_type)
    return tool_name.lower() in [t.lower() for t in allowed]


def get_max_audits(plan_type: PlanType) -> int:
    """Obtiene el máximo de auditorías mensuales para un plan."""
    config = get_plan_config(plan_type)
    return config.get("max_audits_month", 5)


def get_max_contract_size(plan_type: PlanType) -> int:
    """Obtiene el tamaño máximo de contrato en KB para un plan."""
    config = get_plan_config(plan_type)
    return config.get("max_contract_size_kb", 50)


def is_ai_enabled(plan_type: PlanType) -> bool:
    """Verifica si la IA está habilitada para un plan."""
    config = get_plan_config(plan_type)
    return config.get("ai_enabled", False)
