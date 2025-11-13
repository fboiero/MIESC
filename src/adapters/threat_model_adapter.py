"""
Threat Model Adapter - Layer 7 Enhancement
==========================================

Integrates threat modeling (STRIDE/DREAD) into MIESC for audit readiness.
Systematically identifies threats using modeling frameworks.

Tool: Custom (analysis based on STRIDE/DREAD frameworks)
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-09
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional
import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ThreatModelAdapter(ToolAdapter):
    """
    Analizador de Threat Modeling usando STRIDE y DREAD.

    STRIDE Framework:
    - Spoofing: Suplantación de identidad
    - Tampering: Manipulación de datos
    - Repudiation: No-repudio / registro inadecuado
    - Information Disclosure: Divulgación de información
    - Denial of Service: Denegación de servicio
    - Elevation of Privilege: Elevación de privilegios

    DREAD Scoring:
    - Damage: Daño potencial (1-10)
    - Reproducibility: Facilidad de reproducción (1-10)
    - Exploitability: Facilidad de explotación (1-10)
    - Affected Users: Usuarios afectados (1-10)
    - Discoverability: Facilidad de descubrimiento (1-10)
    """

    # Patrones para detectar amenazas STRIDE
    STRIDE_PATTERNS = {
        # SPOOFING: Suplantación de identidad
        "spoofing_tx_origin": {
            "regex": r"tx\.origin\s*==",
            "stride_category": "Spoofing",
            "threat": "tx.origin can be spoofed via phishing attack",
            "impact": "Attacker can impersonate authorized user",
            "mitigation": "Use msg.sender instead of tx.origin for authorization",
            "dread": {"damage": 8, "reproducibility": 9, "exploitability": 7, "affected_users": 8, "discoverability": 6}
        },
        "spoofing_no_auth": {
            "regex": r"function\s+\w+\([^)]*\)\s+external\s+(?!.*onlyOwner)(?!.*require\(msg\.sender)",
            "stride_category": "Spoofing",
            "threat": "External function without authentication",
            "impact": "Anyone can call privileged function",
            "mitigation": "Add access control modifiers (onlyOwner, onlyRole, etc.)",
            "dread": {"damage": 9, "reproducibility": 10, "exploitability": 10, "affected_users": 10, "discoverability": 9}
        },

        # TAMPERING: Manipulación de datos
        "tampering_public_state": {
            "regex": r"(uint|address|bool|mapping)\s+public\s+\w+\s*;",
            "stride_category": "Tampering",
            "threat": "Public state variable without setter protection",
            "impact": "State can be read by attackers for manipulation timing",
            "mitigation": "Use internal/private visibility and controlled setters",
            "dread": {"damage": 6, "reproducibility": 10, "exploitability": 5, "affected_users": 7, "discoverability": 10}
        },
        "tampering_no_validation": {
            "regex": r"function\s+set\w+\([^)]*\)\s+[^{]*\{(?![^}]*require)",
            "stride_category": "Tampering",
            "threat": "Setter function without input validation",
            "impact": "Invalid data can corrupt contract state",
            "mitigation": "Add require() statements to validate inputs",
            "dread": {"damage": 7, "reproducibility": 9, "exploitability": 8, "affected_users": 8, "discoverability": 7}
        },

        # REPUDIATION: No-repudio
        "repudiation_no_events": {
            "regex": r"function\s+\w+\([^)]*\)\s+external\s+[^{]*\{(?![^}]*emit)",
            "stride_category": "Repudiation",
            "threat": "State-changing function without event emission",
            "impact": "Actions cannot be audited or proven",
            "mitigation": "Emit events for all state changes",
            "dread": {"damage": 5, "reproducibility": 10, "exploitability": 3, "affected_users": 6, "discoverability": 8}
        },

        # INFORMATION DISCLOSURE: Divulgación de información
        "disclosure_private_data": {
            "regex": r"(private|internal)\s+(bytes32|string|uint)\s+\w*(secret|password|key|seed)",
            "stride_category": "Information Disclosure",
            "threat": "Sensitive data stored on-chain",
            "impact": "Private data is visible to everyone on blockchain",
            "mitigation": "Never store secrets on-chain, use off-chain or encryption",
            "dread": {"damage": 9, "reproducibility": 10, "exploitability": 1, "affected_users": 10, "discoverability": 5}
        },
        "disclosure_balance_leak": {
            "regex": r"this\.balance",
            "stride_category": "Information Disclosure",
            "threat": "Contract balance exposed in logic",
            "impact": "Attackers can time attacks based on contract balance",
            "mitigation": "Use internal accounting instead of relying on balance",
            "dread": {"damage": 6, "reproducibility": 10, "exploitability": 6, "affected_users": 7, "discoverability": 9}
        },

        # DENIAL OF SERVICE: Denegación de servicio
        "dos_unbounded_loop": {
            "regex": r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length",
            "stride_category": "Denial of Service",
            "threat": "Unbounded loop over dynamic array",
            "impact": "Gas limit can prevent function execution",
            "mitigation": "Add array size limits or use pull pattern",
            "dread": {"damage": 7, "reproducibility": 8, "exploitability": 7, "affected_users": 10, "discoverability": 6}
        },
        "dos_external_call_loop": {
            "regex": r"for\s*\([^)]*\)\s*\{[^}]*(\.call|\.transfer|\.send)",
            "stride_category": "Denial of Service",
            "threat": "External calls in loop",
            "impact": "Single failing call can block entire operation",
            "mitigation": "Use pull pattern instead of push",
            "dread": {"damage": 8, "reproducibility": 9, "exploitability": 8, "affected_users": 10, "discoverability": 7}
        },
        "dos_block_gas_limit": {
            "regex": r"while\s*\(true\)|while\s*\(\w+\s*>\s*0\)",
            "stride_category": "Denial of Service",
            "threat": "Potentially infinite loop",
            "impact": "Contract can become unusable",
            "mitigation": "Add iteration limits and break conditions",
            "dread": {"damage": 9, "reproducibility": 6, "exploitability": 5, "affected_users": 10, "discoverability": 4}
        },

        # ELEVATION OF PRIVILEGE: Elevación de privilegios
        "privilege_delegatecall": {
            "regex": r"delegatecall\(",
            "stride_category": "Elevation of Privilege",
            "threat": "Delegatecall to potentially malicious contract",
            "impact": "Caller can execute code in context of this contract",
            "mitigation": "Validate delegatecall target or use library pattern",
            "dread": {"damage": 10, "reproducibility": 7, "exploitability": 8, "affected_users": 10, "discoverability": 6}
        },
        "privilege_selfdestruct": {
            "regex": r"selfdestruct\(",
            "stride_category": "Elevation of Privilege",
            "threat": "Selfdestruct without proper authorization",
            "impact": "Contract and funds can be destroyed",
            "mitigation": "Add multi-sig or timelock for selfdestruct",
            "dread": {"damage": 10, "reproducibility": 8, "exploitability": 9, "affected_users": 10, "discoverability": 8}
        },
        "privilege_upgrade_no_check": {
            "regex": r"function\s+upgrade\w*\([^)]*\)\s+[^{]*\{(?![^}]*onlyOwner)",
            "stride_category": "Elevation of Privilege",
            "threat": "Upgrade function without access control",
            "impact": "Anyone can upgrade contract to malicious implementation",
            "mitigation": "Add onlyOwner or multi-sig requirement",
            "dread": {"damage": 10, "reproducibility": 10, "exploitability": 10, "affected_users": 10, "discoverability": 9}
        }
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="threat_model",
            version="1.0.0",
            category=ToolCategory.AUDIT_READINESS,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC/blob/main/docs/TOOL_INTEGRATION_GUIDE.md",
            installation_cmd="# Built-in, no installation required",
            capabilities=[
                ToolCapability(
                    name="threat_modeling",
                    description="Modelado de amenazas usando STRIDE y DREAD",
                    supported_languages=["solidity"],
                    detection_types=[
                        "spoofing",
                        "tampering",
                        "repudiation",
                        "information_disclosure",
                        "denial_of_service",
                        "elevation_of_privilege"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance
        )

    def is_available(self) -> ToolStatus:
        """ThreatModel es built-in, siempre disponible"""
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta threat modeling en el contrato.

        Args:
            contract_path: Ruta al archivo .sol
            **kwargs:
                - framework: "STRIDE" o "DREAD" (default: "STRIDE")
                - min_dread_score: Score mínimo DREAD para incluir (default: 5.0)

        Returns:
            Resultados normalizados con threat model
        """
        import time
        start = time.time()

        try:
            # Leer contrato
            with open(contract_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            # Analizar amenazas STRIDE
            threats = self._analyze_stride_threats(source_code, contract_path)

            # Filtrar por DREAD score si se especifica
            min_dread = kwargs.get("min_dread_score", 0.0)
            if min_dread > 0:
                threats = [t for t in threats if t.get("dread_score", 0) >= min_dread]

            # Calcular métricas de threat model
            threat_summary = self._calculate_threat_metrics(threats)

            return {
                "tool": "threat_model",
                "version": "1.0.0",
                "status": "success",
                "findings": threats,
                "metadata": {
                    "total_threats": len(threats),
                    "stride_breakdown": threat_summary["stride_breakdown"],
                    "average_dread_score": threat_summary["avg_dread"],
                    "highest_risk_category": threat_summary["highest_risk"],
                    "audit_readiness_score": threat_summary["audit_readiness"],
                    "framework": "STRIDE/DREAD"
                },
                "execution_time": time.time() - start
            }

        except Exception as e:
            logger.error(f"ThreatModel error: {e}")
            return {
                "tool": "threat_model",
                "version": "1.0.0",
                "status": "error",
                "error": str(e),
                "findings": [],
                "execution_time": time.time() - start
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normaliza findings al formato MIESC.
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        return []

    def _analyze_stride_threats(self, source_code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analiza amenazas usando framework STRIDE"""
        threats = []
        lines = source_code.split('\n')

        for pattern_name, pattern_info in self.STRIDE_PATTERNS.items():
            regex = re.compile(pattern_info["regex"], re.MULTILINE)

            for line_num, line in enumerate(lines, 1):
                matches = regex.finditer(line)

                for match in matches:
                    # Calcular DREAD score
                    dread_scores = pattern_info["dread"]
                    dread_score = sum(dread_scores.values()) / len(dread_scores)

                    # Determinar severidad basada en DREAD
                    severity = self._dread_to_severity(dread_score)

                    threat = {
                        "id": f"THREAT-{pattern_info['stride_category'].upper()}-{line_num}",
                        "type": "threat_model",
                        "severity": severity,
                        "confidence": 0.75,  # Threat modeling es predictivo
                        "location": {
                            "file": str(Path(contract_path).name),
                            "line": line_num,
                            "column": match.start(),
                            "code_snippet": line.strip()
                        },
                        "message": f"[{pattern_info['stride_category']}] {pattern_info['threat']}",
                        "description": (
                            f"Threat identified via STRIDE analysis:\n"
                            f"Category: {pattern_info['stride_category']}\n"
                            f"Threat: {pattern_info['threat']}\n"
                            f"Impact: {pattern_info['impact']}"
                        ),
                        "recommendation": pattern_info["mitigation"],
                        "swc_id": None,  # Threat modeling es preventivo
                        "cwe_id": None,
                        "owasp_category": "A04:2021-Insecure Design",
                        "stride_category": pattern_info["stride_category"],
                        "dread_score": round(dread_score, 2),
                        "dread_breakdown": dread_scores,
                        "impact": pattern_info["impact"]
                    }
                    threats.append(threat)

        return threats

    def _dread_to_severity(self, dread_score: float) -> str:
        """Convierte DREAD score (1-10) a severidad MIESC"""
        if dread_score >= 8.5:
            return "Critical"
        elif dread_score >= 7.0:
            return "High"
        elif dread_score >= 5.0:
            return "Medium"
        elif dread_score >= 3.0:
            return "Low"
        return "Info"

    def _calculate_threat_metrics(self, threats: List[Dict]) -> Dict[str, Any]:
        """Calcula métricas del threat model"""
        if not threats:
            return {
                "stride_breakdown": {},
                "avg_dread": 0.0,
                "highest_risk": "None",
                "audit_readiness": 100.0
            }

        # Breakdown por categoría STRIDE
        stride_breakdown = {}
        for threat in threats:
            category = threat.get("stride_category", "Unknown")
            stride_breakdown[category] = stride_breakdown.get(category, 0) + 1

        # DREAD promedio
        avg_dread = sum(t.get("dread_score", 0) for t in threats) / len(threats)

        # Categoría de mayor riesgo
        highest_risk = max(stride_breakdown, key=stride_breakdown.get)

        # Audit readiness score (100 - penalización por amenazas)
        # Cada amenaza Critical -10, High -5, Medium -2, Low -1
        penalty = sum(
            10 if t["severity"] == "Critical" else
            5 if t["severity"] == "High" else
            2 if t["severity"] == "Medium" else
            1 for t in threats
        )
        audit_readiness = max(0, 100 - penalty)

        return {
            "stride_breakdown": stride_breakdown,
            "avg_dread": round(avg_dread, 2),
            "highest_risk": highest_risk,
            "audit_readiness": round(audit_readiness, 2)
        }

    def can_analyze(self, contract_path: str) -> bool:
        """Verifica si el archivo es un contrato Solidity"""
        return contract_path.endswith('.sol')

    def get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto"""
        return {
            "framework": "STRIDE",
            "min_dread_score": 0.0,
            "include_all_categories": True
        }
