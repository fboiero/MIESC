"""
Oyente Adapter - Layer 3 Enhancement
====================================

Integrates Oyente (symbolic execution) into MIESC to complement Mythril/Manticore.
Detects vulnerabilities through symbolic analysis of smart contracts.

Tool: Oyente (https://github.com/enzymefinance/oyente)
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2025-01-09
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional
import subprocess
import json
import logging
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class OyenteAdapter(ToolAdapter):
    """
    Adapter for Oyente - Symbolic Execution Tool.

    Oyente uses symbolic analysis to explore multiple execution paths
    and detect vulnerabilities such as:
    - Integer overflow/underflow
    - Reentrancy
    - Transaction ordering dependence
    - Timestamp dependence
    - Callstack depth attack
    - Delegatecall issues
    """

    # Mapeo de códigos de vulnerabilidad de Oyente a SWC/CWE
    OYENTE_VULN_MAPPING = {
        "Integer Overflow": {
            "swc_id": "SWC-101",
            "cwe_id": "CWE-190",
            "owasp": "A04:2021-Insecure Design",
            "severity": "High"
        },
        "Integer Underflow": {
            "swc_id": "SWC-101",
            "cwe_id": "CWE-191",
            "owasp": "A04:2021-Insecure Design",
            "severity": "High"
        },
        "Reentrancy": {
            "swc_id": "SWC-107",
            "cwe_id": "CWE-841",
            "owasp": "A04:2021-Insecure Design",
            "severity": "Critical"
        },
        "Transaction-Ordering Dependence": {
            "swc_id": "SWC-114",
            "cwe_id": "CWE-362",
            "owasp": "A04:2021-Insecure Design",
            "severity": "Medium"
        },
        "Timestamp Dependence": {
            "swc_id": "SWC-116",
            "cwe_id": "CWE-829",
            "owasp": "A04:2021-Insecure Design",
            "severity": "Low"
        },
        "Callstack Depth Attack": {
            "swc_id": "SWC-113",
            "cwe_id": "CWE-841",
            "owasp": "A04:2021-Insecure Design",
            "severity": "Medium"
        },
        "Delegatecall to Untrusted Callee": {
            "swc_id": "SWC-112",
            "cwe_id": "CWE-829",
            "owasp": "A03:2021-Injection",
            "severity": "High"
        }
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="oyente",
            version="1.0.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="Melonport (enzymefinance)",
            license="GPL-3.0",
            homepage="https://github.com/enzymefinance/oyente",
            repository="https://github.com/enzymefinance/oyente",
            documentation="https://github.com/enzymefinance/oyente#readme",
            installation_cmd="docker pull enzymefinance/oyente",
            capabilities=[
                ToolCapability(
                    name="symbolic_execution",
                    description="Análisis simbólico para detectar vulnerabilidades",
                    supported_languages=["solidity"],
                    detection_types=[
                        "integer_overflow",
                        "integer_underflow",
                        "reentrancy",
                        "transaction_ordering",
                        "timestamp_dependence",
                        "callstack_depth",
                        "delegatecall_issues"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance
        )

    def is_available(self) -> ToolStatus:
        """Verifica si Oyente está disponible (vía Docker)"""
        try:
            # Verificar si Docker está disponible
            docker_check = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5
            )
            if docker_check.returncode != 0:
                return ToolStatus.NOT_INSTALLED

            # Verificar si la imagen de Oyente existe
            result = subprocess.run(
                ["docker", "images", "-q", "enzymefinance/oyente"],
                capture_output=True,
                timeout=5,
                text=True
            )

            if result.stdout.strip():
                return ToolStatus.AVAILABLE
            return ToolStatus.NOT_INSTALLED

        except FileNotFoundError:
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error(f"Error checking Oyente availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta análisis simbólico con Oyente.

        Args:
            contract_path: Ruta al archivo .sol
            **kwargs:
                - timeout: Timeout en segundos (default: 300)
                - solc_version: Versión de solc a usar (default: "0.8.19")
                - enable_integer_overflow: Detectar overflows (default: True)
                - max_depth: Profundidad máxima de análisis (default: 50)

        Returns:
            Resultados normalizados
        """
        import time
        start = time.time()

        try:
            # Configuración
            timeout = kwargs.get("timeout", 300)
            solc_version = kwargs.get("solc_version", "0.8.19")
            enable_overflow = kwargs.get("enable_integer_overflow", True)
            max_depth = kwargs.get("max_depth", 50)

            # Preparar paths
            contract_path = os.path.abspath(contract_path)
            contract_dir = os.path.dirname(contract_path)
            contract_file = os.path.basename(contract_path)

            # Ejecutar Oyente via Docker
            cmd = [
                "docker", "run", "--rm",
                "-v", f"{contract_dir}:/data",
                "enzymefinance/oyente",
                "-s", f"/data/{contract_file}",
                "-j",  # JSON output
                "--timeout", str(timeout)
            ]

            if enable_overflow:
                cmd.append("--integer-overflow")

            logger.info(f"Running Oyente: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,  # Buffer adicional
            )

            # Oyente puede retornar != 0 si encuentra vulnerabilidades
            if result.returncode not in [0, 1]:
                return {
                    "tool": "oyente",
                    "version": "1.0.0",
                    "status": "error",
                    "error": f"Oyente execution failed: {result.stderr}",
                    "findings": [],
                    "execution_time": time.time() - start
                }

            # Parsear output JSON
            try:
                raw_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                # Si no es JSON, intentar parsear texto
                logger.warning("Oyente output is not valid JSON, attempting text parsing")
                raw_output = self._parse_text_output(result.stdout)

            # Normalizar findings
            findings = self.normalize_findings(raw_output)

            return {
                "tool": "oyente",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "total_vulnerabilities": len(findings),
                    "severity_breakdown": self._severity_breakdown(findings),
                    "contract_analyzed": contract_file,
                    "solc_version": solc_version,
                    "max_depth_reached": raw_output.get("max_depth_reached", False)
                },
                "execution_time": time.time() - start
            }

        except subprocess.TimeoutExpired:
            logger.error("Oyente execution timeout")
            return {
                "tool": "oyente",
                "version": "1.0.0",
                "status": "error",
                "error": "Execution timeout - contract may be too complex",
                "findings": [],
                "execution_time": time.time() - start
            }
        except Exception as e:
            logger.error(f"Oyente execution error: {e}")
            return {
                "tool": "oyente",
                "version": "1.0.0",
                "status": "error",
                "error": str(e),
                "findings": [],
                "execution_time": time.time() - start
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normaliza findings de Oyente a formato MIESC.
        """
        findings = []

        # Oyente puede retornar diferentes formatos
        if isinstance(raw_output, dict):
            vulnerabilities = raw_output.get("vulnerabilities", [])
        elif isinstance(raw_output, list):
            vulnerabilities = raw_output
        else:
            return []

        for idx, vuln in enumerate(vulnerabilities):
            vuln_type = vuln.get("type", "Unknown")
            vuln_info = self.OYENTE_VULN_MAPPING.get(
                vuln_type,
                {
                    "swc_id": None,
                    "cwe_id": None,
                    "owasp": None,
                    "severity": "Medium"
                }
            )

            finding = {
                "id": f"OYENTE-{vuln_type.upper().replace(' ', '-')}-{idx + 1}",
                "type": vuln_type.lower().replace(" ", "_"),
                "severity": vuln_info["severity"],
                "confidence": 0.80,  # Symbolic execution tiene buena precisión
                "location": {
                    "file": vuln.get("file", "unknown"),
                    "line": vuln.get("line", 0),
                    "function": vuln.get("function", "unknown"),
                    "code_snippet": vuln.get("code", "")
                },
                "message": f"{vuln_type} detected via symbolic execution",
                "description": (
                    f"Oyente symbolic analysis detected: {vuln.get('description', vuln_type)}. "
                    f"Execution path: {vuln.get('path', 'N/A')}"
                ),
                "recommendation": self._get_recommendation(vuln_type),
                "swc_id": vuln_info["swc_id"],
                "cwe_id": vuln_info["cwe_id"],
                "owasp_category": vuln_info["owasp"],
                "execution_path": vuln.get("path", []),
                "symbolic_constraints": vuln.get("constraints", [])
            }
            findings.append(finding)

        return findings

    def _parse_text_output(self, text_output: str) -> List[Dict]:
        """
        Parsea output de texto de Oyente (fallback si no es JSON).
        """
        vulnerabilities = []
        lines = text_output.split('\n')

        current_vuln = None
        for line in lines:
            # Detectar inicio de vulnerabilidad
            if "WARNING:" in line or "CRITICAL:" in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)

                vuln_type = line.split(":")[-1].strip()
                current_vuln = {
                    "type": vuln_type,
                    "description": vuln_type,
                    "file": "unknown",
                    "line": 0
                }
            # Parsear detalles
            elif current_vuln and "at line" in line.lower():
                try:
                    line_num = int(line.split("line")[-1].strip())
                    current_vuln["line"] = line_num
                except ValueError:
                    pass

        if current_vuln:
            vulnerabilities.append(current_vuln)

        return vulnerabilities

    def _get_recommendation(self, vuln_type: str) -> str:
        """Retorna recomendación específica por tipo de vulnerabilidad"""
        recommendations = {
            "Integer Overflow": "Use SafeMath library or Solidity ^0.8.0 built-in overflow protection",
            "Integer Underflow": "Use SafeMath library or Solidity ^0.8.0 built-in underflow protection",
            "Reentrancy": "Use checks-effects-interactions pattern or ReentrancyGuard modifier",
            "Transaction-Ordering Dependence": "Avoid state changes dependent on tx.origin or use commit-reveal",
            "Timestamp Dependence": "Use block.number instead of block.timestamp for time-sensitive logic",
            "Callstack Depth Attack": "Update to Solidity ^0.8.0 (no longer vulnerable)",
            "Delegatecall to Untrusted Callee": "Validate delegatecall target or use library pattern"
        }
        return recommendations.get(vuln_type, "Review code and apply secure coding practices")

    def _severity_breakdown(self, findings: List[Dict]) -> Dict[str, int]:
        """Calcula distribución de severidades"""
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            severity = finding.get("severity", "Info")
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

    def can_analyze(self, contract_path: str) -> bool:
        """Verifica si el archivo es un contrato Solidity"""
        return contract_path.endswith('.sol')

    def get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto de Oyente"""
        return {
            "timeout": 300,
            "solc_version": "0.8.19",
            "enable_integer_overflow": True,
            "max_depth": 50
        }

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Valida configuración de Oyente"""
        if "timeout" in config:
            if config["timeout"] <= 0:
                return False

        if "max_depth" in config:
            if config["max_depth"] <= 0:
                return False

        return True
