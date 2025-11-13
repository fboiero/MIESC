"""
Gas Analyzer Adapter - Layer 1 Enhancement
===========================================

Integrates gas optimization analysis into MIESC.
Detects patterns that waste gas unnecessarily in smart contracts.

Tool: Custom (pattern-based analysis using known Solidity patterns)
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


class GasAnalyzerAdapter(ToolAdapter):
    """
    Analizador de optimización de gas para Solidity.

    Detecta:
    - SLOAD/SSTORE innecesarios
    - Loops con operaciones costosas
    - Variables de estado que podrían ser inmutables/constantes
    - Uso ineficiente de storage
    - Operaciones redundantes
    """

    # Patrones de anti-patrones de gas
    GAS_PATTERNS = {
        # SLOAD innecesario en loop
        "sload_in_loop": {
            "regex": r"for\s*\([^)]*\)\s*{[^}]*\b(\w+)\[",
            "severity": "Medium",
            "message": "Storage array access in loop - cache to memory",
            "gas_impact": 2100,  # ~2100 gas por SLOAD
            "recommendation": "Cache array length to memory variable before loop"
        },
        # Variable de estado sin immutable/constant
        "missing_immutable": {
            "regex": r"^\s*(address|uint256|uint|bytes32)\s+(\w+)\s*;\s*$",
            "severity": "Low",
            "message": "State variable could be immutable or constant",
            "gas_impact": 2000,  # Deployment gas savings
            "recommendation": "Add 'immutable' or 'constant' if value doesn't change"
        },
        # String en storage (debería ser en calldata o memory)
        "string_storage": {
            "regex": r"function\s+\w+\([^)]*string\s+storage",
            "severity": "High",
            "message": "String parameter using storage - use calldata",
            "gas_impact": 3000,
            "recommendation": "Change 'string storage' to 'string calldata' or 'string memory'"
        },
        # ++i vs i++
        "postfix_increment": {
            "regex": r"\b(\w+)\+\+\s*\)",
            "severity": "Low",
            "message": "Post-increment (i++) costs more gas than pre-increment (++i)",
            "gas_impact": 5,
            "recommendation": "Use ++i instead of i++ in loops"
        },
        # Repeated external calls
        "repeated_external_call": {
            "regex": r"(\w+\.\w+\(\))[^;]*\1",
            "severity": "Medium",
            "message": "Repeated external call - cache result",
            "gas_impact": 2600,  # CALL opcode base cost
            "recommendation": "Store result in variable and reuse"
        },
        # Public function that could be external
        "public_not_external": {
            "regex": r"function\s+\w+\([^)]*\)\s+public",
            "severity": "Low",
            "message": "Public function that could be external",
            "gas_impact": 200,
            "recommendation": "Change 'public' to 'external' if not called internally"
        },
        # Unnecessary zero initialization
        "zero_init": {
            "regex": r"(uint|uint256|int|int256)\s+\w+\s*=\s*0",
            "severity": "Low",
            "message": "Unnecessary zero initialization",
            "gas_impact": 3,
            "recommendation": "Remove '= 0' (variables are zero-initialized by default)"
        },
        # Array length in loop condition
        "array_length_loop": {
            "regex": r"for\s*\([^;]*;\s*\w+\s*<\s*(\w+)\.length",
            "severity": "Medium",
            "message": "Reading .length in every loop iteration",
            "gas_impact": 100,  # per iteration
            "recommendation": "Cache array.length before loop: uint len = array.length"
        }
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="gas_analyzer",
            version="1.0.0",
            category=ToolCategory.GAS_OPTIMIZATION,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC/blob/main/docs/TOOL_INTEGRATION_GUIDE.md",
            installation_cmd="# Built-in, no installation required",
            capabilities=[
                ToolCapability(
                    name="gas_optimization",
                    description="Detecta patrones que consumen gas innecesario",
                    supported_languages=["solidity"],
                    detection_types=[
                        "sload_optimization",
                        "loop_optimization",
                        "storage_packing",
                        "function_visibility",
                        "unnecessary_operations"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance
        )

    def is_available(self) -> ToolStatus:
        """GasAnalyzer es built-in, siempre disponible"""
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta análisis de gas en el contrato.

        Args:
            contract_path: Ruta al archivo .sol
            **kwargs:
                - min_severity: Filtrar por severidad mínima

        Returns:
            Resultados normalizados
        """
        import time
        start = time.time()

        try:
            # Leer contrato
            with open(contract_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            # Analizar patrones
            findings = self._analyze_patterns(source_code, contract_path)

            # Filtrar por severidad si se especifica
            min_severity = kwargs.get("min_severity")
            if min_severity:
                findings = [f for f in findings if self._severity_level(f["severity"]) >=
                           self._severity_level(min_severity)]

            # Calcular gas total ahorrable
            total_gas_savings = sum(f.get("gas_saved", 0) for f in findings)

            return {
                "tool": "gas_analyzer",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "total_issues": len(findings),
                    "total_gas_savings": total_gas_savings,
                    "severity_breakdown": self._severity_breakdown(findings)
                },
                "execution_time": time.time() - start
            }

        except Exception as e:
            logger.error(f"GasAnalyzer error: {e}")
            return {
                "tool": "gas_analyzer",
                "version": "1.0.0",
                "status": "error",
                "error": str(e),
                "findings": [],
                "execution_time": time.time() - start
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normaliza findings al formato MIESC.

        En este caso, analyze() ya retorna findings normalizados,
        pero este método está disponible para conversiones adicionales.
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        return []

    def _analyze_patterns(self, source_code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analiza código buscando anti-patrones de gas"""
        findings = []
        lines = source_code.split('\n')

        for pattern_name, pattern_info in self.GAS_PATTERNS.items():
            regex = re.compile(pattern_info["regex"], re.MULTILINE)

            for line_num, line in enumerate(lines, 1):
                matches = regex.finditer(line)

                for match in matches:
                    finding = {
                        "id": f"GAS-{pattern_name.upper()}-{line_num}",
                        "type": "gas_optimization",
                        "severity": pattern_info["severity"],
                        "confidence": 0.85,  # Pattern matching tiene alta confianza
                        "location": {
                            "file": str(Path(contract_path).name),
                            "line": line_num,
                            "column": match.start(),
                            "code_snippet": line.strip()
                        },
                        "message": pattern_info["message"],
                        "description": f"Gas optimization opportunity detected: {pattern_info['message']}",
                        "recommendation": pattern_info["recommendation"],
                        "swc_id": None,  # No aplica para optimizaciones
                        "cwe_id": None,
                        "owasp_category": None,
                        "gas_saved": pattern_info["gas_impact"],
                        "pattern": pattern_name
                    }
                    findings.append(finding)

        return findings

    def _severity_level(self, severity: str) -> int:
        """Convierte severidad a nivel numérico para filtrado"""
        levels = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return levels.get(severity, 0)

    def _severity_breakdown(self, findings: List[Dict]) -> Dict[str, int]:
        """Calcula distribución de severidades"""
        breakdown = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            severity = finding.get("severity", "Info")
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

    def can_analyze(self, contract_path: str) -> bool:
        """Verifica si el archivo es un contrato Solidity"""
        return contract_path.endswith('.sol')

    def get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto"""
        return {
            "min_severity": "Low",
            "enable_all_patterns": True
        }
