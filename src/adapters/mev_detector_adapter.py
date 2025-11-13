"""
MEV Detector Adapter - Layer 1 Enhancement
==========================================

Integrates MEV (Maximal Extractable Value) vulnerability detection into MIESC.
Detects front-running vectors, sandwich attacks, and transaction manipulation.

Tool: Custom (pattern-based analysis using known MEV attack vectors)
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


class MEVDetectorAdapter(ToolAdapter):
    """
    Detector de vulnerabilidades MEV (Maximal Extractable Value).

    Detecta:
    - Front-running opportunities
    - Sandwich attack vectors
    - Transaction ordering dependencies
    - Timestamp manipulation
    - Oracle manipulation
    - Flash loan vulnerabilities
    - Arbitrage risks
    - Unbounded loops exploitable for MEV
    """

    # Patrones de vulnerabilidades MEV
    MEV_PATTERNS = {
        # Front-running: función pública que modifica precio/estado sin protección
        "frontrun_price_update": {
            "regex": r"function\s+\w+\([^)]*\)\s+public\s+[^{]*\{[^}]*(price|rate|value)\s*=",
            "severity": "High",
            "message": "Public function updates price/rate without front-running protection",
            "impact": "Front-running",
            "recommendation": "Add commit-reveal scheme or use flashbots/private mempool"
        },
        # Sandwich attack: swap sin slippage protection
        "sandwich_swap": {
            "regex": r"function\s+swap\w*\([^)]*\)\s+[^{]*\{(?![^}]*minAmountOut)(?![^}]*slippage)",
            "severity": "Critical",
            "message": "Swap function without slippage protection",
            "impact": "Sandwich attack",
            "recommendation": "Add minAmountOut parameter and validate against slippage"
        },
        # Timestamp dependence (manipulable por mineros)
        "timestamp_dependence": {
            "regex": r"(block\.timestamp|now)\s*[<>!=]=",
            "severity": "Medium",
            "message": "Logic depends on block.timestamp (miner manipulable)",
            "impact": "Timestamp manipulation",
            "recommendation": "Use block.number or oracle-based time if critical"
        },
        # Oracle sin validación de freshness
        "stale_oracle": {
            "regex": r"(getPrice|getRate|latestAnswer)\(\)(?![^;]*require\([^)]*timestamp)",
            "severity": "High",
            "message": "Oracle price used without freshness validation",
            "impact": "Oracle manipulation/stale data",
            "recommendation": "Validate oracle timestamp and add staleness check"
        },
        # Flash loan sin protección reentrancy
        "flashloan_reentrancy": {
            "regex": r"function\s+flashLoan\w*\([^)]*\)\s+[^{]*\{(?![^}]*nonReentrant)(?![^}]*ReentrancyGuard)",
            "severity": "Critical",
            "message": "Flash loan function without reentrancy protection",
            "impact": "Flash loan + reentrancy attack",
            "recommendation": "Add nonReentrant modifier or ReentrancyGuard"
        },
        # Arbitraje: diferencia de precio sin límite
        "arbitrage_opportunity": {
            "regex": r"(buy|sell|swap)\w*\([^)]*\)\s+[^{]*\{[^}]*(getPrice|price)\([^)]*\)[^}]*(?!require\([^)]*maxPriceDiff)",
            "severity": "Medium",
            "message": "Price-dependent function without arbitrage protection",
            "impact": "Arbitrage exploitation",
            "recommendation": "Add price deviation limits and TWAP (Time-Weighted Average Price)"
        },
        # Ordering dependence: resultado depende del orden de transacciones
        "tx_ordering_dependence": {
            "regex": r"(require|assert)\([^)]*\.balance\s*[<>]",
            "severity": "Medium",
            "message": "Logic depends on contract balance (transaction order dependent)",
            "impact": "Transaction ordering manipulation",
            "recommendation": "Use internal accounting instead of balance checks"
        },
        # Unbounded loop (gas griefing for MEV)
        "unbounded_loop_mev": {
            "regex": r"for\s*\([^)]*;\s*\w+\s*<\s*\w+\.length[^)]*\)\s*\{[^}]*(call|transfer|send)",
            "severity": "High",
            "message": "Unbounded loop with external calls (MEV + DoS risk)",
            "impact": "Gas griefing + MEV extraction",
            "recommendation": "Add loop bounds, use pull pattern, or batch processing"
        },
        # Public liquidation sin delay
        "instant_liquidation": {
            "regex": r"function\s+liquidate\w*\([^)]*\)\s+public\s+[^{]*\{(?![^}]*delay)(?![^}]*timelock)",
            "severity": "Medium",
            "message": "Public liquidation without delay mechanism",
            "impact": "MEV extraction via instant liquidation",
            "recommendation": "Add grace period or Dutch auction for liquidations"
        },
        # Oracle precio único (no TWAP)
        "single_price_oracle": {
            "regex": r"(latestPrice|currentPrice|getPrice)\(\)[^;]*(?!TWAP)(?!average)(?!median)",
            "severity": "Medium",
            "message": "Using single-point oracle price instead of TWAP",
            "impact": "Price manipulation via MEV",
            "recommendation": "Use TWAP (Time-Weighted Average Price) or Chainlink"
        },
        # Auction sin commit-reveal
        "public_auction": {
            "regex": r"function\s+(bid|placeBid)\w*\([^)]*\)\s+public\s+[^{]*\{(?![^}]*commit)(?![^}]*reveal)",
            "severity": "High",
            "message": "Public auction without commit-reveal scheme",
            "impact": "Front-running of bids",
            "recommendation": "Implement commit-reveal pattern or sealed-bid auction"
        },
        # DEX sin MEV protection
        "dex_no_mev_protection": {
            "regex": r"function\s+(addLiquidity|removeLiquidity)\w*\([^)]*\)\s+public\s+[^{]*\{(?![^}]*deadline)",
            "severity": "Medium",
            "message": "Liquidity function without deadline parameter",
            "impact": "MEV via delayed execution",
            "recommendation": "Add deadline parameter to prevent stale transactions"
        }
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="mev_detector",
            version="1.0.0",
            category=ToolCategory.MEV_DETECTION,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC/blob/main/docs/TOOL_INTEGRATION_GUIDE.md",
            installation_cmd="# Built-in, no installation required",
            capabilities=[
                ToolCapability(
                    name="mev_detection",
                    description="Detecta vectores de MEV (Maximal Extractable Value)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "frontrunning",
                        "sandwich_attacks",
                        "timestamp_manipulation",
                        "oracle_manipulation",
                        "flash_loan_attacks",
                        "arbitrage_risks",
                        "transaction_ordering",
                        "liquidation_mev"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance
        )

    def is_available(self) -> ToolStatus:
        """MEVDetector es built-in, siempre disponible"""
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta análisis de MEV en el contrato.

        Args:
            contract_path: Ruta al archivo .sol
            **kwargs:
                - min_severity: Filtrar por severidad mínima
                - include_defi_only: Solo analizar si es contrato DeFi

        Returns:
            Resultados normalizados
        """
        import time
        start = time.time()

        try:
            # Leer contrato
            with open(contract_path, 'r', encoding='utf-8') as f:
                source_code = f.read()

            # Verificar si es contrato DeFi (opcional)
            if kwargs.get("include_defi_only", False):
                if not self._is_defi_contract(source_code):
                    return {
                        "tool": "mev_detector",
                        "version": "1.0.0",
                        "status": "skipped",
                        "reason": "Not a DeFi contract",
                        "findings": [],
                        "execution_time": time.time() - start
                    }

            # Analizar patrones MEV
            findings = self._analyze_mev_patterns(source_code, contract_path)

            # Filtrar por severidad si se especifica
            min_severity = kwargs.get("min_severity")
            if min_severity:
                findings = [f for f in findings if self._severity_level(f["severity"]) >=
                           self._severity_level(min_severity)]

            # Calcular métricas de MEV
            mev_risk_score = self._calculate_mev_risk(findings)

            return {
                "tool": "mev_detector",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "total_issues": len(findings),
                    "mev_risk_score": mev_risk_score,
                    "risk_level": self._risk_level(mev_risk_score),
                    "severity_breakdown": self._severity_breakdown(findings),
                    "attack_vectors": self._extract_attack_vectors(findings)
                },
                "execution_time": time.time() - start
            }

        except Exception as e:
            logger.error(f"MEVDetector error: {e}")
            return {
                "tool": "mev_detector",
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

    def _analyze_mev_patterns(self, source_code: str, contract_path: str) -> List[Dict[str, Any]]:
        """Analiza código buscando vulnerabilidades MEV"""
        findings = []
        lines = source_code.split('\n')

        for pattern_name, pattern_info in self.MEV_PATTERNS.items():
            regex = re.compile(pattern_info["regex"], re.MULTILINE | re.DOTALL)

            # Analizar todo el código (algunos patrones requieren contexto multi-línea)
            for line_num, line in enumerate(lines, 1):
                # Para patrones simples, analizar línea por línea
                matches = regex.finditer(line)

                for match in matches:
                    finding = {
                        "id": f"MEV-{pattern_name.upper()}-{line_num}",
                        "type": "mev_vulnerability",
                        "severity": pattern_info["severity"],
                        "confidence": 0.80,  # Pattern matching con contexto limitado
                        "location": {
                            "file": str(Path(contract_path).name),
                            "line": line_num,
                            "column": match.start(),
                            "code_snippet": line.strip()
                        },
                        "message": pattern_info["message"],
                        "description": f"MEV vulnerability detected: {pattern_info['message']}",
                        "recommendation": pattern_info["recommendation"],
                        "swc_id": None,  # MEV no está en SWC Registry
                        "cwe_id": None,
                        "owasp_category": "A10:2021-Cryptographic Failures",  # Closest match
                        "mev_impact": pattern_info["impact"],
                        "attack_vector": pattern_name
                    }
                    findings.append(finding)

        return findings

    def _is_defi_contract(self, source_code: str) -> bool:
        """Detecta si es un contrato DeFi basado en keywords"""
        defi_keywords = [
            "swap", "liquidity", "pool", "vault", "lending", "borrow",
            "flashLoan", "oracle", "price", "stake", "yield", "farm",
            "DEX", "AMM", "TWAP", "liquidate"
        ]
        return any(keyword in source_code for keyword in defi_keywords)

    def _calculate_mev_risk(self, findings: List[Dict]) -> float:
        """
        Calcula score de riesgo MEV basado en severidad y cantidad.
        Score: 0-100 (0 = sin riesgo, 100 = crítico)
        """
        if not findings:
            return 0.0

        severity_weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 1}
        total_score = sum(severity_weights.get(f["severity"], 0) for f in findings)

        # Normalizar a 0-100
        max_score = len(findings) * 25  # Asumiendo el peor caso (todos Critical)
        risk_score = min(100, (total_score / max_score) * 100 if max_score > 0 else 0)

        return round(risk_score, 2)

    def _risk_level(self, risk_score: float) -> str:
        """Convierte score numérico a nivel de riesgo"""
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        elif risk_score > 0:
            return "Low"
        return "None"

    def _severity_level(self, severity: str) -> int:
        """Convierte severidad a nivel numérico para filtrado"""
        levels = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return levels.get(severity, 0)

    def _severity_breakdown(self, findings: List[Dict]) -> Dict[str, int]:
        """Calcula distribución de severidades"""
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            severity = finding.get("severity", "Info")
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

    def _extract_attack_vectors(self, findings: List[Dict]) -> List[str]:
        """Extrae vectores de ataque únicos detectados"""
        vectors = set()
        for finding in findings:
            vector = finding.get("mev_impact", "")
            if vector:
                vectors.add(vector)
        return sorted(list(vectors))

    def can_analyze(self, contract_path: str) -> bool:
        """Verifica si el archivo es un contrato Solidity"""
        return contract_path.endswith('.sol')

    def get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto"""
        return {
            "min_severity": "Low",
            "include_defi_only": False,
            "enable_all_patterns": True
        }
