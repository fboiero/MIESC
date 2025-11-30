"""
Vertigo Adapter - Layer 2 Enhancement
======================================

Integra Vertigo (mutation testing) a MIESC para validar calidad de tests.
Detecta tests débiles mediante introducción de mutaciones en el código.

Herramienta: Vertigo (https://github.com/JoranHonig/vertigo)
Autor: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Fecha: 2025-01-09
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


class VertigoAdapter(ToolAdapter):
    """
    Adapter para Vertigo - Mutation Testing Tool.

    Vertigo introduce mutaciones (pequeños cambios) en el código y ejecuta
    los tests para verificar si detectan los cambios. Esto valida la calidad
    de la suite de tests.

    Mutaciones detectadas:
    - Boundary mutations (< → <=, > → >=)
    - Arithmetic mutations (+, -, *, /, %)
    - Logical mutations (&&, ||, !)
    - Require/assert removal
    - Return value mutations
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="vertigo",
            version="1.0.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Joran Honig (JoranHonig)",
            license="MIT",
            homepage="https://github.com/JoranHonig/vertigo",
            repository="https://github.com/JoranHonig/vertigo",
            documentation="https://github.com/JoranHonig/vertigo#readme",
            installation_cmd="pip install eth-vertigo",
            capabilities=[
                ToolCapability(
                    name="mutation_testing",
                    description="Valida calidad de tests mediante mutaciones del código",
                    supported_languages=["solidity"],
                    detection_types=[
                        "weak_tests",
                        "missing_test_cases",
                        "boundary_conditions",
                        "logic_coverage",
                        "assertion_quality"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance
        )

    def is_available(self) -> ToolStatus:
        """Verifica si Vertigo está disponible (via Foundry)"""
        try:
            # Vertigo requires Foundry for running tests
            result = subprocess.run(
                ["forge", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                logger.info("Vertigo: Foundry available for mutation testing")
                return ToolStatus.AVAILABLE
            return ToolStatus.NOT_INSTALLED
        except FileNotFoundError:
            logger.info("Vertigo requires Foundry. Install: curl -L https://foundry.paradigm.xyz | bash")
            return ToolStatus.NOT_INSTALLED
        except Exception as e:
            logger.error(f"Error checking Vertigo availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Ejecuta mutation testing con Vertigo.

        Args:
            contract_path: Ruta al archivo .sol o directorio del proyecto
            **kwargs:
                - test_command: Comando para ejecutar tests (default: "forge test")
                - mutation_count: Número de mutaciones a generar (default: 10)
                - sample_ratio: Ratio de código a mutar (default: 0.1)
                - timeout: Timeout por test en segundos (default: 30)
                - output_dir: Directorio para resultados (default: /tmp/vertigo_output)

        Returns:
            Resultados normalizados con mutation score y findings
        """
        import time
        start = time.time()

        try:
            # Configuración
            test_command = kwargs.get("test_command", "forge test")
            mutation_count = kwargs.get("mutation_count", 10)
            sample_ratio = kwargs.get("sample_ratio", 0.1)
            timeout = kwargs.get("timeout", 30)
            output_dir = kwargs.get("output_dir", "/tmp/vertigo_output")

            # Detectar directorio del proyecto
            if os.path.isfile(contract_path):
                project_dir = str(Path(contract_path).parent)
            else:
                project_dir = contract_path

            # Ejecutar Vertigo
            cmd = [
                "vertigo",
                "run",
                "--project-dir", project_dir,
                "--test-command", test_command,
                "--sample-ratio", str(sample_ratio),
                "--mutation-count", str(mutation_count),
                "--timeout", str(timeout),
                "--output", output_dir,
                "--format", "json"
            ]

            logger.info(f"Running Vertigo: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout * mutation_count + 60,  # Buffer adicional
                cwd=project_dir
            )

            if result.returncode != 0:
                # Vertigo puede retornar != 0 si hay mutantes vivos (tests débiles)
                # Esto NO es un error, es el resultado esperado
                logger.warning(f"Vertigo finished with code {result.returncode}")

            # Parsear output JSON
            output_file = os.path.join(output_dir, "vertigo_results.json")
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    raw_output = json.load(f)
            else:
                # Si no hay archivo JSON, intentar parsear stdout
                try:
                    raw_output = json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {
                        "tool": "vertigo",
                        "version": "1.0.0",
                        "status": "error",
                        "error": f"No JSON output found. stderr: {result.stderr}",
                        "findings": [],
                        "execution_time": time.time() - start
                    }

            # Normalizar findings
            findings = self.normalize_findings(raw_output)

            # Calcular mutation score
            mutation_score = self._calculate_mutation_score(raw_output)

            return {
                "tool": "vertigo",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "mutation_score": mutation_score,
                    "total_mutants": raw_output.get("total_mutants", 0),
                    "killed_mutants": raw_output.get("killed_mutants", 0),
                    "survived_mutants": raw_output.get("survived_mutants", 0),
                    "timeout_mutants": raw_output.get("timeout_mutants", 0),
                    "test_quality": self._test_quality_level(mutation_score),
                    "project_dir": project_dir
                },
                "execution_time": time.time() - start
            }

        except subprocess.TimeoutExpired:
            logger.error("Vertigo execution timeout")
            return {
                "tool": "vertigo",
                "version": "1.0.0",
                "status": "error",
                "error": "Execution timeout - tests may be too slow",
                "findings": [],
                "execution_time": time.time() - start
            }
        except Exception as e:
            logger.error(f"Vertigo execution error: {e}")
            return {
                "tool": "vertigo",
                "version": "1.0.0",
                "status": "error",
                "error": str(e),
                "findings": [],
                "execution_time": time.time() - start
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normaliza findings de Vertigo a formato MIESC.

        Cada mutante vivo (survived) indica un test débil o faltante.
        """
        findings = []

        # Obtener mutantes sobrevivientes (los que los tests NO detectaron)
        survived_mutants = raw_output.get("survived_mutants_details", [])

        for idx, mutant in enumerate(survived_mutants):
            # Determinar severidad basada en tipo de mutación
            mutation_type = mutant.get("mutation_type", "unknown")
            severity = self._mutation_severity(mutation_type)

            finding = {
                "id": f"VERTIGO-WEAK-TEST-{idx + 1}",
                "type": "test_quality_issue",
                "severity": severity,
                "confidence": 0.95,  # Mutation testing es muy confiable
                "location": {
                    "file": mutant.get("file", "unknown"),
                    "line": mutant.get("line", 0),
                    "function": mutant.get("function", "unknown"),
                    "code_snippet": mutant.get("original_code", "")
                },
                "message": f"Test suite did not catch {mutation_type} mutation",
                "description": (
                    f"Mutation testing revealed that changing '{mutant.get('original_code', '')}' "
                    f"to '{mutant.get('mutated_code', '')}' was NOT detected by tests. "
                    f"This indicates weak test coverage or missing test cases."
                ),
                "recommendation": (
                    f"Add test case that validates the behavior changed by this mutation. "
                    f"Original: {mutant.get('original_code', '')}, "
                    f"Mutated: {mutant.get('mutated_code', '')}"
                ),
                "swc_id": None,  # Test quality no está en SWC
                "cwe_id": None,
                "owasp_category": None,
                "mutation_type": mutation_type,
                "original_code": mutant.get("original_code", ""),
                "mutated_code": mutant.get("mutated_code", ""),
                "test_command": mutant.get("test_command", "")
            }
            findings.append(finding)

        return findings

    def _calculate_mutation_score(self, raw_output: Dict) -> float:
        """
        Calcula mutation score: (killed / total) * 100

        Score alto = tests fuertes (detectan mutaciones)
        Score bajo = tests débiles (no detectan mutaciones)
        """
        total = raw_output.get("total_mutants", 0)
        killed = raw_output.get("killed_mutants", 0)

        if total == 0:
            return 0.0

        return round((killed / total) * 100, 2)

    def _test_quality_level(self, mutation_score: float) -> str:
        """Convierte mutation score a nivel de calidad"""
        if mutation_score >= 90:
            return "Excellent"
        elif mutation_score >= 75:
            return "Good"
        elif mutation_score >= 50:
            return "Fair"
        elif mutation_score >= 25:
            return "Poor"
        return "Critical"

    def _mutation_severity(self, mutation_type: str) -> str:
        """
        Determina severidad basada en tipo de mutación.

        Mutaciones críticas (require/assert removal) son más severas.
        """
        critical_mutations = [
            "require_removal",
            "assert_removal",
            "revert_removal",
            "access_control_removal"
        ]

        high_mutations = [
            "boundary_mutation",
            "logical_operator",
            "arithmetic_operator"
        ]

        if mutation_type in critical_mutations:
            return "High"
        elif mutation_type in high_mutations:
            return "Medium"
        return "Low"

    def can_analyze(self, contract_path: str) -> bool:
        """
        Vertigo requiere un proyecto con tests configurados.
        No solo un archivo .sol aislado.
        """
        # Si es un directorio con foundry.toml o hardhat.config.js, sí
        if os.path.isdir(contract_path):
            has_foundry = os.path.exists(os.path.join(contract_path, "foundry.toml"))
            has_hardhat = os.path.exists(os.path.join(contract_path, "hardhat.config.js"))
            return has_foundry or has_hardhat

        # Si es archivo .sol, verificar que el directorio padre tenga config
        if contract_path.endswith('.sol'):
            parent = Path(contract_path).parent
            has_foundry = (parent / "foundry.toml").exists()
            has_hardhat = (parent / "hardhat.config.js").exists()
            return has_foundry or has_hardhat

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Configuración por defecto de Vertigo"""
        return {
            "test_command": "forge test",
            "mutation_count": 10,
            "sample_ratio": 0.1,
            "timeout": 30,
            "min_mutation_score": 75.0  # Score mínimo aceptable
        }

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Valida configuración de Vertigo"""
        required_keys = ["test_command"]
        if not all(key in config for key in required_keys):
            return False

        # Validar rangos
        if "sample_ratio" in config:
            if not 0 < config["sample_ratio"] <= 1:
                return False

        if "timeout" in config:
            if config["timeout"] <= 0:
                return False

        return True
