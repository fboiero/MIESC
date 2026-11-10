"""
Caracal Static Analyzer Adapter — Cairo / Starknet (Layer 1)
============================================================

Integrates Caracal (crytic's Rust static analyzer for Starknet smart contracts)
into MIESC. Caracal compiles Cairo to Sierra and runs detectors over the Sierra
representation. This adapter targets the Cairo-2.x line via the
``adrienlacombe/caracal`` fork (v0.3.0), which upgraded the bundled compiler to
Cairo 2.20.0 and restored/added detectors that had gone inert on Cairo >= 2.6.

Tool: Caracal (https://github.com/crytic/caracal) — Trail of Bits — AGPL-3.0.
Cairo 2.20 fork: https://github.com/adrienlacombe/caracal (AGPL-3.0).
Adapter author: Fernando Boiero <fboiero@frvm.utn.edu.ar>

Honest-error contract (verified against the fork's ``detect --help`` and runs):
    exit 0   -> analysis ran; a JSON array of findings on stdout (may be empty)
    exit 1   -> finding at/above a ``--fail-on`` threshold (we do NOT pass it)
    exit 2   -> caracal failed to run (compilation error, invalid target, bad arg)
    exit 101 -> Rust panic (seen on malformed-but-parseable input)
This adapter runs WITHOUT ``--fail-on`` and treats any exit code other than 0
as ``status="error"`` (never ``success`` with 0 findings), mirroring the
fuzzing-adapter honest-error fix.
"""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from miesc.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)

_VERSION = "1.0.0"


class CaracalAdapter(ToolAdapter):
    """Caracal adapter for Cairo / Starknet static analysis.

    The caracal binary is resolved, in order, from the ``CARACAL_BIN``
    environment variable (absolute path to a specific build — used by the PoC
    and the test suite), then ``~/.cargo/bin/caracal`` (``cargo install``
    location), then ``PATH``.
    """

    # Caracal's textual confidence -> MIESC confidence float.
    CONFIDENCE_MAP = {"high": 0.9, "medium": 0.75, "low": 0.55}

    # Per-detector enrichment: detector slug -> mapping.
    #   severity: explicit MIESC severity, or None to trust caracal's own impact
    #   cwe:      CWE identifier (None if not applicable)
    #   owasp:    OWASP Smart Contract Top 10 (2025) category, or a Starknet-
    #             specific label where no standard SC## fits
    #   rec:      one-line remediation
    # Detectors not listed fall back to caracal's impact + a generic rec.
    DETECTOR_MAP: Dict[str, Dict[str, Optional[str]]] = {
        # --- Reentrancy family (SC01) ---
        "reentrancy": {
            "severity": None, "cwe": "CWE-841", "owasp": "SC01: Reentrancy",
            "rec": "Apply the checks-effects-interactions pattern: update storage before external calls, or add a reentrancy guard.",
        },
        "read-only-reentrancy": {
            "severity": None, "cwe": "CWE-841", "owasp": "SC01: Reentrancy",
            "rec": "A view read during a reentrant call can observe inconsistent state; guard the state-changing path.",
        },
        "reentrancy-events": {
            "severity": "Low", "cwe": "CWE-841", "owasp": "SC01: Reentrancy",
            "rec": "Emit events before external calls so off-chain consumers see a consistent ordering.",
        },
        "reentrancy-benign": {
            "severity": "Low", "cwe": "CWE-841", "owasp": "SC01: Reentrancy",
            "rec": "State is written after an external call but without an obvious exploit; still prefer checks-effects-interactions.",
        },
        # --- Access control / class-hash & upgrade safety (SC02) ---
        "tx-origin": {
            "severity": None, "cwe": "CWE-477", "owasp": "SC02: Access Control",
            "rec": "Do not authorize with get_caller_address() compared against tx origin; use explicit owner/role checks.",
        },
        "controlled-library-call": {
            "severity": None, "cwe": "CWE-829", "owasp": "SC02: Access Control",
            "rec": "Never library_call_syscall a user-controlled class hash; restrict the class hash to a vetted allowlist.",
        },
        "controlled-replace-class": {
            "severity": None, "cwe": "CWE-829", "owasp": "SC02: Access Control",
            "rec": "replace_class_syscall with a user-controlled class hash is an arbitrary upgrade; gate it behind strict access control.",
        },
        "unprotected-replace-class": {
            "severity": None, "cwe": "CWE-284", "owasp": "SC02: Access Control",
            "rec": "replace_class_syscall must be protected by an owner/admin check; an unprotected upgrade bricks or hijacks the contract.",
        },
        "controlled-deploy": {
            "severity": None, "cwe": "CWE-829", "owasp": "SC02: Access Control",
            "rec": "deploy_syscall with a user-controlled class hash deploys arbitrary code; constrain the class hash.",
        },
        "unchecked-zero-owner": {
            "severity": None, "cwe": "CWE-284", "owasp": "SC02: Access Control",
            "rec": "Reject the zero address when setting an owner/admin to avoid an unrecoverable or unowned contract.",
        },
        "privileged-write-no-event": {
            "severity": "Low", "cwe": "CWE-778", "owasp": "SC02: Access Control",
            "rec": "Emit an event on privileged storage writes so admin actions are auditable off-chain.",
        },
        # --- L1 <-> L2 messaging (Starknet-specific) ---
        "unchecked-l1-handler-from": {
            "severity": None, "cwe": "CWE-346", "owasp": "Starknet: L1<->L2 Messaging",
            "rec": "Validate the `from_address` of an #[l1_handler] against the expected L1 sender before trusting the payload.",
        },
        "controlled-l1-message": {
            "severity": None, "cwe": "CWE-346", "owasp": "Starknet: L1<->L2 Messaging",
            "rec": "Do not send_message_to_l1_syscall to a user-controlled to_address; pin the L1 recipient.",
        },
        "unchecked-l1-message": {
            "severity": None, "cwe": "CWE-346", "owasp": "Starknet: L1<->L2 Messaging",
            "rec": "Validate L1 message parameters before acting on them.",
        },
        # --- Arithmetic (SC03) ---
        "felt252-unsafe-arithmetic": {
            "severity": None, "cwe": "CWE-190", "owasp": "SC03: Arithmetic",
            "rec": "felt252 arithmetic wraps modulo the field prime with no overflow check; use bounded integer types (u256/u128) or explicit range checks.",
        },
        # --- Unchecked return values (SC04) ---
        "unchecked-transfer": {
            "severity": None, "cwe": "CWE-252", "owasp": "SC04: Unchecked Return Values",
            "rec": "Check the boolean result of ERC-20 transfer/transferFrom, or use a safe-transfer wrapper that reverts on failure.",
        },
        "unused-return": {
            "severity": "Low", "cwe": "CWE-252", "owasp": "SC04: Unchecked Return Values",
            "rec": "Handle or explicitly discard the return value of called functions.",
        },
        # --- Randomness ---
        "block-values-for-randomness": {
            "severity": None, "cwe": "CWE-330", "owasp": "SC06: Bad Randomness",
            "rec": "Block timestamp/number are predictable/manipulable; use a VRF or commit-reveal for randomness.",
        },
        # --- Array / span misuse ---
        "use-after-pop-front": {
            "severity": None, "cwe": "CWE-125", "owasp": "Starknet: Array/Span misuse",
            "rec": "Do not reuse an array/span after pop_front removed elements; re-read length or hold a fresh snapshot.",
        },
        "deploy-from-zero": {
            "severity": None, "cwe": "CWE-665", "owasp": "SC02: Access Control",
            "rec": "deploy_syscall with deploy_from_zero=true makes the deployed address independent of the deployer; confirm that is intended.",
        },
        # --- Code quality / informational ---
        "unused-events": {"severity": "Info", "cwe": "CWE-561", "owasp": None,
                          "rec": "Remove the declared-but-never-emitted event, or emit it."},
        "unused-arguments": {"severity": "Info", "cwe": "CWE-561", "owasp": None,
                             "rec": "Remove the unused argument or use it."},
        "dead-code": {"severity": "Info", "cwe": "CWE-561", "owasp": None,
                      "rec": "Remove unreachable/unused code to reduce attack surface."},
    }

    DEFAULT_RECOMMENDATION = (
        "Review the finding against Starknet/Cairo security best practices."
    )

    # ------------------------------------------------------------------ binary
    def _binary(self) -> str:
        override = os.environ.get("CARACAL_BIN")
        if override:
            return override
        return self.find_binary(
            "caracal",
            priority_paths=[os.path.expanduser("~/.cargo/bin/caracal")],
        )

    # ---------------------------------------------------------------- metadata
    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="caracal",
            version=_VERSION,
            category=ToolCategory.STATIC_ANALYSIS,
            author="Trail of Bits / adrienlacombe fork (Adapter by Fernando Boiero)",
            license="AGPL-3.0",
            homepage="https://github.com/crytic/caracal",
            repository="https://github.com/adrienlacombe/caracal",
            documentation="https://github.com/crytic/caracal#readme",
            installation_cmd=(
                "cargo install --git https://github.com/adrienlacombe/caracal "
                "--profile release --force  # requires rustc >= 1.94 (Cairo 2.20)"
            ),
            capabilities=[
                ToolCapability(
                    name="static_analysis",
                    description="Sierra-level static analysis for Cairo / Starknet",
                    supported_languages=["cairo", "starknet"],
                    detection_types=[
                        "reentrancy",
                        "read_only_reentrancy",
                        "tx_origin",
                        "controlled_library_call",
                        "controlled_deploy",
                        "controlled_replace_class",
                        "unprotected_replace_class",
                        "unchecked_l1_handler_from",
                        "controlled_l1_message",
                        "felt252_unsafe_arithmetic",
                        "unchecked_transfer",
                        "use_after_pop_front",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,  # DPGA: graceful degradation when not installed
            requires_llm=False,
        )

    def version_command(self) -> Optional[List[str]]:
        return [self._binary(), "--version"]

    def is_available(self) -> ToolStatus:
        return self.check_binary_available(self._binary(), "--version")

    def can_analyze(self, contract_path: str) -> bool:
        """Caracal handles Cairo: a single ``.cairo`` file or a project
        directory that holds ``.cairo`` sources or a ``Scarb.toml``."""
        path = Path(contract_path)
        if path.is_file():
            return path.suffix == ".cairo"
        if path.is_dir():
            if (path / "Scarb.toml").is_file():
                return True
            return any(path.glob("**/*.cairo"))
        # Not on disk yet: fall back to the extension so routing still works.
        return contract_path.endswith(".cairo")

    # ----------------------------------------------------------------- analyze
    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
        start_time = time.time()

        if not Path(contract_path).exists():
            return self.create_result(
                status="error",
                error=f"Contract path does not exist: {contract_path}",
                execution_time=time.time() - start_time,
                metadata={"contract_analyzed": contract_path},
            )

        status = self.is_available()
        if status != ToolStatus.AVAILABLE:
            return self.create_result(
                status="error",
                error=f"Caracal not available: {status.value}",
                execution_time=time.time() - start_time,
                metadata={"tool_status": status.value},
            )

        binary = self._binary()
        timeout = kwargs.get("timeout", 300)
        cmd = [binary, "detect", "--format", "json", contract_path]
        logger.info("Running Caracal analysis: %s", " ".join(cmd))

        try:
            returncode, stdout, stderr = self.run_subprocess(cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            return self.create_result(
                status="error",
                error=f"Caracal analysis timed out after {timeout}s",
                execution_time=time.time() - start_time,
                metadata={"timeout": timeout},
            )
        except FileNotFoundError:
            return self.create_result(
                status="error",
                error=f"Caracal binary not found: {binary}",
                execution_time=time.time() - start_time,
                metadata={"binary": binary},
            )
        except Exception as exc:  # noqa: BLE001 - surface anything as honest error
            logger.error("Unexpected error running Caracal: %s", exc, exc_info=True)
            return self.create_result(
                status="error",
                error=f"Unexpected error: {exc}",
                execution_time=time.time() - start_time,
                metadata={"exception": str(exc)},
            )

        execution_time = time.time() - start_time

        # Honest-error contract: any non-zero exit (2 = compile/target error,
        # 101 = panic, anything else) is an error, NOT success-with-0-findings.
        if returncode != 0:
            err_tail = (stderr or stdout or "").strip()[-800:]
            logger.error(
                "Caracal failed (exit %s) on %s: %s",
                returncode, contract_path, err_tail or "(no output)",
            )
            return self.create_result(
                status="error",
                error=f"Caracal failed to run (exit code {returncode})",
                execution_time=execution_time,
                metadata={
                    "exit_code": returncode,
                    "stderr": err_tail,
                    "contract_analyzed": contract_path,
                },
            )

        # exit 0: stdout is a JSON array of findings (possibly empty).
        try:
            raw = json.loads(stdout) if stdout.strip() else []
        except json.JSONDecodeError as exc:
            return self.create_result(
                status="error",
                error=f"Caracal returned exit 0 but invalid JSON: {exc}",
                execution_time=execution_time,
                metadata={"exit_code": returncode, "stdout_head": stdout[:500]},
            )

        if not isinstance(raw, list):
            return self.create_result(
                status="error",
                error="Caracal JSON output was not an array of findings",
                execution_time=execution_time,
                metadata={"exit_code": returncode},
            )

        findings = self.normalize_findings(raw)
        logger.info(
            "Caracal analysis completed: %d findings in %.2fs",
            len(findings), execution_time,
        )
        return self.create_result(
            status="success",
            findings=findings,
            execution_time=execution_time,
            metadata={
                "contract_analyzed": contract_path,
                "raw_findings_count": len(raw),
                "normalized_findings_count": len(findings),
                "binary": binary,
            },
        )

    # ------------------------------------------------------------- normalize
    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize a parsed Caracal JSON array to MIESC findings.

        Each Caracal finding looks like::

            {"detector": "reentrancy", "impact": "Medium",
             "confidence": "Medium", "message": "...",
             "locations": [{"file": "a.cairo", "line": 36, "col": 9}, ...]}
        """
        normalized: List[Dict[str, Any]] = []
        if not isinstance(raw_output, list):
            logger.error("Caracal normalize_findings expected a list, got %s", type(raw_output))
            return normalized

        for idx, item in enumerate(raw_output):
            if not isinstance(item, dict):
                continue
            detector = str(item.get("detector", "unknown"))
            impact = str(item.get("impact", "Low"))
            confidence_str = str(item.get("confidence", "Medium"))
            message = str(item.get("message", ""))
            locations = item.get("locations") or []

            file_path, line = "", 0
            if locations and isinstance(locations[0], dict):
                file_path = str(locations[0].get("file", ""))
                line = int(locations[0].get("line", 0) or 0)

            mapping = self.DETECTOR_MAP.get(detector, {})
            severity_override = mapping.get("severity")
            severity = (
                severity_override
                if severity_override is not None
                else self.normalize_severity(impact)
            )
            confidence = self.CONFIDENCE_MAP.get(confidence_str.lower(), 0.75)
            cwe_id = mapping.get("cwe")
            owasp = mapping.get("owasp")
            recommendation = mapping.get("rec") or self.DEFAULT_RECOMMENDATION

            # Short message = first line; full multi-line text -> description.
            short_message = message.split("\n", 1)[0].strip() or detector

            normalized.append(
                {
                    "id": f"caracal-{detector}-{idx}",
                    "type": detector,
                    "severity": severity,
                    "confidence": max(0.0, min(1.0, confidence)),
                    "location": {
                        "file": file_path,
                        "line": line,
                        "function": "",
                    },
                    "message": short_message,
                    "description": message or short_message,
                    "recommendation": recommendation,
                    "swc_id": None,  # SWC is EVM-specific; not applicable to Cairo
                    "cwe_id": cwe_id,
                    "owasp_category": owasp,
                    "chain": "starknet",
                    "_caracal_detector": detector,  # for cross-tool correlation (F3)
                    "_caracal_impact": impact,
                    "_caracal_confidence": confidence_str,
                }
            )

        return normalized

    def get_default_config(self) -> Dict[str, Any]:
        return {"timeout": 300, "output_format": "json"}


# Export for registry
__all__ = ["CaracalAdapter"]
