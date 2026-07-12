"""
Formal verification spec generation + execution.

Bridges MIESC findings to formal verification tools:
  - Certora Prover (CVL)
  - Scribble (inline annotations)
  - SMTChecker (solc built-in)
  - Halmos (symbolic testing)
"""

from miesc.formal.spec_generator import (
    GeneratedSpec,
    SpecFormat,
    SpecGenerator,
)
from miesc.formal.spec_runner import (
    SpecRunner,
    VerificationResult,
    run_all_available,
)
from miesc.formal.unified_report import (
    UNAVAILABLE,
    Counterexample,
    ProverVerdict,
    UnifiedVerificationReport,
    normalize_status,
)

__all__ = [
    "Counterexample",
    "GeneratedSpec",
    "ProverVerdict",
    "SpecFormat",
    "SpecGenerator",
    "SpecRunner",
    "UNAVAILABLE",
    "UnifiedVerificationReport",
    "VerificationResult",
    "normalize_status",
    "run_all_available",
]
