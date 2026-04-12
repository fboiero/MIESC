"""
Formal verification spec generation + execution.

Bridges MIESC findings to formal verification tools:
  - Certora Prover (CVL)
  - Scribble (inline annotations)
  - SMTChecker (solc built-in)
  - Halmos (symbolic testing)
"""

from src.formal.spec_generator import (
    GeneratedSpec,
    SpecFormat,
    SpecGenerator,
)
from src.formal.spec_runner import (
    SpecRunner,
    VerificationResult,
    run_all_available,
)

__all__ = [
    "GeneratedSpec",
    "SpecFormat",
    "SpecGenerator",
    "SpecRunner",
    "VerificationResult",
    "run_all_available",
]
