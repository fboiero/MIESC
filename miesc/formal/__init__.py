"""
Formal verification spec generation + execution.

Bridges MIESC findings to formal verification tools:
  - Certora Prover (CVL)
  - Scribble (inline annotations)
  - SMTChecker (solc built-in)
  - Halmos (symbolic testing)
"""

from miesc.formal.economic_harness import (
    EconomicHarnessBuilder,
    HarnessArtifact,
    RunnableProperty,
    run_economic_fuzz,
    supported_invariants,
)
from miesc.formal.economic_invariants import (
    ECONOMIC_INVARIANT_TEMPLATES,
    EconomicInvariantTemplate,
    detect_economic_invariants,
)
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
    "ECONOMIC_INVARIANT_TEMPLATES",
    "EconomicHarnessBuilder",
    "EconomicInvariantTemplate",
    "GeneratedSpec",
    "HarnessArtifact",
    "RunnableProperty",
    "run_economic_fuzz",
    "supported_invariants",
    "ProverVerdict",
    "SpecFormat",
    "SpecGenerator",
    "SpecRunner",
    "UNAVAILABLE",
    "UnifiedVerificationReport",
    "VerificationResult",
    "detect_economic_invariants",
    "normalize_status",
    "run_all_available",
]
