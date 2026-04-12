"""
Formal verification spec generation (Certora CVL, Scribble, SMTChecker).

Bridges MIESC findings to formal verification tools.
"""

from src.formal.spec_generator import (
    GeneratedSpec,
    SpecFormat,
    SpecGenerator,
)

__all__ = ["GeneratedSpec", "SpecFormat", "SpecGenerator"]
