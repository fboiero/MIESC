"""
MIESC - Multi-layer Intelligent Evaluation for Smart Contracts

A production-grade, modular blockchain security framework with MCP support.

Author: Fernando Boiero
Institution: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
License: GPL-3.0
"""

__version__ = "3.3.0"
__author__ = "Fernando Boiero"
__license__ = "GPL-3.0"

from miesc.core import analyzer, verifier, classifier

__all__ = [
    "analyzer",
    "verifier",
    "classifier",
]
