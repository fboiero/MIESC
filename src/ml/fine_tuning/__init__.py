"""
MIESC Fine-Tuning Module for Solidity Security LLM

This module provides tools for fine-tuning language models
specifically for Solidity smart contract security analysis.

Author: Fernando Boiero
"""

from .dataset_generator import SoliditySecurityDatasetGenerator
from .fine_tuning_trainer import SoliditySecurityTrainer

__all__ = [
    "SoliditySecurityDatasetGenerator",
    "SoliditySecurityTrainer"
]
