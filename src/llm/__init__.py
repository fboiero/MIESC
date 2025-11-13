"""
LLM Integration Module - MIESC v3.5.0
=====================================

Sovereign LLM integration using Ollama for intelligent post-processing
of security analysis results across all layers.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 1.0.0
"""

from .openllama_helper import (
    OpenLLaMAHelper,
    enhance_findings_with_llm,
    explain_technical_output,
    prioritize_findings,
    generate_remediation_advice
)

__all__ = [
    "OpenLLaMAHelper",
    "enhance_findings_with_llm",
    "explain_technical_output",
    "prioritize_findings",
    "generate_remediation_advice"
]
