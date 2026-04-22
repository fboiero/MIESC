"""
CSV Reporter Plugin — Example MIESC Plugin
==========================================

Demonstrates how to implement a ReporterPlugin that converts
MIESC findings to CSV format.
"""

from .reporter import CSVReporterPlugin

__all__ = ["CSVReporterPlugin"]
