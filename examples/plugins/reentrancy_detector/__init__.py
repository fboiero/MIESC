"""
Reentrancy Detector Plugin — Example MIESC Plugin
==================================================

Demonstrates how to implement a DetectorPlugin that uses regex
to identify reentrancy patterns in Solidity source code.
"""

from .detector import ReentrancyDetectorPlugin

__all__ = ["ReentrancyDetectorPlugin"]
