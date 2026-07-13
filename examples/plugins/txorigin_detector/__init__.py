"""
tx.origin Authentication Detector Plugin — Example MIESC Plugin
==============================================================

Demonstrates how to implement a DetectorPlugin that uses regex to
identify tx.origin-based authorization checks in Solidity source code.
"""

from .detector import TxOriginAuthDetectorPlugin

__all__ = ["TxOriginAuthDetectorPlugin"]
