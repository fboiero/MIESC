#!/usr/bin/env python3
"""
MIESC Setup Script

Multi-layer Intelligent Evaluation for Smart Contracts
MCP-compatible blockchain security framework

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
License: GPL-3.0
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="miesc",
    version="4.0.0",
    description="Multi-layer Intelligent Evaluation for Smart Contracts - AI-enhanced MCP-compatible security framework",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Fernando Boiero",
    author_email="fboiero@frvm.utn.edu.ar",
    url="https://github.com/fboiero/MIESC",
    project_urls={
        "Documentation": "https://fboiero.github.io/MIESC",
        "Bug Tracker": "https://github.com/fboiero/MIESC/issues",
        "Source Code": "https://github.com/fboiero/MIESC",
    },
    license="GPL-3.0",
    packages=find_packages(exclude=["tests", "tests.*", "docs", "examples"]),
    package_data={
        "miesc": ["py.typed"],
    },
    python_requires=">=3.9",
    install_requires=[
        "fastapi>=0.104.0",
        "uvicorn>=0.24.0",
        "click>=8.1.0",
        "pydantic>=2.0.0",
        "slither-analyzer>=0.10.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.0.0",
        ],
        "all-tools": [
            "mythril>=0.24.0",
            "web3>=6.0.0",
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "miesc=miesc.cli.miesc_cli:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "blockchain",
        "ethereum",
        "smart-contracts",
        "security",
        "static-analysis",
        "formal-verification",
        "vulnerability-detection",
        "mcp",
        "model-context-protocol",
    ],
    zip_safe=False,
)
