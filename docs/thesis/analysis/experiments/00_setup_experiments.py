#!/usr/bin/env python3
"""
Experiment Setup Script - MIESC Thesis

Prepares experimental environment for scientific validation:
- Downloads datasets (SmartBugs, Etherscan)
- Sets up ground truth labels
- Configures experiment parameters

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import os
import sys
import json
import requests
import logging
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ExperimentSetup:
    """Setup experimental environment"""

    def __init__(self, base_dir: str = "analysis/experiments"):
        self.base_dir = Path(base_dir)
        self.datasets_dir = self.base_dir / "datasets"
        self.ground_truth_dir = self.base_dir / "ground_truth"
        self.results_dir = self.base_dir / "results"

        # Create directories
        for dir_path in [self.datasets_dir, self.ground_truth_dir, self.results_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def setup_all(self):
        """Run complete setup"""
        logger.info("🔬 Setting up MIESC experiments...")

        logger.info("\n📦 Step 1: Downloading datasets...")
        self.download_smartbugs()
        self.create_sample_dataset()

        logger.info("\n🏷️  Step 2: Creating ground truth labels...")
        self.create_ground_truth()

        logger.info("\n⚙️  Step 3: Creating experiment configuration...")
        self.create_experiment_config()

        logger.info("\n✅ Experiment setup complete!")
        logger.info(f"   Datasets: {self.datasets_dir}")
        logger.info(f"   Ground truth: {self.ground_truth_dir}")
        logger.info(f"   Results: {self.results_dir}")

    def download_smartbugs(self):
        """Download SmartBugs dataset"""
        logger.info("Downloading SmartBugs curated dataset...")

        smartbugs_url = "https://raw.githubusercontent.com/smartbugs/smartbugs/master/dataset"

        # Note: In practice, you'd clone the SmartBugs repo
        # For this example, we'll create a sample structure
        smartbugs_dir = self.datasets_dir / "smartbugs"
        smartbugs_dir.mkdir(exist_ok=True)

        logger.info(f"   Created SmartBugs directory: {smartbugs_dir}")
        logger.info("   ℹ️  To download full dataset, run:")
        logger.info("   git clone https://github.com/smartbugs/smartbugs.git")

    def create_sample_dataset(self):
        """Create sample dataset for testing"""
        logger.info("Creating sample dataset...")

        sample_dir = self.datasets_dir / "sample"
        sample_dir.mkdir(exist_ok=True)

        # Sample vulnerable contract (reentrancy)
        reentrancy_contract = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Reentrancy
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;  // State change after external call
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
"""

        # Save sample contract
        with open(sample_dir / "reentrancy_vulnerable.sol", "w") as f:
            f.write(reentrancy_contract)

        # Sample safe contract
        safe_contract = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SafeBank is ReentrancyGuard {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: Uses ReentrancyGuard and checks-effects-interactions
    function withdraw() public nonReentrant {
        uint amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        balances[msg.sender] = 0;  // State change before external call

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function getBalance() public view returns (uint) {
        return address(this).balance;
    }
}
"""

        with open(sample_dir / "safe_bank.sol", "w") as f:
            f.write(safe_contract)

        logger.info(f"   Created 2 sample contracts in {sample_dir}")

    def create_ground_truth(self):
        """Create ground truth labels for validation"""
        logger.info("Creating ground truth labels...")

        # Ground truth for sample contracts
        ground_truth = {
            "metadata": {
                "created": "2025-01-01T00:00:00Z",
                "version": "1.0",
                "annotator": "Fernando Boiero",
                "methodology": "Manual expert review + automated tool validation"
            },
            "contracts": [
                {
                    "name": "reentrancy_vulnerable.sol",
                    "is_vulnerable": 1,
                    "vulnerabilities": [
                        {
                            "type": "reentrancy",
                            "severity": "High",
                            "location": {"line": 14, "function": "withdraw"},
                            "cwe": "CWE-841",
                            "swc": "SWC-107",
                            "owasp": "SC01-Reentrancy"
                        }
                    ]
                },
                {
                    "name": "safe_bank.sol",
                    "is_vulnerable": 0,
                    "vulnerabilities": []
                }
            ]
        }

        gt_path = self.ground_truth_dir / "sample_ground_truth.json"
        with open(gt_path, "w") as f:
            json.dump(ground_truth, f, indent=2)

        logger.info(f"   Created ground truth: {gt_path}")

        # Create binary labels for metrics calculation
        binary_labels = {
            "contract_names": ["reentrancy_vulnerable.sol", "safe_bank.sol"],
            "labels": [1, 0],  # 1 = vulnerable, 0 = safe
            "description": "Binary labels for scientific metrics calculation"
        }

        binary_path = self.ground_truth_dir / "binary_labels.json"
        with open(binary_path, "w") as f:
            json.dump(binary_labels, f, indent=2)

        logger.info(f"   Created binary labels: {binary_path}")

    def create_experiment_config(self):
        """Create experiment configuration"""
        logger.info("Creating experiment configuration...")

        config = {
            "experiment_metadata": {
                "title": "MIESC Multi-Tool Validation Experiment",
                "researcher": "Fernando Boiero",
                "institution": "UNDEF - IUA Córdoba",
                "date": "2025-01-01",
                "hypothesis": "Integrating multiple security tools with AI correlation improves vulnerability detection accuracy",
                "research_questions": [
                    "RQ1: Does multi-tool integration improve recall over single tools?",
                    "RQ2: Does AI correlation reduce false positive rate?",
                    "RQ3: What is Cohen's Kappa for inter-tool agreement?",
                    "RQ4: How does MIESC compare to baseline tools (Slither, Mythril)?"
                ]
            },
            "independent_variables": [
                "tool_combination",
                "ai_model_type",
                "vulnerability_class"
            ],
            "dependent_variables": [
                "precision",
                "recall",
                "f1_score",
                "cohens_kappa",
                "execution_time",
                "false_positive_rate"
            ],
            "experimental_groups": [
                {
                    "name": "baseline_slither",
                    "description": "Slither only (baseline)",
                    "tools": ["slither"],
                    "ai_enabled": false
                },
                {
                    "name": "baseline_mythril",
                    "description": "Mythril only (baseline)",
                    "tools": ["mythril"],
                    "ai_enabled": false
                },
                {
                    "name": "multi_tool_no_ai",
                    "description": "Multiple tools without AI",
                    "tools": ["slither", "mythril", "aderyn"],
                    "ai_enabled": false
                },
                {
                    "name": "miesc_full",
                    "description": "MIESC with AI correlation (experimental group)",
                    "tools": ["slither", "mythril", "aderyn"],
                    "ai_enabled": true
                }
            ],
            "datasets": {
                "smartbugs": {
                    "path": "analysis/experiments/datasets/smartbugs",
                    "size": 143,
                    "description": "SmartBugs curated vulnerable contracts"
                },
                "sample": {
                    "path": "analysis/experiments/datasets/sample",
                    "size": 2,
                    "description": "Sample contracts for quick testing"
                }
            },
            "metrics": {
                "precision": "TP / (TP + FP)",
                "recall": "TP / (TP + FN)",
                "f1_score": "2 * (precision * recall) / (precision + recall)",
                "cohens_kappa": "Inter-rater agreement measure",
                "false_positive_rate": "FP / (FP + TN)"
            },
            "statistical_analysis": {
                "significance_level": 0.05,
                "power": 0.8,
                "minimum_sample_size": 30,
                "statistical_tests": [
                    "paired_t_test",
                    "wilcoxon_signed_rank",
                    "cohens_d_effect_size"
                ]
            },
            "validity_threats": {
                "internal": [
                    "Tool version differences",
                    "Configuration variations",
                    "Execution environment differences"
                ],
                "external": [
                    "Dataset representativeness",
                    "Real-world applicability",
                    "Solidity version coverage"
                ],
                "construct": [
                    "Ground truth accuracy",
                    "Vulnerability definition consistency"
                ]
            },
            "ethical_considerations": {
                "data_privacy": "All contracts are public or synthetic",
                "responsible_disclosure": "Vulnerabilities reported through proper channels",
                "ai_governance": "ISO/IEC 42001 compliance for AI usage"
            }
        }

        config_path = self.results_dir / "experiment_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        logger.info(f"   Created experiment config: {config_path}")


if __name__ == "__main__":
    setup = ExperimentSetup()
    setup.setup_all()

    print("\n" + "="*60)
    print("📊 Next Steps:")
    print("="*60)
    print("1. Run experiments:  python analysis/experiments/10_run_experiments.py")
    print("2. Analyze results:  python analysis/experiments/20_analyze_results.py")
    print("3. Generate plots:   python analysis/experiments/30_generate_plots.py")
    print("="*60)
