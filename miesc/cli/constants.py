"""
MIESC CLI Constants

Centralized constants for the MIESC CLI including banners,
layer definitions, tool mappings, and profiles.

Author: Fernando Boiero
License: AGPL-3.0
"""

from typing import Any, Dict, List

# Version and banner
BANNER = r"""
  __  __ ___ _____ ____   ____
 |  \/  |_ _| ____/ ___| / ___|
 | |\/| || ||  _| \___ \| |
 | |  | || || |___ ___) | |___
 |_|  |_|___|_____|____/ \____|
"""

# Complete 9-layer architecture with 50 tools
LAYERS: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "Static Analysis",
        "description": "Pattern-based code analysis",
        "tools": ["slither", "aderyn", "solhint", "wake", "semgrep", "fouranalyzer", "vyper"],
    },
    2: {
        "name": "Dynamic Testing",
        "description": "Fuzzing and property testing",
        "tools": ["echidna", "medusa", "foundry", "dogefuzz", "vertigo", "hardhat"],
    },
    3: {
        "name": "Symbolic Execution",
        "description": "Path exploration and constraint solving",
        "tools": ["mythril", "manticore", "halmos", "oyente", "pakala"],
    },
    4: {
        "name": "Formal Verification",
        "description": "Mathematical proofs of correctness",
        "tools": ["certora", "smtchecker", "propertygpt", "scribble", "solcmc"],
    },
    5: {
        "name": "AI Analysis",
        "description": "LLM-powered vulnerability detection",
        "tools": [
            "smartllm",
            "gptscan",
            "llmsmartaudit",
            "gptlens",
            "llamaaudit",
            "iaudit",
            "smartguard",
        ],
    },
    6: {
        "name": "Heuristic & Pattern Detection",
        "description": (
            "Regex/rule-based pattern matching and graph-structure heuristics. "
            "No trained ML model weights are shipped or loaded today: dagnn/"
            "peculiar/smartbugs_ml fall back to heuristics when GNN weights "
            "are absent, and smartbugs_detector is pure regex."
        ),
        "tools": ["dagnn", "smartbugs_ml", "smartbugs_detector", "peculiar"],
    },
    7: {
        "name": "Specialized Analysis",
        "description": "Domain-specific security checks",
        "tools": [
            "threat_model",
            "gas_analyzer",
            "mev_detector",
            "contract_clone_detector",
            "defi",
            "advanced_detector",
            "upgradability_checker",
        ],
    },
    8: {
        "name": "Cross-Chain & ZK Security",
        "description": (
            "Bridge security and zero-knowledge circuit analysis. zk_circuit/l2_validator "
            "are now proactively selected by `audit deep`/`audit smart` via "
            "DeepAuditAgent._classify_risk_profile's is_zk/is_l2 flags (keyword patterns "
            "on the Solidity source). circom_analyzer still only runs when this layer is "
            "invoked directly (`audit layer 8`, `audit full`): detecting it needs a "
            "sibling .circom file on disk, not a signal in the .sol source text, so there "
            "is no is_circom flag."
        ),
        "tools": ["crosschain", "zk_circuit", "bridge_monitor", "l2_validator", "circom_analyzer"],
    },
    9: {
        "name": "Advanced AI Ensemble",
        "description": (
            "Multi-LLM ensemble with consensus-based detection. Only llmbugscanner "
            "reads the contract on its own; audit_consensus/exploit_synthesizer/"
            "vuln_verifier are second-opinion reviewers over layers 1-8's findings — "
            "MLOrchestrator.analyze() runs them in a second pass (after layers 1-8 "
            "produce findings, feeding findings_map/findings), so `audit full` and "
            "any other command that goes through MLOrchestrator now gets real Layer 9 "
            "output instead of an always-empty findings list. remediation_validator "
            "is deliberately excluded from that pass: it compares original vs. "
            "patched source to verify a fix, a job `miesc remediate --compile "
            "--rescan` already does natively and more rigorously (a real compile "
            "check) — there's no original/patched distinction in a single audit "
            "pass to feed it, so it still returns an empty findings list there."
        ),
        "tools": [
            "llmbugscanner",
            "audit_consensus",
            "exploit_synthesizer",
            "vuln_verifier",
            "remediation_validator",
        ],
    },
}

# Quick scan tools (fast, high-value, all <10s per contract)
# Mythril removed: too slow (~90s/contract) and often unavailable.
# Use `miesc audit full` if you need symbolic execution (Mythril, Halmos, Manticore).
QUICK_TOOLS: List[str] = ["slither", "aderyn", "solhint"]

# Adapter class mapping (tool name -> adapter class name)
ADAPTER_MAP: Dict[str, str] = {
    # Layer 1: Static Analysis
    "slither": "SlitherAdapter",
    "aderyn": "AderynAdapter",
    "solhint": "SolhintAdapter",
    "wake": "WakeAdapter",
    "semgrep": "SemgrepAdapter",
    "fouranalyzer": "FourAnalyzerAdapter",
    "vyper": "VyperAdapter",
    # Layer 2: Dynamic Testing
    "echidna": "EchidnaAdapter",
    "medusa": "MedusaAdapter",
    "foundry": "FoundryAdapter",
    "dogefuzz": "DogeFuzzAdapter",
    "vertigo": "VertigoAdapter",
    "hardhat": "HardhatAdapter",
    # Layer 3: Symbolic Execution
    "mythril": "MythrilAdapter",
    "manticore": "ManticoreAdapter",
    "halmos": "HalmosAdapter",
    "oyente": "OyenteAdapter",
    "pakala": "PakalaAdapter",
    # Layer 4: Formal Verification
    "certora": "CertoraAdapter",
    "smtchecker": "SMTCheckerAdapter",
    "propertygpt": "PropertyGPTAdapter",
    "scribble": "ScribbleAdapter",
    "solcmc": "SolCMCAdapter",
    # Layer 5: AI Analysis
    "smartllm": "SmartLLMAdapter",
    "gptscan": "GPTScanAdapter",
    "llmsmartaudit": "LLMSmartAuditAdapter",
    "gptlens": "GPTLensAdapter",
    "llamaaudit": "LlamaAuditAdapter",
    "iaudit": "IAuditAdapter",
    "frontier_llm": "FrontierLLMAdapter",
    # Layer 6: ML Detection
    "dagnn": "DAGNNAdapter",
    "smartbugs_ml": "SmartBugsMLAdapter",
    "smartbugs_detector": "SmartBugsDetectorAdapter",
    "smartguard": "SmartGuardAdapter",
    "peculiar": "PeculiarAdapter",
    # Layer 7: Specialized Analysis
    "threat_model": "ThreatModelAdapter",
    "gas_analyzer": "GasAnalyzerAdapter",
    "mev_detector": "MEVDetectorAdapter",
    "contract_clone_detector": "ContractCloneDetectorAdapter",
    "defi": "DeFiAdapter",
    "advanced_detector": "AdvancedDetectorAdapter",
    "upgradability_checker": "UpgradabilityCheckerAdapter",
    # Layer 8: Cross-Chain & ZK Security
    "crosschain": "CrossChainAdapter",
    "zk_circuit": "ZKCircuitAdapter",
    "bridge_monitor": "BridgeMonitorAdapter",
    "l2_validator": "L2ValidatorAdapter",
    "circom_analyzer": "CircomAnalyzerAdapter",
    # Layer 9: Advanced AI Ensemble
    "llmbugscanner": "LLMBugScannerAdapter",
    "audit_consensus": "AuditConsensusAdapter",
    "exploit_synthesizer": "ExploitSynthesizerAdapter",
    "vuln_verifier": "VulnVerifierAdapter",
    "remediation_validator": "RemediationValidatorAdapter",
}

# Available profiles for CLI help
AVAILABLE_PROFILES: List[str] = [
    "fast",
    "balanced",
    "thorough",
    "security",
    "ci",
    "audit",
    "defi",
    "token",
]

# Severity levels for findings
SEVERITY_LEVELS: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Default timeout for tool execution (seconds)
DEFAULT_TIMEOUT: int = 300

# Output format options
OUTPUT_FORMATS: List[str] = ["json", "sarif", "html", "pdf", "markdown"]

# Report templates. Single source of truth for `miesc report --template` (both the
# click.Choice and its error message) -- keep in sync with the .md files actually
# shipped in miesc/data/templates/reports/.
REPORT_TEMPLATES: List[str] = [
    "professional",
    "executive",
    "technical",
    "github-pr",
    "simple",
    "profesional",
    "premium",
]
