#!/usr/bin/env python3
"""
MIESC Direct Adapter Diagnostic - Tests each adapter directly.
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Suppress warnings for cleaner output
import warnings
warnings.filterwarnings('ignore')

# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'

print("=" * 70)
print("MIESC Direct Adapter Diagnostic v5.0.3")
print(f"OLLAMA_HOST: {os.environ.get('OLLAMA_HOST', 'not set')}")
print("=" * 70)
print()

# Import ToolStatus
from src.core.tool_protocol import ToolStatus

# All adapters to test with their layer info
ADAPTERS_CONFIG = [
    # Layer 1 - Static Analysis
    ("slither", "SlitherAdapter", "slither_adapter", "L1-Static"),
    ("aderyn", "AderynAdapter", "aderyn_adapter", "L1-Static"),
    ("solhint", "SolhintAdapter", "solhint_adapter", "L1-Static"),
    ("semgrep", "SemgrepAdapter", "semgrep_adapter", "L1-Static"),
    ("wake", "WakeAdapter", "wake_adapter", "L1-Static"),
    ("fouranalyzer", "FourAnalyzerAdapter", "fouranalyzer_adapter", "L1-Static"),

    # Layer 2 - Dynamic Testing
    ("echidna", "EchidnaAdapter", "echidna_adapter", "L2-Fuzzing"),
    ("medusa", "MedusaAdapter", "medusa_adapter", "L2-Fuzzing"),
    ("foundry", "FoundryAdapter", "foundry_adapter", "L2-Fuzzing"),
    ("dogefuzz", "DogeFuzzAdapter", "dogefuzz_adapter", "L2-Fuzzing"),
    ("hardhat", "HardhatAdapter", "hardhat_adapter", "L2-Fuzzing"),
    ("vertigo", "VertigoAdapter", "vertigo_adapter", "L2-Fuzzing"),

    # Layer 3 - Symbolic Execution
    ("mythril", "MythrilAdapter", "mythril_adapter", "L3-Symbolic"),
    ("manticore", "ManticoreAdapter", "manticore_adapter", "L3-Symbolic"),
    ("halmos", "HalmosAdapter", "halmos_adapter", "L3-Symbolic"),
    ("oyente", "OyenteAdapter", "oyente_adapter", "L3-Symbolic"),
    ("pakala", "PakalaAdapter", "pakala_adapter", "L3-Symbolic"),

    # Layer 4 - Formal Verification
    ("certora", "CertoraAdapter", "certora_adapter", "L4-Formal"),
    ("smtchecker", "SMTCheckerAdapter", "smtchecker_adapter", "L4-Formal"),
    ("propertygpt", "PropertyGPTAdapter", "propertygpt_adapter", "L4-Formal"),
    ("scribble", "ScribbleAdapter", "scribble_adapter", "L4-Formal"),
    ("solcmc", "SolCMCAdapter", "solcmc_adapter", "L4-Formal"),

    # Layer 5 - AI Analysis
    ("smartllm", "SmartLLMAdapter", "smartllm_adapter", "L5-AI"),
    ("gptscan", "GPTScanAdapter", "gptscan_adapter", "L5-AI"),
    ("llmsmartaudit", "LLMSmartAuditAdapter", "llmsmartaudit_adapter", "L5-AI"),
    ("gptlens", "GPTLensAdapter", "gptlens_adapter", "L5-AI"),
    ("llamaaudit", "LlamaAuditAdapter", "llamaaudit_adapter", "L5-AI"),
    ("iaudit", "IAuditAdapter", "iaudit_adapter", "L5-AI"),

    # Layer 6 - ML Detection
    ("dagnn", "DAGNNAdapter", "dagnn_adapter", "L6-ML"),
    ("smartguard", "SmartGuardAdapter", "smartguard_adapter", "L6-ML"),
    ("smartbugs_ml", "SmartBugsMLAdapter", "smartbugs_ml_adapter", "L6-ML"),
    ("smartbugs_detector", "SmartBugsDetectorAdapter", "smartbugs_detector_adapter", "L6-ML"),
    ("peculiar", "PeculiarAdapter", "peculiar_adapter", "L6-ML"),

    # Layer 7 - Specialized
    ("gas_analyzer", "GasAnalyzerAdapter", "gas_analyzer_adapter", "L7-Special"),
    ("mev_detector", "MEVDetectorAdapter", "mev_detector_adapter", "L7-Special"),
    ("threat_model", "ThreatModelAdapter", "threat_model_adapter", "L7-Special"),
    ("contract_clone_detector", "ContractCloneDetectorAdapter", "contract_clone_detector_adapter", "L7-Special"),
    ("defi", "DeFiAdapter", "defi_adapter", "L7-Special"),
    ("advanced_detector", "AdvancedDetectorAdapter", "advanced_detector_adapter", "L7-Special"),
    ("upgradability_checker", "UpgradabilityCheckerAdapter", "upgradability_checker_adapter", "L7-Special"),

    # Layer 8 - Cross-Chain & ZK
    ("crosschain", "CrossChainAdapter", "crosschain_adapter", "L8-CrossZK"),
    ("zk_circuit", "ZKCircuitAdapter", "zk_circuit_adapter", "L8-CrossZK"),
    ("bridge_monitor", "BridgeMonitorAdapter", "bridge_monitor_adapter", "L8-CrossZK"),
    ("l2_validator", "L2ValidatorAdapter", "l2_validator_adapter", "L8-CrossZK"),
    ("circom_analyzer", "CircomAnalyzerAdapter", "circom_analyzer_adapter", "L8-CrossZK"),

    # Layer 9 - Advanced Ensemble
    ("llmbugscanner", "LLMBugScannerAdapter", "llmbugscanner_adapter", "L9-Ensemble"),
    ("audit_consensus", "AuditConsensusAdapter", "audit_consensus_adapter", "L9-Ensemble"),
    ("exploit_synthesizer", "ExploitSynthesizerAdapter", "exploit_synthesizer_adapter", "L9-Ensemble"),
    ("vuln_verifier", "VulnVerifierAdapter", "vuln_verifier_adapter", "L9-Ensemble"),
    ("remediation_validator", "RemediationValidatorAdapter", "remediation_validator_adapter", "L9-Ensemble"),
]

# Results
results = {
    'available': [],
    'not_installed': [],
    'config_error': [],
    'license_required': [],
    'import_error': [],
}

current_layer = None

for name, class_name, module_name, layer in ADAPTERS_CONFIG:
    # Print layer header
    if layer != current_layer:
        current_layer = layer
        print(f"\n=== {layer} ===")

    try:
        # Dynamic import
        module = __import__(f"src.adapters.{module_name}", fromlist=[class_name])
        adapter_class = getattr(module, class_name)

        # Instantiate
        adapter = adapter_class()

        # Check availability
        status = adapter.is_available()

        # Get version if available
        try:
            metadata = adapter.get_metadata()
            version = metadata.version
        except:
            version = "?"

        # Categorize result
        if status == ToolStatus.AVAILABLE:
            results['available'].append((name, layer, version))
            print(f"{Colors.GREEN}[PASS]{Colors.NC} {name} v{version}")
        elif status == ToolStatus.NOT_INSTALLED:
            results['not_installed'].append((name, layer, "binary not found"))
            print(f"{Colors.RED}[FAIL]{Colors.NC} {name} - not installed")
        elif status == ToolStatus.CONFIGURATION_ERROR:
            results['config_error'].append((name, layer, "config issue"))
            print(f"{Colors.YELLOW}[CONF]{Colors.NC} {name} - configuration error")
        elif status == ToolStatus.LICENSE_REQUIRED:
            results['license_required'].append((name, layer, "API key needed"))
            print(f"{Colors.YELLOW}[KEY ]{Colors.NC} {name} - license/API key required")
        else:
            results['not_installed'].append((name, layer, str(status)))
            print(f"{Colors.RED}[????]{Colors.NC} {name} - {status}")

    except ImportError as e:
        results['import_error'].append((name, layer, str(e)))
        print(f"{Colors.RED}[IMPT]{Colors.NC} {name} - import error: {e}")
    except Exception as e:
        results['not_installed'].append((name, layer, str(e)))
        print(f"{Colors.RED}[ERR ]{Colors.NC} {name} - {e}")

# Summary
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

total = sum(len(v) for v in results.values())
available = len(results['available'])
not_installed = len(results['not_installed'])
config_error = len(results['config_error'])
license_required = len(results['license_required'])
import_error = len(results['import_error'])

print(f"\nTotal adapters:     {total}")
print(f"{Colors.GREEN}Available:          {available}{Colors.NC}")
print(f"{Colors.RED}Not installed:      {not_installed}{Colors.NC}")
print(f"{Colors.YELLOW}Config error:       {config_error}{Colors.NC}")
print(f"{Colors.YELLOW}License required:   {license_required}{Colors.NC}")
print(f"{Colors.RED}Import error:       {import_error}{Colors.NC}")

if total > 0:
    pass_rate = (available / total) * 100
    print(f"\nPass rate: {pass_rate:.1f}%")

# Details for failed
if results['not_installed']:
    print(f"\n{Colors.RED}=== NOT INSTALLED ==={Colors.NC}")
    for name, layer, reason in results['not_installed']:
        print(f"  {layer}: {name} - {reason}")

if results['config_error']:
    print(f"\n{Colors.YELLOW}=== CONFIG ERRORS ==={Colors.NC}")
    for name, layer, reason in results['config_error']:
        print(f"  {layer}: {name} - {reason}")

if results['license_required']:
    print(f"\n{Colors.YELLOW}=== LICENSE REQUIRED ==={Colors.NC}")
    for name, layer, reason in results['license_required']:
        print(f"  {layer}: {name} - {reason}")

if results['import_error']:
    print(f"\n{Colors.RED}=== IMPORT ERRORS ==={Colors.NC}")
    for name, layer, reason in results['import_error']:
        print(f"  {layer}: {name}")
        print(f"    {reason}")

print("\n" + "=" * 70)
print("LAYER BREAKDOWN")
print("=" * 70)

# Layer stats
layer_stats = {}
for category, items in results.items():
    for name, layer, _ in items:
        if layer not in layer_stats:
            layer_stats[layer] = {'available': 0, 'failed': 0}
        if category == 'available':
            layer_stats[layer]['available'] += 1
        else:
            layer_stats[layer]['failed'] += 1

for layer in sorted(layer_stats.keys()):
    stats = layer_stats[layer]
    total_layer = stats['available'] + stats['failed']
    print(f"{layer}: {stats['available']}/{total_layer} available")

print()
