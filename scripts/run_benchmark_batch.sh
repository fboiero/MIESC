#!/bin/bash
# Batch Benchmark Script for MIESC AI Tools Comparison
# Runs comparison on all available contracts

echo "============================================================"
echo "🛡️  MIESC - Batch Benchmark Execution"
echo "============================================================"
echo ""

# Activate virtual environment
source venv/bin/activate

# Array of contracts to analyze
contracts=(
    "examples/vulnerable_bank.sol"
    "examples/voting.sol"
    "examples/secure_bank.sol"
    "examples/ManualOracle.sol"
    "examples/Whitelist.sol"
)

# Counter
total=${#contracts[@]}
current=0

echo "📋 Analyzing $total contracts..."
echo ""

# Run analysis on each contract
for contract in "${contracts[@]}"; do
    current=$((current + 1))

    echo "[$current/$total] Analyzing: $(basename $contract)"
    echo "-----------------------------------------------------------"

    # Run comparison (suppress INFO logs)
    python demo_ai_tools_comparison.py "$contract" 2>&1 | grep -v "^INFO:" | tail -40

    echo ""
done

echo "============================================================"
echo "✅ Batch Benchmark Complete"
echo "============================================================"
echo ""
echo "📊 Generating updated visualizations..."
python visualize_comparison.py

echo ""
echo "✅ All done! Results in outputs/"
echo ""
