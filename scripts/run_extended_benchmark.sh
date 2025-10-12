#!/bin/bash
# Extended Benchmark - 10 contracts total

source venv/bin/activate

contracts=(
    "examples/reentrancy_simple.sol"
    "examples/integer_overflow.sol"
    "examples/unchecked_send.sol"
    "examples/tx_origin.sol"
    "examples/delegatecall_injection.sol"
)

echo "============================================================"
echo "🛡️  MIESC - Extended Benchmark (5 new contracts)"
echo "============================================================"

for contract in "${contracts[@]}"; do
    echo ""
    echo "Analyzing: $(basename $contract)"
    python demo_ai_tools_comparison.py "$contract" 2>&1 | grep -E "(Found|Analysis complete|COMPARISON|Findings|High|Medium)" | tail -20
done

echo ""
echo "============================================================"
echo "✅ Extended Benchmark Complete"
echo "============================================================"
echo ""
echo "Regenerating visualizations with 10 contracts..."
python visualize_comparison.py

echo ""
echo "✅ All done! Total: 10 contracts analyzed"
ls -1 outputs/ai_tools_comparison_*.json | wc -l
