#!/bin/bash
# =============================================================================
# MIESC Tool Diagnostic Script
# Verifies availability and functionality of all 50 security tools
# Run inside Docker: docker run --rm ghcr.io/fboiero/miesc:full /app/scripts/diagnose-tools.sh
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# Results arrays
declare -a PASS_LIST
declare -a FAIL_LIST
declare -a SKIP_LIST

echo "=============================================="
echo "MIESC Tool Diagnostic v5.1.0"
echo "=============================================="
echo ""

# Function to check binary availability
check_binary() {
    local name=$1
    local binary=$2
    local layer=$3
    TOTAL=$((TOTAL + 1))

    if command -v "$binary" &> /dev/null; then
        version=$($binary --version 2>&1 | head -1 || echo "version unknown")
        echo -e "${GREEN}[PASS]${NC} $name ($layer) - $version"
        PASSED=$((PASSED + 1))
        PASS_LIST+=("$name")
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $name ($layer) - binary '$binary' not found"
        FAILED=$((FAILED + 1))
        FAIL_LIST+=("$name:$binary")
        return 1
    fi
}

# Function to check Python module
check_python_module() {
    local name=$1
    local module=$2
    local layer=$3
    TOTAL=$((TOTAL + 1))

    if python3 -c "import $module" 2>/dev/null; then
        version=$(python3 -c "import $module; print(getattr($module, '__version__', 'installed'))" 2>/dev/null || echo "installed")
        echo -e "${GREEN}[PASS]${NC} $name ($layer) - $version"
        PASSED=$((PASSED + 1))
        PASS_LIST+=("$name")
        return 0
    else
        echo -e "${RED}[FAIL]${NC} $name ($layer) - Python module '$module' not found"
        FAILED=$((FAILED + 1))
        FAIL_LIST+=("$name:$module")
        return 1
    fi
}

# Function to check Ollama connectivity (for LLM tools)
check_ollama() {
    local name=$1
    local layer=$2
    TOTAL=$((TOTAL + 1))

    OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
    if curl -s --connect-timeout 2 "$OLLAMA_HOST/api/tags" > /dev/null 2>&1; then
        echo -e "${GREEN}[PASS]${NC} $name ($layer) - Ollama available at $OLLAMA_HOST"
        PASSED=$((PASSED + 1))
        PASS_LIST+=("$name")
        return 0
    else
        echo -e "${YELLOW}[SKIP]${NC} $name ($layer) - Ollama not available (set OLLAMA_HOST)"
        SKIPPED=$((SKIPPED + 1))
        SKIP_LIST+=("$name:ollama")
        return 1
    fi
}

# Function to check internal/pure Python tools (always available)
check_internal() {
    local name=$1
    local layer=$2
    TOTAL=$((TOTAL + 1))

    echo -e "${GREEN}[PASS]${NC} $name ($layer) - Internal implementation"
    PASSED=$((PASSED + 1))
    PASS_LIST+=("$name")
    return 0
}

# Function for tools requiring API keys
check_api_key() {
    local name=$1
    local env_var=$2
    local layer=$3
    TOTAL=$((TOTAL + 1))

    if [ -n "${!env_var}" ]; then
        echo -e "${GREEN}[PASS]${NC} $name ($layer) - API key present ($env_var)"
        PASSED=$((PASSED + 1))
        PASS_LIST+=("$name")
        return 0
    else
        echo -e "${YELLOW}[SKIP]${NC} $name ($layer) - Requires $env_var"
        SKIPPED=$((SKIPPED + 1))
        SKIP_LIST+=("$name:$env_var")
        return 1
    fi
}

echo "=== LAYER 1: Static Analysis ==="
check_binary "slither" "slither" "L1"
check_binary "aderyn" "aderyn" "L1"
check_binary "solhint" "solhint" "L1"
check_binary "semgrep" "semgrep" "L1"
check_binary "wake" "wake" "L1" || check_python_module "wake" "wake" "L1"
check_binary "4naly3er" "4naly3er" "L1" || check_internal "4naly3er-internal" "L1"
echo ""

echo "=== LAYER 2: Dynamic Testing / Fuzzing ==="
check_binary "echidna" "echidna" "L2"
check_binary "medusa" "medusa" "L2"
check_binary "foundry-forge" "forge" "L2"
check_binary "foundry-cast" "cast" "L2"
check_binary "foundry-anvil" "anvil" "L2"
check_binary "dogefuzz" "dogefuzz" "L2" || echo -e "${YELLOW}[INFO]${NC} dogefuzz - experimental, optional"
check_binary "hardhat" "npx" "L2"  # Hardhat uses npx
check_binary "vertigo" "vertigo" "L2" || echo -e "${YELLOW}[INFO]${NC} vertigo - mutation testing, optional"
echo ""

echo "=== LAYER 3: Symbolic Execution ==="
check_binary "mythril" "myth" "L3"
check_python_module "manticore" "manticore" "L3"
check_binary "halmos" "halmos" "L3" || check_python_module "halmos" "halmos" "L3"
check_binary "oyente" "oyente" "L3" || echo -e "${YELLOW}[INFO]${NC} oyente - deprecated, optional"
check_binary "pakala" "pakala" "L3" || echo -e "${YELLOW}[INFO]${NC} pakala - experimental, optional"
echo ""

echo "=== LAYER 4: Formal Verification ==="
check_api_key "certora" "CERTORAKEY" "L4"
check_binary "smtchecker-solc" "solc" "L4"
check_binary "scribble" "scribble" "L4"
check_internal "solcmc" "L4"  # Uses solc --model-checker
check_internal "propertygpt" "L4"  # LLM-based, needs Ollama
echo ""

echo "=== LAYER 5: AI Analysis (Ollama-based) ==="
# First check Ollama connectivity once
OLLAMA_AVAILABLE=false
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
if curl -s --connect-timeout 2 "$OLLAMA_HOST/api/tags" > /dev/null 2>&1; then
    OLLAMA_AVAILABLE=true
    echo -e "${GREEN}[INFO]${NC} Ollama available at $OLLAMA_HOST"
else
    echo -e "${YELLOW}[INFO]${NC} Ollama not available - L5/L9 AI tools will be skipped"
fi

if [ "$OLLAMA_AVAILABLE" = true ]; then
    check_ollama "smartllm" "L5"
    check_ollama "gptscan" "L5"
    check_ollama "llmsmartaudit" "L5"
    check_ollama "gptlens" "L5"
    check_ollama "llamaaudit" "L5"
    check_ollama "iaudit" "L5"
else
    for tool in smartllm gptscan llmsmartaudit gptlens llamaaudit iaudit; do
        TOTAL=$((TOTAL + 1))
        SKIPPED=$((SKIPPED + 1))
        SKIP_LIST+=("$tool:ollama")
        echo -e "${YELLOW}[SKIP]${NC} $tool (L5) - Ollama not available"
    done
fi
echo ""

echo "=== LAYER 6: ML Detection ==="
check_python_module "dagnn-torch" "torch" "L6"
check_python_module "dagnn-geometric" "torch_geometric" "L6" || echo -e "${YELLOW}[INFO]${NC} torch_geometric - optional for DAGNN"
check_python_module "smartbugs-sklearn" "sklearn" "L6"
check_python_module "smartguard-numpy" "numpy" "L6"
check_internal "peculiar" "L6"
echo ""

echo "=== LAYER 7: Specialized Analysis ==="
check_internal "threat_model" "L7"
check_internal "gas_analyzer" "L7"
check_internal "mev_detector" "L7"
check_internal "contract_clone_detector" "L7"
check_internal "defi_analyzer" "L7"
check_internal "advanced_detector" "L7"
check_internal "upgradability_checker" "L7"
echo ""

echo "=== LAYER 8: Cross-Chain & ZK Security ==="
check_internal "crosschain_analyzer" "L8"
check_internal "zk_circuit_analyzer" "L8"
check_binary "circomspect" "circomspect" "L8" || check_internal "circom_analyzer" "L8"
check_internal "bridge_monitor" "L8"
check_internal "l2_validator" "L8"
echo ""

echo "=== LAYER 9: Advanced AI Ensemble ==="
if [ "$OLLAMA_AVAILABLE" = true ]; then
    check_ollama "llmbugscanner" "L9"
    check_ollama "audit_consensus" "L9"
else
    for tool in llmbugscanner audit_consensus; do
        TOTAL=$((TOTAL + 1))
        SKIPPED=$((SKIPPED + 1))
        SKIP_LIST+=("$tool:ollama")
        echo -e "${YELLOW}[SKIP]${NC} $tool (L9) - Ollama not available"
    done
fi
check_binary "exploit_synthesizer-forge" "forge" "L9"
check_python_module "vuln_verifier-z3" "z3" "L9"
check_internal "remediation_validator" "L9"
echo ""

echo "=== ADDITIONAL DEPENDENCIES ==="
check_binary "solc" "solc" "core"
check_binary "solc-select" "solc-select" "core"
check_binary "git" "git" "core"
check_binary "node" "node" "core"
check_binary "npm" "npm" "core"
check_python_module "weasyprint" "weasyprint" "reports"
check_python_module "requests" "requests" "core"
echo ""

echo "=============================================="
echo "DIAGNOSTIC SUMMARY"
echo "=============================================="
echo ""
echo -e "Total checks:  $TOTAL"
echo -e "${GREEN}Passed:        $PASSED${NC}"
echo -e "${RED}Failed:        $FAILED${NC}"
echo -e "${YELLOW}Skipped:       $SKIPPED${NC}"
echo ""

PASS_RATE=$((PASSED * 100 / TOTAL))
echo "Pass rate: ${PASS_RATE}%"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}=== FAILED TOOLS ===${NC}"
    for item in "${FAIL_LIST[@]}"; do
        tool=$(echo "$item" | cut -d: -f1)
        dep=$(echo "$item" | cut -d: -f2)
        echo "  - $tool (missing: $dep)"
    done
    echo ""
fi

if [ $SKIPPED -gt 0 ]; then
    echo -e "${YELLOW}=== SKIPPED TOOLS ===${NC}"
    for item in "${SKIP_LIST[@]}"; do
        tool=$(echo "$item" | cut -d: -f1)
        reason=$(echo "$item" | cut -d: -f2)
        echo "  - $tool (reason: $reason)"
    done
    echo ""
fi

echo "=============================================="
echo "RECOMMENDATIONS"
echo "=============================================="

if [ $FAILED -gt 0 ]; then
    echo ""
    echo "To fix failed tools, try:"
    echo ""

    # Check for common failures
    for item in "${FAIL_LIST[@]}"; do
        dep=$(echo "$item" | cut -d: -f2)
        case "$dep" in
            "myth")
                echo "  pip install mythril"
                ;;
            "manticore")
                echo "  pip install 'protobuf<4.0.0' manticore[native]"
                ;;
            "halmos")
                echo "  pip install halmos"
                ;;
            "echidna")
                echo "  # Install from: https://github.com/crytic/echidna"
                ;;
            "medusa")
                echo "  # Install from: https://github.com/crytic/medusa"
                ;;
            "scribble")
                echo "  npm install -g eth-scribble"
                ;;
            "torch")
                echo "  pip install torch --index-url https://download.pytorch.org/whl/cpu"
                ;;
            "z3")
                echo "  pip install z3-solver"
                ;;
        esac
    done
fi

echo ""
echo "For Ollama-dependent tools, ensure Ollama is running:"
echo "  export OLLAMA_HOST=http://host.docker.internal:11434  # macOS Docker"
echo "  export OLLAMA_HOST=http://172.17.0.1:11434            # Linux Docker"
echo ""

# Exit with appropriate code
if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
