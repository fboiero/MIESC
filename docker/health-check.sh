#!/bin/bash
# MIESC Health Check Script
# Verifies that all services are running correctly

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
OLLAMA_HOST="${OLLAMA_HOST:-localhost}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
API_PORT="${API_PORT:-8000}"
TIMEOUT=5

# Counters
PASSED=0
FAILED=0
WARNINGS=0

print_header() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}              MIESC Health Check Report                       ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_pass() {
    echo -e "  ${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

check_fail() {
    echo -e "  ${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

check_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
    ((WARNINGS++))
}

check_info() {
    echo -e "  ${BLUE}[INFO]${NC} $1"
}

# Check Ollama service
check_ollama() {
    echo -e "${BLUE}[1/4] Checking Ollama Service${NC}"

    # Check if Ollama API is responding
    if curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/tags" > /dev/null 2>&1; then
        check_pass "Ollama API is responding"
    else
        check_fail "Ollama API is not responding at ${OLLAMA_HOST}:${OLLAMA_PORT}"
        return 1
    fi

    # Check Ollama version
    OLLAMA_VERSION=$(curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/version" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
    check_info "Ollama version: $OLLAMA_VERSION"
}

# Check required models
check_models() {
    echo ""
    echo -e "${BLUE}[2/4] Checking LLM Models${NC}"

    # Get model list
    MODELS=$(curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/tags" 2>/dev/null)

    if [ -z "$MODELS" ]; then
        check_fail "Cannot retrieve model list"
        return 1
    fi

    # Check deepseek-coder
    if echo "$MODELS" | grep -q "deepseek-coder"; then
        check_pass "deepseek-coder:6.7b is available"

        # Get model size
        SIZE=$(echo "$MODELS" | grep -o '"deepseek-coder[^}]*' | grep -o '"size":[0-9]*' | cut -d: -f2 | head -1)
        if [ -n "$SIZE" ]; then
            SIZE_GB=$(echo "scale=2; $SIZE / 1024 / 1024 / 1024" | bc 2>/dev/null || echo "?")
            check_info "Model size: ${SIZE_GB}GB"
        fi
    else
        check_fail "deepseek-coder:6.7b is NOT available"
        check_info "Run: docker exec miesc-ollama ollama pull deepseek-coder:6.7b"
    fi

    # Check mistral
    if echo "$MODELS" | grep -q "mistral"; then
        check_pass "mistral:latest is available"
    else
        check_fail "mistral:latest is NOT available"
        check_info "Run: docker exec miesc-ollama ollama pull mistral:latest"
    fi
}

# Test model inference
check_inference() {
    echo ""
    echo -e "${BLUE}[3/4] Testing Model Inference${NC}"

    # Test deepseek-coder
    echo -n "  Testing deepseek-coder... "
    RESPONSE=$(curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/generate" \
        -d '{"model":"deepseek-coder:6.7b","prompt":"// test","stream":false,"options":{"num_predict":1}}' \
        --max-time 60 2>/dev/null)

    if [ -n "$RESPONSE" ] && echo "$RESPONSE" | grep -q "response"; then
        check_pass "deepseek-coder inference works"
    else
        check_warn "deepseek-coder inference timeout or error"
    fi

    # Test mistral
    echo -n "  Testing mistral... "
    RESPONSE=$(curl -sf "http://${OLLAMA_HOST}:${OLLAMA_PORT}/api/generate" \
        -d '{"model":"mistral:latest","prompt":"test","stream":false,"options":{"num_predict":1}}' \
        --max-time 60 2>/dev/null)

    if [ -n "$RESPONSE" ] && echo "$RESPONSE" | grep -q "response"; then
        check_pass "mistral inference works"
    else
        check_warn "mistral inference timeout or error"
    fi
}

# Check Docker containers
check_containers() {
    echo ""
    echo -e "${BLUE}[4/4] Checking Docker Containers${NC}"

    # Check for running containers
    CONTAINERS=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -E "miesc|ollama" || true)

    if [ -z "$CONTAINERS" ]; then
        check_warn "No MIESC containers running"
    else
        for CONTAINER in $CONTAINERS; do
            STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
            HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "no healthcheck")

            if [ "$STATUS" = "running" ]; then
                if [ "$HEALTH" = "healthy" ] || [ "$HEALTH" = "no healthcheck" ]; then
                    check_pass "$CONTAINER: running"
                else
                    check_warn "$CONTAINER: running but $HEALTH"
                fi
            else
                check_fail "$CONTAINER: $STATUS"
            fi
        done
    fi
}

# Check MIESC API (if available)
check_api() {
    # Only check if API container is running
    if docker ps --format "{{.Names}}" 2>/dev/null | grep -q "miesc-api"; then
        echo ""
        echo -e "${BLUE}[BONUS] Checking MIESC API${NC}"

        if curl -sf "http://localhost:${API_PORT}/health" > /dev/null 2>&1; then
            check_pass "MIESC API is healthy"

            # Get API version
            VERSION=$(curl -sf "http://localhost:${API_PORT}/health" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
            check_info "API version: $VERSION"
        else
            check_warn "MIESC API is not responding"
        fi
    fi
}

# Print summary
print_summary() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    TOTAL=$((PASSED + FAILED))
    echo -e "  ${GREEN}Passed:${NC}   $PASSED"
    echo -e "  ${RED}Failed:${NC}   $FAILED"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo ""

    if [ $FAILED -eq 0 ]; then
        echo -e "  ${GREEN}Status: All critical checks passed!${NC}"
        if [ $WARNINGS -gt 0 ]; then
            echo -e "  ${YELLOW}Note: Some warnings detected - review above for details${NC}"
        fi
        echo ""
        echo -e "  ${GREEN}MIESC SmartLLM is ready for smart contract analysis.${NC}"
        return 0
    else
        echo -e "  ${RED}Status: Some checks failed!${NC}"
        echo ""
        echo "  Troubleshooting:"
        echo "    1. Ensure Docker services are running:"
        echo "       docker-compose --profile llm up -d"
        echo ""
        echo "    2. Wait for models to download:"
        echo "       docker logs -f miesc-ollama-init"
        echo ""
        echo "    3. Re-run health check:"
        echo "       ./deploy/health-check.sh"
        return 1
    fi
}

# Main
main() {
    print_header

    check_ollama || true
    check_models || true
    check_inference || true
    check_containers || true
    check_api || true

    print_summary
}

main "$@"
