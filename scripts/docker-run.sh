#!/bin/bash
# MIESC v3.3.0 - Docker Run Script
# Runs MIESC Docker container in various modes

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="miesc:3.3.0"
CONTAINER_NAME="miesc-container"

# Usage information
usage() {
    echo "MIESC v3.3.0 - Docker Run Script"
    echo ""
    echo "Usage: $0 <mode> [options]"
    echo ""
    echo "Modes:"
    echo "  test       Run test suite"
    echo "  api        Run FastAPI server (port 8000)"
    echo "  shell      Interactive bash shell"
    echo "  analyze    Analyze a smart contract"
    echo "  version    Show tool versions"
    echo ""
    echo "Examples:"
    echo "  $0 test"
    echo "  $0 api"
    echo "  $0 shell"
    echo "  $0 analyze /app/contracts/MyToken.sol"
    echo "  $0 version"
    echo ""
    exit 1
}

# Check if mode is provided
if [ $# -lt 1 ]; then
    usage
fi

MODE=$1
shift  # Remove mode from arguments

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo -e "${RED}Error: Docker daemon is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

# Check if image exists
if ! docker images | grep -q "miesc.*3.3.0"; then
    echo -e "${RED}Error: MIESC image not found${NC}"
    echo "Please run ./docker-build.sh first to build the image"
    exit 1
fi

echo "======================================"
echo "MIESC v3.3.0 - Docker Run"
echo "======================================"
echo ""

case "$MODE" in
    test)
        echo -e "${BLUE}Running MIESC test suite...${NC}"
        docker run --rm \
            --name "${CONTAINER_NAME}-test" \
            -e MIESC_ENV=docker-test \
            "${IMAGE_NAME}" \
            sh -c "python -m pytest tests/ -v --tb=short --maxfail=5 --cov=src --cov-report=term-missing"
        ;;
    
    api)
        echo -e "${BLUE}Starting MIESC API server on port 8000...${NC}"
        echo "API will be available at: http://localhost:8000"
        echo "Press Ctrl+C to stop"
        echo ""
        docker run --rm \
            --name "${CONTAINER_NAME}-api" \
            -p 8000:8000 \
            -e MIESC_ENV=docker-api \
            "${IMAGE_NAME}" \
            uvicorn src.api.main:app --host 0.0.0.0 --port 8000
        ;;
    
    shell)
        echo -e "${BLUE}Starting interactive shell...${NC}"
        echo "Type 'exit' to leave the container"
        echo ""
        docker run --rm -it \
            --name "${CONTAINER_NAME}-shell" \
            -e MIESC_ENV=docker-shell \
            --entrypoint /bin/bash \
            "${IMAGE_NAME}"
        ;;
    
    analyze)
        if [ $# -lt 1 ]; then
            echo -e "${RED}Error: Contract path required${NC}"
            echo "Usage: $0 analyze <contract_path>"
            exit 1
        fi
        CONTRACT_PATH=$1
        echo -e "${BLUE}Analyzing contract: ${CONTRACT_PATH}${NC}"
        docker run --rm \
            --name "${CONTAINER_NAME}-analyze" \
            -e MIESC_ENV=docker-analyzer \
            -v "$(pwd)/contracts:/app/contracts:ro" \
            "${IMAGE_NAME}" \
            python -m src.cli.miesc_cli analyze "${CONTRACT_PATH}"
        ;;
    
    version)
        echo -e "${BLUE}Checking installed tools...${NC}"
        docker run --rm \
            --name "${CONTAINER_NAME}-version" \
            "${IMAGE_NAME}" \
            sh -c "echo 'MIESC Version: 3.3.0' && \
                   echo '==================' && \
                   echo 'Python:' && python --version && \
                   echo 'Slither:' && slither --version 2>&1 | head -1 && \
                   echo 'Mythril:' && myth version 2>&1 | head -1 && \
                   echo 'Aderyn:' && aderyn --version 2>&1 | head -1 && \
                   echo 'Solc:' && solc --version | head -1 && \
                   echo 'Manticore:' && manticore --version 2>&1 | head -1"
        ;;
    
    *)
        echo -e "${RED}Error: Unknown mode '${MODE}'${NC}"
        echo ""
        usage
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
