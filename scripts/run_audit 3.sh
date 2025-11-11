#!/bin/bash
# Xaudit - Smart Contract Audit Runner
# Usage: ./run_audit.sh <contract_path> <solidity_version> [tag]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Xaudit - Smart Contract Auditor${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Check arguments
if [ $# -lt 2 ]; then
    echo -e "${RED}Error: Missing arguments${NC}"
    echo "Usage: $0 <contract_path> <solidity_version> [tag]"
    echo "Example: $0 examples/voting.sol 0.8.0 voting_audit"
    exit 1
fi

CONTRACT_PATH=$1
SOLIDITY_VERSION=$2
TAG=${3:-"default"}

# Check if contract exists
if [ ! -f "$CONTRACT_PATH" ]; then
    echo -e "${RED}Error: Contract file not found: $CONTRACT_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}Contract:${NC} $CONTRACT_PATH"
echo -e "${YELLOW}Solidity Version:${NC} $SOLIDITY_VERSION"
echo -e "${YELLOW}Tag:${NC} $TAG\n"

# Activate virtual environment
if [ -d "venv" ]; then
    echo -e "${GREEN}Activating virtual environment...${NC}"
    source venv/bin/activate
else
    echo -e "${RED}Error: Virtual environment not found. Run: python -m venv venv${NC}"
    exit 1
fi

# Check if OpenAI API key is set (for GPTLens)
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "${YELLOW}Warning: OPENAI_API_KEY not set. GPTLens will not work.${NC}"
    echo -e "${YELLOW}Set it in .env file or export OPENAI_API_KEY=your_key${NC}\n"
fi

# Create output directory
mkdir -p output/$TAG

# Run the audit
echo -e "${GREEN}Starting audit...${NC}\n"
python main.py "$CONTRACT_PATH" "$TAG"

# Check if output was generated
if [ -f "output.pdf" ]; then
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Audit completed successfully!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${YELLOW}Report:${NC} output.pdf"
    echo -e "${YELLOW}Output directory:${NC} output/$TAG"
else
    echo -e "\n${YELLOW}Audit completed. Check output/$TAG for results.${NC}"
fi
