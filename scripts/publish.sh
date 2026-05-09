#!/bin/bash
# MIESC PyPI Publishing Script
#
# Usage:
#   ./scripts/publish.sh test    # Publish to TestPyPI
#   ./scripts/publish.sh prod    # Publish to PyPI (production)
#
# Requirements:
#   - PyPI/TestPyPI API tokens configured in ~/.pypirc or environment
#   - build and twine installed in the active Python environment
#
# Author: Fernando Boiero
# Institution: UNDEF - IUA Cordoba
# License: AGPL-3.0

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Change to project root
cd "$(dirname "$0")/.."

echo -e "${BLUE}"
echo "MIESC PyPI Publishing Tool"
echo "=========================="
echo -e "${NC}"

# Get version from package
VERSION=$(python3 -c "from miesc import __version__; print(__version__)" 2>/dev/null || echo "unknown")
echo -e "Version: ${GREEN}$VERSION${NC}"
echo ""

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}✗ Python 3 not found${NC}"
    exit 1
fi

python3 -m pip show build &> /dev/null || {
    echo -e "${YELLOW}Installing python-build...${NC}"
    python3 -m pip install build
}

python3 -m pip show twine &> /dev/null || {
    echo -e "${YELLOW}Installing twine...${NC}"
    python3 -m pip install twine
}

echo -e "${GREEN}✓ Dependencies ready${NC}"
echo ""

# Build packages
echo -e "${YELLOW}Building packages...${NC}"
make build
echo -e "${GREEN}✓ Built successfully${NC}"
echo ""

# Check package
echo -e "${YELLOW}Checking package integrity...${NC}"
make build-check
echo -e "${GREEN}✓ Package checks passed${NC}"
echo ""

# Determine target
TARGET=${1:-""}

if [ "$TARGET" == "test" ]; then
    echo -e "${BLUE}Publishing to TestPyPI...${NC}"
    python3 -m twine upload --repository testpypi dist/*
    echo ""
    echo -e "${GREEN}✓ Published to TestPyPI!${NC}"
    echo ""
    echo "To install from TestPyPI:"
    echo -e "${YELLOW}  pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ miesc${NC}"
    echo ""

elif [ "$TARGET" == "prod" ]; then
    echo -e "${RED}WARNING: Publishing to production PyPI!${NC}"
    echo ""
    read -p "Type 'yes' to confirm: " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Aborted."
        exit 1
    fi

    echo -e "${BLUE}Publishing to PyPI...${NC}"
    python3 -m twine upload dist/*
    echo ""
    echo -e "${GREEN}✓ Published to PyPI!${NC}"
    echo ""
    echo "Install with:"
    echo -e "${YELLOW}  pip install miesc${NC}"
    echo ""

else
    echo -e "${YELLOW}Packages built and ready. Choose publishing target:${NC}"
    echo ""
    echo "  ./scripts/publish.sh test   # Upload to TestPyPI"
    echo "  ./scripts/publish.sh prod   # Upload to PyPI (production)"
    echo ""
    echo "Or manually:"
    echo "  python3 -m twine upload --repository testpypi dist/*  # TestPyPI"
    echo "  python3 -m twine upload dist/*                         # PyPI"
    echo ""
fi

echo -e "${GREEN}Done!${NC}"
