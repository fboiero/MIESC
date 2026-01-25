#!/bin/bash
# MIESC Quick Installer
# Usage: curl -sSL https://raw.githubusercontent.com/fboiero/MIESC/main/install.sh | bash
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
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "  __  __ ___ _____ ____   ____"
echo " |  \/  |_ _| ____/ ___| / ___|"
echo " | |\/| || ||  _| \___ \| |"
echo " | |  | || || |___ ___) | |___"
echo " |_|  |_|___|_____|____/ \____|"
echo -e "${NC}"
echo "Multi-layer Intelligent Evaluation for Smart Contracts"
echo "======================================================="
echo ""

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 12 ]; then
        echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
    else
        echo -e "${RED}✗ Python 3.12+ required (found $PYTHON_VERSION)${NC}"
        echo "  Please install Python 3.12 or later"
        exit 1
    fi
else
    echo -e "${RED}✗ Python 3 not found${NC}"
    echo "  Please install Python 3.12+"
    exit 1
fi

# Check pip
echo -e "${YELLOW}Checking pip...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip found${NC}"
else
    echo -e "${RED}✗ pip not found${NC}"
    echo "  Installing pip..."
    python3 -m ensurepip --upgrade
fi

# Install MIESC
echo ""
echo -e "${YELLOW}Installing MIESC...${NC}"

# Determine installation type
if [ "$1" == "--full" ]; then
    echo "Installing with all optional dependencies..."
    pip3 install miesc[full]
elif [ "$1" == "--dev" ]; then
    echo "Installing with development dependencies..."
    pip3 install miesc[dev]
else
    echo "Installing basic MIESC package..."
    pip3 install miesc
fi

# Verify installation
echo ""
echo -e "${YELLOW}Verifying installation...${NC}"
if command -v miesc &> /dev/null; then
    MIESC_VERSION=$(miesc --version 2>&1)
    echo -e "${GREEN}✓ MIESC installed: $MIESC_VERSION${NC}"
else
    echo -e "${RED}✗ Installation verification failed${NC}"
    echo "  Try running: pip3 install --upgrade miesc"
    exit 1
fi

# Check optional tools
echo ""
echo -e "${YELLOW}Checking security tools...${NC}"

if command -v slither &> /dev/null; then
    echo -e "${GREEN}✓ Slither available${NC}"
else
    echo -e "${YELLOW}○ Slither not found (optional: pip install slither-analyzer)${NC}"
fi

if command -v aderyn &> /dev/null; then
    echo -e "${GREEN}✓ Aderyn available${NC}"
else
    echo -e "${YELLOW}○ Aderyn not found (optional: cargo install aderyn)${NC}"
fi

if command -v myth &> /dev/null; then
    echo -e "${GREEN}✓ Mythril available${NC}"
else
    echo -e "${YELLOW}○ Mythril not found (optional: pip install mythril)${NC}"
fi

# Success message
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}MIESC installation complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "Quick start:"
echo "  miesc --help              # Show all commands"
echo "  miesc scan contract.sol   # Quick vulnerability scan"
echo "  miesc audit quick file.sol # Quick 4-tool audit"
echo "  miesc doctor              # Check tool availability"
echo ""
echo "Documentation: https://fboiero.github.io/MIESC"
echo ""
