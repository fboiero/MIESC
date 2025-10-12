#!/bin/bash
# Xaudit Setup Script
# Automates the installation and configuration of Xaudit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   Xaudit Setup Wizard${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check Python version
echo -e "${GREEN}[1/6] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "Python version: $PYTHON_VERSION"

# Create virtual environment
echo -e "\n${GREEN}[2/6] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists. Skipping...${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created successfully!${NC}"
fi

# Activate virtual environment
echo -e "\n${GREEN}[3/6] Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "\n${GREEN}[4/6] Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "\n${GREEN}[5/6] Installing dependencies...${NC}"
echo -e "${YELLOW}This may take several minutes...${NC}"

if [ -f "requirements_minimal.txt" ]; then
    echo -e "${BLUE}Installing minimal requirements (core tools only)...${NC}"
    pip install -r requirements_minimal.txt
else
    echo -e "${BLUE}Installing from requirements.txt...${NC}"
    pip install -r requirements.txt || {
        echo -e "${YELLOW}Some dependencies failed. Trying minimal install...${NC}"
        pip install python-dotenv openai solc-select slither-analyzer fpdf2 markdown
    }
fi

# Setup config file
echo -e "\n${GREEN}[6/6] Setting up configuration...${NC}"
if [ ! -f "config.py" ]; then
    if [ -f "config.py.example" ]; then
        cp config.py.example config.py
        echo -e "${GREEN}Created config.py from example${NC}"
    fi
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo -e "\n${YELLOW}Creating .env file...${NC}"
    cat > .env << EOF
# OpenAI API Key for GPTLens
OPENAI_API_KEY=your_openai_api_key_here

# Optional: Other API keys
# ANTHROPIC_API_KEY=your_anthropic_key_here
EOF
    echo -e "${GREEN}Created .env file. Please edit it and add your API keys.${NC}"
fi

# Create output directory
mkdir -p output

# Make scripts executable
chmod +x run_audit.sh 2>/dev/null || true
chmod +x setup.sh 2>/dev/null || true

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}Setup completed successfully!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Edit ${BLUE}.env${NC} file and add your OpenAI API key"
echo -e "2. Review ${BLUE}config.py${NC} to enable/disable tools"
echo -e "3. Run an audit: ${BLUE}./run_audit.sh examples/voting.sol 0.8.0${NC}\n"

echo -e "${YELLOW}Note:${NC} If you need Mythril or LLM features, install additional dependencies:"
echo -e "  ${BLUE}pip install mythril transformers torch${NC}\n"
