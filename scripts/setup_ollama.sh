#!/bin/bash

# MIESC - Ollama Setup Script
#
# This script installs Ollama and downloads recommended models for smart contract analysis

set -e  # Exit on error

echo "=========================================="
echo "MIESC - Ollama Setup"
echo "=========================================="
echo ""

# Check if Ollama is already installed
if command -v ollama &> /dev/null; then
    echo "✓ Ollama is already installed"
    ollama --version
else
    echo "Installing Ollama..."
    curl -fsSL https://ollama.ai/install.sh | sh

    if [ $? -eq 0 ]; then
        echo "✓ Ollama installed successfully"
    else
        echo "✗ Ollama installation failed"
        exit 1
    fi
fi

echo ""
echo "=========================================="
echo "Downloading Models"
echo "=========================================="
echo ""

# Function to pull model with retry
pull_model() {
    local model=$1
    echo "Downloading $model..."

    if ollama pull "$model"; then
        echo "✓ $model downloaded successfully"
        return 0
    else
        echo "✗ Failed to download $model"
        return 1
    fi
}

# Ask user which models to install
echo "Select models to install:"
echo ""
echo "1. Minimal (codellama:7b) - 3.8GB, fast"
echo "2. Recommended (codellama:13b + deepseek-coder:6.7b) - 11GB"
echo "3. Complete (all models) - ~25GB"
echo "4. Custom selection"
echo ""
read -p "Enter choice (1-4): " choice

case $choice in
    1)
        echo "Installing minimal setup..."
        pull_model "codellama:7b"
        ;;
    2)
        echo "Installing recommended setup..."
        pull_model "codellama:13b"
        pull_model "deepseek-coder:6.7b"
        pull_model "mistral:7b-instruct"
        ;;
    3)
        echo "Installing complete setup..."
        pull_model "codellama:7b"
        pull_model "codellama:13b"
        pull_model "deepseek-coder:6.7b"
        pull_model "deepseek-coder:33b"
        pull_model "mistral:7b-instruct"
        pull_model "phi:latest"
        ;;
    4)
        echo "Available models:"
        echo "  - codellama:7b (3.8GB)"
        echo "  - codellama:13b (7.4GB)"
        echo "  - deepseek-coder:6.7b (3.8GB)"
        echo "  - deepseek-coder:33b (19GB)"
        echo "  - mistral:7b-instruct (4.1GB)"
        echo "  - phi:latest (1.6GB)"
        echo ""
        read -p "Enter model names (space-separated): " models
        for model in $models; do
            pull_model "$model"
        done
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Setup Complete"
echo "=========================================="
echo ""
echo "Installed models:"
ollama list
echo ""
echo "To use Ollama with MIESC:"
echo "  python xaudit.py --target contract.sol --ai-agent ollama"
echo ""
echo "To change model:"
echo "  python xaudit.py --target contract.sol --ai-agent ollama --ai-model codellama:13b"
echo ""
echo "To test Ollama directly:"
echo "  ollama run codellama:13b"
echo ""
