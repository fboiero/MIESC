#!/bin/bash

# MIESC - Ollama Setup Helper for macOS
# This script helps configure Ollama after manual installation

echo "════════════════════════════════════════════════════════════════"
echo "🔧 MIESC - Ollama Setup Helper"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Step 1: Check if Ollama.app exists
echo "[1/5] Checking if Ollama is installed..."
if [ -d "/Applications/Ollama.app" ]; then
    echo "✓ Ollama.app found in Applications"
else
    echo "✗ Ollama.app not found in Applications"
    echo "Please install Ollama from: https://ollama.com/download"
    exit 1
fi

# Step 2: Open Ollama app
echo ""
echo "[2/5] Starting Ollama app..."
open -a Ollama
echo "✓ Ollama app opened"
echo "  (You should see a llama icon in your menu bar)"

# Wait for Ollama to start
echo ""
echo "[3/5] Waiting for Ollama to start (10 seconds)..."
sleep 10

# Step 3: Add Ollama to PATH if needed
echo ""
echo "[4/5] Configuring PATH..."

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
    SHELL_NAME="zsh"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bash_profile"
    SHELL_NAME="bash"
else
    SHELL_RC="$HOME/.profile"
    SHELL_NAME="sh"
fi

echo "  Detected shell: $SHELL_NAME"
echo "  Config file: $SHELL_RC"

# Add PATH if not already there
if ! grep -q "/usr/local/bin" "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH="/usr/local/bin:$PATH"' >> "$SHELL_RC"
    echo "✓ Added /usr/local/bin to PATH in $SHELL_RC"
else
    echo "✓ PATH already configured"
fi

# Source the file
source "$SHELL_RC" 2>/dev/null || true

# Also add for current session
export PATH="/usr/local/bin:$PATH"

# Step 4: Verify ollama command
echo ""
echo "[5/5] Verifying ollama command..."

# Wait a bit more and try
sleep 5

if command -v ollama &> /dev/null; then
    echo "✓ ollama command is available"
    ollama --version
else
    echo "⚠️  ollama command not found yet"
    echo ""
    echo "Please try these steps:"
    echo "  1. Close this terminal"
    echo "  2. Open a new terminal"
    echo "  3. Run: ollama --version"
    echo ""
    echo "If still doesn't work, add this to your $SHELL_RC:"
    echo '  export PATH="/usr/local/bin:$PATH"'
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ OLLAMA SETUP COMPLETE!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo ""
echo "1. Download a model:"
echo "   $ ollama pull codellama:13b"
echo ""
echo "2. Test ollama:"
echo "   $ ollama list"
echo ""
echo "3. Run MIESC test:"
echo "   $ python scripts/test_ollama_crewai.py"
echo ""
echo "4. Or analyze directly:"
echo "   $ python main_ai.py examples/reentrancy.sol test --use-ollama"
echo ""
echo "════════════════════════════════════════════════════════════════"
