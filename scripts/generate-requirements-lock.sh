#!/bin/bash
# Generate requirements-lock.txt for reproducible builds
#
# Usage:
#   ./scripts/generate-requirements-lock.sh
#
# This creates a locked requirements file with exact versions
# for all dependencies, ensuring reproducible installations.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Generating requirements-lock.txt ==="
echo ""

# Check if pip-tools is available
if command -v pip-compile &> /dev/null; then
    echo "Using pip-compile (pip-tools)..."
    pip-compile pyproject.toml -o requirements-lock.txt \
        --generate-hashes \
        --allow-unsafe \
        --resolver=backtracking
else
    echo "pip-tools not found, using pip freeze..."
    echo ""
    echo "For better results, install pip-tools:"
    echo "  pip install pip-tools"
    echo ""

    # Create a temporary venv for clean dependency resolution
    TEMP_VENV=$(mktemp -d)/venv
    python3 -m venv "$TEMP_VENV"
    source "$TEMP_VENV/bin/activate"

    # Install the package
    pip install --quiet --upgrade pip
    pip install --quiet -e .

    # Generate lock file
    echo "# Auto-generated requirements lock file" > requirements-lock.txt
    echo "# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> requirements-lock.txt
    echo "# Python: $(python --version)" >> requirements-lock.txt
    echo "# Platform: $(uname -s)-$(uname -m)" >> requirements-lock.txt
    echo "#" >> requirements-lock.txt
    echo "# To install: pip install -r requirements-lock.txt" >> requirements-lock.txt
    echo "" >> requirements-lock.txt

    pip freeze | grep -v "^-e" | grep -v "^miesc==" >> requirements-lock.txt

    # Cleanup
    deactivate
    rm -rf "$(dirname "$TEMP_VENV")"
fi

echo ""
echo "=== Generated: requirements-lock.txt ==="
echo ""
head -20 requirements-lock.txt
echo "..."
echo ""
echo "Total packages: $(grep -c "==" requirements-lock.txt || echo 0)"
