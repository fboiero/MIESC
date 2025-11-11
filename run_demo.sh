#!/bin/bash
# MIESC Cyberpunk Demo Runner
# Quick launcher for the cyberpunk demo

echo "🔥 MIESC Cyberpunk Demo 🔥"
echo ""

if [ "$1" = "" ]; then
    echo "Running demo with sample vulnerable contract..."
    python3 cyberpunk_demo.py
else
    echo "Analyzing: $1"
    python3 cyberpunk_demo.py "$1"
fi
