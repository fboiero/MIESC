#!/bin/bash
# Script simplificado para agregar todos los archivos restantes
# Usa un enfoque más directo

set -e

echo "🧹 Limpiando locks..."
rm -f .git/index.lock

echo "📦 Agregando archivos restantes..."

# Método 1: Intentar git add --all con timeout
timeout 60 git add --all 2>&1 || {
    echo "⚠️  Timeout en git add --all, usando método alternativo..."

    # Método 2: Si falla, agregar directorios explícitamente
    rm -f .git/index.lock

    for dir in analysis css data demo docker docs examples js k8s mcp pages policies scripts src standards tests thesis video_assets vulnerable_contracts webapp website; do
        if [ -d "$dir" ]; then
            echo "  → $dir"
            timeout 30 git add "$dir" 2>/dev/null || echo "    ⚠️  Saltando $dir"
            rm -f .git/index.lock
        fi
    done
}

echo "✅ Proceso completado"
git status --short | wc -l | xargs echo "Archivos en staging:"
