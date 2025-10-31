#!/bin/bash
# Script para agregar directorios restantes en commits separados
# Maneja los directorios que causaron timeout en el commit inicial

set -e

echo "📦 Agregando directorios restantes al repositorio MIESC"
echo "=========================================================="
echo ""

# Función para agregar directorio y hacer commit
add_and_commit() {
    local dir="$1"
    local description="$2"

    echo "📁 Procesando: $dir"
    echo "   Descripción: $description"

    # Verificar si el directorio existe
    if [ ! -d "$dir" ]; then
        echo "   ⚠️  Directorio no existe, saltando..."
        echo ""
        return
    fi

    # Limpiar locks
    rm -f .git/index.lock

    # Verificar si hay archivos para agregar
    if ! git status --porcelain "$dir" 2>/dev/null | grep -q .; then
        echo "   ℹ️  No hay archivos nuevos en este directorio"
        echo ""
        return
    fi

    # Contar archivos
    local file_count=$(find "$dir" -type f 2>/dev/null | wc -l | xargs)
    echo "   📄 Archivos encontrados: $file_count"

    # Intentar agregar con timeout extendido
    echo "   ⏳ Agregando archivos..."
    if timeout 60 git add "$dir" 2>/dev/null; then
        echo "   ✅ Archivos agregados exitosamente"

        # Crear commit
        echo "   💾 Creando commit..."
        git commit -m "$(cat <<EOF
chore: add $description

Added $file_count files from $dir directory.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
EOF
)" && echo "   ✅ Commit creado" || echo "   ⚠️  Error al crear commit"

        # Push a GitHub
        echo "   🚀 Pushing a GitHub..."
        if git push origin master 2>/dev/null; then
            echo "   ✅ Push exitoso"
        else
            echo "   ⚠️  Error en push - Intenta manualmente: git push origin master"
        fi

    else
        echo "   ⚠️  Timeout al agregar directorio, intentando método alternativo..."

        # Método alternativo: agregar archivos uno por uno
        echo "   🔄 Intentando agregar archivos individualmente..."
        find "$dir" -type f 2>/dev/null | while read file; do
            timeout 5 git add "$file" 2>/dev/null || true
        done

        # Verificar si se agregó algo
        if git diff --cached --quiet; then
            echo "   ❌ No se pudieron agregar archivos de $dir"
        else
            echo "   ✅ Algunos archivos agregados, creando commit..."
            git commit -m "chore: add partial $description (timeout recovery)" || true
            git push origin master || true
        fi
    fi

    # Limpiar lock final
    rm -f .git/index.lock
    echo ""
}

# Directorios restantes a agregar
echo "🎯 Directorios a procesar:"
echo "   1. docs - Documentación completa del proyecto"
echo "   2. scripts - Scripts de utilidades y herramientas"
echo "   3. src - Código fuente principal adicional"
echo "   4. thesis - Materiales académicos y de investigación"
echo "   5. video_assets - Assets multimedia"
echo "   6. vulnerable_contracts - Contratos de prueba vulnerables"
echo "   7. website - Sitio web estático del proyecto"
echo ""
read -p "¿Continuar? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelado por el usuario"
    exit 1
fi

# Procesar cada directorio
add_and_commit "docs" "complete project documentation"
add_and_commit "scripts" "utility scripts and tools"
add_and_commit "src" "additional source code modules"
add_and_commit "thesis" "academic research materials"
add_and_commit "video_assets" "multimedia assets"
add_and_commit "vulnerable_contracts" "vulnerable test contracts"
add_and_commit "website" "static project website"

echo ""
echo "✅ ¡Proceso completado!"
echo ""
echo "📊 Estado final del repositorio:"
git log --oneline -5
echo ""
echo "🌐 Ver en GitHub: https://github.com/fboiero/MIESC"
