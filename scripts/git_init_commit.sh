#!/bin/bash
# Script optimizado para realizar el commit inicial del proyecto MIESC
# Evita problemas de bloqueo agregando archivos de forma incremental

set -e  # Exit on error

echo "🚀 Iniciando commit inicial optimizado..."

# Limpiar posibles locks previos
rm -f .git/index.lock

# Configurar git para mejor rendimiento
git config core.preloadindex false
git config core.fscache true

# Función para agregar archivos con timeout
add_with_timeout() {
    local timeout_sec=30
    local files="$1"
    local description="$2"

    echo "  → Agregando: $description"

    # Usar timeout para evitar bloqueos
    if timeout $timeout_sec git add $files 2>/dev/null; then
        echo "    ✓ Completado"
        return 0
    else
        echo "    ✗ Timeout o error, intentando archivo por archivo..."
        # Si falla, intentar uno por uno
        for file in $files; do
            if [ -e "$file" ]; then
                timeout 10 git add "$file" 2>/dev/null || echo "    ⚠ Falló: $file"
            fi
        done
        return 1
    fi
}

# 1. Archivos de configuración raíz (críticos primero)
echo "📋 Fase 1: Configuración raíz"
git add .gitignore 2>/dev/null || true
git add .gitattributes 2>/dev/null || true
git add .dockerignore 2>/dev/null || true
git add .env.example 2>/dev/null || true
git add .pre-commit-config.yaml 2>/dev/null || true

# 2. Archivos de build y dependencias
echo "📦 Fase 2: Build y dependencias"
git add foundry.toml 2>/dev/null || true
git add Makefile 2>/dev/null || true
git add mkdocs.yml 2>/dev/null || true
git add requirements*.txt 2>/dev/null || true

# 3. Documentación raíz
echo "📚 Fase 3: Documentación raíz"
for doc in README.md LICENSE CITATION.cff CODEOWNERS CONTRIBUTING.md SECURITY.md CHANGELOG.md; do
    [ -e "$doc" ] && git add "$doc" 2>/dev/null || true
done

# 4. Archivos de resumen y documentación técnica
echo "📄 Fase 4: Documentación técnica"
git add *SUMMARY*.md 2>/dev/null || true
git add *IMPLEMENTATION*.md 2>/dev/null || true
git add *UPGRADE*.md 2>/dev/null || true
git add *RELEASE*.md 2>/dev/null || true
git add *PLAN*.md 2>/dev/null || true

# 5. Archivos web
echo "🌐 Fase 5: Archivos web"
git add index.html index.md 2>/dev/null || true

# 6. Directorios principales (uno por uno para evitar bloqueos)
echo "📁 Fase 6: Directorios principales"
for dir in .github config scripts src tests docs examples demo policies standards; do
    if [ -d "$dir" ]; then
        echo "  → Agregando directorio: $dir"
        # Usar find para agregar archivos de forma controlada
        find "$dir" -type f -not -path "*/\.*" 2>/dev/null | while read file; do
            timeout 5 git add "$file" 2>/dev/null || true
        done
        echo "    ✓ Completado: $dir"
    fi
done

# 7. Directorios restantes
echo "📂 Fase 7: Directorios adicionales"
for dir in analysis data css js pages k8s mcp docker webapp website thesis vulnerable_contracts video_assets; do
    if [ -d "$dir" ]; then
        echo "  → Agregando directorio: $dir"
        find "$dir" -type f -not -path "*/\.*" 2>/dev/null | while read file; do
            timeout 5 git add "$file" 2>/dev/null || true
        done
        echo "    ✓ Completado: $dir"
    fi
done

echo ""
echo "✅ Todos los archivos agregados al staging area"
echo ""

# Mostrar estadísticas
echo "📊 Estadísticas:"
git diff --cached --stat | tail -n 1

echo ""
echo "🎯 Listo para commit. Archivos en staging:"
git diff --cached --name-only | wc -l | xargs echo "  Total de archivos:"

echo ""
echo "💡 Para crear el commit, ejecuta:"
echo "   git commit -m \"chore: initial commit - MIESC v3.x project structure\""
echo ""
echo "🚀 Para push a GitHub:"
echo "   git push -u origin master"
