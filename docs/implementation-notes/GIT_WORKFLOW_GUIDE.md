# MIESC Git Workflow Guide

## Resumen de Problemas Resueltos

### Problema Original
El comando `git add .` se quedaba bloqueado indefinidamente, impidiendo crear commits y hacer push a GitHub.

### Causas Identificadas

1. **Archivo de bloqueo persistente**: `.git/index.lock` quedaba bloqueado de intentos previos
2. **Directorios con nombres problemáticos**: `src/{tools,utils}` causaba problemas con expansión de shell
3. **Directorios `__pycache__`**: Aunque estaban en `.gitignore`, git intentaba procesarlos
4. **Directorios grandes**: `docs/`, `src/`, `scripts/` con muchos archivos causaban timeouts
5. **Configuración de git no optimizada**: Settings por defecto no adecuados para repos grandes

### Soluciones Implementadas

#### 1. Limpieza de Archivos Problemáticos

```bash
# Eliminar directorios con nombres problemáticos
rm -rf "src/{tools,utils}"

# Limpiar caches de Python
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null
```

#### 2. Configuración Optimizada de Git

```bash
# Configurar usuario (siempre como fboiero)
git config user.name "Fernando Boiero"
git config user.email "fboiero@frvm.utn.edu.ar"

# Optimizaciones de rendimiento
git config core.preloadindex false
git config core.fscache true

# Configurar remoto
git remote add origin https://github.com/fboiero/MIESC.git
```

#### 3. Método de Commit Incremental

En lugar de `git add .` (que se bloquea), usar commits incrementales:

```bash
# 1. Limpiar cualquier bloqueo previo
rm -f .git/index.lock

# 2. Agregar archivos por categorías
git add .gitignore .gitattributes .dockerignore
git add *.md LICENSE
git add requirements*.txt Makefile foundry.toml

# 3. Para directorios, usar timeout y manejo de errores
timeout 30 git add directorio/ || echo "Saltando directorio"
rm -f .git/index.lock  # Limpiar después de cada intento

# 4. Commit con lo agregado exitosamente
git commit -m "mensaje descriptivo"

# 5. Push a GitHub
git push -u origin master
```

## Scripts Creados

### 1. `scripts/git_init_commit.sh`
Script completo con método incremental por fases.

### 2. `scripts/git_add_simple.sh`
Script simplificado con timeouts y manejo robusto de errores.

### 3. `scripts/git_add_remaining.sh` (A crear)
Para agregar directorios restantes en commits separados.

## Workflow Recomendado para Futuros Commits

### Para Commits Normales (Cambios Pequeños)

```bash
# Verificar estado
git status

# Agregar archivos específicos
git add archivo1.py archivo2.py

# O agregar por directorio
git add src/module/

# Commit
git commit -m "feat: descripción del cambio

Detalles adicionales si son necesarios.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# Push
git push origin master
```

### Para Cambios Grandes (Muchos Archivos)

```bash
# 1. Limpiar locks previos
rm -f .git/index.lock

# 2. Ver qué archivos cambiar on
git status --short | head -50

# 3. Agregar por lotes con timeout
for dir in src docs tests; do
    timeout 30 git add $dir/ 2>/dev/null || echo "Timeout en $dir"
    rm -f .git/index.lock
done

# 4. Verificar qué se agregó
git diff --cached --stat

# 5. Commit
git commit -m "descripción"

# 6. Push
git push
```

## Configuración del Usuario Git

El usuario siempre debe ser **fboiero**:

```bash
git config --global user.name "Fernando Boiero"
git config --global user.email "fboiero@frvm.utn.edu.ar"
```

Para verificar:
```bash
git config user.name
git config user.email
```

## Manejo de Errores Comunes

### Error: "Unable to create .git/index.lock: File exists"

```bash
rm -f .git/index.lock
```

### Error: Git Add se Queda Bloqueado

```bash
# 1. Matar el proceso (Ctrl+C)
# 2. Limpiar lock
rm -f .git/index.lock
# 3. Usar timeout
timeout 30 git add archivo_o_directorio/
```

### Error: "Authentication Failed" en Push

```bash
# Verificar URL del remoto
git remote -v

# Si es HTTPS, asegurarse de tener token de acceso configurado
# O cambiar a SSH:
git remote set-url origin git@github.com:fboiero/MIESC.git
```

## Mejores Prácticas

1. **Commits frecuentes y pequeños**: Mejor hacer varios commits pequeños que uno grande
2. **Siempre limpiar locks**: `rm -f .git/index.lock` antes de operaciones git
3. **Usar timeout**: Para directorios grandes, usar `timeout 30 git add dir/`
4. **Verificar antes de commit**: `git diff --cached --stat` para ver qué se va a comitear
5. **Mensajes descriptivos**: Seguir conventional commits (feat:, fix:, chore:, etc.)
6. **Push frecuente**: Hacer push después de cada commit o grupo de commits relacionados

## Estado Actual del Repositorio

### Commit Inicial Completado ✅
- 104 archivos
- 25,421 inserciones
- Hash: `9d3ddf9`
- Mensaje: "chore: initial commit - MIESC v3.x Multi-chain Smart Contract Security Framework"

### Archivos Pendientes de Agregar

Los siguientes directorios causaron timeout y deben agregarse en commits separados:

1. `docs/` - Documentación completa (~264K)
2. `src/` - Código fuente adicional (archivos grandes ~112K)
3. `scripts/` - Scripts adicionales (~28K)
4. `thesis/` - Materiales de tesis
5. `video_assets/` - Assets de video
6. `vulnerable_contracts/` - Contratos vulnerables de prueba
7. `website/` - Sitio web estático

## Próximos Pasos

1. Crear commits separados para cada directorio grande restante
2. Usar el siguiente script para agregar directorios restantes de forma controlada
3. Mantener el repositorio actualizado con pushes frecuentes

## Script para Directorios Restantes

Ver `scripts/git_add_remaining.sh` (próximo a crear)

---

**Nota**: Este documento debe actualizarse cuando se encuentren nuevos problemas o soluciones.

Última actualización: 2025-10-20
Por: Fernando Boiero (con asistencia de Claude Code)
