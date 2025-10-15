# Instalación de Ollama en macOS

## Guía Rápida (5 minutos)

### Opción 1: Instalador .dmg (Recomendado)

1. **Descargar el instalador**
   ```
   Visita: https://ollama.ai/download
   Descarga: Ollama-darwin.dmg
   ```

2. **Instalar**
   - Abre el archivo .dmg descargado
   - Arrastra Ollama a la carpeta Applications
   - Abre Ollama desde Applications

3. **Verificar instalación**
   ```bash
   ollama --version
   ```

4. **Descargar modelo recomendado**
   ```bash
   ollama pull codellama:13b
   ```

---

### Opción 2: Homebrew

Si tienes Homebrew instalado:

```bash
# Instalar Ollama
brew install ollama

# Iniciar servicio
brew services start ollama

# Verificar
ollama --version

# Descargar modelo
ollama pull codellama:13b
```

---

### Opción 3: Script de instalación

```bash
# Descargar e instalar
curl -fsSL https://ollama.ai/install.sh | sh

# Verificar
ollama --version

# Descargar modelo
ollama pull codellama:13b
```

---

## Modelos Recomendados

### Desarrollo Rápido
```bash
ollama pull codellama:7b
# Tamaño: 3.8GB
# Tiempo: ~30s por análisis
```

### Uso General (Recomendado)
```bash
ollama pull codellama:13b
# Tamaño: 7.4GB
# Tiempo: ~60s por análisis
```

### Máxima Calidad
```bash
ollama pull deepseek-coder:33b
# Tamaño: 19GB
# Tiempo: ~120s por análisis
```

---

## Verificar Instalación

```bash
# 1. Verificar que Ollama está instalado
which ollama
# Debe mostrar: /usr/local/bin/ollama (o similar)

# 2. Verificar que Ollama está corriendo
ollama list
# Debe mostrar los modelos instalados

# 3. Probar un modelo
ollama run codellama:13b "Hello"
# Debe responder con texto generado
```

---

## Ejecutar Test de MIESC

Una vez instalado Ollama:

```bash
# 1. Instalar dependencias Python
pip install -r requirements_agents.txt

# 2. Ejecutar test interactivo
python scripts/test_ollama_crewai.py
```

El test ahora debe pasar todos los checks:
```
System Requirements
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Requirement    ┃ Status     ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Python 3.8+    │ ✓ PASSED   │
│ Ollama         │ ✓ PASSED   │
└────────────────┴────────────┘
```

---

## Uso con MIESC

### Análisis Básico
```bash
python main_ai.py examples/reentrancy.sol test --use-ollama
```

### Análisis Completo
```bash
python main_ai.py examples/reentrancy.sol audit \
  --use-ollama \
  --use-crewai \
  --ollama-model codellama:13b
```

### Modo Rápido
```bash
python main_ai.py examples/reentrancy.sol test --quick
```

---

## Troubleshooting

### Ollama no se encuentra después de instalar

```bash
# Verificar PATH
echo $PATH

# Agregar Ollama al PATH (si es necesario)
export PATH="/usr/local/bin:$PATH"

# Agregar a ~/.zshrc o ~/.bash_profile
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Ollama instalado pero no corre

```bash
# Iniciar Ollama manualmente
open -a Ollama

# O desde terminal
ollama serve &
```

### Modelo no descarga

```bash
# Verificar espacio en disco
df -h

# Verificar conexión
ping ollama.ai

# Reintentar descarga
ollama pull codellama:13b
```

### Out of Memory

Si tu Mac tiene < 16GB RAM:

```bash
# Usar modelo más pequeño
ollama pull codellama:7b

# O el más pequeño
ollama pull phi:latest
```

---

## Configuración Avanzada

### Usar GPU (M1/M2/M3 Macs)

Ollama automáticamente usa el GPU en Macs con Apple Silicon:

```bash
# Verificar que está usando GPU
ollama ps
```

### Cambiar Ubicación de Modelos

```bash
# Crear variable de entorno
export OLLAMA_MODELS=/path/to/models

# Agregar a ~/.zshrc
echo 'export OLLAMA_MODELS=/path/to/models' >> ~/.zshrc
```

### Limitar Uso de Memoria

```bash
# Limitar a 8GB
export OLLAMA_MAX_VRAM=8192

# Agregar a ~/.zshrc
echo 'export OLLAMA_MAX_VRAM=8192' >> ~/.zshrc
```

---

## Desinstalación

### Si instalaste con Homebrew:
```bash
brew uninstall ollama
brew services stop ollama
```

### Si instalaste con .dmg:
```bash
# Eliminar aplicación
rm -rf /Applications/Ollama.app

# Eliminar modelos
rm -rf ~/.ollama
```

---

## Recursos

- **Sitio oficial**: https://ollama.ai
- **Documentación**: https://github.com/jmorganca/ollama
- **Modelos disponibles**: https://ollama.ai/library
- **MIESC Docs**: docs/OLLAMA_CREWAI_GUIDE.md

---

## Próximos Pasos

1. ✅ Ollama instalado
2. ✅ Modelo descargado
3. → Ejecutar: `python scripts/test_ollama_crewai.py`
4. → Leer: `IMPLEMENTACION_COMPLETA.md`
5. → Usar: `python main_ai.py contract.sol test --use-ollama`

**¡Listo para análisis AI gratis y privado!** 🎉
