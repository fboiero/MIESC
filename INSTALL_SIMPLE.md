# Instalación Simple de Ollama para MIESC

## 🎯 Resumen Rápido

Tu sistema tiene Python 3.9, lo cual es suficiente para **Ollama** pero **CrewAI requiere Python 3.10+**.

**Solución:** Usa solo Ollama (¡es excelente y gratis!)

---

## ✅ INSTALACIÓN PASO A PASO (5 minutos)

### Paso 1: Descargar Ollama manualmente

1. **Abre tu navegador** y ve a: https://ollama.com/download
2. **Descarga** "Ollama-darwin.dmg"
3. **Abre** el archivo .dmg descargado
4. **Arrastra** Ollama a la carpeta Applications
5. **Abre** Ollama desde Applications (aparecerá en la barra de menú)

### Paso 2: Descargar un modelo

Abre una terminal y ejecuta:

```bash
ollama pull codellama:13b
```

Esto descargará el modelo recomendado (~7.4GB). Tomará unos minutos.

### Paso 3: Verificar que funciona

```bash
# Verificar que Ollama está instalado
ollama --version

# Verificar que el modelo está descargado
ollama list

# Probar el modelo
ollama run codellama:13b "Hello"
```

---

## 🚀 USAR CON MIESC

Una vez instalado Ollama, puedes usar MIESC así:

```bash
# Análisis básico con Ollama
python main_ai.py examples/reentrancy.sol test --use-ollama

# Con modelo específico
python main_ai.py examples/reentrancy.sol test \
  --use-ollama \
  --ollama-model codellama:13b

# Modo rápido (modelo más pequeño)
python main_ai.py examples/reentrancy.sol test --quick
```

---

## 💰 BENEFICIOS DE OLLAMA

✅ **Gratis**: $0 por análisis
✅ **Privado**: 100% local
✅ **Sin límites**: Usa cuanto quieras
✅ **Funciona con Python 3.9**: No necesitas actualizar

---

## 🔍 ¿Y CrewAI?

CrewAI requiere Python 3.10+. Tienes dos opciones:

### Opción 1: Solo Ollama (Recomendado para empezar)

- Ollama ya ofrece excelente calidad
- Más rápido que CrewAI
- Más simple de usar
- **Esta es la mejor opción para empezar**

### Opción 2: Actualizar Python (Si quieres CrewAI)

```bash
# Con Homebrew
brew install python@3.11

# O descarga de python.org
https://www.python.org/downloads/
```

Después de actualizar Python, reinstala los paquetes:

```bash
# Crear nuevo environment con Python 3.11
conda create -n miesc311 python=3.11
conda activate miesc311

# Instalar dependencias
pip install -r requirements_agents.txt

# Ahora sí podrás usar CrewAI
python main_ai.py contract.sol test --use-ollama --use-crewai
```

---

## 📊 COMPARACIÓN

| Característica | Solo Ollama | Ollama + CrewAI |
|----------------|-------------|-----------------|
| **Python requerido** | 3.8+ ✅ | 3.10+ ❌ |
| **Velocidad** | Rápido (60s) | Más lento (120s) |
| **Calidad** | Alta (F1: 75) | Muy alta (F1: 81.5) |
| **Costo** | $0 | $0 |
| **Setup** | Simple | Complejo |
| **Recomendado para** | Empezar, día a día | Auditorías críticas |

---

## 🎯 RECOMENDACIÓN FINAL

**Para tu caso (Python 3.9):**

1. ✅ **Usa solo Ollama** - Es excelente y suficiente
2. ✅ **Instálalo manualmente** desde https://ollama.com/download
3. ✅ **Descarga codellama:13b**: `ollama pull codellama:13b`
4. ✅ **Analiza contratos**: `python main_ai.py contract.sol test --use-ollama`

**Más adelante, si quieres CrewAI:**
- Actualiza a Python 3.10+ o 3.11
- Reinstala con el nuevo Python
- Disfruta de multi-agente

---

## 🆘 AYUDA RÁPIDA

### Ollama no arranca

```bash
# Abrir Ollama manualmente
open -a Ollama

# Verificar que está corriendo
ollama ps
```

### Modelo tarda en descargar

Es normal. codellama:13b son 7.4GB. Con buena conexión toma 5-10 minutos.

### Out of memory

Tu Mac necesita al menos 12GB RAM para codellama:13b. Si tienes menos, usa:

```bash
ollama pull codellama:7b  # Solo 8GB RAM necesarios
```

---

## ✅ CHECKLIST

- [ ] Descargué Ollama-darwin.dmg
- [ ] Arrastré a Applications
- [ ] Abrí Ollama
- [ ] Ejecuté `ollama pull codellama:13b`
- [ ] Verifiqué con `ollama list`
- [ ] Analicé mi primer contrato: `python main_ai.py contract.sol test --use-ollama`

---

## 🎉 ¡LISTO!

Con Ollama instalado ya puedes hacer análisis AI **gratis**, **privados** y **de alta calidad**.

**No necesitas CrewAI para empezar. Ollama es suficiente.**

Cualquier duda, revisa `IMPLEMENTACION_COMPLETA.md` o `docs/OLLAMA_CREWAI_GUIDE.md`.
