# 🦙 LLaMA Model Setup Guide

Guía completa para configurar LLaMA 3.1 local en MIESC (SmartLLM Agent).

---

## 📋 Tabla de Contenidos

1. [¿Por Qué LLaMA Local?](#por-qué-llama-local)
2. [Requisitos del Sistema](#requisitos-del-sistema)
3. [Instalación Paso a Paso](#instalación-paso-a-paso)
4. [Descarga del Modelo](#descarga-del-modelo)
5. [Configuración en MIESC](#configuración-en-miesc)
6. [Testing](#testing)
7. [Performance Tuning](#performance-tuning)

---

## 🤔 ¿Por Qué LLaMA Local?

### Ventajas

✅ **Sin Costo API**: $0 después de setup inicial
✅ **Privacy**: Datos no salen del servidor
✅ **Offline**: Funciona sin internet
✅ **Control Total**: Ajustar parámetros libremente
✅ **Escalabilidad**: Sin rate limits

### Desventajas

⚠️ **Hardware**: Requiere 16GB+ RAM (8B model)
⚠️ **Setup**: Más complejo que cloud API
⚠️ **Performance**: Más lento que GPT-4 (pero aceptable)
⚠️ **Precisión**: ~85% vs 90% de GPT-4

### Cuándo Usar

- ✅ Auditorías en entornos airgapped
- ✅ Volumen alto (100+ contratos)
- ✅ Investigación que requiere privacy
- ✅ Budget limitado

---

## 💻 Requisitos del Sistema

### Mínimo (LLaMA 3.1 8B)

- **CPU**: 4+ cores
- **RAM**: 16 GB
- **Disk**: 10 GB libres
- **OS**: Linux, macOS, Windows (WSL2)

### Recomendado

- **CPU**: 8+ cores (Intel i7/AMD Ryzen 7+)
- **RAM**: 32 GB
- **GPU**: NVIDIA con 8GB+ VRAM (opcional, 10x más rápido)
- **Disk**: SSD con 20 GB

### Verificar Sistema

```bash
# CPU cores
nproc  # Linux
sysctl -n hw.ncpu  # macOS

# RAM total
free -h  # Linux
sysctl hw.memsize  # macOS

# Disk espacio
df -h

# GPU (si aplica)
nvidia-smi  # NVIDIA
```

---

## 🚀 Instalación Paso a Paso

### Opción 1: llama-cpp-python (Recomendado)

**Ventajas**: Más rápido, mejor soporte, bindings C++

#### Paso 1: Instalar Dependencias del Sistema

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake python3-dev
```

**macOS**:
```bash
# Con Homebrew
brew install cmake
```

**Windows (WSL2)**:
```bash
sudo apt-get update
sudo apt-get install build-essential cmake
```

#### Paso 2: Instalar llama-cpp-python

**Sin GPU (CPU only)**:
```bash
source venv/bin/activate
pip install llama-cpp-python
```

**Con GPU NVIDIA (recomendado si tienes)**:
```bash
source venv/bin/activate

# Para CUDA 11.8
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python

# Para CUDA 12.1
CMAKE_ARGS="-DLLAMA_CUBLAS=on -DCMAKE_CUDA_ARCHITECTURES=native" pip install llama-cpp-python
```

**Con GPU AMD ROCm**:
```bash
CMAKE_ARGS="-DLLAMA_HIPBLAS=on" pip install llama-cpp-python
```

**Con Apple Metal (Mac M1/M2/M3)**:
```bash
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python
```

#### Paso 3: Verificar Instalación

```bash
python -c "from llama_cpp import Llama; print('✅ llama-cpp-python instalado')"
```

---

### Opción 2: transformers (Alternativa)

**Ventajas**: Integración con HuggingFace, más fácil para modelos finetuneados

```bash
source venv/bin/activate
pip install transformers torch accelerate bitsandbytes
```

---

## 📥 Descarga del Modelo

### Método 1: HuggingFace (Recomendado)

#### Opción A: GGUF (Quantized - Recomendado)

Formato optimizado para `llama-cpp-python` (más eficiente en CPU/RAM).

```bash
# Instalar HuggingFace CLI
pip install huggingface-hub

# Login (opcional, para modelos gated)
huggingface-cli login

# Descargar LLaMA 3.1 8B Instruct (GGUF Q4_K_M - 4.9GB)
huggingface-cli download \
    TheBloke/Llama-3.1-8B-Instruct-GGUF \
    llama-3.1-8b-instruct.Q4_K_M.gguf \
    --local-dir ./models \
    --local-dir-use-symlinks False
```

**Modelos Disponibles** (TheBloke GGUF):

| Quantization | Size | RAM | Quality | Speed |
|--------------|------|-----|---------|-------|
| Q2_K | 3.5 GB | 8 GB | Baja | Muy rápido |
| Q4_K_M | 4.9 GB | 12 GB | Media | Rápido |
| Q5_K_M | 5.9 GB | 14 GB | Alta | Medio |
| Q8_0 | 8.5 GB | 16 GB | Muy alta | Lento |

**Recomendación**: `Q4_K_M` para balance calidad/performance.

#### Opción B: Full Precision (Para GPU)

```bash
# LLaMA 3.1 8B completo (~16GB)
huggingface-cli download \
    meta-llama/Meta-Llama-3.1-8B-Instruct \
    --local-dir ./models/llama-3.1-8b \
    --local-dir-use-symlinks False
```

**Nota**: Requiere aceptar licencia en HuggingFace primero:
https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct

### Método 2: Descarga Manual

Si `huggingface-cli` falla, descarga manualmente:

1. Ve a: https://huggingface.co/TheBloke/Llama-3.1-8B-Instruct-GGUF
2. Click en "Files and versions"
3. Descarga `llama-3.1-8b-instruct.Q4_K_M.gguf`
4. Mueve a `models/`:
   ```bash
   mkdir -p models
   mv ~/Downloads/llama-3.1-8b-instruct.Q4_K_M.gguf models/
   ```

---

## ⚙️ Configuración en MIESC

### Paso 1: Verificar Path del Modelo

```bash
ls -lh models/llama-3.1-8b-instruct.Q4_K_M.gguf
```

**Output esperado**:
```
-rw-r--r-- 1 user user 4.9G Oct 12 10:00 models/llama-3.1-8b-instruct.Q4_K_M.gguf
```

### Paso 2: Configurar SmartLLM Agent

**Opción A: Variable de Entorno**

```bash
# Agregar a .env
echo "LLAMA_MODEL_PATH=models/llama-3.1-8b-instruct.Q4_K_M.gguf" >> .env
```

**Opción B: Parámetro Directo**

```python
from agents.smartllm_agent import SmartLLMAgent

agent = SmartLLMAgent(
    model_path="models/llama-3.1-8b-instruct.Q4_K_M.gguf",
    use_local_llm=True
)

results = agent.run("examples/vulnerable_bank.sol")
```

### Paso 3: Test de Carga

```bash
python << EOF
from llama_cpp import Llama

print("🦙 Cargando LLaMA 3.1 8B...")
llm = Llama(
    model_path="models/llama-3.1-8b-instruct.Q4_K_M.gguf",
    n_ctx=2048,  # Context window
    n_threads=4,  # CPU threads
    n_gpu_layers=0  # 0 = CPU only, >0 = GPU
)

print("✅ Modelo cargado!")

# Test simple
response = llm("Say: Hello World", max_tokens=10)
print(f"Respuesta: {response['choices'][0]['text']}")
EOF
```

**Primera ejecución**: Puede tardar 30-60 segundos en cargar.

---

## 🧪 Testing

### Test 1: SmartLLM Agent Básico

```bash
# Con LLaMA local
python -m agents.smartllm_agent examples/vulnerable_bank.sol
```

**Buscar en output**:
```
📦 Loading LLaMA model from: models/...
✅ Local LLM loaded successfully
Local LLM: True  ← ¡Debe ser True!
```

### Test 2: Análisis Completo

```bash
python << EOF
from agents.smartllm_agent import SmartLLMAgent

agent = SmartLLMAgent(
    model_path="models/llama-3.1-8b-instruct.Q4_K_M.gguf"
)

print(f"LLM Available: {agent.llm_available}")

if agent.llm_available:
    results = agent.run("examples/reentrancy_simple.sol")
    print(f"Findings: {len(results['smartllm_findings'])}")
    print(f"Time: {results['execution_time']:.2f}s")
else:
    print("❌ LLM no disponible, usando fallback")
EOF
```

### Test 3: Benchmark de Performance

```bash
time python -m agents.smartllm_agent examples/vulnerable_bank.sol
```

**Tiempos esperados**:
- CPU (4 cores): 30-60s
- CPU (8 cores): 15-30s
- GPU NVIDIA: 5-10s
- Mac M1/M2: 10-20s (Metal)

---

## ⚡ Performance Tuning

### Optimización CPU

```python
from llama_cpp import Llama

llm = Llama(
    model_path="models/llama-3.1-8b-instruct.Q4_K_M.gguf",
    n_ctx=2048,          # Context size (reducir para más velocidad)
    n_threads=8,         # Usar todos los cores disponibles
    n_batch=512,         # Batch size (aumentar para más velocidad)
    n_gpu_layers=0,      # CPU only
    use_mlock=True,      # Lock model en RAM (más rápido)
    use_mmap=True,       # Memory mapping (reduce RAM usage)
    low_vram=False       # Desactivar si hay RAM suficiente
)
```

### Optimización GPU

```python
llm = Llama(
    model_path="models/llama-3.1-8b-instruct.Q4_K_M.gguf",
    n_ctx=4096,          # Más context con GPU
    n_threads=4,         # Menos threads en GPU
    n_batch=512,
    n_gpu_layers=33,     # Todas las layers en GPU (ajustar según VRAM)
    main_gpu=0,          # GPU ID
    tensor_split=None    # Para multi-GPU
)
```

### Optimización Memoria

**Si tienes 16GB RAM** (justo):
```python
# Usar modelo más pequeño
# Q2_K (3.5GB) o Q4_K_S (4.3GB)

llm = Llama(
    model_path="models/llama-3.1-8b-instruct.Q2_K.gguf",
    n_ctx=1024,   # Context reducido
    n_threads=4,
    use_mmap=True,
    low_vram=True
)
```

**Si tienes 32GB+ RAM**:
```python
# Usar modelo de mayor calidad
# Q8_0 (8.5GB) o sin quantization

llm = Llama(
    model_path="models/llama-3.1-8b-instruct.Q8_0.gguf",
    n_ctx=8192,   # Context extendido
    n_threads=8,
    use_mlock=True
)
```

---

## 🐛 Troubleshooting

### Error: "No module named 'llama_cpp'"

**Solución**:
```bash
source venv/bin/activate
pip install llama-cpp-python
```

### Error: "Failed to load model"

**Causa**: Archivo corrupto o path incorrecto

**Solución**:
```bash
# Verificar archivo existe y tiene tamaño correcto
ls -lh models/*.gguf

# Re-descargar si es necesario
huggingface-cli download TheBloke/Llama-3.1-8B-Instruct-GGUF \
    llama-3.1-8b-instruct.Q4_K_M.gguf \
    --local-dir ./models --force-download
```

### Error: "Out of memory"

**Solución 1**: Usar modelo más pequeño (Q2_K)

**Solución 2**: Reducir context window
```python
llm = Llama(
    model_path="...",
    n_ctx=512,  # Reducir de 2048 a 512
    use_mmap=True,
    low_vram=True
)
```

**Solución 3**: Cerrar aplicaciones pesadas

### Warning: "AVX/AVX2 not supported"

**Causa**: CPU antiguo sin extensiones AVX2

**Solución**: Compilar llama.cpp sin AVX2
```bash
CMAKE_ARGS="-DLLAMA_AVX2=off" pip install llama-cpp-python --force-reinstall
```

### Performance Lento (>60s por contrato)

**Diagnóstico**:
```bash
# Ver uso de CPU durante ejecución
top -p $(pgrep python)

# Ver threads usados
grep "n_threads" agents/smartllm_agent.py
```

**Soluciones**:
1. Aumentar `n_threads` al número de cores
2. Usar modelo más pequeño (Q2_K)
3. Considerar GPU o cloud API

---

## 📊 Comparación: Local vs Cloud

| Feature | LLaMA Local | GPT-4 Cloud |
|---------|-------------|-------------|
| **Cost** | $0 (después de setup) | $0.03/1K tokens |
| **Privacy** | ✅ 100% local | ❌ Data to OpenAI |
| **Performance** | 15-30s/contrato | 2-5s/contrato |
| **Precision** | ~85% | ~90% |
| **Setup** | ⚠️ Complejo (1-2h) | ✅ Simple (5 min) |
| **Hardware** | ⚠️ 16GB+ RAM | ✅ Cualquiera |
| **Scalability** | ✅ Sin limits | ⚠️ Rate limits |
| **Offline** | ✅ Yes | ❌ Requiere internet |

---

## 🎓 Para la Tesis

### Configuración Recomendada

**Si tienes buen hardware** (32GB+ RAM o GPU):
```bash
# Usar LLaMA local para toda la tesis
# Costo: $0
# Demo impresionante (100% offline)
```

**Si hardware limitado** (16GB RAM):
```bash
# Híbrido:
# - Static analysis: Slither (local, gratis)
# - AI triage: GPT-4 (cloud, $5 total)
# - Demo LLaMA: Q2_K model (para mostrar)
```

### Demo en Vivo

```bash
# Script para defensa
echo "🦙 Demostración SmartLLM - Local AI"
echo ""
echo "Hardware: $(nproc) cores, $(free -h | grep Mem | awk '{print $2}') RAM"
echo "Modelo: LLaMA 3.1 8B (4.9GB quantized)"
echo ""

time python -m agents.smartllm_agent examples/vulnerable_bank.sol

echo ""
echo "✅ Análisis completado 100% offline!"
```

---

## 📚 Referencias

- [LLaMA 3.1 Official](https://llama.meta.com/)
- [llama-cpp-python GitHub](https://github.com/abetlen/llama-cpp-python)
- [TheBloke GGUF Models](https://huggingface.co/TheBloke)
- [Quantization Guide](https://github.com/ggerganov/llama.cpp/blob/master/examples/quantize/README.md)

---

**Autor**: Fernando Boiero
**Email**: fboiero@frvm.utn.edu.ar
**Última Actualización**: Octubre 2025
**Versión**: 1.0
**Tiempo Setup**: 1-2 horas
**Costo**: $0 (modelo opensource)
