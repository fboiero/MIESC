# 🔑 API Configuration Guide

Guía para configurar OpenAI API y otras APIs necesarias para las funcionalidades AI de MIESC.

## 📋 Tabla de Contenidos

1. [OpenAI API (GPT-4)](#openai-api-gpt-4)
2. [Modo Sin API (Demo/Fallback)](#modo-sin-api-demofallback)
3. [Configuración Local](#configuración-local)
4. [Testing de Configuración](#testing-de-configuración)
5. [Limitaciones y Costos](#limitaciones-y-costos)

---

## 🤖 OpenAI API (GPT-4)

### ¿Para Qué se Usa?

OpenAI API (GPT-4) se utiliza en MIESC para:

1. **GPTScanAgent**: Análisis de lógica de vulnerabilidades
   - Analiza patrones extraídos por Slither
   - Detecta logic bugs que herramientas estáticas no encuentran
   - Precisión >90% según paper ICSE 2024

2. **LLM-SmartAuditAgent**: Framework multi-agente conversacional
   - 3 sub-agentes: Contract Analysis, Vuln ID, Report Gen
   - Análisis contextual y reasoning

3. **AIAgent (Layer 6)**: Triage de falsos positivos
   - Reduce FP rate de ~20% a <10%
   - Root cause analysis
   - Remediation generation

### Obtener API Key

1. **Crear Cuenta OpenAI**:
   - Ir a: https://platform.openai.com/signup
   - Crear cuenta con email

2. **Generar API Key**:
   - Login → API Keys: https://platform.openai.com/api-keys
   - Click "Create new secret key"
   - Copiar la key (solo se muestra una vez)

3. **Agregar Créditos** (si es necesario):
   - Billing: https://platform.openai.com/account/billing
   - Mínimo: $5 USD
   - Costo estimado MIESC: ~$0.10-0.50 por contrato

### Configurar en MIESC

**Opción 1: Environment Variable (Recomendado)**

```bash
# Crear archivo .env
cp .env.example .env

# Editar .env
nano .env  # o tu editor preferido

# Agregar tu key:
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx
```

**Opción 2: Export Temporal**

```bash
# Solo para sesión actual
export OPENAI_API_KEY="sk-proj-xxxxxxxxxxxxxxxxxxxxx"

# Ejecutar MIESC
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

**Opción 3: Pasar como Parámetro**

```python
from agents.gptscan_agent import GPTScanAgent

agent = GPTScanAgent(openai_api_key="sk-proj-xxxxxxxxxxxxx")
results = agent.run("examples/vulnerable_bank.sol")
```

---

## 🔓 Modo Sin API (Demo/Fallback)

### ¿Qué Pasa Sin API Key?

MIESC funciona **sin OpenAI API** con funcionalidad reducida:

**GPTScanAgent**:
- ✅ Análisis estático (Slither)
- ✅ Extracción de patrones
- ❌ Análisis GPT-4 (usa solo Slither)
- ⚠️  Modo: "GPTScan (Static Only)"

**LLM-SmartAuditAgent**:
- ✅ Análisis básico con heurísticas
- ✅ Pattern matching
- ❌ Análisis LLM conversacional
- ⚠️  Confianza: 70% (vs 85% con LLM)

**AIAgent**:
- ✅ Agregación de findings
- ✅ Análisis de criticidad básico
- ❌ Triage AI de falsos positivos
- ❌ Root cause analysis
- ⚠️  FP Rate: Sin reducción

### Cuándo Usar Modo Demo

- ✅ Testing rápido
- ✅ Validación de instalación
- ✅ Demos sin costo
- ✅ Benchmarking básico
- ❌ Auditorías productivas
- ❌ Tesis defense (recomendado con API)

---

## 💻 Configuración Local

### Paso 1: Copiar Template

```bash
cd /path/to/xaudit
cp .env.example .env
```

### Paso 2: Editar .env

```bash
# Linux/macOS
nano .env

# Windows
notepad .env
```

Contenido mínimo:
```env
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx
```

### Paso 3: Verificar .gitignore

```bash
# Asegurar que .env NO se commitee
cat .gitignore | grep "^\.env$"
```

Debe aparecer: `.env`

### Paso 4: Load Environment

Python carga automáticamente desde `.env` usando `python-dotenv`:

```python
import os
from dotenv import load_dotenv

load_dotenv()  # Lee .env
api_key = os.getenv("OPENAI_API_KEY")
```

---

## 🧪 Testing de Configuración

### Test 1: Verificar API Key

```bash
# Activar venv
source venv/bin/activate

# Test simple
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('API Key:', os.getenv('OPENAI_API_KEY')[:20] + '...' if os.getenv('OPENAI_API_KEY') else 'NOT SET')"
```

**Output esperado**:
```
API Key: sk-proj-xxxxxxxxxxxxx...
```

### Test 2: GPTScanAgent con API

```bash
# Ejecutar con API habilitada
python agents/gptscan_agent.py examples/vulnerable_bank.sol
```

**Buscar en output**:
```
GPT Enabled: True
[3/3] Analyzing with GPT-4...
```

### Test 3: Demo Completo con API

```bash
# Ejecutar demo comparison
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

**Verificar**:
- GPTScan: `GPT Analyzed: > 0 patterns`
- AIAgent: FP Rate reducida

### Test 4: OpenAI Direct Test

```bash
python << EOF
import os
from dotenv import load_dotenv
load_dotenv()

try:
    import openai
    openai.api_key = os.getenv("OPENAI_API_KEY")

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Say 'API working'"}],
        max_tokens=10
    )

    print("✅ OpenAI API Working!")
    print(f"Response: {response.choices[0].message.content}")
except Exception as e:
    print(f"❌ Error: {e}")
EOF
```

---

## 💰 Limitaciones y Costos

### Modelos Disponibles

MIESC usa por defecto:

| Component | Model | Context | Tokens/Request |
|-----------|-------|---------|----------------|
| GPTScanAgent | gpt-4 | 8k | ~1,000-1,500 |
| LLM-SmartAudit | gpt-4 | 8k | ~1,500-2,000 |
| AIAgent | gpt-4 | 8k | ~800-1,200 |

### Costos Estimados (Octubre 2024)

**GPT-4 Pricing**:
- Input: $0.03 / 1K tokens
- Output: $0.06 / 1K tokens

**Por Contrato** (promedio):
- GPTScan: ~$0.05-0.10
- LLM-SmartAudit: ~$0.08-0.12
- AIAgent: ~$0.03-0.05
- **Total**: ~$0.15-0.30 por contrato

**Benchmark Completo** (5 contratos):
- Costo total: ~$0.75-1.50 USD

**Tesis Defense** (10-20 contratos):
- Costo estimado: $3-6 USD

### Límites de Rate

OpenAI tiene rate limits por minuto:

| Tier | RPM | TPM | Costo Mínimo |
|------|-----|-----|--------------|
| Free Trial | 3 | 40K | $0 (limitado) |
| Tier 1 | 500 | 60K | $5 depositados |
| Tier 2 | 3500 | 80K | $50 gastados |

**Recomendación para Tesis**: Tier 1 ($5) es suficiente.

### Alternativas

Si no quieres usar OpenAI:

1. **Modo Demo**: Sin API key (funcionalidad reducida)
2. **Local LLMs**: Implementar SmartLLM con LLaMA local (sin costo API)
3. **Anthropic Claude**: API alternativa (implementar en AIAgent)
4. **Azure OpenAI**: Mismos modelos, billing empresarial

---

## 🔐 Seguridad

### Buenas Prácticas

✅ **DO**:
- Usar `.env` para keys
- Verificar `.env` en `.gitignore`
- Rotar keys regularmente
- Usar environment variables en CI/CD

❌ **DON'T**:
- Commitear `.env` a Git
- Hardcodear keys en código
- Compartir keys en chat/email
- Publicar keys en GitHub Issues

### Si Expones una Key

1. **Revocar inmediatamente**: https://platform.openai.com/api-keys
2. Generar nueva key
3. Actualizar `.env`
4. Revisar billing por uso no autorizado
5. Opcional: Rotar también Git secrets: `git filter-branch`

---

## 📞 Troubleshooting

### Error: "OPENAI_API_KEY not set"

**Causa**: No se encuentra la variable de entorno

**Solución**:
```bash
# Verificar archivo .env existe
ls -la .env

# Verificar contenido
cat .env | grep OPENAI_API_KEY

# Recargar environment
source venv/bin/activate
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

### Error: "Invalid API Key"

**Causa**: Key incorrecta o revocada

**Solución**:
1. Verificar key copiada completa (empieza con `sk-proj-`)
2. Regenerar key en OpenAI dashboard
3. Verificar billing activo

### Error: "Rate limit exceeded"

**Causa**: Demasiadas requests por minuto

**Solución**:
```python
# Agregar delay entre requests
import time
time.sleep(2)  # 2 segundos entre análisis
```

### Error: "Insufficient quota"

**Causa**: Créditos agotados

**Solución**:
1. Agregar créditos: https://platform.openai.com/account/billing
2. Verificar usage: https://platform.openai.com/usage

---

## 📚 Referencias

- [OpenAI API Docs](https://platform.openai.com/docs)
- [OpenAI Pricing](https://openai.com/pricing)
- [python-dotenv Docs](https://github.com/theskumar/python-dotenv)
- [Best Practices for API Key Safety](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)

---

**Última Actualización**: Octubre 2025
**Versión**: 1.0
**Autor**: Fernando Boiero (fboiero@frvm.utn.edu.ar)
