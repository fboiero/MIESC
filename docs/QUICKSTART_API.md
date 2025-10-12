# 🚀 Quick Start: OpenAI API Configuration

Guía práctica paso a paso para configurar OpenAI API en MIESC en **menos de 5 minutos**.

---

## ⚡ Quick Steps (5 minutos)

### 1. Obtener API Key (2 min)

1. Ve a: https://platform.openai.com/signup
2. Crea cuenta o login
3. Ve a: https://platform.openai.com/api-keys
4. Click **"Create new secret key"**
5. Copia la key (empieza con `sk-proj-...`)

### 2. Configurar en MIESC (1 min)

```bash
# En el directorio de MIESC
cd /path/to/xaudit

# Copiar template
cp .env.example .env

# Editar .env (usar tu editor favorito)
nano .env
```

**Pegar tu key**:
```env
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx
```

Guardar y salir (Ctrl+X, Y, Enter en nano)

### 3. Verificar Configuración (1 min)

```bash
# Activar venv
source venv/bin/activate

# Test rápido
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('✅ API Key configurada!' if os.getenv('OPENAI_API_KEY') else '❌ API Key NO encontrada')"
```

**Output esperado**: `✅ API Key configurada!`

### 4. Ejecutar Demo con API (1 min)

```bash
# Ejecutar análisis con GPT-4 habilitado
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

**Buscar en output**:
```
GPT Enabled: True  ← ¡Debería decir True!
[3/3] Analyzing with GPT-4...
```

---

## 💰 Agregar Créditos (Opcional)

Si ves error `"insufficient_quota"`:

1. Ve a: https://platform.openai.com/account/billing
2. Click **"Add payment method"**
3. Agregar tarjeta
4. **"Add to credit balance"**: $5 USD mínimo
5. Esperar 1-2 minutos para activación

**Costo estimado MIESC**:
- 1 contrato: ~$0.15-0.30
- 10 contratos: ~$1.50-3.00
- 100 contratos: ~$15-30

💡 **Tip**: $5 USD es suficiente para toda la tesis (~20-30 contratos)

---

## 🧪 Tests de Verificación

### Test 1: Variable de Entorno

```bash
source venv/bin/activate
python << EOF
import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("OPENAI_API_KEY")

if key:
    print(f"✅ API Key encontrada: {key[:20]}...")
else:
    print("❌ API Key NO encontrada")
    print("Verifica que .env existe y tiene OPENAI_API_KEY=...")
EOF
```

### Test 2: OpenAI Connection

```bash
python << EOF
import os
from dotenv import load_dotenv
load_dotenv()

try:
    import openai
    openai.api_key = os.getenv("OPENAI_API_KEY")

    # Test simple con GPT-4
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Say: API working"}],
        max_tokens=10
    )

    print("✅ OpenAI API funcionando!")
    print(f"Respuesta: {response.choices[0].message.content}")

except openai.error.AuthenticationError:
    print("❌ API Key inválida")
    print("Verifica que copiaste la key completa")

except openai.error.RateLimitError:
    print("❌ Rate limit excedido")
    print("Espera 1 minuto y prueba de nuevo")

except Exception as e:
    print(f"❌ Error: {e}")
EOF
```

### Test 3: GPTScan Agent

```bash
python -m agents.gptscan_agent examples/vulnerable_bank.sol 2>&1 | grep "GPT Enabled"
```

**Output esperado**: `GPT Enabled: True`

### Test 4: Demo Completo

```bash
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol 2>&1 | grep -A 3 "GPTScan"
```

**Buscar**:
```
2️⃣  GPTScan (ICSE 2024)
GPT Enabled: True
GPT Analyzed: > 0 patterns  ← Debería ser > 0
```

---

## 🐛 Troubleshooting

### Problema: "OPENAI_API_KEY not set"

**Causa**: `.env` no se está cargando

**Solución**:
```bash
# 1. Verificar que .env existe
ls -la .env

# 2. Verificar contenido
cat .env | grep OPENAI_API_KEY

# 3. Verificar que python-dotenv está instalado
pip list | grep python-dotenv

# 4. Reinstalar si es necesario
pip install python-dotenv

# 5. Export manual temporalmente
export OPENAI_API_KEY="sk-proj-xxxxx"
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

### Problema: "Invalid API Key"

**Causa**: Key incorrecta, revocada o incompleta

**Solución**:
1. Ve a https://platform.openai.com/api-keys
2. Revoca la key antigua
3. Crea nueva key
4. Copia **completa** (empieza con `sk-proj-`)
5. Pega en `.env` sin espacios:
   ```env
   OPENAI_API_KEY=sk-proj-abcd1234...
   ```
6. NO uses comillas:
   ```env
   # ❌ MAL
   OPENAI_API_KEY="sk-proj-..."
   OPENAI_API_KEY='sk-proj-...'

   # ✅ BIEN
   OPENAI_API_KEY=sk-proj-...
   ```

### Problema: "Rate limit exceeded"

**Causa**: Demasiadas requests por minuto

**Tier limits**:
- Free trial: 3 RPM (requests per minute)
- Tier 1 ($5): 500 RPM
- Tier 2 ($50): 3,500 RPM

**Solución**:
```bash
# Opción 1: Agregar delay entre requests
# (modifica demo_ai_tools_comparison.py)
import time
time.sleep(2)  # 2 segundos entre análisis

# Opción 2: Esperar 1 minuto
sleep 60
python demo_ai_tools_comparison.py ...

# Opción 3: Upgrade tier (agregar $5)
# https://platform.openai.com/account/billing
```

### Problema: "Insufficient quota"

**Causa**: Créditos agotados

**Solución**:
1. Ve a https://platform.openai.com/account/billing
2. Check "Usage": Cuánto has gastado
3. Click "Add to credit balance"
4. Agregar $5-10 USD
5. Esperar 1-2 minutos
6. Reintentar

### Problema: GPT Enabled: False (pero tengo API key)

**Causa**: Módulo `openai` no instalado

**Solución**:
```bash
source venv/bin/activate
pip install openai==0.28.0

# Verificar instalación
python -c "import openai; print(openai.__version__)"
```

---

## 📊 Comparación: Con API vs Sin API

### Sin API (Modo Demo/Fallback)

```bash
# SIN configurar .env
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

**Resultados**:
- GPTScan: Static-only (Slither)
- AIAgent: Sin triage de FPs
- LLM-SmartAudit: Pattern matching básico
- ⚠️ Precision más baja, FP rate más alto

**Uso**: Testing rápido, validación de instalación

### Con API (Modo Completo)

```bash
# CON .env configurado
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol
```

**Resultados**:
- GPTScan: Static + GPT-4 (mejor precisión)
- AIAgent: Triage AI (reduce FPs ~50%)
- LLM-SmartAudit: Análisis conversacional completo
- ✅ Precision alta, FP rate bajo

**Uso**: Auditorías reales, tesis defense, producción

---

## 💡 Best Practices

### 1. Seguridad

✅ **DO**:
- Guardar `.env` en `.gitignore` (ya configurado)
- Usar `.env` local, NO hardcodear keys
- Rotar keys cada 3-6 meses
- Revocar keys si las expones accidentalmente

❌ **DON'T**:
- Commitear `.env` a Git
- Compartir keys por email/chat
- Publicar keys en GitHub Issues
- Usar keys en logs públicos

### 2. Costos

💰 **Tips para Reducir Costos**:

1. **Usar AI solo para triage** (no detección):
   ```bash
   # Solo static (gratis)
   python -m agents.static_agent examples/contract.sol

   # Static + AI triage ($0.05)
   python demo_ai_tools_comparison.py examples/contract.sol
   ```

2. **Batch processing con delay**:
   ```bash
   for contract in examples/*.sol; do
       python demo_ai_tools_comparison.py "$contract"
       sleep 2  # Evita rate limits
   done
   ```

3. **Cache de resultados**:
   - MIESC guarda resultados en `outputs/`
   - No re-analizar el mismo contrato

4. **Usar GPTScan solo cuando necesario**:
   - Para token contracts (DeFi)
   - Para logic bugs complejos
   - Resto: Slither + Mythril (gratis)

### 3. Performance

⚡ **Optimizaciones**:

1. **Parallel execution** (cuidado con rate limits):
   ```bash
   # Solo si tienes Tier 2+ (500+ RPM)
   # No recomendado para Free trial
   ```

2. **Selective analysis**:
   ```python
   # Solo analizar con AI si static encuentra issues
   static_results = static_agent.run(contract)
   if len(static_results) > 5:
       ai_results = ai_agent.run(contract, findings=static_results)
   ```

3. **Use cheaper models para testing**:
   ```python
   # En lugar de gpt-4 ($0.03/1K tokens)
   # Usar gpt-3.5-turbo ($0.001/1K tokens) para dev
   # (pero menor precisión)
   ```

---

## 🎓 Para la Tesis

### Configuración Recomendada

```bash
# 1. Obtener API key
# https://platform.openai.com/api-keys

# 2. Agregar $5 créditos
# https://platform.openai.com/account/billing

# 3. Configurar .env
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxx

# 4. Test de smoke
python demo_ai_tools_comparison.py examples/vulnerable_bank.sol

# 5. Benchmark completo (costo: ~$2-3)
./run_extended_benchmark.sh

# 6. Generar visualizaciones
python visualize_comparison.py
```

### Validación Pre-Defensa

Checklist antes de la defensa:

- [ ] API key configurada y funcionando
- [ ] Créditos suficientes ($5+)
- [ ] Benchmark ejecutado en 10+ contratos
- [ ] Visualizaciones generadas (5 charts)
- [ ] Demo script funciona en vivo
- [ ] Backup de resultados en `outputs/`

### Demo en Vivo

```bash
# Script para defensa (2-3 minutos)
echo "🎓 Demostración MIESC - Defensa de Tesis"
echo ""
echo "1. Análisis de contrato vulnerable..."
time python demo_ai_tools_comparison.py examples/vulnerable_bank.sol | tail -50

echo ""
echo "2. Visualizaciones generadas:"
ls -lh outputs/visualizations/

echo ""
echo "3. Resultados exportados:"
cat outputs/ai_tools_comparison_vulnerable_bank.json | jq '.results | keys'
```

---

## 📚 Referencias

- [OpenAI API Docs](https://platform.openai.com/docs)
- [OpenAI Pricing](https://openai.com/pricing)
- [Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [Best Practices](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety)

---

## 📞 Soporte

**¿Problemas con la configuración?**

1. Revisa esta guía paso a paso
2. Consulta `docs/API_SETUP.md` (guía completa)
3. Verifica logs: `python demo_ai_tools_comparison.py ... 2>&1 | tee debug.log`

**Contacto**:
- Email: fboiero@frvm.utn.edu.ar
- GitHub Issues: https://github.com/fboiero/xaudit/issues

---

**Última Actualización**: Octubre 2025
**Versión**: 1.0
**Tiempo estimado**: 5 minutos
**Costo estimado**: $5 USD (suficiente para tesis completa)
