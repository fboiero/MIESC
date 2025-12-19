# Fine-Tuning LLM para Seguridad en Solidity

Esta guía documenta el proceso de fine-tuning de modelos de lenguaje (LLM) para análisis de seguridad de smart contracts en Solidity, como parte de la Capa 7 de MIESC.

## Objetivo

Crear un modelo especializado en:
- Detección de vulnerabilidades en smart contracts
- Generación de código corregido
- Explicación de vectores de ataque
- Recomendaciones de remediación

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    Pipeline de Fine-Tuning                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Dataset    │───▶│   Training   │───▶│   Modelo     │  │
│  │  Generator   │    │   Trainer    │    │  Fine-tuned  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                    │          │
│         ▼                   ▼                    ▼          │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  - Alpaca    │    │  - LoRA      │    │  - HF Model  │  │
│  │  - ChatML    │    │  - QLoRA     │    │  - Ollama    │  │
│  │  - ShareGPT  │    │  - Full FT   │    │  - GGUF      │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Requisitos

### Hardware Recomendado

| Configuración | GPU VRAM | Batch Size | Método |
|--------------|----------|------------|--------|
| Mínima | 8 GB | 1 | QLoRA 4-bit |
| Recomendada | 16 GB | 4 | QLoRA 4-bit |
| Óptima | 24+ GB | 8 | LoRA 8-bit |
| Full FT | 48+ GB | 16 | Full fine-tune |

### Software

```bash
# Dependencias base
pip install torch transformers>=4.36.0 peft>=0.7.0
pip install bitsandbytes>=0.41.0 datasets>=2.15.0
pip install trl>=0.7.0 accelerate>=0.25.0

# Opcional para optimización
pip install flash-attn --no-build-isolation
pip install xformers
```

## Uso Rápido

### 1. Generar Dataset

```python
from src.ml.fine_tuning import SoliditySecurityDatasetGenerator

# Crear generador
generator = SoliditySecurityDatasetGenerator(output_dir="data/fine_tuning")

# Generar dataset completo
paths = generator.generate_full_dataset()

print(f"Dataset generado: {paths}")
```

Output:
```
data/fine_tuning/
├── solidity_security_alpaca.json    # Formato Alpaca
├── solidity_security_chatml.jsonl   # Formato ChatML
├── solidity_security_sharegpt.json  # Formato ShareGPT
└── dataset_stats.json               # Estadísticas
```

### 2. Entrenar Modelo

```python
from src.ml.fine_tuning import SoliditySecurityTrainer, TrainingConfig

# Configuración
config = TrainingConfig(
    base_model="deepseek-ai/deepseek-coder-6.7b-instruct",
    output_dir="models/miesc-solidity-security",
    num_epochs=3,
    batch_size=4,
    use_lora=True,
    use_4bit=True
)

# Entrenar
trainer = SoliditySecurityTrainer(config)
trainer.train("data/fine_tuning/solidity_security_chatml.jsonl")
```

### 3. Desplegar en Ollama

```python
# Generar Modelfile para Ollama
trainer.generate_ollama_modelfile("models/miesc-solidity-security")

# Crear modelo en Ollama
trainer.create_ollama_model(
    "miesc-solidity-security",
    "models/miesc-solidity-security/Modelfile"
)
```

```bash
# Usar el modelo
ollama run miesc-solidity-security "Analyze this Solidity code for vulnerabilities..."
```

## Estructura del Dataset

### Formato Alpaca

```json
{
  "instruction": "Analyze this Solidity code for security vulnerabilities.",
  "input": "function withdraw(uint256 amount) external {\n    require(balances[msg.sender] >= amount);\n    (bool success, ) = msg.sender.call{value: amount}(\"\");\n    require(success);\n    balances[msg.sender] -= amount;\n}",
  "output": "**Vulnerability Found: Reentrancy**\n\n**Severity:** CRITICAL\n**CWE:** CWE-841\n**SWC:** SWC-107\n\n**Explanation:**\nReentrancy vulnerability occurs when external calls are made before state updates..."
}
```

### Formato ChatML

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are an expert Solidity security auditor..."
    },
    {
      "role": "user",
      "content": "Analyze this code for vulnerabilities:\n```solidity\n...\n```"
    },
    {
      "role": "assistant",
      "content": "**Vulnerability Found: Reentrancy**..."
    }
  ]
}
```

## Vulnerabilidades Cubiertas

| Tipo | Severidad | CWE | SWC |
|------|-----------|-----|-----|
| Reentrancy | Critical | CWE-841 | SWC-107 |
| Integer Overflow | High | CWE-190 | SWC-101 |
| Access Control | Critical | CWE-284 | SWC-105 |
| Unchecked Return | High | CWE-252 | SWC-104 |
| tx.origin | Medium | CWE-477 | SWC-115 |
| Frontrunning | Medium | CWE-362 | SWC-114 |
| Oracle Manipulation | Critical | CWE-829 | - |
| Flash Loan Attack | Critical | CWE-362 | - |
| DoS Gas Limit | Medium | CWE-400 | SWC-128 |
| Signature Replay | High | CWE-294 | SWC-121 |

## Configuración Avanzada

### Parámetros de Training

```python
config = TrainingConfig(
    # Modelo base
    base_model="deepseek-ai/deepseek-coder-6.7b-instruct",
    output_dir="models/miesc-solidity-security",

    # Hiperparámetros
    num_epochs=3,
    batch_size=4,
    gradient_accumulation_steps=4,
    learning_rate=2e-5,
    warmup_ratio=0.1,
    weight_decay=0.01,
    max_seq_length=2048,

    # LoRA
    use_lora=True,
    lora_r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    lora_target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],

    # Cuantización
    use_4bit=True,
    bnb_4bit_compute_dtype="float16",
    bnb_4bit_quant_type="nf4",

    # Optimización
    gradient_checkpointing=True,
    flash_attention=True,
    bf16=True
)
```

### Usando Axolotl (Distributed Training)

```bash
# Generar configuración Axolotl
python -c "
from src.ml.fine_tuning import SoliditySecurityTrainer
trainer = SoliditySecurityTrainer()
trainer.generate_axolotl_config('data/fine_tuning/solidity_security_alpaca.json')
"

# Entrenar con Axolotl
accelerate launch -m axolotl.cli.train models/miesc-solidity-security/axolotl_config.yml
```

### Multi-GPU Training

```bash
# Usando DeepSpeed ZeRO-3
accelerate launch --config_file accelerate_config.yaml \
    -m src.ml.fine_tuning.fine_tuning_trainer \
    --train data/fine_tuning/solidity_security_chatml.jsonl \
    --deepspeed ds_config.json
```

## Evaluación del Modelo

### Métricas

1. **Precisión de Detección**: % de vulnerabilidades correctamente identificadas
2. **Recall**: % de vulnerabilidades reales detectadas
3. **F1-Score**: Balance entre precisión y recall
4. **Calidad de Remediación**: Evaluación humana de los fixes propuestos

### Benchmark

```python
from src.ml.fine_tuning import evaluate_model

results = evaluate_model(
    model_path="models/miesc-solidity-security",
    test_dataset="data/test/vulnerabilities.json"
)

print(f"Precision: {results['precision']:.2%}")
print(f"Recall: {results['recall']:.2%}")
print(f"F1-Score: {results['f1']:.2%}")
```

## Ampliación del Dataset

### Agregar Ejemplos de Auditorías Reales

```python
from src.ml.fine_tuning import SoliditySecurityDatasetGenerator, VulnerabilityExample

generator = SoliditySecurityDatasetGenerator()

# Agregar ejemplo de auditoría real
example = VulnerabilityExample(
    id="audit_001",
    vulnerability_type="price_manipulation",
    severity="critical",
    vulnerable_code="...",
    fixed_code="...",
    explanation="...",
    detection_pattern=r"getReserves\(\)",
    remediation="Use Chainlink oracles",
    cwe_id="CWE-829",
    source="real_audit"
)

generator.examples.append(example)
```

### Integrar con Feedback Loop de MIESC

```python
from src.ml.feedback_loop import FeedbackCollector

# Recolectar feedback de auditorías
collector = FeedbackCollector()
new_examples = collector.get_validated_findings()

# Añadir al dataset
generator.examples.extend(new_examples)
generator.generate_full_dataset()
```

## Despliegue en Producción

### Ollama (Recomendado)

```bash
# Crear modelo
ollama create miesc-security -f Modelfile

# Servir
ollama serve

# API
curl http://localhost:11434/api/generate -d '{
  "model": "miesc-security",
  "prompt": "Analyze for reentrancy:\n```solidity\n...\n```"
}'
```

### vLLM (Alto Rendimiento)

```bash
python -m vllm.entrypoints.openai.api_server \
    --model models/miesc-solidity-security \
    --tensor-parallel-size 2
```

### Hugging Face Text Generation Inference

```bash
docker run --gpus all -p 8080:80 \
    -v models/miesc-solidity-security:/model \
    ghcr.io/huggingface/text-generation-inference \
    --model-id /model
```

## Limitaciones y Consideraciones

1. **Falsos Positivos**: El modelo puede generar alertas sobre código seguro
2. **Nuevas Vulnerabilidades**: No detectará patrones no incluidos en el training
3. **Contexto Limitado**: Dificultad con contratos muy largos o dependencias complejas
4. **Validación Humana**: Siempre verificar las recomendaciones manualmente

## Contribuir

Para contribuir al dataset o mejorar el modelo:

1. Fork el repositorio
2. Agregar ejemplos en `data/contributed/`
3. Ejecutar validación: `python -m pytest tests/test_fine_tuning.py`
4. Crear Pull Request

## Referencias

- [DeepSeek-Coder](https://github.com/deepseek-ai/DeepSeek-Coder)
- [LoRA Paper](https://arxiv.org/abs/2106.09685)
- [QLoRA Paper](https://arxiv.org/abs/2305.14314)
- [SWC Registry](https://swcregistry.io/)
- [CWE Database](https://cwe.mitre.org/)

## Licencia

GPL-3.0 - Este módulo es parte del proyecto MIESC.

## Autor

**Fernando Boiero**
Maestría en Ciberdefensa - UNDEF
fboiero@undef.edu.ar
