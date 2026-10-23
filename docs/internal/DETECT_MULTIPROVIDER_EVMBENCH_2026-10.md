# Detector multi-provider + EVMBench — change note & evidence (2026-10-23)

## Context

Fase 2 del trabajo "mejorar la detección agénticamente". Fase 1 (PR #203) hizo configurable el
pase LLM del *verificador* de falsos positivos. Fase 2 ataca la **cobertura**: los bugs de
lógica de negocio que los detectores estáticos no ven. Ese camino de detección por LLM ya
existía (`FrontierLLMAdapter` + `miesc scan --model` + `benchmarks/evmbench_eval.py`) y la
corrida previa midió **gpt-5 88.2% vs qwen32b 41.2%** en EVMBench, pero solo soportaba
**anthropic/openai** (deepseek vía un caso especial; **Kimi no estaba**).

## Qué cambió

1. **Registro compartido** `miesc/llm/provider_registry.py`: una sola fuente de verdad para la
   spec de proveedores (API style, env de keys, base URL, modelo default) y el parser del
   string de modelo. Lo leen TANTO el verificador de Fase 1 (`benign_context_verifier`, que
   perdió su tabla local) COMO el detector. Se comparte la *spec*, no el call-path.
2. **Detector multi-proveedor**: `FrontierLLMAdapter` construye el cliente OpenAI-compatible
   desde el registro (base URL + key por proveedor), agregando **Moonshot/Kimi** del mismo modo
   que DeepSeek. `is_available`, el dispatch y `_detect_provider` reconocen kimi.
3. **Provider maps**: `kimi`/`moonshot` agregados a `miesc scan --model` (y a su `click.Choice`)
   y a los `provider_map`/`model_map` de `benchmarks/evmbench_eval.py`.

**Invariantes:** `--model` sigue opt-in; sin key o ante error, el proveedor se reporta no
disponible / degrada; CI y runs sin key no cambian. Defaults locales intactos.

## Verificación

### Plumbing (unit, sin red/keys)
- `tests/test_frontier_multiprovider.py` (8 tests): el constructor `openai.OpenAI` se arma con
  el `base_url`/`api_key` correcto por proveedor — Kimi → `api.moonshot.ai` + `KIMI_API_KEY`/
  `MOONSHOT_API_KEY`; DeepSeek → `api.deepseek.com` + `DEEPSEEK_API_KEY`; OpenAI → cliente por
  defecto. `is_available` para kimi (AVAILABLE con key, CONFIGURATION_ERROR sin key). Y el
  registro como única fuente de verdad.
- `tests/test_benign_context_verifier.py` (56 tests): regresión de Fase 1 verde tras mover la
  tabla al registro.
- Total **64 tests** verdes bajo `env -u` de todas las keys. ruff + black limpios sobre los
  archivos tocados (los 2 avisos F541 de `evmbench_eval.py` son pre-existentes en `origin/main`).

### API real (end-to-end)
Smoke `evmbench_eval.py --max-audits 1 --model gpt` (gpt-4o) sobre el audit `2024-01-canto`:
**2/2 detectado, recall 100%, 1 API call, 11.749 in / 676 out tokens, $0.04.** Prueba que el
camino de detección multi-proveedor dispara contra una API real.

### Cobertura comparativa (EVMBench, subset acotado — con keys)

Corrida bounded sobre los **5 audits más chicos por SLOC** (11 vulns ground-truth; mismo
criterio de selección que la corrida previa de 10). Directional, no un claim definitivo de
cobertura (subset chico; ver sesgo de selección en `EVMBENCH_FRONTIER_RUN_2026-10.md`).

| Proveedor | Recall | Precision | $/audit | Nota |
|---|---|---|---|---|
| gpt-4o (`--model gpt`) | 72.7% | 53.3% (TP8/FP7) | $0.037 | API (OpenAI) |
| deepseek (`--model deepseek`) | **100.0%** | 18.3% (TP11/FP49) | ~$0* | API (OpenAI-compat vía registro) |
| qwen2.5-coder:14b (`--model qwen14b`) | 54.5% | 27.3% (TP6/FP16) | $0 | local, baseline |
| Kimi/Moonshot | — | — | — | plumbing + test mockeado (no hay key disponible) |

*deepseek: la tabla de costos del harness no lo pricea (reporta $0; 5 calls, 64.7k in / 36.1k
out tokens) → costo real bajo pero NO cero.

**Lectura honesta:** los proveedores API cubren **más** que el local — deepseek 100% y gpt-4o
72.7% de recall vs qwen14b local 54.5%. Es decir, la cobertura **mejora con un proveedor API**,
que es exactamente el punto de Fase 2, y el multi-proveedor (incluido el camino OpenAI-compatible
que agregó Kimi/DeepSeek) dispara contra APIs reales. Nota complementaria: deepseek inunda de
falsos positivos (18.3% precision, 49 FP) — justo el caso que el gate recall-safe de Fase 1 (PR
#203) está hecho para triar. Las dos fases se potencian: Fase 2 sube cobertura, Fase 1 recupera
precisión sin perder recall.

### Corrida canónica completa (maintainer/CI, con crédito)
Para el número comparable al 88%/41% previo, sobre los 10 audits más chicos:
```bash
# keys con crédito en el entorno (OPENAI/ANTHROPIC/DEEPSEEK_API_KEY)
python benchmarks/evmbench_eval.py --max-audits 10 --model gpt-5
python benchmarks/evmbench_eval.py --max-audits 10 --model claude
python benchmarks/evmbench_eval.py --max-audits 10 --model deepseek
python benchmarks/evmbench_eval.py --max-audits 10 --model qwen32b   # local, gratis
```

## Coordinación con #203
Esta rama (`feat/detect-multiprovider`) se cortó del tip de #203 porque el registro compartido
mueve la tabla de proveedores fuera de `benign_context_verifier.py` (que #203 modificó).
**Mergear #203 primero**, luego esta.

## Archivos
- **nuevo** `miesc/llm/provider_registry.py` — spec única + `parse_model` + resolvers.
- `miesc/ml/benign_context_verifier.py` — importa el registro (tabla local removida).
- `miesc/adapters/frontier_llm_adapter.py` — cliente por proveedor desde el registro (+ kimi).
- `miesc/cli/commands/scan.py` — `--model` + `provider_map` con kimi.
- `benchmarks/evmbench_eval.py` — `provider_map`/`model_map` con kimi.
- `tests/test_frontier_multiprovider.py` (nuevo) + `tests/test_benign_context_verifier.py`.

No se tocó ningún artefacto congelado.
