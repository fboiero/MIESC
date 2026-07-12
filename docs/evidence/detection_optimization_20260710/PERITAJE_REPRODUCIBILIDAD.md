# Peritaje y reproducibilidad — Detection-Optimization

Registro de grado forense de las corridas experimentales de detección. Objetivo:
que un perito independiente pueda **verificar** los resultados y **re-ejecutar**
los experimentos. Todo artefacto está preservado, con procedencia, integridad
(SHA256) y cadena de custodia (git).

---

## 1. Cadena de custodia

- **Autoría**: todos los commits firmados `Fernando Boiero <fboiero@frvm.utn.edu.ar>`.
- **Inmutabilidad**: rama `paper/ribci-camera-ready-harness`, historia en Git y
  espejada en GitHub (`github.com/fboiero/MIESC`). Cada corrida quedó en un commit
  datado; el historial es el registro de custodia.
- **Fecha de las corridas**: 2026-07-10.
- **Aditividad**: estos artefactos NO modifican ningún artefacto congelado del
  paper (validación de freeze pasa en cada commit). Son evidencia nueva y datada.

## 2. Procedencia (entorno y modelos)

- **Hardware**: Apple M5 Pro, 48 GB memoria unificada (GPU para el modelo local).
- **SO/runtime**: macOS (Darwin 25.4); Python 3.12 (`.venv`, ejecución de MIESC)
  y Python 3.14 (sistema, con `openai`/`anthropic` para las llamadas a API).
- **Ollama**: instancia única en `localhost:11434` (un conflicto de dos instancias
  Homebrew+app fue detectado y resuelto; ver §7).

**Modelos e IDs exactos** (lo que un perito debe poder auditar):

| Alias | Model ID | Proveedor | Endpoint | Config |
|---|---|---|---|---|
| local | `qwen3-coder:30b` | Ollama (local, GPU) | `http://localhost:11434/api/chat` | num_predict=2048 |
| open-source hosted | `deepseek-reasoner` | DeepSeek | `https://api.deepseek.com` | reasoning, max_tokens=32768 |
| frontier | `gpt-5` | OpenAI | API estándar | max_completion_tokens=32768, reasoning_effort=low |
| frontier | `gpt-4o` | OpenAI | API estándar | max_tokens=8192 |
| frontier | `claude-sonnet-4-6` | Anthropic | API estándar | max_tokens=8192 |
| frontier premium | `claude-fable-5` | Anthropic | API estándar | max_tokens=8192 |

Las claves de API son del usuario, en `apik.sh` (gitignored, **fuera de la
evidencia** por seguridad — correcto). Ningún valor de clave aparece en ningún
artefacto.

## 3. Configuración por experimento

- **Etapa 1 (static)**: `evaluate corpus --layers 1 --no-intelligence`,
  SmartBugs-curated (143), solc por-pragma. Artefacto: `s1_static_full_baseline.json`.
- **Etapa 2 (FP-filter)**: orchestrator `fp_strictness` off/medium/high, subset
  de 29. Artefacto: `s2_fp_measure*.json`, script `s2_fp_measure.py`.
- **Etapa 3 (DeepSeek variance/ensemble)**: 6 corridas independientes, prompt
  "lever" DeFi-aware, corpus de 29 (4 contratos). Matching type-aware: finding a
  ±5 líneas del marcador **y** keyword de tipo. Artefactos: `s3_ds_*.json`,
  scripts `s3_deepseek_measure.py`, `s3_selfensemble_curve.py`, `s3_union_analysis.py`.
- **Cost-efficiency head-to-head**: 6 modelos, corpus de 29 corregido (27 vulns:
  se descartan FlashLoanVault L112/L125 por etiqueta inválida — ver EVIDENCE.md
  §Stage 5). Costo capturado por-llamada. Artefactos: `costeff_headtohead.json`,
  `costeff_measure.py`.
- **Cost-efficiency SmartBugs**: 5 modelos (Fable excluido: se niega), n=143,
  matching por-categoría (directorio SmartBugs) vía `_normalize_category`.
  Artefactos: `costeff_smartbugs.json`, `costeff_smartbugs.py`.

## 4. Criterio de matching (validez de constructo)

- **Corpus de 29**: type-aware = finding dentro de ±5 líneas del ground-truth Y
  cuyo tipo/SWC contiene un keyword de la clase. Ventana permisiva en línea,
  estricta en tipo. Declarado como decisión de operacionalización.
- **SmartBugs**: un contrato cuenta como detectado si el modelo reporta un finding
  cuyo tipo normalizado (`_normalize_category`) coincide con la categoría del
  directorio (ground truth). Recall por-contrato, n=143.

## 5. Integridad

- `SHA256SUMS.txt` en este dossier cubre `EVIDENCE.md`, este peritaje, y todos
  los artefactos. Cualquier alteración cambia el hash → tamper-evident.
- El manifiesto de freeze del proyecto valida en cada commit (evidencia aditiva,
  no toca lo congelado).

## 6. Reproducción

```bash
# Entorno: exportar claves (no incluidas en la evidencia)
set -a; source apik.sh; set +a   # DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY
# Modelo local:
ollama pull qwen3-coder:30b       # 1 sola instancia de Ollama en :11434

# Re-ejecutar (los números NO serán idénticos — ver §7 no-determinismo):
python3 -u artifacts/costeff_measure.py       # head-to-head (corpus 29)
python3 -u artifacts/costeff_smartbugs.py      # SmartBugs (n=143)
python3    artifacts/s3_union_analysis.py       # análisis de union (sin API)
python3    artifacts/s3_selfensemble_curve.py   # curva de convergencia (sin API)
```

## 7. Limitaciones declaradas (honestidad pericial)

1. **No-determinismo de LLM**: las salidas de los modelos NO son bit-reproducibles
   (temperatura/sampling/reasoning). Re-ejecutar da resultados **estadísticamente
   consistentes, no idénticos**. Por eso el número que se reporta es el
   **ensemble convergente** o la **media ± CI de Wilson**, no una corrida suelta.
   Ver `STATISTICAL_FOUNDATIONS.md` §3.
2. **Persistencia de salidas**: los artefactos guardan las métricas medidas
   (recall, costo por-llamada en tokens reales) y los **IDs de vulnerabilidad
   detectados** por cada modelo/ensemble; las corridas de Etapa 3 guardan además
   los **findings parseados** por contrato (`raw` en `s3_ds_*.json`). El texto
   crudo completo de cada respuesta NO se persistió en todas las corridas — una
   mejora pendiente para auditoría 100% offline. La verificación del análisis
   (matching, unión, CIs) es reproducible a partir de lo guardado.
3. **Tarifas de costo**: costo = uso real de tokens (medido) × tarifa publicada.
   Fable exacto (doc Anthropic $10/$50 MTok); DeepSeek/GPT-5/Claude tarifas
   publicadas (confirmar vigencia). Tokens de razonamiento ocultos SÍ se facturan
   y están incluidos en `completion_tokens`.
4. **Muestra**: el corpus de 29 (27 corregido) da CIs anchos; SmartBugs-143 da CIs
   angostos pero es de patrones clásicos. Ambos declarados.
5. **Rechazo de Fable**: el 0% de Fable es un **rechazo de política** (guardrail),
   no un resultado de capacidad. Reportado como REFUSED, verificado con 3 framings.

---

*Para el detalle metodológico-estadístico ver
[`../methodology/STATISTICAL_FOUNDATIONS.md`](../../methodology/STATISTICAL_FOUNDATIONS.md).*
