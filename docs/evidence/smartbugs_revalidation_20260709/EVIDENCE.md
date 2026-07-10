# Evidencia peritable — Re-validación SmartBugs (2026-07-09)

Expediente de reproducibilidad para la re-validación independiente de la métrica
SmartBugs de MIESC v5.4.1. Su objetivo es que un tercero (perito, jurado,
revisor) pueda **reproducir y verificar** el resultado sin confiar en la palabra
del autor. Todo artefacto está referenciado por su hash SHA-256 en
[`SHA256SUMS`](./SHA256SUMS).

## 1. Motivo

El documento de tesis `docs/tesis/JUSTIFICACION_ESTADISTICAS_Y_DEMOS.md`
reportaba, en una tabla de validación post-tesis, `SmartBugs (parcial) | 143 |
89.47% precisión | 86.2% recall`. Ese triple **no correspondía a ningún
artefacto de resultados registrado** en el repositorio: las precisiones
por-categoría del run canónico van de 0.10 a 0.45 y la global es 0.2219; ningún
valor es 0.8947. Se re-corrió la evaluación completa para establecer el número
real de forma auditable.

## 2. Resultado (n = 143)

| Métrica | Re-validación 2026-07-09 | Artefacto canónico congelado v5.4.1 |
|---|---|---|
| Precisión | **0.1991 (19.9%)** | 0.2219 (22.2%) |
| Recall | **0.979 (97.9%)** | 0.958 (95.8%) |
| F1 | 0.331 | 0.360 |
| TP / FP / FN | 140 / 563 / 3 | 137 / 481 / 6 |
| Duración | 280.1 s | — |

**Conclusión:** el perfil real es *recall-first* (~20% precisión, ~98% recall).
El `89.47% / 86.2%` de la tesis queda **refutado por evidencia fresca**. El
resultado converge con el artefacto congelado y con dos smokes independientes
(nativo 23.1%, contenedor 21.4%).

## 3. Entorno exacto (cadena de custodia)

| Elemento | Valor |
|---|---|
| Fecha de corrida | 2026-07-09 |
| Host | macOS (Darwin), Apple Silicon **arm64** |
| Imagen base | `ghcr.io/fboiero/miesc@sha256:68a00d6b98d183557b6dce40e5deed6817d02b820b5ffc66cabf7f807f41dcee` (tag `5.4.1`) |
| Imagen derivada | `miesc:5.4.1-solc` — Id `sha256:b8360526a05de7d32161aeaea12d457beb45cd7bd0da0ab1aae0dc91126424c2` |
| Dockerfile | [`Dockerfile.solc`](./Dockerfile.solc) — `sha256:7d2ae7488ffaf8bb1c002b6b59e3d2ed3ffc0ebabe16f26a47135d5526fc98a1` |
| MIESC version | 5.4.1 (reportada por el CLI y embebida en el JSON) |
| Capas evaluadas | `1,6,7` (idénticas al artefacto congelado `paper1_smartbugs_eval_layers_1_6_7.json`) |
| Modelo LLM | `qwen2.5-coder:14b` — Ollama digest `9ec8897f747e…`, modified 2026-04-26 |
| Transporte LLM | contenedor → host vía `host.docker.internal:11434` → Ollama nativo del host (GPU Apple) |
| solc instalados | 0.4.0, 0.4.2, 0.4.9, 0.4.10, 0.4.11, 0.4.13, 0.4.15, 0.4.16, 0.4.18, 0.4.19, 0.4.21, 0.4.22, 0.4.23, 0.4.24, 0.4.25, 0.4.26, 0.5.0, 0.8.35 |
| Dataset | SmartBugs-curated, **143** contratos `.sol`; huella del conjunto `sha256(list-of-file-hashes) = 912e54cecf867e74666ea08a1977d4d86448d798e7a79b1361c9521937cb0527` |
| Repo | branch `paper/ribci-camera-ready-harness`, HEAD `bad130d3726b5952b8f56743c4f1742c6bfd9271` |

Nota sobre el GPU: las capas 6 y 7 (`smartbugs_detector`, `peculiar`,
`threat_model`, `gas_analyzer`) son detectores de patrones, **no LLM**. El modelo
LLM interviene solo como filtro auxiliar de falsos positivos; por eso la
utilización del GPU es intermitente y baja — es esperado, no una anomalía.

## 4. Comandos exactos

**Construcción de la imagen** (instala los `solc` legacy que el corpus requiere;
en arm64 corren como binarios x86 vía la emulación binfmt/qemu de Docker
Desktop, mientras Slither y el resto quedan arm64-nativos):

```bash
docker build --platform linux/arm64 -t miesc:5.4.1-solc -f Dockerfile.solc .
```

**Corrida de evaluación** (salida aditiva y fechada; no sobrescribe artefactos
congelados):

```bash
docker run --rm --platform linux/arm64 \
  --add-host=host.docker.internal:host-gateway \
  -e OLLAMA_HOST=http://host.docker.internal:11434 \
  -e MIESC_LLM_MODEL=qwen2.5-coder:14b \
  -v "$(pwd)/benchmarks/datasets/smartbugs-curated/dataset:/data/dataset:ro" \
  -v "$(pwd)/benchmarks/results:/out" \
  miesc:5.4.1-solc \
  evaluate corpus /data/dataset --layers 1,6,7 \
  --output /out/paper1_smartbugs_revalidation_docker_20260709.json \
  --jsonl  /out/paper1_smartbugs_revalidation_docker_20260709.jsonl
```

## 5. Artefactos incluidos

| Archivo | SHA-256 | Contenido |
|---|---|---|
| `result.json` | `abebab6b0efa108a68919f9e64a47269eecb40d45d11a3df3b9f8c986fd2354a` | Métricas agregadas + por categoría + por contrato |
| `result.jsonl` | `ce37996298795a9d66c265742a9538abff2a7141a934fa1a33413c75a6dbc5d4` | Traza por-contrato (una línea por contrato) |
| `Dockerfile.solc` | `7d2ae7488ffaf8bb1c002b6b59e3d2ed3ffc0ebabe16f26a47135d5526fc98a1` | Receta del entorno |
| `run.log` | ver `SHA256SUMS` | Log completo de la corrida |

Los `result.*` son copias fieles de
`benchmarks/results/paper1_smartbugs_revalidation_docker_20260709.{json,jsonl}`.

## 6. Cómo verificar (para el perito)

```bash
# 1. Integridad de los artefactos de este expediente
shasum -a 256 -c SHA256SUMS

# 2. Reproducir desde cero
docker build --platform linux/arm64 -t miesc:5.4.1-solc -f Dockerfile.solc .
docker run ... (comando de la sección 4)

# 3. Confirmar que la métrica no es 89.47%
python3 -c "import json;print(json.load(open('result.json'))['aggregate'])"
```

## 7. Honestidad sobre las diferencias (por qué 19.9% y no 22.2%)

La re-validación no reproduce el artefacto congelado bit-a-bit, y esto se
declara abiertamente:

1. **Toolset distinto en la capa 1.** La imagen oficial `5.4.1` (arm64) **no
   incluye** `wake`, `semgrep` ni `mythril`, que sí estaban presentes en el host
   que produjo el artefacto congelado. Un conjunto de herramientas distinto
   produce un conjunto de findings distinto → 563 FP vs 481 FP, y por tanto
   precisión 19.9% vs 22.2%. Ambos números describen el mismo perfil recall-first.
2. **No-determinismo LLM.** El filtro de FP asistido por LLM es estocástico entre
   corridas; los outputs crudos del artefacto congelado son la evidencia primaria
   y no se espera reproducción bit-a-bit de las capas LLM.
3. **`experiment_card` y `reproducibility`** ya forman parte del schema de salida
   v5.4.1, cerrando el gap M1 señalado en la auditoría de integridad.

Ninguna de estas diferencias altera la conclusión: la precisión real es ~20%,
el recall ~98%, y el `89.47%/86.2%` original carecía de respaldo.
