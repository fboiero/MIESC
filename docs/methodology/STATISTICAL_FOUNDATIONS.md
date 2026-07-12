# Fundamentos estadísticos y científicos — MIESC

Base metodológica para la tesis y los dos papers (detección y remediación). Cada
método está anclado en las mediciones reales del proyecto y en estadística
establecida. El principio rector es el de toda la línea de trabajo: **ninguna
afirmación sin su intervalo de confianza y su umbral de validez; toda limitación
se declara.**

---

## 1. Marco de medición (validez de constructo)

**Qué se mide.** Detección *type-aware*: un hallazgo cuenta como verdadero
positivo si cae dentro de una ventana de ±k líneas del marcador de ground-truth
**y** su tipo/SWC coincide con la clase de la vulnerabilidad. Esto distingue dos
métricas que suelen confundirse:

- **Recall de cobertura**: ¿hay *algún* hallazgo cerca de la vulnerabilidad?
- **Recall type-aware**: ¿el hallazgo cercano tiene el *tipo correcto*?

La tesis y Paper 1 reportan **type-aware** (más estricto y honesto). La ventana
±k (k=5) es una decisión de operacionalización que hay que declarar: es
*permisiva* en línea y *estricta* en tipo. Una ventana más chica sube la
precisión de la medición pero puede penalizar off-by-one en el mapeo de líneas.

**Ground truth y su validez.** El ground truth se construye a partir de
marcadores curados. Su calidad es una **amenaza de validez interna medible**: en
el corpus de 29 vulnerabilidades detectamos 2–3 etiquetas inválidas
(vulnerabilidades de *shares* etiquetadas en un vault de contabilidad 1:1 sin
shares; una etiqueta de *unchecked return* sobre una función correcta). Una
etiqueta que describe una vulnerabilidad ausente del código **no es detectable
por ningún método** e infla el denominador. Corregirla sube el recall real ~7pp.
**Conclusión metodológica: el ground truth se audita antes de reportar techos de
capacidad.**

---

## 2. Estimadores puntuales e intervalos de confianza

Todas las métricas de recall/precisión son **proporciones binomiales**
(detectado / total). Para el intervalo de confianza se usa el **método de
Wilson**, no el de Wald (normal), por dos razones:

1. Con **n chico** (n=11 exploits, n=29 corpus) el intervalo de Wald es
   inválido (puede exceder [0,1] y subcubre).
2. Con **proporciones extremas** (recall cerca de 1.0 en varias categorías) Wald
   colapsa; Wilson mantiene cobertura nominal.

**Intervalo de Wilson** para $\hat{p}=x/n$ al nivel $z$ (z=1.96 para 95%):

$$\text{CI} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

| Afirmación | n | Estimador | 95% CI (Wilson) | Lectura |
|---|---|---|---|---|
| Exploits DeFi reales | 11 | 9/11 = 81.8% | **[52%, 95%]** | indicativo, no definitivo |
| SmartBugs-curated (recall) | 143 | 137/143 = 95.8% | [91.1%, 98.1%] | robusto |
| EVMBench ensemble (recall) | 120 | 111/120 = 92.5% | [86.4%, 96.0%] | robusto |

**Adecuación del tamaño muestral.** El CI ancho del corpus de exploits
([52%, 95%]) es la razón por la que se reporta como *"indicativo, no
definitivo"* — no es un defecto ocultable, es la consecuencia honesta de n=11.
Los corpus grandes (n≥120) dan CIs angostos y afirmaciones fuertes. **Regla: n<30
→ el número va con su CI y la etiqueta de indicativo; nunca como punto seco.**

Nota histórica: la versión previa usaba **Cohen's κ**, que mide acuerdo
inter-evaluador y **es inválido para un diseño de una sola herramienta con
ground-truth all-positive**. Se retiró en favor del CI de Wilson. Es un ejemplo
de por qué el estadístico tiene que corresponder al diseño.

---

## 3. La no-determinación del LLM como objeto estadístico (contribución)

Este es el aporte metodológico central para modelos de razonamiento.

**El recall single-run de un LLM es una variable aleatoria, no un punto.**
Empíricamente, 6 corridas *independientes* del mismo modelo (DeepSeek-reasoner),
mismo prompt, sobre el mismo corpus de 29 vulnerabilidades:

| Estadístico | Valor |
|---|---|
| mínimo | 24.1% (7/29) |
| media | 47.7% |
| máximo | 65.5% (19/29) |
| rango | **41 puntos** |

Un rango de 41pp entre llamadas idénticas. **Reportar una sola corrida no es
reproducible** (un revisor re-corre y aterriza en cualquier punto del rango) y
además **subestima la capacidad** (la media, 47.7%, está muy por debajo del techo
real). Dos formas correctas de reportar:

**(a) Distribución.** Media ± CI sobre N corridas, con N declarado:
`recall = 47.7% ± 16pp (n=6 runs)`. Honesto pero débil (CI ancho).

**(b) Ensemble (recomendado).** La unión de K corridas es un **estimador de
reducción de varianza**: converge al *soporte* del modelo (el conjunto de
vulnerabilidades que puede detectar con probabilidad positiva). Curva de
saturación de cobertura, order-independent (promedio sobre todos los k-subsets):

| K corridas unidas | Recall | Marginal |
|---|---|---|
| 1 | 47.7% | — |
| 2 | 68.0% | +20.3 |
| 3 | 77.4% | +9.4 |
| 4 | 82.8% | +5.4 |
| 5 | 85.6% | +2.8 |
| 6 | 86.2% | +0.6 (plateau) |

Rendimientos decrecientes clásicos; **plateau en K≈5**. El ensemble es
**inmune a las tiradas malas** (la 6ª corrida, 37.9%, no mueve la unión).

**Consecuencia para el reporte:** el número honesto y reproducible de un LLM de
alta varianza es el **ensemble convergente (K declarado)**, no una corrida. Esto
valida reportar el ensemble como métrica principal (Paper 1: EVMBench 92.5%) y el
per-modelo como secundario, con su distribución.

**Controles de determinismo.** temperature=0 + seed logran determinismo
bit-a-bit en modelos locales (qwen/Ollama); en modelos de razonamiento
(DeepSeek-V4, o-series) el seed es *best-effort* — los hallazgos crudos difieren
pero la métrica type-aware es más estable. La varianza residual es la razón de la
metodología de ensemble.

---

## 4. Comparación de modelos (estadística inferencial)

Comparar modelos (DeepSeek vs GPT-5 vs Fable) sobre el **mismo** corpus es una
comparación **pareada** de detección binaria por-vulnerabilidad. Métodos:

- **Test de McNemar** sobre la tabla 2×2 de discordancias (vulns que A detecta y
  B no, vs viceversa). Es el test correcto para binarios pareados; no usar χ²
  independiente ni comparar recalls con un t-test no pareado.
- **Bootstrap** (remuestreo de vulnerabilidades con reemplazo, ~10k réplicas)
  para el CI de la *diferencia* de recall. Si el CI de la diferencia **contiene
  0**, los modelos son **estadísticamente indistinguibles** en ese corpus.

**Marco de cost-efficiency (contribución para la tesis).** La hipótesis
—*un modelo open-source alcanza detección comparable a N× menos presupuesto*— se
formaliza así:

- "Comparable" = la diferencia de recall (ensemble vs ensemble) tiene un CI
  bootstrap que contiene 0 (indistinguible), **o** está acotada por un margen
  pre-declarado δ.
- El eje de eficiencia es **recall-por-dólar**. Costo medido con tokens reales
  (input + output, incluyendo tokens de razonamiento ocultos que se facturan).
- El diseño experimental es honesto por construcción: los modelos caros se miden
  en una **muestra chica** (head-to-head real), y su costo **a escala se proyecta**
  desde las tarifas por-token (no se corre). Medido: a escala SmartBugs-143, GPT-5
  sería **~4×** y Fable **~29×** más caro que DeepSeek para K=5 corridas.

**Advertencia de comparaciones múltiples:** al comparar varios modelos se corrige
por familia (Bonferroni/Holm) o se declara el número de comparaciones.

---

## 5. Precisión, recall y F1

- **Perfil recall-first** (justificación científica): una vulnerabilidad no
  detectada se vuelve un exploit en producción (costo alto, asimétrico); un falso
  positivo se filtra barato en triage. Por eso el recall es la métrica primaria y
  la precisión es baja **por diseño** (~22% en SmartBugs), no por defecto.
- **F1** = media armónica de P y R; se reporta para no ocultar la precisión baja
  detrás de un recall alto. En SmartBugs: R=95.8%, P=22.1% → **F1=0.36**.
- **Recall-safety del filtro de FP** (invariante verificado): una heurística de
  "patrón seguro" nunca *dropea* un hallazgo de severidad real — lo baja a
  needs-review. Verificado a escala (off/medium/high preservan recall 27/27; el
  overflow real de BECToken sobrevive en todos los niveles). Cualquier ganancia de
  precisión reportada debe demostrarse **recall-safe a escala**, no en un contrato.

---

## 6. Amenazas a la validez (declaración explícita)

**Interna:**
- Calidad del ground-truth (defectos de etiquetado — §1). Mitigación: auditar el
  corpus antes de reportar techos.
- Leniencia del matching (±5 líneas). Puede contar como acierto un hallazgo del
  tipo correcto en la función adyacente.
- Disponibilidad de herramientas (arm64: Manticore/Echidna/Medusa limitados).

**Externa:**
- Corpus curados chicos (n=11, n=29) → CIs anchos. Generalización limitada.
- Frontera DeFi: manipulación de oráculo/precio, share-inflation, flash-loan
  governance no se cruzan ni con ensemble; es el límite de capacidad real.
- Un solo benchmark por dominio → sesgo de benchmark.

**De constructo:**
- type-aware vs cobertura; dependencia del mapeo a SWC.

**Reproducibilidad:**
- Determinismo (temp=0, seed), semillas globales, y un manifiesto de checksums
  (freeze) que congela los artefactos canónicos. Todo experimento nuevo es
  **aditivo** (archivo datado nuevo), no pisa la evidencia congelada.

---

## 7. Mapeo por documento

**Paper 1 (detección).** Ya usa Wilson CI para el corpus de exploits y reporta el
ensemble como headline. *Fortalezas a explicitar en defensa:* la elección de
Wilson sobre Wald; el ensemble como estimador de varianza; el retiro de κ.
*Recomendado agregar (si hubiera revisión):* disclosure de varianza per-modelo y
McNemar para las comparaciones entre proveedores.

**Paper 2 (remediación).** Mantiene **cuatro métricas separadas**
deliberadamente (parche emitido / compila / elimina la clase / analizador
externo limpio) porque responden preguntas distintas; la más conservadora
(57% Slither-clean) se pone al frente por honestidad (re-escanear con el propio
pipeline es circular). El **umbral de no-regresión** se reporta como una *curva*
(tolerancia 0→10), no un punto, lo que es un análisis de robustez, no un número
elegido. *Recomendado:* CIs de Wilson sobre las tasas de parche (n=123).

**Tesis.** Adopta el marco completo: type-aware + Wilson por-claim (§2), la
metodología ensemble-convergente (§3) como aporte, McNemar/bootstrap para RQ2
(§4), la contribución de **cost-efficiency open-source** (§4), el corpus
corregido (§1), y la sección de amenazas a la validez (§6). Las RQ se anclan así:
RQ1 (disponibilidad, 25/25) es un conteo; RQ2 (mejora de detección) es la
comparación pareada + ensemble; RQ3 (deduplicación) es una reducción de conteo
con su tasa.

---

*Los números citados se reproducen desde `docs/evidence/detection_optimization_20260710/`
y `benchmarks/results/paper1_claims_matrix.json`. Este documento es aditivo y no
modifica ningún artefacto congelado.*
