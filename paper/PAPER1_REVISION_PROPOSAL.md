# Paper 1 Revision Proposal

Fecha: 2026-05-06

Estado: aplicado parcialmente y superado por la version reproducible del
2026-05-06. El paper final usa SmartBugs `1,6,7` con 93.7% recall como perfil
full-corpus, EVMBench ensemble 111/120 (92.5%) como evidencia de business
logic, y un smoke `1..9` como evidencia de integracion completa.

Archivo objetivo: `paper/miesc-paper.tex`

## Objetivo

Mejorar el Paper 1 sin debilitar su contribucion central: MIESC como framework
multi-capa para triage de seguridad en smart contracts. La prioridad es que cada
claim cuantitativo tenga evidencia trazable en el repositorio o una fuente
externa primaria.

## Autoria y metadatos

Autores del Paper 1:

- Ing. Fernando Boiero, Universidad Tecnologica Nacional (UTN), Facultad
  Regional Villa Maria, `fboiero@frvm.utn.edu.ar`.
- Ing. Sebastian Norberto Mussetta, Universidad Tecnologica Nacional (UTN), Facultad
  Regional Villa Maria, `smussetta@frvm.utn.edu.ar`.
- Ing. Norberto Gaspar Cena, Universidad Tecnologica Nacional (UTN), Facultad
  Regional Villa Maria, `ngcena@frvm.utn.edu.ar`.

ORCID:

- Fernando Boiero: `0009-0005-7935-2758`.
- Sebastian Norberto Mussetta: `0009-0007-8025-9846`.
- Norberto Gaspar Cena: pendiente/no informado.

Commits y derechos:

- Los commits del repositorio deben quedar atribuidos a
  `fboiero@frvm.utn.edu.ar`.
- No se debe agregar autoria, copyright ni metadatos que indiquen que los
  cambios fueron realizados por una IA.

## Diagnostico

El paper actual tiene una narrativa fuerte, pero mezcla tres generaciones de
resultados:

- Resultados historicos de publicacion: `54.6% static / 80% all layers` en las
  instrucciones antiguas.
- Resultados actuales declarados en el paper: `96.5% static + intelligence` y
  `~98.6% all layers + LLM`.
- Resultados EVMBench v5.3.1: JSONs locales para proveedores individuales, con
  una claim de ensemble que todavia necesita artefacto reproducible dedicado.

El riesgo principal no es LaTeX ni redaccion: es trazabilidad cientifica.

## Claims: mantener, ajustar o respaldar

| Claim | Estado | Accion propuesta |
|---|---|---|
| 35 modulos, 9 capas | Mantenible | Agregar tabla o apendice con lista exacta de modulos por capa. |
| SmartBugs 96.5% / 98.6% | Riesgoso | Mantener solo si generamos un JSON reproducible nuevo con esos numeros. Si no, bajar a `80% all layers` o presentarlo como resultado preliminar no central. |
| SmartBugs 8/10 categorias al 100% | Inconsistente | Corregir tabla/texto. La tabla actual no respalda esa frase. |
| Real exploits 81.8%, kappa 0.77 | Mantenible con cautela | Agregar archivo de ground truth y resultado agregado legible. Explicar que son 11 casos curados, no una muestra estadistica grande. |
| EVMBench 82.5% Claude, 77.5% GPT-5, 59.2% Ollama | Respaldado localmente | Citar los JSONs locales y aclarar version `v5.3.1`. |
| EVMBench GPT-4o 73.7% en 40 audits | Ajustar | El JSON local registra 39 audits / 118 vulns. Cambiar `n=39` o regenerar. |
| EVMBench ensemble 92.5% | Necesita respaldo | Crear `benchmarks/results/evmbench/evmbench_ensemble_40.json` con union reproducible de findings y metodologia. |
| EVMBench 120 vulns | Necesita precision | La fuente primaria OpenAI/arXiv describe 117 vulnerabilidades curadas en 40 repositorios/audits. Si usamos 120, llamarlo "our local extraction/version". |
| Cecuro 87.7% | Fuente secundaria/promocional | Se puede mencionar, pero no como "state of the art" sin matiz. Preferible: "reported by Cecuro/Chainwire". |
| "Any LLM + static beats best LLM alone" | Demasiado fuerte | Reescribir como resultado observado en nuestros modos evaluados, no ley general. |

## Estrategia editorial recomendada

### Opcion A: conservadora y publicable rapido

Usar SmartBugs como benchmark clasico y EVMBench como benchmark moderno.

- Abstract:
  - SmartBugs: reportar el ultimo resultado reproducible verificable.
  - EVMBench: reportar proveedores individuales respaldados por JSON.
  - Ensemble: incluir solo si generamos artefacto reproducible antes de publicar.
- Discussion:
  - Enfatizar que SmartBugs mide patrones historicos y EVMBench mide business
    logic.
  - Bajar la precision de claims universales.
- Ventaja: menor riesgo de rechazo por claims inconsistentes.

### Opcion B: ambiciosa, requiere una corrida mas

Preservar la narrativa `96.5% / 98.6% / 92.5%`, pero antes generar evidencia:

1. Ejecutar `miesc evaluate corpus` sobre SmartBugs con config fija.
2. Guardar `experiment_card`, JSON y JSONL.
3. Regenerar EVMBench GPT-4o para 40/120 o corregir tabla a 39/118.
4. Crear resultado de ensemble con union documentada.
5. Actualizar paper y README para apuntar a esos artefactos.

Ventaja: paper mas fuerte. Costo: requiere tiempo/API y disciplina de
reproducibilidad.

## Cambios concretos en `miesc-paper.tex`

1. **Abstract**
   - Reducir claims absolutos.
   - Distinguir "SmartBugs-curated" de "EVMBench local extraction".
   - Evitar "strictly superior" salvo que haya prueba formal/estadistica.

2. **Experimental Setup**
   - Separar entornos:
     - SmartBugs: herramientas, capas, dataset, criterio de matching.
     - EVMBench: snapshot, numero de audits/vulnerabilidades, proveedor/modelo,
       token budget, matcher, juez LLM si aplica.
   - Incluir fecha de corrida y version MIESC.

3. **Results**
   - Tabla SmartBugs: usar una sola fuente de verdad.
   - Tabla EVMBench: agregar columna `source artifact`.
   - Si hay n distinto por proveedor, mostrarlo claramente.

4. **Threats to Validity**
   - Agregar:
     - Diferencia entre EVMBench oficial y extraccion local.
     - Posible data contamination en benchmarks derivados de Code4rena.
     - No equivalencia entre recall por contrato y recall por vulnerabilidad.
     - Uso de LLM judge en matching.

5. **Data Availability**
   - Listar rutas exactas:
     - `benchmarks/results/...`
     - `benchmarks/evmbench_eval.py`
     - `docs/guides/RESEARCH.md`

## Artefactos que conviene crear

1. `benchmarks/results/paper1_claims_matrix.json`
   - Claim, valor, archivo fuente, comando, fecha, version.

2. `benchmarks/results/evmbench/evmbench_ensemble_40.json`
   - Union de detecciones por vulnerabilidad.
   - Conteo de vulnerabilidades detectadas por cada proveedor.
   - Conteo de vulnerabilidades detectadas por mas de un proveedor.

3. `paper/PAPER1_REPRODUCIBILITY.md`
   - Comandos exactos para SmartBugs y EVMBench.
   - Hardware/software.
   - Variables de entorno sin secretos.

4. `paper/CLAIMS_AUDIT.md`
   - Checklist antes de publicar.

## Skills y herramientas

Skills disponibles revisadas:

- `skill-installer`: usado para consultar el catalogo.
- No hay skill academica especifica instalada.
- Skills potencialmente utiles, pero no necesarias todavia:
  - `pdf`: para inspeccion/render si el layout PDF se vuelve el cuello de botella.
  - `jupyter-notebook`: para notebook reproducible de metricas.
  - `security-threat-model`: util para docs de threat modeling, no para este paper.

Mi recomendacion: no instalar nada por ahora. Primero ordenar evidencia y claims.

## Fuentes externas verificadas

- OpenAI, "Introducing EVMbench", 2026-02-18:
  https://openai.com/index/introducing-evmbench/
- arXiv:2603.04915, "EVMbench: Evaluating AI Agents on Smart Contract Security":
  https://arxiv.org/abs/2603.04915
- Paradigm GitHub repo:
  https://github.com/paradigmxyz/evmbench
- Chainwire/Cecuro report, 2026-04-16:
  https://chainwire.org/2026/04/16/ai-audit-firm-cecuro-outperforms-nearest-rival-by-2x-on-openai-smart-contract-exploit-benchmark/

Nota: OpenAI/arXiv hablan de 117 vulnerabilidades curadas; Cecuro/Chainwire y
algunos artefactos locales hablan de 120 high-severity findings. El paper debe
explicar esa diferencia si conserva `120`.

## Decision editorial: bajada fuerte y reproducible

Se adopta la ruta ambiciosa, pero con gate de reproducibilidad:

1. EVMBench pasa a ser el resultado principal del paper. El ensemble ya tiene
   artefacto reproducible: `benchmarks/results/evmbench/evmbench_ensemble_40.json`
   con `111/120 = 92.5%`.
2. SmartBugs queda como benchmark clasico complementario con el ultimo JSON
   local completo (`80.0%` recall) hasta corregir `miesc evaluate corpus` para
   seleccionar `solc` por pragma.
3. La claim `96.5% / 98.6%` no se elimina conceptualmente; queda bloqueada por
   reproducibilidad. Vuelve al paper cuando exista un JSON nuevo que la sostenga.
4. El paper debe decir "EVMBench local high-severity extraction (120 findings)"
   y aclarar que la fuente oficial describe 117 vulnerabilidades curadas.
5. Todas las claims numericas deben aparecer en
   `benchmarks/results/paper1_claims_matrix.json`.

Comando reproducible principal:

```bash
python3 benchmarks/generate_paper1_artifacts.py
```

Resultado:

```text
EVMBench ensemble: 111/120 (92.5%)
```
