<!-- COVER PAGE -->
<div class="cover-page">

<div style="margin-bottom: 60px;">
<h1 style="font-size: 42pt; margin-bottom: 10px; color: white; border: none;">🛡️ MIESC</h1>
<p style="font-size: 14pt; color: #94a3b8;">Evaluación Inteligente Multicapa para Contratos Inteligentes</p>
</div>

<h2 style="font-size: 28pt; font-weight: 300; color: white; margin: 40px 0;">Auditoría de Seguridad de Contratos Inteligentes</h2>

<div style="background: rgba(255,255,255,0.1); border-radius: 12px; padding: 30px; margin: 30px 0;">
<h3 style="font-size: 22pt; color: #60a5fa; border: none; margin: 0;">{{ contract_name }}</h3>
<p style="color: #94a3b8; margin-top: 10px;">{{ client_name | default('Cliente') }}</p>
</div>

<div style="margin-top: 60px; text-align: left; display: inline-block;">
<table style="background: transparent; border: none;">
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Elaborado por:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ auditor_name | default('MIESC Security') }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Fecha de auditoría:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ audit_date }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Fecha del informe:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ generation_date }}</strong></td></tr>
<tr><td style="color: #94a3b8; border: none; padding: 8px 20px 8px 0;">Versión:</td><td style="color: white; border: none; padding: 8px 0;"><strong>{{ report_version | default('1.0') }}</strong></td></tr>
</table>
</div>

<div style="margin-top: 50px;">
<span style="background: #dc3545; color: white; padding: 8px 20px; border-radius: 4px; font-weight: 600; font-size: 10pt;">{{ classification | default('CONFIDENCIAL') }}</span>
</div>

<p style="color: #64748b; font-size: 9pt; margin-top: 60px; max-width: 400px;">
Este documento contiene hallazgos de seguridad confidenciales y está destinado únicamente a su destinatario. Queda prohibida su distribución no autorizada.
</p>

</div>

---

# Índice

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Alcance y Metodología](#alcance-y-metodologia)
3. [Evaluación de Riesgo](#evaluacion-de-riesgo)
4. [Panorama de Hallazgos](#panorama-de-hallazgos)
5. [Hallazgos Detallados](#hallazgos-detallados)
6. [Hoja de Ruta de Remediación](#hoja-de-ruta-de-remediacion)
7. [Anexos](#anexos)

---

# 1. Resumen Ejecutivo

## 1.1 Puntos Clave

{{ llm_executive_summary | default('No hay resumen asistido por IA disponible.') }}

## 1.2 Recomendación de Despliegue

<div class="recommendation-box" style="border: 2px solid {{ deployment_recommendation_color | default('#ff9800') }}; padding: 20px; margin: 15px 0; border-radius: 8px; background: {{ deployment_recommendation_bg | default('#fff8e1') }};">
<p style="margin: 0 0 10px 0; font-size: 11pt;">
<strong style="color: {{ deployment_recommendation_color | default('#ff9800') }};">Recomendación:</strong>
<span style="font-weight: bold; font-size: 14pt; margin-left: 8px;">{{ deployment_recommendation | default('CONDITIONAL') }}</span>
</p>
<p style="margin: 0; color: #4a5568; line-height: 1.5;">{{ deployment_justification | default('Revise y atienda los hallazgos antes del despliegue.') }}</p>
</div>

## 1.3 Resumen de Riesgo

| Métrica | Valor |
|--------|-------|
| **Puntaje de Riesgo General** | {{ overall_risk_score | default('N/D') }}/100 |
| **Explotabilidad** | {{ exploitability_rating | default('Media') }} |
| **Impacto en el Negocio** | {{ business_impact | default('Medio') }} |
| **Nivel de Confianza** | {{ confidence_level | default('Alto') }} |

### Hallazgos por Severidad

| Severidad | Cantidad | % del Total |
|----------|------:|----------:|
| **Crítica** | {{ critical_count | default(0) }} | {{ critical_percent | default(0) }}% |
| **Alta** | {{ high_count | default(0) }} | {{ high_percent | default(0) }}% |
| **Media** | {{ medium_count | default(0) }} | {{ medium_percent | default(0) }}% |
| **Baja** | {{ low_count | default(0) }} | {{ low_percent | default(0) }}% |
| **Informativa** | {{ info_count | default(0) }} | {{ info_percent | default(0) }}% |
| **Total** | **{{ total_findings | default(0) }}** | 100% |

## 1.4 Evaluación de Impacto

{%- if value_at_risk %}
| Escenario | Impacto Estimado |
|----------|-----------------|
| Peor caso (todas las críticas explotadas) | {{ value_at_risk.worst_case | default('No se puede estimar') }} |
| Caso probable | {{ value_at_risk.likely_case | default('No se puede estimar') }} |
| Mejor caso (solo explotaciones menores) | {{ value_at_risk.best_case | default('No se puede estimar') }} |
{%- else %}
Con base en las vulnerabilidades identificadas:

| Categoría de Impacto | Evaluación |
|----------------|------------|
| **Confidencialidad** | {{ 'Alto' if critical_count > 0 else ('Medio' if high_count > 0 else 'Bajo') }} - {% if critical_count > 0 or high_count > 0 %}Datos o estado sensibles podrían quedar expuestos{% else %}No se identificaron riesgos significativos de confidencialidad{% endif %} |
| **Integridad** | {{ 'Alto' if critical_count > 0 else ('Medio' if high_count > 0 else 'Bajo') }} - {% if critical_count > 0 or high_count > 0 %}El estado del contrato podría ser manipulado{% else %}La lógica del contrato parece sólida{% endif %} |
| **Disponibilidad** | {{ availability_rating | default('Bajo') }} - {{ availability_note | default('No se identificaron riesgos significativos de disponibilidad') }} |
{%- endif %}

---

# 2. Alcance y Metodología

## 2.1 Detalles del Trabajo

| Propiedad | Valor |
|----------|-------|
| **Cliente** | {{ client_name | default('N/D') }} |
| **Contrato** | {{ contract_name }} |
| **Repositorio** | {{ repository | default('N/D') }} |
| **Hash de commit** | `{{ commit_hash | default('N/D') }}` |
| **Red** | {{ target_network | default('Ethereum Mainnet') }} |
| **Tipo de trabajo** | {{ engagement_type | default('Auditoría de Seguridad Completa') }} |

## 2.2 Alcance

### En Alcance

| Archivo | Líneas | Descripción |
|------|------:|-------------|
{%- for file in files_in_scope %}
| `{{ file.path }}` | {{ file.lines }} | {{ file.description | default('Código fuente del contrato') }} |
{%- endfor %}

**Total:** {{ files_count }} archivos, {{ lines_of_code }} líneas de código

### Fuera de Alcance

{%- if out_of_scope %}
{%- for item in out_of_scope %}
- {{ item }}
{%- endfor %}
{%- else %}
- Dependencias externas y librerías importadas
- Componentes off-chain
- Análisis económico/tokenómica
- Aplicaciones de frontend/backend
{%- endif %}

## 2.3 Metodología

Esta auditoría empleó la metodología integral de defensa en profundidad de 9 capas de MIESC:

```
Capa 1: Análisis Estático         [{{ layer1_coverage | default('--') }}]
Capa 2: Pruebas Dinámicas         [{{ layer2_coverage | default('--') }}]
Capa 3: Ejecución Simbólica       [{{ layer3_coverage | default('--') }}]
Capa 4: Verificación Formal       [{{ layer4_coverage | default('--') }}]
Capa 5: Pruebas de Propiedades    [{{ layer5_coverage | default('--') }}]
Capa 6: Análisis con IA/LLM       [{{ layer6_coverage | default('--') }}]
Capa 7: Reconocimiento de Patrones[{{ layer7_coverage | default('--') }}]
Capa 8: Seguridad DeFi            [{{ layer8_coverage | default('--') }}]
Capa 9: Detección Avanzada        [{{ layer9_coverage | default('--') }}]
```

### Herramientas Utilizadas

| Capa | Herramienta | Versión | Estado |
|-------|------|---------|--------|
{%- for tool in tools_execution_summary %}
| {{ tool.layer }} | {{ tool.name }} | {{ tool.version | default('latest') }} | {{ tool.status_icon }} {{ tool.status }} |
{%- endfor %}

### Proceso de Auditoría

1. **Evaluación inicial** - Analizar las fuentes objetivo y construir el alcance del análisis
2. **Análisis automatizado** - Ejecutar el conjunto de herramientas multicapa
3. **Análisis multiherramienta** - Análisis estático, dinámico y simbólico automatizado a través de las capas de defensa en profundidad
4. **Correlación con IA** - Cruzar hallazgos, reducir falsos positivos
5. **Corroboración y filtrado** - Corroboración entre herramientas, filtrado de falsos positivos y confirmación por ejecución donde esté habilitada
6. **Generación del informe** - Documentar hallazgos con guía de remediación

## 2.4 Limitaciones

- Trabajo acotado en el tiempo ({{ audit_duration | default('N/D') }})
- Análisis basado en una instantánea del código en el commit `{{ commit_hash | default('N/D') }}`
- No se garantiza la detección de todas las vulnerabilidades
- Los vectores de ataque económicos no se modelan por completo
- Pueden existir vulnerabilidades de dependencias más allá del alcance del análisis

---

# 3. Evaluación de Riesgo

## 3.1 Matriz de Riesgo

La siguiente matriz ubica los hallazgos por **Impacto** (vertical) y **Probabilidad** (horizontal):

<table style="width: 100%; max-width: 500px; margin: 20px auto; border-collapse: collapse; text-align: center;">
<tr>
<td style="border: none; width: 80px;"></td>
<td style="border: none;" colspan="3"><strong>PROBABILIDAD</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none; color: #6b7280; padding: 8px;">Baja</td>
<td style="border: none; color: #6b7280; padding: 8px;">Media</td>
<td style="border: none; color: #6b7280; padding: 8px;">Alta</td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Alto</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Media</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_low | default(0) }}</strong></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><small>Alta</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_med | default(0) }}</strong></td>
<td style="background: #dc2626; color: white; padding: 15px; border-radius: 4px;"><small>Crítica</small><br><strong style="font-size: 18pt;">{{ risk_matrix.high_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Med</strong></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><small>Baja</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_low | default(0) }}</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Media</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_med | default(0) }}</strong></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><small>Alta</small><br><strong style="font-size: 18pt;">{{ risk_matrix.med_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Bajo</strong></td>
<td style="background: #94a3b8; color: white; padding: 15px; border-radius: 4px;"><small>Info</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_low | default(0) }}</strong></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><small>Baja</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_med | default(0) }}</strong></td>
<td style="background: #fbbf24; color: white; padding: 15px; border-radius: 4px;"><small>Media</small><br><strong style="font-size: 18pt;">{{ risk_matrix.low_high | default(0) }}</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none;" colspan="3"><em style="color: #6b7280; font-size: 9pt;">IMPACTO →</em></td>
</tr>
</table>

## 3.2 Puntuación tipo CVSS

| ID del Hallazgo | Título | Puntaje Base | Vector |
|------------|-------|-----------|--------|
{%- for score in cvss_scores %}
| {{ score.finding_id }} | {{ score.title }} | **{{ score.base_score }}** | {{ score.vector }} |
{%- endfor %}

**Metodología de puntuación:**
- **Vector de Ataque (AV):** Red, Adyacente, Local, Físico
- **Complejidad del Ataque (AC):** Baja, Alta
- **Privilegios Requeridos (PR):** Ninguno, Bajo, Alto
- **Interacción del Usuario (UI):** Ninguna, Requerida
- **Impacto:** Confidencialidad, Integridad, Disponibilidad

## 3.3 Narrativa de Riesgo

{%- if llm_risk_narrative %}
{{ llm_risk_narrative }}
{%- else %}
El contrato analizado presenta preocupaciones de seguridad que deberían atenderse antes del despliegue en producción. La combinación de hallazgos indica potencial de explotación si no se mitiga.
{%- endif %}

---

# 4. Panorama de Hallazgos

## 4.1 Tabla Resumen

| ID | Título | Severidad | Verificación | Estado | CVSS |
|----|-------|----------|--------------|--------|-----:|
{%- for finding in findings %}
| {{ finding.id }} | {{ finding.title }} | {{ finding.severity_badge }} | {{ finding.verification }} | {{ finding.status }} | {{ finding.cvss_score | default('--') }} |
{%- endfor %}

## 4.2 Distribución por Categoría

| Categoría | Cantidad | Desglose por Severidad |
|----------|------:|-------------------|
{%- for cat in category_summary %}
| {{ cat.name }} | {{ cat.count }} | {{ cat.breakdown }} |
{%- endfor %}

## 4.3 Análisis de Cobertura por Capa

| Capa | Herramientas Ejecutadas | Exitosas | Fallidas | Hallazgos | Cobertura |
|-------|----------:|-------:|-------:|----------:|----------|
{%- for layer in layer_summary %}
| {{ layer.name }} | {{ layer.tools }} | {{ layer.success_count }} | {{ layer.failed_count }} | {{ layer.findings_count }} | {{ layer.coverage_bar }} |
{%- endfor %}

## 4.4 Análisis de Propiedades e Invariantes

Esta sección reporta la capa de evidencia formal y de invariantes por separado de los
hallazgos estáticos anteriores. Un hallazgo verificado por ejecución es un contraejemplo
que se reprodujo ejecutando la llamada bajo Foundry: un contraejemplo dinámico, no una
prueba formal. Aquí no se afirma que ningún invariante quede matemáticamente establecido.

{%- if not formal_verification_tools and not execution_verified_findings %}

**No realizado en este trabajo.** Ni la verificación formal (Capa 4) ni la comprobación
de invariantes basada en ejecución produjeron evidencia para este contrato. Para habilitar
la capa de invariantes verificada por ejecución, ejecute el agente de auditoría profunda con
`enable_gap_execution` (brechas de control de acceso) y/o `enable_gap_reasoning`
(brechas de pausa y frescura).
{%- else %}

### 4.4.1 Verificación Formal (Capa 4)

{%- if formal_verification_tools %}

Solo estado de ejecución y conteo de hallazgos de las herramientas — ningún invariante se
reporta como establecido por estas herramientas.

| Herramienta | Estado | Hallazgos |
|------|--------|---------:|
{%- for tool in formal_verification_tools %}
| {{ tool.name }} | {{ tool.status_icon }} {{ tool.status }} | {{ tool.findings_count | default(0) }} |
{%- endfor %}
{%- else %}

Ninguna herramienta de verificación formal (certora, smtchecker, scribble, pyrometer,
propertygpt) se ejecutó en este trabajo.
{%- endif %}

### 4.4.2 Hallazgos Verificados por Ejecución

{%- if execution_verified_findings %}

Los siguientes hallazgos se reprodujeron por ejecución bajo Foundry — un contraejemplo
dinámico, no una prueba formal.

{%- for finding in execution_verified_findings %}

**{{ finding.id }}. {{ finding.title }}** &nbsp; {{ finding.severity_badge }} &nbsp; `{{ finding.location }}`

- **Verificación:** {{ finding.verification }}
{%- for line in finding.evidence %}
- Evidencia: {{ line }}
{%- endfor %}
{%- endfor %}
{%- else %}

No se produjeron contraejemplos verificados por ejecución en este trabajo.
{%- endif %}
{%- endif %}

## 4.5 Modelo de Confianza y Roles Privilegiados
{%- if not governance_plans and not trust_inventory_ran and not trust_findings %}

**Modelo de confianza no evaluado en este trabajo.** No se extrajo ningún inventario de
roles privilegiados y no se reportaron hallazgos relevantes para la confianza (control de
acceso, centralización o proxy/actualización).
{%- else %}

Esta sección inventaría los actores y roles privilegiados que el código fuente del contrato
declara y cruza los hallazgos relevantes para la confianza anteriores. Es un **modelo
estático y orientativo de autoridad**, no una auditoría de gobernanza: un rol es una
asunción de confianza, no una vulnerabilidad, y nada aquí cambia ningún conteo de hallazgos
ni el puntaje de riesgo.

> **Custodia.** Esta auditoría no verificó la custodia de llaves ni la gobernanza off-chain;
> los roles son los declarados en el código. No se asume que una cuenta llamada `owner` sea
> un multisig o un timelock.
>
> **Completitud.** El inventario de roles se identifica por extracción estática; puede omitir
> autoridad heredada, delegada vía proxy o a nivel de ensamblador, y puede estar incompleto.
> El grafo de roles extraído se produce solo para auditorías agénticas de un único archivo —
> las auditorías de directorio llevan el cruce de hallazgos de §4.5.2 pero no el grafo de roles.

### 4.5.1 Roles privilegiados identificados
{%- if governance_plans %}

Identificados por extracción estática (orientativo). Cada actor y rol se ancla a las líneas
de fuente donde se observó.
{%- for plan in governance_plans %}

{{ plan.objective }}
{%- if plan.actors %}

**Actores**

| Actor | Tipo declarado | Fuente | Funciones que protege | Anclas de fuente |
|-------|---------------|--------|------------------|----------------|
{%- for actor in plan.actors %}
| `{{ actor.id }}` | {{ actor.kind }} | {{ actor.source }} | {{ actor.guards | default('—', true) }} | {{ actor.anchors | default('—', true) }} |
{%- endfor %}
{%- endif %}
{%- if plan.roles %}

**Roles**

| Rol | Rol administrador | Funciones que protege | Funciones de otorgamiento | Funciones de revocación |
|------|------------|------------------|-----------------|------------------|
{%- for role in plan.roles %}
| `{{ role.name }}` | {{ role.admin_role | default('—', true) }} | {{ role.guards | default('—', true) }} | {{ role.grant_functions | default('—', true) }} | {{ role.revoke_functions | default('—', true) }} |
{%- endfor %}
{%- endif %}
{%- if plan.truncated %}

_Nota: este inventario alcanzó el tope de extracción por lista y puede estar truncado._
{%- endif %}
{%- endfor %}
{%- elif trust_inventory_ran %}

La extracción estática se ejecutó; no se identificaron actores ni roles privilegiados en el
código analizado. Esto no establece que no existan (véase la nota de completitud anterior).
{%- else %}

Inventario de roles no extraído en este trabajo. Habilítelo con `enable_advisory_plans`
(auditorías agénticas de un único archivo).
{%- endif %}

### 4.5.2 Hallazgos relevantes para la confianza
{%- if trust_findings %}

Hallazgos anteriores cuya categoría canónica concierne a la autoridad privilegiada (control
de acceso, centralización o proxy/actualización), cruzados por id y severidad. El detalle y
la puntuación quedan en §5; esto es un cruce de referencias, no un nuevo hallazgo.

| Hallazgo | Título | Categoría | Severidad |
|---------|-------|----------|----------|
{%- for f in trust_findings %}
| {{ f.id }} | {{ f.title }} | {{ f.category }} | {{ f.severity_badge }} |
{%- endfor %}
{%- else %}

No se reportaron hallazgos relevantes para la confianza (control de acceso, centralización o
proxy/actualización) en este trabajo.
{%- endif %}
{%- endif %}

## 4.6 Pruebas Dinámicas y Fuzzing
{%- if fuzzing_tools %}

En este trabajo se ejecutaron campañas de fuzzing. Las métricas siguientes describen el
alcance y el resultado de cada campaña y corresponden a la **Capa 2 (Pruebas Dinámicas)** de
la metodología (§2.3). Una estadística de campaña no es un hallazgo: cualquier problema que
un fuzzer haya producido ya está contado en §1 y detallado en §5, y aquí se cruza por id,
nunca se vuelve a contar.
{%- for ft in fuzzing_tools %}
{%- if ft.is_foundry %}
{%- if ft.stats_unparsed %}

- **Suite de pruebas {{ ft.display }}:** se ejecutó con {{ ft.fuzz_runs | default('--', true) }} corridas de fuzz configuradas por prueba; las estadísticas de campaña no pudieron parsearse de la salida de la herramienta.{% if ft.finding_ids %} Hallazgos reproducidos por ejecución: {{ ft.finding_ids }}.{% endif %}
{%- else %}

- **Suite de pruebas {{ ft.display }}:** {{ ft.tests_run }} pruebas ({{ ft.tests_passed | default(0, true) }} exitosas / {{ ft.tests_failed | default(0, true) }} fallidas), {{ ft.fuzz_runs | default('--', true) }} corridas de fuzz configuradas por prueba.{% if ft.finding_ids %} Hallazgos reproducidos por ejecución: {{ ft.finding_ids }}.{% endif %}
{%- endif %}
{%- else %}

- **{{ ft.display }}:** límite de pruebas configurado {{ ft.test_limit | default('--', true) }} (un tope, no la cantidad de secuencias ejecutadas); {{ ft.property_violations | default(0, true) }} violaciones de propiedades reportadas por la herramienta.{% if ft.finding_ids %} Véase {{ ft.finding_ids }}.{% endif %}
{%- endif %}
{%- endfor %}
{%- elif dynamic_layer_ran %}

Se ejecutó herramienta de pruebas dinámicas en este trabajo (**Capa 2**, §2.3) pero no se
registraron estadísticas de campaña de fuzzing. Cualquier resultado reproducido por ejecución
se reporta en §4.4 (Análisis de Propiedades e Invariantes).
{%- else %}

No se realizaron pruebas dinámicas ni de fuzzing en este trabajo. Esta es la **Capa 2
(Pruebas Dinámicas)** de la metodología (§2.3); el fuzzing basado en propiedades con Foundry,
Echidna o Medusa proveería esta capa.
{%- endif %}

---

# 5. Hallazgos Detallados

{%- for finding in findings %}

## {{ finding.id }}. {{ finding.title }}

| Propiedad | Valor |
|----------|-------|
| **Severidad** | <span style="background: {{ finding.severity_color | default('#e0e0e0') }}; color: white; padding: 2px 8px; border-radius: 4px;">{{ finding.severity_badge }}</span> |
| **Categoría** | {{ finding.canonical_category or finding.category }} |
| **Puntaje CVSS** | {{ finding.cvss_score | default('N/D') }} |
| **Ubicación** | `{{ finding.location }}` |
| **Estado** | {{ finding.status }} |
| **Detectado por** | {{ finding.tool }} |
| **Verificación** | {{ finding.verification }} |

### Descripción

{{ finding.description }}

### Código Vulnerable

```solidity
{{ finding.vulnerable_code | default(finding.poc) }}
```

### Análisis de Impacto

{{ finding.impact }}

{%- if finding.attack_scenario %}

### Escenario de Ataque

{{ finding.attack_scenario }}

**Paso a paso:**
{%- for step in finding.attack_steps %}
{{ loop.index }}. {{ step }}
{%- endfor %}
{%- endif %}
{%- if finding.poc_available %}

### Prueba de Concepto

**Plantilla de PoC:** `{{ finding.poc_name }}`

> **Resultado esperado:** {{ finding.poc_expected_outcome }}

**Prerrequisitos:**
{%- for prereq in finding.poc_prerequisites %}
- {{ prereq }}
{%- endfor %}

```solidity
{{ finding.poc }}
```

*Generado por el Generador de PoC de MIESC - plantilla de prueba Foundry*
{%- endif %}

### Recomendación

{{ finding.recommendation }}
{%- if finding.remediation_code %}

### Corrección Sugerida

```diff
{{ finding.remediation_code }}
```

**Esfuerzo de remediación:** {{ finding.remediation_effort | default('Medio') }}
**Tiempo estimado de corrección:** {{ finding.fix_time | default('1-2 horas') }}
{%- endif %}
{%- if llm_enabled and finding.llm_interpretation %}

### Análisis Asistido por Modelo

*Generado por {{ llm_model }}*

{{ finding.llm_interpretation }}
{%- endif %}

### Referencias
{%- for ref in finding.references %}
- {{ ref }}
{%- endfor %}
{%- if not finding.references %}
- No hay referencias disponibles
{%- endif %}

---
{%- endfor %}

---

# 6. Hoja de Ruta de Remediación

## 6.1 Acciones Priorizadas

{%- if llm_enabled and llm_remediation_priority %}
| Prioridad | Hallazgo | Severidad | Esfuerzo | Fundamento |
|:--------:|---------|----------|--------|-----------|
{%- for item in llm_remediation_priority %}
| {{ item.priority }} | {{ item.title }} | {{ item.severity }} | {{ item.effort }} | {{ item.reason }} |
{%- endfor %}
{%- else %}
| Prioridad | Hallazgo | Severidad | Acción Recomendada |
|:--------:|---------|----------|-------------------|
{%- for finding in critical_high_findings %}
| {{ loop.index }} | {{ finding.title }} | {{ finding.severity_badge }} | Corrección inmediata requerida |
{%- endfor %}
{%- if not critical_high_findings %}
| -- | Sin hallazgos de severidad crítica o alta | -- | -- |
{%- endif %}
{%- endif %}

## 6.2 Cronograma de Remediación

| Fase | Semana | Prioridad | Hallazgos | Acción |
|:-----:|:----:|----------|:--------:|--------|
| <span style="background:#dc2626;color:white;padding:4px 10px;border-radius:50%;">1</span> | **Semana 1** | Crítica y Alta | {{ critical_count }} + {{ high_count }} | Remediación inmediata requerida |
| <span style="background:#f97316;color:white;padding:4px 10px;border-radius:50%;">2</span> | **Semana 2** | Media | {{ medium_count }} | Atender problemas de severidad media |
| <span style="background:#22c55e;color:white;padding:4px 10px;border-radius:50%;">3</span> | **Semana 3** | Baja e Info | {{ low_count }} + {{ info_count }} | Corregir elementos de baja prioridad |
| <span style="background:#3b82f6;color:white;padding:4px 10px;border-radius:50%;">4</span> | **Semana 4** | Verificación | - | Re-auditoría y validación |

## 6.3 Mejoras Rápidas
{%- if quick_wins %}

Las siguientes correcciones ofrecen alto impacto de seguridad con mínimo esfuerzo:
{%- for win in quick_wins %}
- **{{ win.title }}** - {{ win.description }}
{%- endfor %}
{%- else %}

Revise los hallazgos marcados como de esfuerzo "Bajo" para mejoras rápidas de seguridad.
{%- endif %}

## 6.4 Matriz de Esfuerzo vs Impacto

<table style="width: 100%; max-width: 550px; margin: 20px auto; border-collapse: collapse; text-align: center;">
<tr>
<td style="border: none; width: 80px;"></td>
<td style="border: none;" colspan="3"><strong>IMPACTO</strong></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="border: none; color: #6b7280; padding: 8px;">Bajo</td>
<td style="border: none; color: #6b7280; padding: 8px;">Medio</td>
<td style="border: none; color: #6b7280; padding: 8px;">Alto</td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>E<br/>S<br/>F<br/>U<br/>E<br/>R<br/>Z<br/>O</strong></td>
<td style="background: #ef4444; color: white; padding: 15px; border-radius: 4px;"><strong>Evitar</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #f97316; color: white; padding: 15px; border-radius: 4px;"><strong>Considerar</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #eab308; color: white; padding: 15px; border-radius: 4px;"><strong>Agendar</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.high_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
<tr>
<td style="border: none; color: #6b7280; vertical-align: middle;"><strong>Alto<br/>↑<br/>Med<br/>↑<br/>Bajo</strong></td>
<td style="background: #94a3b8; color: white; padding: 15px; border-radius: 4px;"><strong>Diferir</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #3b82f6; color: white; padding: 15px; border-radius: 4px;"><strong>Planificar</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #8b5cf6; color: white; padding: 15px; border-radius: 4px;"><strong>Prioritario</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.medium_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
<tr>
<td style="border: none;"></td>
<td style="background: #64748b; color: white; padding: 15px; border-radius: 4px;"><strong>Si Hay Tiempo</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_low.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #22c55e; color: white; padding: 15px; border-radius: 4px;"><strong>Mejora Rápida</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_medium.count if effort_impact_matrix else 0 }}</span></td>
<td style="background: #16a34a; color: white; padding: 15px; border-radius: 4px;"><strong>¡HACER PRIMERO!</strong><br/><span style="font-size: 18pt;">{{ effort_impact_matrix.low_high.count if effort_impact_matrix else 0 }}</span></td>
</tr>
</table>

{% if effort_impact_matrix %}
**Resumen de priorización:**
{% if effort_impact_matrix.low_high.count > 0 %}- 🚀 **HACER PRIMERO ({{ effort_impact_matrix.low_high.count }})**: Bajo esfuerzo, alto impacto - victorias inmediatas{% endif %}
{% if effort_impact_matrix.low_medium.count > 0 %}- ✅ **Mejoras Rápidas ({{ effort_impact_matrix.low_medium.count }})**: Bajo esfuerzo, impacto medio - mejoras fáciles{% endif %}
{% if effort_impact_matrix.medium_high.count > 0 %}- ⚡ **Prioritario ({{ effort_impact_matrix.medium_high.count }})**: Esfuerzo medio, alto impacto - planifíquelos a continuación{% endif %}
{% if effort_impact_matrix.high_high.count > 0 %}- 📅 **Agendar ({{ effort_impact_matrix.high_high.count }})**: Alto esfuerzo, alto impacto - importantes pero complejos{% endif %}
{% endif %}

---

# 7. Anexos

## Anexo A: Detalles de Ejecución de Herramientas

{%- for tool in tool_outputs %}

### A.{{ loop.index }}. {{ tool.name }}

**Tiempo de ejecución:** {{ tool.duration | default('N/D') }}
**Código de salida:** {{ tool.exit_code | default('0') }}
**Hallazgos:** {{ tool.findings_count | default(0) }}

<details>
<summary>Salida cruda (clic para expandir)</summary>

```
{{ tool.output }}
```

</details>
{%- endfor %}

## Anexo B: Archivos Analizados

| # | Ruta del Archivo | Líneas | Funciones | Hallazgos |
|--:|-----------|------:|----------:|----------:|
{%- for file in files_analyzed %}
| {{ loop.index }} | `{{ file.path }}` | {{ file.lines }} | {{ file.functions | default('--') }} | {{ file.findings }} |
{%- endfor %}

## Anexo C: Cumplimiento del Registro SWC

| SWC ID | Título | Estado | Hallazgo(s) |
|--------|-------|--------|------------|
{%- for swc in swc_mappings %}
| [{{ swc.id }}](https://swcregistry.io/docs/{{ swc.id }}) | {{ swc.title }} | {{ swc.status_icon }} {{ swc.status }} | {{ swc.finding_ids | default('--') }} |
{%- endfor %}

## Anexo D: OWASP Smart Contract Top 10

| Rango | Categoría | Estado | Hallazgos |
|------|----------|--------|----------|
{%- for owasp in owasp_mappings %}
| {{ owasp.id }} | {{ owasp.category }} | {{ owasp.status_icon }} | {{ owasp.count }} |
{%- endfor %}

## Anexo E: Glosario

| Término | Definición |
|------|------------|
| **Reentrancy (Reentrada)** | Vulnerabilidad en la que una llamada externa permite que la ejecución vuelva a entrar al contrato llamante antes de que la primera ejecución termine |
| **Integer Overflow (Desbordamiento de entero)** | Cuando una operación aritmética produce un valor mayor al que puede almacenarse en la variable |
| **Front-running** | Explotar el conocimiento de transacciones pendientes para obtener una ventaja |
| **Flash Loan Attack (Ataque de préstamo flash)** | Usar préstamos sin colateral dentro de una única transacción para manipular protocolos |
| **Oracle Manipulation (Manipulación de oráculo)** | Atacar fuentes de precios o de datos externos para influir en el comportamiento del contrato |
| **Access Control (Control de acceso)** | Mecanismos que restringen quién puede ejecutar funciones sensibles |

## Anexo F: Traza de Auditoría

| Evento | Marca de tiempo | Hash |
|-------|-----------|------|
| Instantánea del contrato | {{ audit_date }} | `{{ commit_hash | default('N/D') }}` |
| Inicio del análisis | {{ analysis_start | default(audit_date) }} | -- |
| Fin del análisis | {{ analysis_end | default(generation_date) }} | -- |
| Informe generado | {{ generation_date }} | -- |
| Hash del informe | {{ generation_date }} | `{{ report_hash | default('N/D') }}` |

### Integridad del Informe

| Atributo | Valor |
|-----------|-------|
| Archivo de resultados de entrada (SHA-256) | `{{ input_sha256 | default('—', true) }}` |
| Versión de la plantilla del informe | {{ report_version | default('1.0') }} |
| Versión del generador (MIESC) | {{ generator_version | default(miesc_version) }} |
| Generado (UTC) | {{ generated_at_utc | default(generation_date) }} |

{% if input_sha256 %}Este informe se generó a partir de results.json con SHA-256 `{{ input_sha256 }}`; recalcúlelo (`shasum -a 256 <results.json>`) para verificar que el informe corresponde a este análisis.{% else %}El archivo de resultados de entrada no estaba disponible para el hash al momento de generar el informe, por lo que no se atesta ningún hash de integridad.{% endif %} Este hash atesta únicamente la correspondencia entre este informe y ese archivo de resultados; no atesta que el análisis se haya ejecutado correctamente, que las herramientas de análisis no hayan sido modificadas, ni que el código fuente analizado no haya sido sustituido.

---

# Descargo de Responsabilidad

Este informe de auditoría se provee "TAL CUAL" sin garantías de ningún tipo, ya sean expresas o implícitas. Los hallazgos y recomendaciones son el resultado de análisis automatizado basado en el alcance y la metodología descritos, y no constituyen una opinión profesional humana salvo que un auditor sea nombrado explícitamente en la portada y los avale.

**Este informe es el resultado de herramientas de seguridad automatizadas (más interpretación opcional por LLM local), no una auditoría profesional manual.** No ha sido revisado ni avalado por un auditor de seguridad humano salvo que un auditor sea nombrado explícitamente en la portada y avale los hallazgos.

**Limitaciones:**
- Esta auditoría no garantiza la ausencia de vulnerabilidades
- La seguridad de contratos inteligentes es un campo en evolución
- Pueden descubrirse nuevas vulnerabilidades tras la auditoría
- Los ataques económicos y de gobernanza pueden no estar completamente modelados
- El cliente es responsable de implementar y probar las correcciones

{%- if llm_enabled %}

**Divulgación sobre interpretación asistida por modelo:** Las secciones etiquetadas como asistidas por modelo se produjeron usando modelos de lenguaje de gran escala ({{ llm_model }}). Estas interpretaciones son complementarias y deben ser revisadas por profesionales de seguridad calificados antes de su uso operativo.
{%- endif %}

---

<div class="footer" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ccc;">

**Impulsado por [MIESC](https://github.com/fboiero/MIESC)**

Evaluación Inteligente Multicapa para Contratos Inteligentes

*Informe generado: {{ generation_date }}*

*Versión del informe: {{ report_version | default('1.0') }}*

</div>
