# Evaluación "No Hacer Daño"

**[English Version](DO_NO_HARM.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**
**Última actualización:** 2026-03-31

Esta evaluación aborda el Indicador 9 del Estándar DPGA y evalúa los riesgos potenciales asociados a MIESC, junto con las estrategias de mitigación implementadas.

---

## 9a. Riesgos de Privacidad y Seguridad de los Datos

### Evaluación de Riesgos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|-------------|---------|------------|
| Exposición de código de contratos propietario | Baja | Alto | Arquitectura local-first, sin exfiltración de datos |
| Filtración de datos de vulnerabilidades a atacantes | Baja | Alto | Almacenamiento local, controles de confidencialidad de reportes |
| LLM enviando código a servicios externos | Media | Medio | Ollama (local) por defecto, opt-in explícito para remoto |
| Exposición de datos del contenedor Docker | Baja | Bajo | Sin llamadas de red desde los contenedores, E/S basada en volúmenes |

### Detalles de Mitigación

1. **Arquitectura local-first:** MIESC procesa todos los datos localmente. Sin telemetría, sin analytics, sin llamadas a APIs externas durante el análisis.

2. **Manejo de datos por el LLM:** Al usar Ollama local, todo el procesamiento del LLM permanece en la máquina del usuario. Los proveedores de LLM remotos (OpenAI, Anthropic, DeepSeek) son opcionales y requieren configuración explícita.

3. **Seguridad de los reportes:** Los reportes generados incluyen encabezados de clasificación de confidencialidad. Los reportes se almacenan localmente y MIESC nunca los transmite.

4. **Sanitización de prompts:** El módulo `prompt_sanitizer` previene ataques de inyección de prompts que podrían extraer información sensible a través de las interacciones con el LLM.

---

## 9b. Riesgo de Doble Uso (Preocupación Principal)

### Naturaleza del Riesgo

MIESC es una **herramienta de seguridad de doble uso**. Su capacidad central —encontrar vulnerabilidades en contratos inteligentes— puede usarse tanto de forma defensiva como ofensiva:

- **Uso defensivo:** Encontrar y corregir vulnerabilidades antes del despliegue
- **Uso ofensivo:** Encontrar vulnerabilidades para explotarlas en contratos desplegados

Este es el mismo desafío de doble uso que enfrentan todos los escáneres de vulnerabilidades (Nessus, Burp Suite, Metasploit, etc.) y es inherente al campo de la seguridad.

### Evaluación de Riesgos

| Componente | Riesgo de Doble Uso | Severidad | Mitigación |
|------------|--------------------|-----------|------------|
| Escáner de vulnerabilidades (núcleo) | Medio | Medio | Riesgo estándar de herramientas de seguridad; igual que Slither, Mythril |
| Generador de PoC | Mayor | Medio | Genera PoC de entorno de prueba, no exploits de producción |
| Análisis con IA/LLM | Bajo | Bajo | Identifica patrones, no genera exploits |
| Generador de reportes | Bajo | Bajo | Documenta hallazgos para su remediación |
| Integración SARIF/CI | Bajo | Bajo | Se integra con flujos de trabajo defensivos |

### Estrategias de Mitigación

1. **Alcance del generador de PoC:** El generador de pruebas de concepto crea scripts de prueba de Foundry diseñados para ejecutarse en entornos de prueba locales. Los PoC generados:
   - Apuntan a redes de prueba locales Foundry/Anvil, no a cadenas de producción
   - Verifican la existencia de la vulnerabilidad, no maximizan el impacto de la explotación
   - Incluyen sugerencias de remediación junto con la demostración del exploit

2. **Política de uso responsable:** MIESC incluye una [Política de Uso Responsable](RESPONSIBLE_USE.md) que prohíbe explícitamente el uso malicioso.

3. **Licencia AGPL-3.0:** La licencia copyleft garantiza que cualquier servicio construido sobre MIESC deba publicar su código fuente, previniendo la instrumentalización propietaria.

4. **Gobernanza comunitaria:** El [Código de Conducta](../CODE_OF_CONDUCT.md) y la [Gobernanza](GOVERNANCE.md) del proyecto establecen expectativas claras para el comportamiento ético.

5. **Precedente de la industria:** MIESC sigue el mismo modelo de divulgación responsable que las herramientas de seguridad de código abierto establecidas:
   - [OWASP ZAP](https://www.zaproxy.org/) (escáner de vulnerabilidades web)
   - [Metasploit](https://www.metasploit.com/) (pruebas de penetración)
   - [Slither](https://github.com/crytic/slither) (análisis de contratos inteligentes)
   - [Mythril](https://github.com/ConsenSys/mythril) (ejecución simbólica)

### Evaluación del Impacto Neto

El **impacto neto es fuertemente positivo**:

- Los exploits de contratos inteligentes causaron **más de USD 1.8 mil millones en pérdidas en 2023** (fuente: DeFi Llama)
- MIESC democratiza el acceso al análisis de seguridad que antes solo estaba disponible a través de costosas firmas de auditoría
- El valor defensivo (prevenir exploits) supera con creces el riesgo ofensivo marginal (que existe con o sin MIESC, a través de otras herramientas disponibles gratuitamente)

---

## 9c. Contenido Inapropiado e Ilegal

### Evaluación

MIESC **no** genera, almacena ni distribuye ningún contenido que pueda clasificarse como inapropiado o ilegal. La herramienta:

- Procesa únicamente código fuente de contratos inteligentes
- Genera únicamente reportes técnicos de seguridad
- No aloja contenido generado por usuarios
- No incluye un componente social ni de mensajería
- No procesa, almacena ni genera datos personales

### Riesgo: Ninguno

---

## 9d. Protección frente al Acoso

### Evaluación

Las interacciones de la comunidad de MIESC se rigen por:

1. **Código de Conducta** ([English](../CODE_OF_CONDUCT.md)): Basado en el Contributor Covenant, estableciendo estándares para una participación respetuosa.

2. **Aplicación:** El mantenedor del proyecto (Fernando Boiero) es responsable de la aplicación, con procedimientos de escalamiento claros documentados en el Código de Conducta.

3. **Reporte:** Los miembros de la comunidad pueden reportar acoso a través de:
   - Email: fboiero@frvm.utn.edu.ar
   - GitHub Issues (para asuntos públicos)
   - Comunicación directa (para asuntos sensibles)

4. **Plazo de respuesta:** Los reportes de acoso se atienden dentro de las 48 horas.

---

## Resumen

| Indicador 9 DPGA | Nivel de Riesgo | Estado |
|------------------|-----------------|--------|
| 9a. Privacidad y Seguridad de Datos | Bajo | Mitigado (arquitectura local-first) |
| 9b. Doble Uso / Uso Dañino | Medio | Mitigado (política de uso responsable, limitaciones de PoC, licencia AGPL) |
| 9c. Contenido Inapropiado | Ninguno | No aplica |
| 9d. Protección frente al Acoso | Bajo | Mitigado (Código de Conducta, proceso de aplicación) |

**Evaluación General:** Los riesgos de MIESC están bien comprendidos, son estándar en la industria para herramientas de seguridad, y están adecuadamente mitigados mediante salvaguardas técnicas, gobernanza comunitaria y políticas de uso responsable.
