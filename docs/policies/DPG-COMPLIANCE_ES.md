# Declaración de Cumplimiento de Bienes Públicos Digitales

**[English Version](DPG-COMPLIANCE.md)**

**MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes**

[![Estándar DPG](https://img.shields.io/badge/Estándar%20DPG-v1.1.6-blue)](https://digitalpublicgoods.net/standard/)
[![Aplicación DPGA](https://img.shields.io/badge/DPGA-En%20Revisión-yellow)](https://app.digitalpublicgoods.net/a/13478)
[![Licencia: AGPL v3](https://img.shields.io/badge/Licencia-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Este documento demuestra el cumplimiento de MIESC con el [Estándar de Bienes Públicos Digitales](https://github.com/DPGAlliance/DPG-Standard) (v1.1.6) establecido por la [Alianza de Bienes Públicos Digitales (DPGA)](https://digitalpublicgoods.net/).

---

## Estado de la Aplicación

| Campo | Valor |
|-------|-------|
| **Aplicación DPGA** | [#13478](https://app.digitalpublicgoods.net/a/13478) |
| **GID (ID Global)** | GID0092948 |
| **Fecha de Envío** | 5 de Diciembre, 2025 |
| **Estado** | En Revisión (enviada el 2025-12-05) |
| **Contacto** | Bolaji Ayodeji (Evangelista DPG) |

> Los dos identificadores corresponden al mismo envío: **13478** es el número de
> aplicación DPGA (usado en la URL de app.digitalpublicgoods.net) y
> **GID0092948** es su ID Global (GID). No son una discrepancia.

---

## Resumen Ejecutivo

MIESC es un framework de análisis de seguridad de código abierto para contratos inteligentes que avanza el **ODS 9 (Industria, Innovación e Infraestructura)** y el **ODS 16 (Paz, Justicia e Instituciones Sólidas)** proporcionando herramientas de ciberseguridad accesibles y transparentes para ecosistemas blockchain.

| Indicador | Estado | Evidencia |
|-----------|--------|-----------|
| 1. Relevancia ODS | Cumple | [Alineación ODS](#indicador-1-relevancia-ods) |
| 2. Licencia Abierta | Cumple | [Licencia AGPL-3.0](https://github.com/fboiero/MIESC/blob/main/LICENSE) |
| 3. Propiedad Clara | Cumple | [Declaración de Propiedad](#indicador-3-propiedad-clara) |
| 4. Independencia de Plataforma | Cumple | [Arquitectura Técnica](#indicador-4-independencia-de-plataforma) |
| 5. Documentación | Cumple | Documentación |
| 6. Extracción de Datos | Cumple | Formatos de Exportación |
| 7. Privacidad y Leyes | Cumple | [Política de Privacidad](./PRIVACY_ES.md) |
| 8. Estándares y Mejores Prácticas | Cumple | Cumplimiento de Estándares |
| 9. No Dañar | Cumple | Prevención de Daños |

---

## Indicador 1: Relevancia ODS

### Alineación Primaria con ODS

**ODS 9: Industria, Innovación e Infraestructura**
- **Meta 9.b**: Apoyar el desarrollo tecnológico nacional, la investigación y la innovación en países en desarrollo
- **Contribución**: MIESC democratiza el acceso a herramientas de seguridad de contratos inteligentes de nivel empresarial, permitiendo a desarrolladores de todo el mundo construir aplicaciones blockchain seguras sin licencias comerciales costosas

**ODS 16: Paz, Justicia e Instituciones Sólidas**
- **Meta 16.5**: Reducir sustancialmente la corrupción y el soborno en todas sus formas
- **Meta 16.6**: Desarrollar instituciones efectivas, responsables y transparentes
- **Contribución**: La verificación de seguridad automatizada de contratos inteligentes aumenta la transparencia y reduce las oportunidades de fraude financiero en sistemas blockchain

### Alineación Secundaria con ODS

**ODS 8: Trabajo Decente y Crecimiento Económico**
- **Meta 8.10**: Fortalecer la capacidad de las instituciones financieras nacionales para fomentar y ampliar el acceso a servicios bancarios, de seguros y financieros
- **Contribución**: Los protocolos DeFi seguros permiten una mayor inclusión financiera a través de finanzas descentralizadas confiables

**ODS 17: Alianzas para los Objetivos**
- **Meta 17.6**: Mejorar la cooperación Norte-Sur, Sur-Sur y triangular regional e internacional en ciencia, tecnología e innovación
- **Contribución**: El framework de código abierto permite la colaboración global en investigación de seguridad blockchain

### Métricas de Impacto

| Métrica | Valor | Evidencia |
|---------|-------|-----------|
| Herramientas Integradas | 50 | A través de 9 capas de defensa (35 contadas como módulos de análisis en Paper 1); orquestación multi-herramienta reduciendo barreras |
| Estándares de Cumplimiento | 12 | Mapeo automatizado a estándares ISO/NIST/OWASP |
| Recall de Detección | 95.8% (137/143) | SmartBugs-curated; ver paper1_smartbugs_eval_layers_1_6_7.json (perfil reproducible de Paper 1) |
| Hallazgos post-filtro | ~2–3 por contrato | Supresión de FP context-aware (Paper 1, Gestión de Falsos Positivos) |
| Costo | Gratis (vs. $20K–60K) | Open-source vs. auditorías comerciales |

### Casos de Uso para el Desarrollo

1. **Proyectos Blockchain Gubernamentales**: Verificación de seguridad para implementaciones blockchain del sector público
2. **DeFi en Mercados Emergentes**: Habilitando finanzas descentralizadas seguras en regiones sub-bancarizadas
3. **Investigación Académica**: Análisis de seguridad reproducible para investigación blockchain
4. **Transparencia de ONGs**: Auditoría de contratos inteligentes para seguimiento de donaciones caritativas

---

## Indicador 2: Licencia Abierta

### Tipo de Licencia

**GNU Affero General Public License v3.0 (AGPL-3.0)**

Esta licencia está [aprobada por OSI](https://opensource.org/licenses/AGPL-3.0) y asegura:
- Libertad para usar, estudiar, modificar y distribuir
- El uso en red activa el copyleft (las modificaciones deben compartirse)
- Las obras derivadas permanecen de código abierto
- Se permite uso comercial con atribución

### Archivo de Licencia

Texto completo de la licencia: [LICENSE](https://github.com/fboiero/MIESC/blob/main/LICENSE)

### Componentes de Terceros

Todas las dependencias usan licencias de código abierto compatibles:

| Componente | Licencia | Compatibilidad |
|------------|----------|----------------|
| Slither | AGPL-3.0 | Compatible |
| Mythril | MIT | Compatible |
| Echidna | AGPL-3.0 | Compatible |
| Foundry | MIT/Apache-2.0 | Compatible |
| Halmos | AGPL-3.0 | Compatible |
| Ollama | MIT | Compatible |

---

## Indicador 3: Propiedad Clara

### Propiedad del Proyecto

| Atributo | Valor |
|----------|-------|
| **Nombre del Proyecto** | MIESC - Evaluación Inteligente Multicapa para Contratos Inteligentes |
| **Titular del Copyright** | Fernando Boiero |
| **Institución** | Originada en la Universidad de la Defensa Nacional (UNDEF); continúa como investigación en la Universidad Tecnológica Nacional, Facultad Regional Villa María (UTN-FRVM), Argentina |
| **Repositorio** | https://github.com/fboiero/MIESC |
| **Contacto** | fboiero@frvm.utn.edu.ar |

### Propiedad Intelectual

- **Código Fuente**: Copyright 2024-2026 Fernando Boiero, licenciado bajo AGPL-3.0
- **Documentación**: Copyright 2024-2026 Fernando Boiero, licenciado bajo CC-BY-4.0
- **Marcas Registradas**: Nombre y logo "MIESC" propiedad de Fernando Boiero
- **Patentes**: No se han solicitado patentes; compromiso con desarrollo libre de patentes

### Contexto Académico

MIESC se originó como una tesis de Maestría en Ciberdefensa en la Universidad de la Defensa Nacional (UNDEF), Argentina, y continúa como proyecto de investigación en la Universidad Tecnológica Nacional, Facultad Regional Villa María (UTN-FRVM). Ambas instituciones apoyan la publicación de código abierto de los resultados de investigación.

---

## Indicador 4: Independencia de Plataforma

### Arquitectura Core

MIESC está diseñado para la independencia de plataforma:

```
┌─────────────────────────────────────────────────┐
│                    MIESC Core                    │
│  (Python 3.12+ - Multiplataforma)               │
├─────────────────────────────────────────────────┤
│  Adaptadores de Herramientas (Arquitectura      │
│                               Pluggable)        │
│  - Cada herramienta es opcional                 │
│  - Degradación elegante cuando herramientas     │
│    no están disponibles                         │
├─────────────────────────────────────────────────┤
│  Estándares Abiertos                            │
│  - JSON-RPC (Protocolo MCP)                     │
│  - SARIF (Resultados de Análisis Estático)      │
│  - OpenAPI (REST API)                           │
└─────────────────────────────────────────────────┘
```

### Análisis de Dependencias

| Dependencia | Tipo | Alternativa Abierta |
|-------------|------|---------------------|
| Python | Runtime | Código abierto (Licencia PSF) |
| Compilador Solidity | Build | Código abierto (GPL-3.0) |
| Ollama | Inferencia IA | Código abierto (MIT) |
| PostgreSQL | Base de datos (opcional) | Código abierto (Licencia PostgreSQL) |
| Docker | Containerización | Código abierto (Apache-2.0) |

### Sin Vendor Lock-in

- **Modelos de IA**: Usa LLMs locales (Ollama) por defecto; no requiere API en la nube
- **Base de datos**: SQLite por defecto; PostgreSQL opcional
- **Servicios en la Nube**: Totalmente funcional offline; sin dependencias de nube
- **Herramientas Propietarias**: Integraciones opcionales (ej., Certora) no requeridas para funcionalidad core

---

## Indicador 5: Documentación

### Estructura de Documentación

| Recurso | Ubicación | Descripción |
|---------|-----------|-------------|
| Guía de Usuario | [docs/index_es.md](../index_es.md) | Instalación, configuración, uso |
| Referencia API | [docs/openapi.yaml](../openapi.yaml) | Especificación OpenAPI 3.0 |
| Arquitectura | [docs/ARCHITECTURE.md](../ARCHITECTURE.md) | Diseño del sistema y componentes |
| Inicio Rápido | [docs/guides/QUICKSTART_ES.md](../guides/QUICKSTART_ES.md) | Tutoriales paso a paso |
| Guía de Desarrollador | [docs/CONTRIBUTING.md](../CONTRIBUTING.md) | Contribuir y extender |
| Docs Hosteados | [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC) | Sitio generado con MkDocs |

### Inicio Rápido

```bash
# Clonar repositorio
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar smoke local
miesc scan tests/fixtures/reentrancy.sol --fp-strictness off
```

### Soporte Multilingüe

- Inglés: [README.md](https://github.com/fboiero/MIESC/blob/main/README.md)
- Español: [README_ES.md](https://github.com/fboiero/MIESC/blob/main/README_ES.md)

---

## Indicador 6: Extracción de Datos

### Formatos de Exportación

MIESC soporta múltiples formatos de exportación abiertos y no propietarios:

| Formato | Estándar | Caso de Uso |
|---------|----------|-------------|
| JSON | RFC 8259 | Reportes legibles por máquina |
| SARIF | OASIS | Integración IDE, CI/CD |
| Markdown | CommonMark | Reportes legibles por humanos |
| HTML | W3C | Dashboards interactivos |
| PDF | ISO 32000 | Documentación formal |
| CSV | RFC 4180 | Análisis en hojas de cálculo |

### Portabilidad de Datos

```python
from miesc import MiescFramework

auditor = MiescFramework()
report = auditor.analyze("contract.sol")

# Exportar a múltiples formatos
report.export("results.json", format="json")
report.export("results.sarif", format="sarif")
report.export("results.md", format="markdown")
report.export("results.csv", format="csv")
```

### Sin Data Lock-in

- Todos los resultados de análisis exportables en formatos abiertos
- Sin formatos binarios propietarios
- Propiedad total de datos retenida por el usuario
- Acceso API a todas las estructuras de datos internas

---

## Indicador 7: Privacidad y Leyes Aplicables

### Declaración de Privacidad

Ver política completa: [PRIVACY_ES.md](./PRIVACY_ES.md)

**Principios Clave**:
1. **Procesamiento Local**: Todo el análisis se ejecuta localmente; el código nunca sale de la máquina del usuario
2. **Sin Telemetría**: Sin recopilación de datos de uso sin consentimiento explícito
3. **IA Soberana**: El LLM por defecto (Ollama) se ejecuta localmente; sin llamadas a API externas
4. **Minimización de Datos**: Solo procesa archivos explícitamente proporcionados por el usuario

### Cumplimiento Legal

| Regulación | Cumplimiento | Notas |
|------------|--------------|-------|
| GDPR (UE) | Cumple | Sin procesamiento de datos personales |
| CCPA (California) | Cumple | Sin recopilación de datos personales |
| Ley de Protección de Datos Argentina | Cumple | Solo procesamiento local |

### Divulgación Responsable

Vulnerabilidades de seguridad: fboiero@frvm.utn.edu.ar (respuesta dentro de 48 horas)

---

## Indicador 8: Estándares y Mejores Prácticas

### Adherencia a Estándares Abiertos

| Estándar | Implementación |
|----------|----------------|
| [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) | Interfaz JSON-RPC para integración de IA |
| [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) | Formato de resultados de análisis estático |
| [OpenAPI 3.0](https://swagger.io/specification/) | Especificación REST API |
| [Registro SWC](https://swcregistry.io/) | Clasificación de vulnerabilidades |
| [CWE](https://cwe.mitre.org/) | Enumeración de Debilidades Comunes |

### Mapeo de Estándares de Seguridad

MIESC mapea hallazgos a 12 estándares internacionales:
- ISO/IEC 27001:2022
- ISO/IEC 42001:2023 (Gobernanza de IA)
- NIST SP 800-218
- OWASP Smart Contract Security
- EU DORA (Resiliencia Operacional Digital)

### Mejores Prácticas de Desarrollo

| Práctica | Implementación |
|----------|----------------|
| Control de Versiones | Git con commits firmados |
| Revisión de Código | Pull request requerido |
| Pruebas | 5967 pruebas pasando, 8 omitidas en la ultima regresion local completa |
| CI/CD | Pipeline de GitHub Actions |
| Escaneo de Seguridad | Bandit, pip-audit, safety (dependencias); Trivy + carga SARIF a CodeQL (imagen Docker) — ver `.github/workflows/ci.yml` |
| Documentación | MkDocs con versionado |

---

## Indicador 9: No Dañar

### Evaluación de Riesgos

| Categoría de Riesgo | Evaluación | Mitigación |
|---------------------|------------|------------|
| **Privacidad** | Bajo | Procesamiento local, sin recopilación de datos |
| **Seguridad** | Bajo | La herramienta emite advertencias, no modifica código |
| **Desinformación** | Bajo | Disclaimer claro sobre limitaciones |
| **Discriminación** | N/A | No procesa datos personales |
| **Daño Económico** | Bajo | Herramienta gratuita reduce costos de auditoría |

### Consideraciones de Doble Uso

MIESC es una herramienta de análisis de vulnerabilidades, y la información de
vulnerabilidades es inherentemente de doble uso: un hallazgo que ayuda a un
desarrollador a corregir un bug podría, en principio, informar a un atacante. Lo
abordamos de forma directa en lugar de ignorarlo:

- **Orientación defensiva**: MIESC está diseñado para triage *previo al despliegue*
  de los contratos propios del usuario. Sus salidas —hallazgos con guía de
  remediación, parches, tests y especificaciones formales generadas— se orientan a
  *cerrar* vulnerabilidades, no a explotarlas.
- **Sin escaneo masivo ni ofensivo**: MIESC analiza el código fuente que el usuario
  provee explícitamente. No rastrea ni escanea a escala contratos desplegados de
  terceros, y no incluye herramientas de explotación o extracción de fondos.
- **Prueba de concepto acotada**: la generación de tests de exploit se limita a
  confirmar una vulnerabilidad en el contrato propio del usuario y a verificar que un
  parche la bloquea—no a producir ataques desplegables.
- **Base de conocimiento pública**: los patrones que MIESC detecta ya son públicos
  (SWC Registry, CWE, literatura revisada por pares, reportes post-mortem). MIESC
  democratiza el *acceso a la defensa*; no crea capacidad ofensiva nueva.
- **Corrección de asimetría**: las auditorías profesionales cuestan \$20K–60K y son
  inaccesibles para la mayoría de los equipos, mientras los atacantes ya están bien
  financiados. Bajar el costo del análisis defensivo hacia cero corre la asimetría de
  seguridad *hacia los defensores*, que es la razón de bien-público del proyecto.
- **Divulgación responsable**: MIESC ofrece un contacto de seguridad con compromiso
  de respuesta en 48 horas para problemas en MIESC, y su documentación fomenta la
  divulgación responsable de vulnerabilidades encontradas en código de terceros.

### Salvaguardas

1. **Disclaimers Claros**: La documentación establece que MIESC es una herramienta de triaje pre-auditoría, no un reemplazo de auditorías profesionales
2. **Sin Arreglos Automáticos**: No modifica código del usuario; solo reporta hallazgos
3. **IA Responsable**: Uso de LLM local previene fuga de datos
4. **Enfoque Educativo**: Incluye explicaciones y guía de remediación

### Moderación de Contenido

No aplica - MIESC no aloja contenido generado por usuarios ni características sociales.

### Seguridad Infantil

No aplica - MIESC es una herramienta de desarrollo que no interactúa con menores.

### Contenido Dañino

Los componentes de IA de MIESC están restringidos al análisis de seguridad y no pueden generar:
- Código malicioso o exploits (más allá de prueba de concepto para propósitos educativos)
- Contenido dañino
- Salidas sesgadas

---

## Gobernanza

### Gobernanza del Proyecto

Ver: [GOVERNANCE_ES.md](./GOVERNANCE_ES.md)

- **Mantenedor**: Fernando Boiero
- **Proceso de Decisión**: Propuestas estilo RFC para cambios mayores
- **Comunidad**: GitHub Discussions para solicitudes de características
- **Código de Conducta**: [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

### Plan de Sostenibilidad

1. **Soporte Académico**: Desarrollo continuo como parte de investigación en curso
2. **Contribuciones de la Comunidad**: Abierto a contribuidores externos
3. **Financiamiento por Grants**: Buscando financiamiento DPGA pathfinder
4. **Adopción Institucional**: Alianzas con universidades e instituciones de investigación

---

## Información de Contacto

| Rol | Contacto |
|-----|----------|
| **Líder del Proyecto** | Fernando Boiero |
| **Email** | fboiero@frvm.utn.edu.ar |
| **Institución** | Originada en la Universidad de la Defensa Nacional (UNDEF); continúa en UTN-FRVM, Argentina |
| **GitHub** | https://github.com/fboiero/MIESC |
| **Documentación** | https://fboiero.github.io/MIESC |

---

## Solicitud de Certificación

Este documento sirve como la aplicación de MIESC para reconocimiento como Bien Público Digital bajo el Estándar DPGA v1.1.6.

**Enviado por**: Fernando Boiero
**Envío DPGA**: 5 de Diciembre de 2025 (aplicación #13478 / GID0092948)
**Última actualización**: Julio 2026 (evidencia reconciliada para la versión v6.0.0)

---

## Referencias

- [Alianza de Bienes Públicos Digitales](https://digitalpublicgoods.net/)
- [Estándar DPG v1.1.6](https://github.com/DPGAlliance/DPG-Standard)
- [Guía de Envío DPGA](https://digitalpublicgoods.net/submission-guide)
- [Hoja de Ruta del Secretario General de la ONU para la Cooperación Digital](https://www.un.org/en/content/digital-cooperation-roadmap/)
