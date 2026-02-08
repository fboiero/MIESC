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
| **ID de Aplicación** | GID0092948 |
| **Fecha de Envío** | 5 de Diciembre, 2025 |
| **Estado** | En Revisión |
| **Revisión Esperada** | 4-8 semanas |
| **Contacto** | Bolaji Ayodeji (Evangelista DPG) |

---

## Resumen Ejecutivo

MIESC es un framework de análisis de seguridad de código abierto para contratos inteligentes que avanza el **ODS 9 (Industria, Innovación e Infraestructura)** y el **ODS 16 (Paz, Justicia e Instituciones Sólidas)** proporcionando herramientas de ciberseguridad accesibles y transparentes para ecosistemas blockchain.

| Indicador | Estado | Evidencia |
|-----------|--------|-----------|
| 1. Relevancia ODS | Cumple | [Alineación ODS](#indicador-1-relevancia-ods) |
| 2. Licencia Abierta | Cumple | [Licencia AGPL-3.0](./LICENSE) |
| 3. Propiedad Clara | Cumple | [Declaración de Propiedad](#indicador-3-propiedad-clara) |
| 4. Independencia de Plataforma | Cumple | [Arquitectura Técnica](#indicador-4-independencia-de-plataforma) |
| 5. Documentación | Cumple | [Documentación](#indicador-5-documentación) |
| 6. Extracción de Datos | Cumple | [Formatos de Exportación](#indicador-6-extracción-de-datos) |
| 7. Privacidad y Leyes | Cumple | [Política de Privacidad](./PRIVACY_ES.md) |
| 8. Estándares y Mejores Prácticas | Cumple | [Cumplimiento de Estándares](#indicador-8-estándares-y-mejores-prácticas) |
| 9. No Dañar | Cumple | [Prevención de Daños](#indicador-9-no-dañar) |

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
| Herramientas Integradas | 25 | Orquestación multi-herramienta reduciendo barreras al análisis de seguridad |
| Estándares de Cumplimiento | 12 | Mapeo automatizado a estándares ISO/NIST/OWASP |
| Precisión de Detección | 94.5% | Validación empírica en dataset SmartBugs |
| Reducción de Falsos Positivos | 89% | Filtrado de correlación asistido por IA |
| Ahorro de Costos | ~$50,000/auditoría | Comparado con alternativas comerciales |

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

Texto completo de la licencia: [LICENSE](./LICENSE)

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
| **Institución** | Universidad de la Defensa Nacional (UNDEF), Argentina |
| **Repositorio** | https://github.com/fboiero/MIESC |
| **Contacto** | fboiero@frvm.utn.edu.ar |

### Propiedad Intelectual

- **Código Fuente**: Copyright 2024-2025 Fernando Boiero, licenciado bajo AGPL-3.0
- **Documentación**: Copyright 2024-2025 Fernando Boiero, licenciado bajo CC-BY-4.0
- **Marcas Registradas**: Nombre y logo "MIESC" propiedad de Fernando Boiero
- **Patentes**: No se han solicitado patentes; compromiso con desarrollo libre de patentes

### Contexto Académico

MIESC fue desarrollado como parte de una tesis de Maestría en Ciberdefensa en la Universidad de la Defensa Nacional (UNDEF), Argentina. La universidad apoya la publicación de código abierto de los resultados de investigación.

---

## Indicador 4: Independencia de Plataforma

### Arquitectura Core

MIESC está diseñado para la independencia de plataforma:

```
┌─────────────────────────────────────────────────┐
│                    MIESC Core                    │
│  (Python 3.9+ - Multiplataforma)                │
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
| Guía de Usuario | [docs/](./docs/) | Instalación, configuración, uso |
| Referencia API | [docs/openapi.yaml](./docs/openapi.yaml) | Especificación OpenAPI 3.0 |
| Arquitectura | [docs/01_ARCHITECTURE.md](./docs/01_ARCHITECTURE.md) | Diseño del sistema y componentes |
| Guía de Demo | [docs/03_DEMO_GUIDE.md](./docs/03_DEMO_GUIDE.md) | Tutoriales paso a paso |
| Guía de Desarrollador | [docs/DEVELOPER_GUIDE.md](./docs/DEVELOPER_GUIDE.md) | Contribuir y extender |
| Docs Hosteados | [fboiero.github.io/MIESC](https://fboiero.github.io/MIESC) | Sitio generado con MkDocs |

### Inicio Rápido

```bash
# Clonar repositorio
git clone https://github.com/fboiero/MIESC.git
cd MIESC

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar demo
python3 examples/demo_v4.0.py
```

### Soporte Multilingüe

- Inglés: [README.md](./README.md)
- Español: [README_ES.md](./README_ES.md)

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
| Pruebas | 117 pruebas, 87.5% cobertura |
| CI/CD | Pipeline de GitHub Actions |
| Escaneo de Seguridad | Bandit, Semgrep, Snyk |
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
- **Código de Conducta**: [CODE_OF_CONDUCT_ES.md](./CODE_OF_CONDUCT_ES.md)

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
| **Institución** | Universidad de la Defensa Nacional (UNDEF) |
| **GitHub** | https://github.com/fboiero/MIESC |
| **Documentación** | https://fboiero.github.io/MIESC |

---

## Solicitud de Certificación

Este documento sirve como la aplicación de MIESC para reconocimiento como Bien Público Digital bajo el Estándar DPGA v1.1.6.

**Enviado por**: Fernando Boiero
**Fecha**: Diciembre 2024
**Versión**: 1.0

---

## Referencias

- [Alianza de Bienes Públicos Digitales](https://digitalpublicgoods.net/)
- [Estándar DPG v1.1.6](https://github.com/DPGAlliance/DPG-Standard)
- [Guía de Envío DPGA](https://digitalpublicgoods.net/submission-guide)
- [Hoja de Ruta del Secretario General de la ONU para la Cooperación Digital](https://www.un.org/en/content/digital-cooperation-roadmap/)
